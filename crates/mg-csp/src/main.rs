/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-csp — Content Security Policy analyzer
 *                  Parses CSP headers from crawl output or live probes,
 *                  flags dangerous directives, and suggests bypass chains.
 * Notes:           CSP is read from crawl stored headers first; falls back
 *                  to a fresh GET for each recon host when crawl is absent.
 *                  Directive parsing is whitespace-split; `;` separates
 *                  directives.  All matching is case-insensitive.
 *******************************************************************/

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "csp";
const AUDIT_TOOL: &str = "mg-csp";
const CSP_HEADER_NAME: &str = "content-security-policy";

// Domains known to have JSONP endpoints — allows CSP bypass via script-src
const JSONP_BYPASS_DOMAINS: &[&str] = &[
    "*.google.com",
    "*.googleapis.com",
    "*.gstatic.com",
    "*.youtube.com",
    "ajax.googleapis.com",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-csp",
    about = "Content Security Policy analyzer — flags dangerous directives and bypass chains"
)]
struct Args {
    /// Engagement name (must have engagement.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent live probes
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Crawl stored response header record
#[derive(Deserialize)]
struct StoredResponse {
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
}

// Mirrors the HostRecord shape from recon/summary.json
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Recon summary root
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// One CSP finding with severity and bypass suggestion
#[derive(Debug, Serialize)]
struct CspFinding {
    directive: String,
    issue: String,
    severity: String,
    bypass_suggestion: String,
}

// Result for one URL/host
#[derive(Debug, Serialize)]
struct CspResult {
    url: String,
    csp_header: Option<String>,
    findings: Vec<CspFinding>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CspResults {
    engagement: String,
    timestamp: String,
    urls_analyzed: usize,
    findings_count: usize,
    results: Vec<CspResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Build base URL for a recon host, preferring HTTPS
fn base_url_for_host(rec: &HostRecord) -> String {
    if rec.open_ports.contains(&443) {
        return format!("https://{}", rec.hostname);
    }
    if rec.open_ports.contains(&80) {
        return format!("http://{}", rec.hostname);
    }
    format!("https://{}", rec.hostname)
}

// Parse a CSP header string into a map of directive name → vec of source values
// All keys are lower-cased; source values preserve case
fn parse_csp(header: &str) -> HashMap<String, Vec<String>> {
    let mut directives: HashMap<String, Vec<String>> = HashMap::new();
    for part in header.split(';') {
        let mut tokens = part.split_whitespace();
        let Some(name) = tokens.next() else { continue };
        let sources: Vec<String> = tokens.map(|s| s.to_string()).collect();
        directives.insert(name.to_lowercase(), sources);
    }
    directives
}

// Check whether a source token matches a known JSONP-bypass domain pattern
fn is_jsonp_domain(source: &str) -> bool {
    let lower = source.to_lowercase();
    for &domain in JSONP_BYPASS_DOMAINS {
        // Simple suffix match: strip leading "*." from pattern and check suffix
        let pattern = domain.trim_start_matches("*.");
        if lower == domain || lower.ends_with(pattern) {
            return true;
        }
    }
    false
}

// Check whether a source token is a wildcard subdomain (*.example.com pattern)
fn is_wildcard_subdomain(source: &str) -> bool {
    source.starts_with("*.") && source.len() > 2
}

// Analyze a parsed CSP directive map and return all findings
fn analyze_csp(directives: &HashMap<String, Vec<String>>) -> Vec<CspFinding> {
    let mut findings = Vec::new();

    let script_sources = directives.get("script-src").cloned().unwrap_or_default();
    let default_sources = directives.get("default-src").cloned().unwrap_or_default();

    // Effective script sources: script-src if present, else fall back to default-src
    let effective_script = if !script_sources.is_empty() {
        &script_sources
    } else {
        &default_sources
    };

    // Wildcard in script-src or default-src → any source allowed
    if effective_script.iter().any(|s| s == "*") {
        let directive = if !script_sources.is_empty() { "script-src" } else { "default-src" };
        findings.push(CspFinding {
            directive: directive.into(),
            issue: "wildcard '*' allows scripts from any origin".into(),
            severity: "HIGH".into(),
            bypass_suggestion: "load malicious JS from any domain".into(),
        });
    }

    // unsafe-inline in script-src
    if effective_script.iter().any(|s| s.eq_ignore_ascii_case("'unsafe-inline'")) {
        findings.push(CspFinding {
            directive: "script-src".into(),
            issue: "'unsafe-inline' allows inline script execution".into(),
            severity: "HIGH".into(),
            bypass_suggestion: "inject <script>alert(1)</script> directly into the page".into(),
        });
    }

    // unsafe-eval in script-src
    if effective_script.iter().any(|s| s.eq_ignore_ascii_case("'unsafe-eval'")) {
        findings.push(CspFinding {
            directive: "script-src".into(),
            issue: "'unsafe-eval' allows eval() and Function() constructor".into(),
            severity: "HIGH".into(),
            bypass_suggestion: "use eval() or setTimeout(string) to execute arbitrary code".into(),
        });
    }

    // data: URI in script-src
    if effective_script.iter().any(|s| s.eq_ignore_ascii_case("data:")) {
        findings.push(CspFinding {
            directive: "script-src".into(),
            issue: "'data:' URI scheme allows inline script via data URI".into(),
            severity: "HIGH".into(),
            bypass_suggestion: "use <script src=\"data:text/javascript,alert(1)\">".into(),
        });
    }

    // Missing both default-src and script-src → no script restriction
    if directives.get("script-src").is_none() && directives.get("default-src").is_none() {
        findings.push(CspFinding {
            directive: "script-src".into(),
            issue: "no script-src or default-src — no script restriction in place".into(),
            severity: "HIGH".into(),
            bypass_suggestion: "CSP provides no script protection; XSS is unrestricted".into(),
        });
    }

    // JSONP-able domains in effective script sources
    for source in effective_script {
        if is_jsonp_domain(source) {
            findings.push(CspFinding {
                directive: "script-src".into(),
                issue: format!("'{source}' is a JSONP-capable domain — CSP bypass possible"),
                severity: "HIGH".into(),
                bypass_suggestion: format!(
                    "use JSONP endpoint on {source} to load attacker-controlled JS"
                ),
            });
        }
    }

    // Wildcard subdomains in script-src
    for source in effective_script {
        if is_wildcard_subdomain(source) {
            findings.push(CspFinding {
                directive: "script-src".into(),
                issue: format!("'{source}' wildcard allows any subdomain — subdomain takeover bypass"),
                severity: "MEDIUM".into(),
                bypass_suggestion: "take over a subdomain matching the wildcard to serve malicious JS".into(),
            });
        }
    }

    // http: in any directive on a page (mixed content bypass)
    for (name, sources) in directives {
        if sources.iter().any(|s| s.eq_ignore_ascii_case("http:")) {
            findings.push(CspFinding {
                directive: name.clone(),
                issue: format!("'http:' in {name} allows loading resources over plaintext HTTP"),
                severity: "MEDIUM".into(),
                bypass_suggestion: "serve malicious resource over HTTP via MitM or rogue HTTP host".into(),
            });
        }
    }

    // Missing frame-ancestors → clickjacking possible
    if !directives.contains_key("frame-ancestors") {
        findings.push(CspFinding {
            directive: "frame-ancestors".into(),
            issue: "missing frame-ancestors — clickjacking not mitigated by CSP".into(),
            severity: "MEDIUM".into(),
            bypass_suggestion: "embed page in an <iframe> on attacker.com".into(),
        });
    }

    // Missing object-src with non-none default → plugin/Flash bypass
    if !directives.contains_key("object-src") {
        let default_is_none = default_sources
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'none'"));
        if !default_is_none {
            findings.push(CspFinding {
                directive: "object-src".into(),
                issue: "missing object-src with non-'none' default — Flash/plugin execution possible".into(),
                severity: "MEDIUM".into(),
                bypass_suggestion: "embed a malicious <object> or <embed> tag".into(),
            });
        }
    }

    findings
}

// Collect CSP values from crawl stored response headers
fn collect_from_crawl(crawl_dir: &Path) -> Vec<(String, String)> {
    // Returns (url, csp_value) pairs
    let mut pairs = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return pairs;
    };
    for host_entry in hosts.flatten() {
        if !host_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let index_path = host_entry.path().join("index.json");
        let Ok(raw) = fs::read_to_string(&index_path) else {
            continue;
        };
        let Ok(entries): Result<Vec<StoredResponse>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for entry in entries {
            // Headers may be stored with mixed case — find case-insensitively
            for (k, v) in &entry.headers {
                if k.to_lowercase() == CSP_HEADER_NAME {
                    pairs.push((entry.url.clone(), v.clone()));
                    break;
                }
            }
        }
    }
    pairs
}

// Fetch CSP header from a live URL via GET request
async fn fetch_csp(client: reqwest::Client, url: String) -> (String, Option<String>) {
    let Ok(resp) = client.get(&url).send().await else {
        return (url, None);
    };
    let csp = resp
        .headers()
        .get(CSP_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (url, csp)
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Try crawl corpus first
    let crawl_pairs = collect_from_crawl(&eng.crawl_dir());

    let mut url_csp_pairs: Vec<(String, Option<String>)> = crawl_pairs
        .into_iter()
        .map(|(url, csp)| (url, Some(csp)))
        .collect();

    // Fall back to live probes if crawl produced nothing
    if url_csp_pairs.is_empty() {
        eprintln!("mg-csp: no crawl CSP data — probing recon hosts");
        let summary_path = eng.recon_dir().join("summary.json");
        let raw = fs::read_to_string(&summary_path).context("read recon/summary.json")?;
        let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;
        let scope = eng.scope().context("load scope")?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout))
            .danger_accept_invalid_certs(true)
            .build()
            .context("build HTTP client")?;

        let mut join_set: JoinSet<(String, Option<String>)> = JoinSet::new();

        for host in &summary.hosts {
            if !host.http_accessible || !scope.is_in_scope(&host.hostname) {
                continue;
            }
            let url = base_url_for_host(host);
            if join_set.len() >= args.concurrency
                && let Some(Ok(pair)) = join_set.join_next().await
            {
                url_csp_pairs.push(pair);
            }
            let c = client.clone();
            join_set.spawn(fetch_csp(c, url));
        }

        while let Some(Ok(pair)) = join_set.join_next().await {
            url_csp_pairs.push(pair);
        }
    }

    eprintln!("mg-csp: {} URLs to analyze", url_csp_pairs.len());

    // Analyze each URL
    let mut all_results: Vec<CspResult> = Vec::new();
    for (url, csp_opt) in url_csp_pairs {
        let findings = match &csp_opt {
            Some(csp) => {
                let directives = parse_csp(csp);
                analyze_csp(&directives)
            }
            None => {
                // No CSP header present at all
                vec![CspFinding {
                    directive: "none".into(),
                    issue: "no Content-Security-Policy header present".into(),
                    severity: "HIGH".into(),
                    bypass_suggestion: "CSP entirely absent — XSS has no browser-level restriction".into(),
                }]
            }
        };

        if !findings.is_empty() {
            eprintln!("  [{}] {} findings", url, findings.len());
        }

        all_results.push(CspResult {
            url,
            csp_header: csp_opt,
            findings,
        });
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);
    let findings_count: usize = all_results.iter().map(|r| r.findings.len()).sum();

    let output = CspResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        urls_analyzed: all_results.len(),
        findings_count,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create csp output dir")?;

    let out_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &out_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write results JSON")?;

    eprintln!(
        "mg-csp: {} URLs, {} findings — {}",
        output.urls_analyzed,
        output.findings_count,
        out_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "urls={} findings={} ts={ts}",
            output.urls_analyzed, output.findings_count
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T09:00:00Z"), "2026-05-18T09_00_00Z");
    }

    #[test]
    fn parse_csp_splits_directives() {
        let csp = "default-src 'self'; script-src 'self' cdn.example.com; object-src 'none'";
        let map = parse_csp(csp);
        assert!(map.contains_key("default-src"));
        assert!(map.contains_key("script-src"));
        assert!(map.contains_key("object-src"));
        assert_eq!(map["script-src"], vec!["'self'", "cdn.example.com"]);
    }

    #[test]
    fn analyze_csp_flags_unsafe_inline() {
        let mut directives = HashMap::new();
        directives.insert(
            "script-src".into(),
            vec!["'self'".into(), "'unsafe-inline'".into()],
        );
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.issue.contains("unsafe-inline")));
    }

    #[test]
    fn analyze_csp_flags_unsafe_eval() {
        let mut directives = HashMap::new();
        directives.insert(
            "script-src".into(),
            vec!["'self'".into(), "'unsafe-eval'".into()],
        );
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.issue.contains("unsafe-eval")));
    }

    #[test]
    fn analyze_csp_flags_wildcard() {
        let mut directives = HashMap::new();
        directives.insert("script-src".into(), vec!["*".into()]);
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.severity == "HIGH" && f.issue.contains("wildcard")));
    }

    #[test]
    fn analyze_csp_flags_missing_frame_ancestors() {
        let directives = HashMap::new(); // empty
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.directive == "frame-ancestors"));
    }

    #[test]
    fn analyze_csp_flags_data_uri() {
        let mut directives = HashMap::new();
        directives.insert("script-src".into(), vec!["'self'".into(), "data:".into()]);
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.issue.contains("data:")));
    }

    #[test]
    fn analyze_csp_flags_jsonp_domain() {
        let mut directives = HashMap::new();
        directives.insert(
            "script-src".into(),
            vec!["'self'".into(), "ajax.googleapis.com".into()],
        );
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.issue.contains("JSONP")));
    }

    #[test]
    fn is_jsonp_domain_matches_known_domains() {
        assert!(is_jsonp_domain("ajax.googleapis.com"));
        assert!(is_jsonp_domain("maps.googleapis.com")); // ends with googleapis.com
        assert!(!is_jsonp_domain("cdn.example.com"));
    }

    #[test]
    fn is_wildcard_subdomain_detects_wildcard() {
        assert!(is_wildcard_subdomain("*.example.com"));
        assert!(!is_wildcard_subdomain("example.com"));
        assert!(!is_wildcard_subdomain("*"));
    }

    #[test]
    fn analyze_csp_flags_missing_script_restriction() {
        // Neither script-src nor default-src
        let directives = HashMap::new();
        let findings = analyze_csp(&directives);
        assert!(findings.iter().any(|f| f.issue.contains("no script-src or default-src")));
    }
}
