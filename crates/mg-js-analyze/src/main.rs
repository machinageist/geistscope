/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-js-analyze — static JavaScript analysis; extracts
 *                  endpoints, secrets, credentials, and source map refs.
 * Notes:           Fetches JS files referenced in the crawl corpus.
 *                  Secrets are masked to first 8 chars before writing.
 *                  Deduplication key is (source_url, finding_type, value).
 *                  Concurrency bounded with tokio::JoinSet; drained at ceiling.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "js-analyze";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-js-analyze";

// Mask secrets to this many characters before writing to disk
const SECRET_MASK_LEN: usize = 8;

// ── Regex patterns (compiled once) ───────────────────────────────────────────

// Compile and return the API endpoint extraction pattern
fn re_api_endpoint() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"['"/](?:api|v\d+|graphql|rest)/[a-zA-Z0-9/_\-]+"#).unwrap()
    })
}

// Compile and return the AWS access key pattern
fn re_aws_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap())
}

// Compile and return the generic API key pattern
fn re_api_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"[Aa][Pp][Ii][_\-]?[Kk]ey['":\s=]+['"]([A-Za-z0-9\-_]{20,})['"]"#).unwrap()
    })
}

// Compile and return the hardcoded password pattern
fn re_password() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"[Pp]assword['":\s=]+['"]([^'"]{6,})['"]"#).unwrap()
    })
}

// Compile and return the JWT token pattern
fn re_jwt() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*").unwrap()
    })
}

// Compile and return the internal IP address pattern
fn re_internal_ip() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\.\d+",
        )
        .unwrap()
    })
}

// Compile and return the source map reference pattern
fn re_source_map() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"sourceMappingURL=([^\s*]+\.map)").unwrap()
    })
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-js-analyze",
    about = "Static JS analysis — endpoints, secrets, source maps from crawl corpus"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent JS file fetches
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One extracted finding from a JS file
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
struct JsFinding {
    source_url: String,
    finding_type: String,
    value: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct JsAnalysisResults {
    engagement: String,
    timestamp: String,
    js_files_analyzed: usize,
    findings: Vec<JsFinding>,
    summary: std::collections::BTreeMap<String, usize>,
}

// Minimal crawl page entry for scraping JS URLs
#[derive(Deserialize)]
struct CrawlEntry {
    #[serde(default)]
    url: String,
    #[serde(default)]
    js_files: Vec<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Collect JS file URLs from crawl output directories
fn collect_js_urls(crawl_dir: &Path) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return urls;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        for filename in &["pages.json", "index.json"] {
            let path = entry.path().join(filename);
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(entries): Result<Vec<CrawlEntry>, _> = serde_json::from_str(&raw) else {
                continue;
            };
            for ce in entries {
                // Direct URL ending in .js
                if ce.url.ends_with(".js") {
                    urls.push(ce.url);
                }
                // Explicit js_files array from crawl output
                for js_url in ce.js_files {
                    if js_url.ends_with(".js") {
                        urls.push(js_url);
                    }
                }
            }
        }
    }
    // Deduplicate preserving first-seen order
    let mut seen = HashSet::new();
    urls.retain(|u| seen.insert(u.clone()));
    urls
}

// Mask a secret value to the first N characters followed by asterisks
fn mask_secret(value: &str) -> String {
    if value.len() <= SECRET_MASK_LEN {
        return "*".repeat(value.len());
    }
    let prefix: String = value.chars().take(SECRET_MASK_LEN).collect();
    format!("{prefix}...")
}

// Extract all findings from a JS source string
fn extract_findings(source_url: &str, js: &str) -> Vec<JsFinding> {
    let mut findings: Vec<JsFinding> = Vec::new();

    // API endpoints
    for m in re_api_endpoint().find_iter(js) {
        findings.push(JsFinding {
            source_url: source_url.to_string(),
            finding_type: "api_endpoint".to_string(),
            value: m.as_str().trim_matches(|c| c == '\'' || c == '"').to_string(),
        });
    }

    // AWS access keys (mask before storing)
    for m in re_aws_key().find_iter(js) {
        findings.push(JsFinding {
            source_url: source_url.to_string(),
            finding_type: "aws_key".to_string(),
            value: mask_secret(m.as_str()),
        });
    }

    // Generic API keys (capture group 1 = key value)
    for cap in re_api_key().captures_iter(js) {
        if let Some(val) = cap.get(1) {
            findings.push(JsFinding {
                source_url: source_url.to_string(),
                finding_type: "api_key".to_string(),
                value: mask_secret(val.as_str()),
            });
        }
    }

    // Hardcoded passwords (capture group 1 = password value)
    for cap in re_password().captures_iter(js) {
        if let Some(val) = cap.get(1) {
            findings.push(JsFinding {
                source_url: source_url.to_string(),
                finding_type: "hardcoded_password".to_string(),
                value: mask_secret(val.as_str()),
            });
        }
    }

    // JWT tokens (mask after first 8 chars)
    for m in re_jwt().find_iter(js) {
        findings.push(JsFinding {
            source_url: source_url.to_string(),
            finding_type: "jwt_token".to_string(),
            value: mask_secret(m.as_str()),
        });
    }

    // Internal IP addresses
    for m in re_internal_ip().find_iter(js) {
        findings.push(JsFinding {
            source_url: source_url.to_string(),
            finding_type: "internal_ip".to_string(),
            value: m.as_str().to_string(),
        });
    }

    // Source map references (capture group 1 = .map filename)
    for cap in re_source_map().captures_iter(js) {
        if let Some(val) = cap.get(1) {
            findings.push(JsFinding {
                source_url: source_url.to_string(),
                finding_type: "source_map".to_string(),
                value: val.as_str().to_string(),
            });
        }
    }

    findings
}

// Fetch one JS URL and return its findings
async fn analyze_js_url(
    client: reqwest::Client,
    js_url: String,
) -> Vec<JsFinding> {
    let Ok(resp) = client.get(&js_url).send().await else {
        return Vec::new();
    };
    let Ok(body) = resp.text().await else {
        return Vec::new();
    };
    extract_findings(&js_url, &body)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Load auth headers from session config
    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    // Build HTTP client with auth headers
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Collect JS URLs from crawl output
    let js_urls = collect_js_urls(&eng.crawl_dir());
    eprintln!("mg-js-analyze: {} JS file(s) to analyze", js_urls.len());

    // Fetch and analyze all JS files with bounded concurrency
    let mut join_set: JoinSet<Vec<JsFinding>> = JoinSet::new();
    let mut raw_findings: Vec<JsFinding> = Vec::new();
    let js_count = js_urls.len();

    for js_url in js_urls {
        eprintln!("  fetching {js_url}");
        if join_set.len() >= args.concurrency
            && let Some(Ok(batch)) = join_set.join_next().await
        {
            raw_findings.extend(batch);
        }
        join_set.spawn(analyze_js_url(client.clone(), js_url));
    }
    while let Some(Ok(batch)) = join_set.join_next().await {
        raw_findings.extend(batch);
    }

    // Deduplicate by (source_url, finding_type, value)
    let mut seen: HashSet<JsFinding> = HashSet::new();
    let mut findings: Vec<JsFinding> = Vec::new();
    for f in raw_findings {
        if seen.insert(f.clone()) {
            findings.push(f);
        }
    }

    // Build per-type summary counts
    let mut summary: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in &findings {
        *summary.entry(f.finding_type.clone()).or_insert(0) += 1;
    }

    println!("\n=== JS Analysis Summary ===");
    for (kind, count) in &summary {
        println!("  {kind}: {count}");
    }
    println!("  total findings: {}", findings.len());

    // Write results JSON
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create js-analyze output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = JsAnalysisResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        js_files_analyzed: js_count,
        findings,
        summary,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Emit standardized findings for HIGH-value secret types
    const HIGH_TYPES: &[&str] = &["aws_key", "api_key", "jwt_token", "password"];
    for f in results.findings.iter().filter(|f| HIGH_TYPES.contains(&f.finding_type.as_str())) {
        let tf = ToolFinding::new(AUDIT_TOOL, format!("JS Secret: {}", f.finding_type), FindingSeverity::High)
            .url(f.source_url.clone())
            .evidence(format!("Type: {} — value: {}", f.finding_type, f.value))
            .recommendation("Remove secrets from client-side JavaScript; use server-side secret management");
        let _ = write_finding(&eng, &tf);
    }

    // Audit log
    let detail = format!(
        "js_files={} findings={}",
        results.js_files_analyzed,
        results.findings.len()
    );
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_aws_key_and_masks_it() {
        let js = r#"var key = "AKIAIOSFODNN7EXAMPLE";"#;
        let findings = extract_findings("https://example.com/app.js", js);
        let aws: Vec<&JsFinding> = findings.iter().filter(|f| f.finding_type == "aws_key").collect();
        assert!(!aws.is_empty());
        // Value should be masked (first 8 chars + ...)
        assert!(aws[0].value.ends_with("..."));
        assert_eq!(aws[0].value.len(), SECRET_MASK_LEN + 3);
    }

    #[test]
    fn extract_api_endpoint_from_fetch_call() {
        let js = r#"fetch("/api/v1/users")"#;
        let findings = extract_findings("https://example.com/app.js", js);
        let ep: Vec<&JsFinding> = findings
            .iter()
            .filter(|f| f.finding_type == "api_endpoint")
            .collect();
        assert!(!ep.is_empty());
        assert!(ep[0].value.contains("/api/"));
    }

    #[test]
    fn extract_source_map_reference() {
        let js = "//# sourceMappingURL=app.js.map";
        let findings = extract_findings("https://example.com/app.js", js);
        let maps: Vec<&JsFinding> = findings
            .iter()
            .filter(|f| f.finding_type == "source_map")
            .collect();
        assert!(!maps.is_empty());
        assert_eq!(maps[0].value, "app.js.map");
    }

    #[test]
    fn extract_internal_ip() {
        let js = r#"var endpoint = "http://10.0.0.5/api";"#;
        let findings = extract_findings("https://example.com/app.js", js);
        let ips: Vec<&JsFinding> = findings
            .iter()
            .filter(|f| f.finding_type == "internal_ip")
            .collect();
        assert!(!ips.is_empty());
        assert_eq!(ips[0].value, "10.0.0.5");
    }

    #[test]
    fn mask_secret_truncates_long_values() {
        let masked = mask_secret("supersecretapikey");
        assert_eq!(masked, "supersec...");
    }

    #[test]
    fn mask_secret_masks_short_values_fully() {
        let masked = mask_secret("abc");
        assert_eq!(masked, "***");
    }

    #[test]
    fn collect_js_urls_returns_empty_for_missing_crawl_dir() {
        let result = collect_js_urls(Path::new("/nonexistent/crawl"));
        assert!(result.is_empty());
    }

    #[test]
    fn collect_js_urls_finds_js_files_from_crawl_output() {
        let tmp = tempfile::tempdir().unwrap();
        let host_dir = tmp.path().join("example.com");
        fs::create_dir_all(&host_dir).unwrap();
        let entries = serde_json::json!([
            {
                "url": "https://example.com/app.js",
                "js_files": ["https://example.com/vendor.js"]
            }
        ]);
        fs::write(
            host_dir.join("pages.json"),
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();
        let urls = collect_js_urls(tmp.path());
        assert!(urls.contains(&"https://example.com/app.js".to_string()));
        assert!(urls.contains(&"https://example.com/vendor.js".to_string()));
    }
}
