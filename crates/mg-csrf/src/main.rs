/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-csrf — CSRF protection analysis
 *                  Identifies state-changing endpoints, checks for CSRF
 *                  token presence, SameSite cookie attributes, and missing
 *                  Origin validation.
 * Notes:           GET to the same path probes for a rendered form; if no
 *                  GET succeeds we skip CSRF-token detection but still send
 *                  the tampered Origin probe.
 *                  Severity: HIGH = no_csrf_token + no_samesite,
 *                            MEDIUM = either alone.
 *******************************************************************/

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

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "csrf";
const AUDIT_TOOL: &str = "mg-csrf";

// Attacker Origin injected in the tampered probe
const ATTACKER_ORIGIN: &str = "https://attacker.com";

// Static file extensions excluded from state-changing endpoint collection
const STATIC_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".pdf",
];

// CSRF token input name attributes we look for in form HTML
const CSRF_TOKEN_NAMES: &[&str] = &[
    "csrf",
    "_token",
    "authenticity_token",
    "__RequestVerificationToken",
];

// HTTP methods that indicate state-changing operations
const STATE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

// ── Regex catalog ─────────────────────────────────────────────────────────────

// Pattern for detecting CSRF token input fields in HTML
static CSRF_INPUT_PATTERN: OnceLock<Regex> = OnceLock::new();

// Initialize and return the CSRF input regex; panics only on syntax error at startup
fn csrf_input_re() -> &'static Regex {
    CSRF_INPUT_PATTERN.get_or_init(|| {
        // Matches <input ... name="csrf|_token|authenticity_token|__RequestVerificationToken" ...>
        let names = CSRF_TOKEN_NAMES.join("|");
        Regex::new(&format!(
            r#"(?i)<input[^>]+name=["\'](?:{names})["\']"#
        ))
        .unwrap()
    })
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-csrf",
    about = "CSRF protection analysis — token presence, SameSite, and Origin validation"
)]
struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize)]
struct EndpointMatch {
    path: String,
    #[serde(default = "default_method")]
    method: String,
}

// State-changing endpoint to probe for CSRF weaknesses
#[derive(Debug, Clone)]
struct StateEndpoint {
    url: String,
    method: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
enum CsrfSeverity {
    High,
    Medium,
    None,
}

// Result of CSRF analysis for one endpoint
#[derive(Debug, Serialize)]
struct CsrfResult {
    url: String,
    method: String,
    has_csrf_token: bool,
    has_samesite: bool,
    origin_rejected: bool,
    severity: CsrfSeverity,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CsrfResults {
    engagement: String,
    timestamp: String,
    endpoints_tested: usize,
    high_count: usize,
    medium_count: usize,
    results: Vec<CsrfResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return default HTTP method for deserialization
fn default_method() -> String {
    "GET".to_string()
}

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for filename use (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Return true if the URL path ends with a static file extension
fn is_static_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    let clean = path_lower.split('?').next().unwrap_or(&path_lower);
    STATIC_EXTENSIONS.iter().any(|ext| clean.ends_with(ext))
}

// Return true if any Set-Cookie header includes SameSite
fn has_samesite_cookie(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all("set-cookie")
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| s.to_lowercase().contains("samesite"))
                .unwrap_or(false)
        })
}

// Collect state-changing endpoints from crawl host directories
fn collect_state_endpoints(crawl_dir: &Path) -> Vec<StateEndpoint> {
    let mut endpoints = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return endpoints;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let ep_path = entry.path().join("endpoints.json");
        let Ok(raw) = fs::read_to_string(&ep_path) else {
            continue;
        };
        let Ok(eps): Result<Vec<EndpointMatch>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for ep in eps {
            if !STATE_METHODS.contains(&ep.method.as_str()) {
                continue;
            }
            let base = ep.path.split('?').next().unwrap_or(&ep.path).to_string();
            if is_static_path(&base) {
                continue;
            }
            endpoints.push(StateEndpoint {
                url: base,
                method: ep.method,
            });
        }
    }
    endpoints
}

// Check if the form page contains a CSRF token input field
fn html_has_csrf_token(html: &str) -> bool {
    csrf_input_re().is_match(html)
}

// Compute severity from the two main indicators
fn compute_severity(has_token: bool, has_samesite: bool) -> CsrfSeverity {
    match (has_token, has_samesite) {
        (false, false) => CsrfSeverity::High,
        (false, true) | (true, false) => CsrfSeverity::Medium,
        (true, true) => CsrfSeverity::None,
    }
}

// Probe one state-changing endpoint; return a CsrfResult
async fn probe_endpoint(
    client: reqwest::Client,
    endpoint: StateEndpoint,
) -> CsrfResult {
    // Step a: GET the same path to look for a CSRF token in the form HTML
    let has_csrf_token = match client.get(&endpoint.url).send().await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            html_has_csrf_token(&body)
        }
        Err(_) => false,
    };

    // Step b: send the state-changing request with attacker Origin and no token
    let method = reqwest::Method::from_bytes(endpoint.method.as_bytes())
        .unwrap_or(reqwest::Method::POST);

    let probe_result = client
        .request(method, &endpoint.url)
        .header("Origin", ATTACKER_ORIGIN)
        .send()
        .await;

    let (has_samesite, origin_rejected) = match probe_result {
        Err(_) => (false, true), // connection refused = effectively rejected
        Ok(resp) => {
            let status = resp.status().as_u16();
            // SameSite check on any Set-Cookie in the response
            let samesite = has_samesite_cookie(resp.headers());
            // Origin rejected = 4xx response (400, 403, etc.) to the tampered Origin
            let rejected = !(200..=399).contains(&status);
            (samesite, rejected)
        }
    };

    let severity = compute_severity(has_csrf_token, has_samesite);

    CsrfResult {
        url: endpoint.url,
        method: endpoint.method,
        has_csrf_token,
        has_samesite,
        origin_rejected,
        severity,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let endpoints = collect_state_endpoints(&eng.crawl_dir());
    if endpoints.is_empty() {
        anyhow::bail!(
            "no state-changing endpoints found — run `mg-crawl {}` first",
            args.engagement
        );
    }

    eprintln!(
        "mg-csrf: {} state-changing endpoints, concurrency={}",
        endpoints.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let mut join_set: JoinSet<CsrfResult> = JoinSet::new();
    let mut all_results: Vec<CsrfResult> = Vec::new();

    for endpoint in endpoints {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(r)) = join_set.join_next().await
        {
            all_results.push(r);
        }
        let c = client.clone();
        join_set.spawn(probe_endpoint(c, endpoint));
    }
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    // Print high/medium findings
    for r in &all_results {
        match r.severity {
            CsrfSeverity::High => eprintln!(
                "  [csrf-HIGH] {} method={} token={} samesite={}",
                r.url, r.method, r.has_csrf_token, r.has_samesite
            ),
            CsrfSeverity::Medium => eprintln!(
                "  [csrf-MEDIUM] {} method={} token={} samesite={}",
                r.url, r.method, r.has_csrf_token, r.has_samesite
            ),
            CsrfSeverity::None => {}
        }
    }

    let high_count = all_results
        .iter()
        .filter(|r| r.severity == CsrfSeverity::High)
        .count();
    let medium_count = all_results
        .iter()
        .filter(|r| r.severity == CsrfSeverity::Medium)
        .count();

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = CsrfResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        endpoints_tested: all_results.len(),
        high_count,
        medium_count,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create csrf output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write CSRF results JSON")?;

    eprintln!(
        "mg-csrf: high={} medium={} — {}",
        output.high_count,
        output.medium_count,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "endpoints={} high={} medium={} ts={ts}",
            output.endpoints_tested, output.high_count, output.medium_count
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_path_css_excluded() {
        assert!(is_static_path("/styles/main.css"));
    }

    #[test]
    fn static_path_js_excluded() {
        assert!(is_static_path("/bundle.js"));
    }

    #[test]
    fn api_path_not_excluded() {
        assert!(!is_static_path("/api/users"));
        assert!(!is_static_path("/login"));
    }

    #[test]
    fn csrf_token_input_detected_csrf_name() {
        let html = r#"<form><input type="hidden" name="csrf" value="abc123"></form>"#;
        assert!(html_has_csrf_token(html));
    }

    #[test]
    fn csrf_token_input_detected_token_name() {
        let html = r#"<input name="_token" value="xyz"/>"#;
        assert!(html_has_csrf_token(html));
    }

    #[test]
    fn csrf_token_input_detected_authenticity_token() {
        let html = r#"<input type="hidden" name="authenticity_token" value="abc">"#;
        assert!(html_has_csrf_token(html));
    }

    #[test]
    fn csrf_token_input_detected_request_verification_token() {
        let html = r#"<input name="__RequestVerificationToken" type="hidden" value="v"/>"#;
        assert!(html_has_csrf_token(html));
    }

    #[test]
    fn no_csrf_token_in_clean_html() {
        let html = r#"<form><input name="username" type="text"></form>"#;
        assert!(!html_has_csrf_token(html));
    }

    #[test]
    fn severity_high_when_no_token_no_samesite() {
        assert_eq!(compute_severity(false, false), CsrfSeverity::High);
    }

    #[test]
    fn severity_medium_when_no_token_but_samesite() {
        assert_eq!(compute_severity(false, true), CsrfSeverity::Medium);
    }

    #[test]
    fn severity_medium_when_token_but_no_samesite() {
        assert_eq!(compute_severity(true, false), CsrfSeverity::Medium);
    }

    #[test]
    fn severity_none_when_token_and_samesite() {
        assert_eq!(compute_severity(true, true), CsrfSeverity::None);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }
}
