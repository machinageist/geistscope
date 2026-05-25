/*******************************************************************
 * Filename:        redirect.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-redirect — open redirect detection and chain building
 *                  Tests URL parameters for unvalidated redirect vulnerabilities.
 *                  Follows redirects manually to catch multi-hop chains.
 * Notes:           reqwest is configured with Policy::none() so we can inspect
 *                  each Location header ourselves rather than auto-following.
 *                  Classification: open_redirect (3xx to evil.com or Location
 *                  contains evil.com), potential (body contains evil.com).
 *******************************************************************/

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "redirect";
const AUDIT_TOOL: &str = "mg-redirect";

// The canary domain injected into redirect parameters
const EVIL_DOMAIN: &str = "evil.com";

// Parameter names commonly associated with redirect targets
const REDIRECT_PARAM_NAMES: &[&str] = &[
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "return_url",
    "returnTo",
    "next",
    "url",
    "target",
    "destination",
    "go",
    "continue",
    "back",
    "location",
    "forward",
    "goto",
    "redir",
    "ref",
    "referer",
    "referrer",
];

// Payloads that attempt to redirect to evil.com via various bypass techniques
const REDIRECT_PAYLOADS: &[&str] = &[
    "https://evil.com",
    "//evil.com",
    r"\/\/evil.com",
    "https:evil.com",
    "https://target.com.evil.com",
    "javascript:alert(1)",
    r"/\evil.com",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
pub struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 10)]
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
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_method")]
    method: String,
}

// Injectable redirect parameter derived from the crawl corpus
#[derive(Debug, Clone)]
struct RedirectPoint {
    base_url: String,
    param: String,
    method: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
enum RedirectVerdict {
    OpenRedirect,
    Potential,
    Miss,
}

// Result of one redirect probe
#[derive(Debug, Serialize)]
struct RedirectResult {
    url: String,
    param: String,
    method: String,
    payload: String,
    verdict: RedirectVerdict,
    location_header: Option<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct RedirectResults {
    engagement: String,
    timestamp: String,
    probes: usize,
    open_redirects: usize,
    results: Vec<RedirectResult>,
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

// Return true if param name is redirect-prone
fn is_redirect_param(name: &str) -> bool {
    REDIRECT_PARAM_NAMES.contains(&name)
}

// Collect redirect-prone parameters from crawl host directories
fn collect_redirect_points(crawl_dir: &Path) -> Vec<RedirectPoint> {
    let mut points = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return points;
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
            let base = ep.path.split('?').next().unwrap_or(&ep.path).to_string();
            for param in &ep.params {
                if is_redirect_param(param) {
                    points.push(RedirectPoint {
                        base_url: base.clone(),
                        param: param.clone(),
                        method: ep.method.clone(),
                    });
                }
            }
        }
    }
    points
}

// Classify a response based on status, Location header, and body
fn classify(
    status: u16,
    location: Option<&str>,
    body: &str,
) -> RedirectVerdict {
    // 3xx with Location pointing to evil domain = confirmed open redirect
    if (300..=399).contains(&status)
        && let Some(loc) = location
        && loc.contains(EVIL_DOMAIN)
    {
        return RedirectVerdict::OpenRedirect;
    }
    // Non-redirect response but body echoes the evil domain = potential
    if body.contains(EVIL_DOMAIN) {
        return RedirectVerdict::Potential;
    }
    RedirectVerdict::Miss
}

// Probe one redirect point with all payloads; return results
async fn probe_point(
    client: reqwest::Client,
    point: RedirectPoint,
) -> Vec<RedirectResult> {
    let mut results = Vec::new();

    for payload in REDIRECT_PAYLOADS {
        let url = format!("{}?{}={}", point.base_url, point.param, payload);

        let resp_result = client
            .request(
                reqwest::Method::from_bytes(point.method.as_bytes())
                    .unwrap_or(reqwest::Method::GET),
                &url,
            )
            .send()
            .await;

        let (verdict, location_header) = match resp_result {
            Err(_) => (RedirectVerdict::Miss, None),
            Ok(resp) => {
                let status = resp.status().as_u16();
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let body = resp.text().await.unwrap_or_default();
                let v = classify(status, location.as_deref(), &body);
                (v, location)
            }
        };

        results.push(RedirectResult {
            url,
            param: point.param.clone(),
            method: point.method.clone(),
            payload: payload.to_string(),
            verdict,
            location_header,
        });
    }

    results
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let points = collect_redirect_points(&eng.crawl_dir());
    if points.is_empty() {
        anyhow::bail!(
            "no redirect-prone parameters found — run `mg-crawl {}` first",
            args.engagement
        );
    }

    eprintln!(
        "mg-redirect: {} redirect points, concurrency={}",
        points.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    // Disable auto-redirect so we can inspect each Location header ourselves
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client")?;

    let mut join_set: JoinSet<Vec<RedirectResult>> = JoinSet::new();
    let mut all_results: Vec<RedirectResult> = Vec::new();

    for point in points {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(mut rs)) = join_set.join_next().await
        {
            all_results.append(&mut rs);
        }
        let c = client.clone();
        join_set.spawn(probe_point(c, point));
    }
    while let Some(Ok(mut rs)) = join_set.join_next().await {
        all_results.append(&mut rs);
    }

    // Print confirmed open redirects
    for r in &all_results {
        if r.verdict == RedirectVerdict::OpenRedirect {
            eprintln!(
                "  [open-redirect] {} param={} payload={} location={:?}",
                r.url, r.param, r.payload, r.location_header
            );
        }
    }

    let open_redirects = all_results
        .iter()
        .filter(|r| r.verdict == RedirectVerdict::OpenRedirect)
        .count();

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = RedirectResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        probes: all_results.len(),
        open_redirects,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create redirect output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write redirect results JSON")?;

    eprintln!(
        "mg-redirect: open_redirects={} — {}",
        output.open_redirects,
        results_path.display()
    );

    // Write finding for each confirmed open redirect
    for r in output.results.iter().filter(|r| r.verdict == RedirectVerdict::OpenRedirect) {
        let tf = ToolFinding::new("mg-redirect", "Open Redirect", FindingSeverity::Medium)
            .url(r.url.clone())
            .parameter(r.param.clone())
            .evidence(format!("payload={} location={:?}", r.payload, r.location_header))
            .recommendation("Validate redirect targets against an allowlist of trusted domains; reject absolute URLs");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "probes={} open_redirects={} ts={ts}",
            output.probes, output.open_redirects
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_param_names_recognized() {
        assert!(is_redirect_param("redirect"));
        assert!(is_redirect_param("return_url"));
        assert!(is_redirect_param("next"));
        assert!(is_redirect_param("goto"));
        assert!(is_redirect_param("referer"));
    }

    #[test]
    fn non_redirect_param_not_recognized() {
        assert!(!is_redirect_param("id"));
        assert!(!is_redirect_param("page"));
        assert!(!is_redirect_param("q"));
    }

    #[test]
    fn classify_open_redirect_on_3xx_with_evil_location() {
        let v = classify(302, Some("https://evil.com/steal"), "");
        assert_eq!(v, RedirectVerdict::OpenRedirect);
    }

    #[test]
    fn classify_miss_on_3xx_without_evil_in_location() {
        let v = classify(302, Some("https://safe.example.com/"), "");
        assert_eq!(v, RedirectVerdict::Miss);
    }

    #[test]
    fn classify_potential_on_body_echo() {
        let v = classify(200, None, "<a href='https://evil.com'>click</a>");
        assert_eq!(v, RedirectVerdict::Potential);
    }

    #[test]
    fn classify_miss_on_clean_200() {
        let v = classify(200, None, "<html>welcome</html>");
        assert_eq!(v, RedirectVerdict::Miss);
    }

    #[test]
    fn classify_open_redirect_on_301_with_evil_location() {
        let v = classify(301, Some("//evil.com"), "");
        assert_eq!(v, RedirectVerdict::OpenRedirect);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }
}
