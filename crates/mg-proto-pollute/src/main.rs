/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-proto-pollute — JavaScript prototype pollution detection
 *                  Injects __proto__ and constructor.prototype payloads into
 *                  JSON bodies and URL params at API endpoints from crawl output.
 * Notes:           Three verdict classes: reflected (HIGH), server_error (MEDIUM),
 *                  no_effect (INFO). Endpoints are collected from crawl/
 *                  endpoints.json files. URL-param probes run against GET endpoints.
 *******************************************************************/

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

const OUTPUT_SUBDIR: &str = "proto-pollute";
const AUDIT_TOOL: &str = "mg-proto-pollute";
const USER_AGENT: &str = "mg-proto-pollute/0.1 (security scanner)";

// Unique marker injected so reflection is unambiguous
const POLL_MARKER: &str = "ppolluted_true";

// URL param probes appended to GET endpoints
const URL_PARAM_PROBES: &[&str] = &[
    "__proto__[polluted]=ppolluted_true",
    "constructor[prototype][polluted]=ppolluted_true",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-proto-pollute",
    about = "Prototype pollution detection — JSON body and URL param injection"
)]
struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize, Clone)]
struct EndpointMatch {
    path: String,
    // params retained for JSON compatibility with crawl output; URL probes use path directly
    #[allow(dead_code)]
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    content_type: String,
}

// Verdict severity for a pollution probe
#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    Reflected,
    ServerError,
    NoEffect,
}

// Result of one prototype pollution probe
#[derive(Debug, Serialize)]
struct PollutionResult {
    url: String,
    probe_type: String,
    payload_label: String,
    status: u16,
    verdict: Verdict,
    // First 256 chars of response, for manual review
    snippet: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct ProtoPollutionResults {
    engagement: String,
    timestamp: String,
    endpoints_probed: usize,
    reflected_count: usize,
    server_error_count: usize,
    results: Vec<PollutionResult>,
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

// Sanitize a timestamp string for use in a filename (colons -> underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Decide if an endpoint is JSON-accepting based on content-type or path heuristics
fn is_json_endpoint(ep: &EndpointMatch) -> bool {
    ep.content_type.contains("application/json")
        || ep.path.contains("/api/")
        || ep.path.contains("/graphql")
        || ep.path.ends_with(".json")
}

// Collect endpoints from all crawl host directories
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
        endpoints.extend(eps);
    }
    endpoints
}

// Classify a response into a Verdict
fn classify(status: u16, body: &str) -> Verdict {
    if body.contains(POLL_MARKER) {
        return Verdict::Reflected;
    }
    if status >= 500 {
        return Verdict::ServerError;
    }
    Verdict::NoEffect
}

// ── Probe functions ──────────────────────────────────────────────────────────

// Probe a JSON POST/PUT endpoint with one payload body
async fn probe_json(
    client: reqwest::Client,
    url: String,
    method: String,
    payload: serde_json::Value,
    label: String,
) -> PollutionResult {
    let builder = if method == "PUT" {
        client.put(&url)
    } else {
        client.post(&url)
    };

    let resp = builder
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(256).collect();
            let verdict = classify(status, &body);
            PollutionResult {
                url,
                probe_type: "json-body".into(),
                payload_label: label,
                status,
                verdict,
                snippet,
            }
        }
        Err(_) => PollutionResult {
            url,
            probe_type: "json-body".into(),
            payload_label: label,
            status: 0,
            verdict: Verdict::NoEffect,
            snippet: String::new(),
        },
    }
}

// Probe a GET endpoint with URL param pollution
async fn probe_url_param(
    client: reqwest::Client,
    base_url: String,
    param_suffix: String,
) -> PollutionResult {
    let url = if base_url.contains('?') {
        format!("{}&{}", base_url, param_suffix)
    } else {
        format!("{}?{}", base_url, param_suffix)
    };

    let resp = client.get(&url).send().await;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(256).collect();
            let verdict = classify(status, &body);
            PollutionResult {
                url,
                probe_type: "url-param".into(),
                payload_label: param_suffix,
                status,
                verdict,
                snippet,
            }
        }
        Err(_) => PollutionResult {
            url,
            probe_type: "url-param".into(),
            payload_label: param_suffix,
            status: 0,
            verdict: Verdict::NoEffect,
            snippet: String::new(),
        },
    }
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
            "no endpoints found in crawl output — run `mg-crawl {}` first",
            args.engagement
        );
    }

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(USER_AGENT)
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // JSON body payloads: (label, value)
    let json_payloads: Vec<(&str, serde_json::Value)> = vec![
        (
            "__proto__.polluted",
            serde_json::json!({"__proto__": {"polluted": POLL_MARKER}}),
        ),
        (
            "constructor.prototype.polluted",
            serde_json::json!({"constructor": {"prototype": {"polluted": POLL_MARKER}}}),
        ),
        (
            "__proto__.isAdmin",
            serde_json::json!({"__proto__": {"isAdmin": true}}),
        ),
        (
            "__proto__.crash",
            serde_json::json!({"__proto__": {"toString": "[object Object]", "valueOf": 1}}),
        ),
    ];

    eprintln!(
        "mg-proto-pollute: {} endpoints, concurrency={}",
        endpoints.len(),
        args.concurrency
    );

    let mut join_set: JoinSet<PollutionResult> = JoinSet::new();
    let mut results: Vec<PollutionResult> = Vec::new();
    let mut endpoints_probed: usize = 0;

    for ep in &endpoints {
        let method_upper = ep.method.to_uppercase();

        // JSON body probes on POST/PUT endpoints
        if (method_upper == "POST" || method_upper == "PUT") && is_json_endpoint(ep) {
            endpoints_probed += 1;
            for (label, payload) in &json_payloads {
                while join_set.len() >= args.concurrency {
                    if let Some(Ok(r)) = join_set.join_next().await {
                        results.push(r);
                    }
                }
                join_set.spawn(probe_json(
                    client.clone(),
                    ep.path.clone(),
                    method_upper.clone(),
                    payload.clone(),
                    label.to_string(),
                ));
            }
        }

        // URL param probes on GET endpoints
        if method_upper == "GET" {
            endpoints_probed += 1;
            for param in URL_PARAM_PROBES {
                while join_set.len() >= args.concurrency {
                    if let Some(Ok(r)) = join_set.join_next().await {
                        results.push(r);
                    }
                }
                join_set.spawn(probe_url_param(
                    client.clone(),
                    ep.path.clone(),
                    param.to_string(),
                ));
            }
        }
    }

    // Drain remaining
    while let Some(Ok(r)) = join_set.join_next().await {
        results.push(r);
    }

    let reflected_count = results.iter().filter(|r| r.verdict == Verdict::Reflected).count();
    let server_error_count = results
        .iter()
        .filter(|r| r.verdict == Verdict::ServerError)
        .count();

    // Print notable findings
    for r in &results {
        if r.verdict != Verdict::NoEffect {
            eprintln!(
                "  [{:?}] {} probe={} payload={}",
                r.verdict, r.url, r.probe_type, r.payload_label
            );
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = ProtoPollutionResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        endpoints_probed,
        reflected_count,
        server_error_count,
        results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create proto-pollute output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write proto-pollute results")?;

    eprintln!(
        "mg-proto-pollute: reflected={} server_errors={} — {}",
        reflected_count,
        server_error_count,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "endpoints={} reflected={} server_errors={} ts={ts}",
            endpoints_probed, reflected_count, server_error_count
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-18T10:30:00Z"),
            "2026-05-18T10_30_00Z"
        );
    }

    #[test]
    fn classify_reflected_when_marker_in_body() {
        let v = classify(200, &format!("response: {}", POLL_MARKER));
        assert_eq!(v, Verdict::Reflected);
    }

    #[test]
    fn classify_server_error_on_5xx() {
        let v = classify(500, "Internal Server Error");
        assert_eq!(v, Verdict::ServerError);
    }

    #[test]
    fn classify_no_effect_on_clean_200() {
        let v = classify(200, "Welcome to the API");
        assert_eq!(v, Verdict::NoEffect);
    }

    #[test]
    fn is_json_endpoint_detects_api_path() {
        let ep = EndpointMatch {
            path: "https://example.com/api/users".into(),
            params: vec![],
            method: "POST".into(),
            content_type: String::new(),
        };
        assert!(is_json_endpoint(&ep));
    }

    #[test]
    fn is_json_endpoint_detects_content_type() {
        let ep = EndpointMatch {
            path: "https://example.com/submit".into(),
            params: vec![],
            method: "POST".into(),
            content_type: "application/json".into(),
        };
        assert!(is_json_endpoint(&ep));
    }

    #[test]
    fn is_json_endpoint_rejects_html_form() {
        let ep = EndpointMatch {
            path: "https://example.com/contact".into(),
            params: vec![],
            method: "POST".into(),
            content_type: "application/x-www-form-urlencoded".into(),
        };
        assert!(!is_json_endpoint(&ep));
    }
}
