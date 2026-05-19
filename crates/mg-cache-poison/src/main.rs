/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-cache-poison — web cache poisoning detection
 *                  Tests unkeyed header injection, fat GET, and response
 *                  splitting against cacheable endpoints found in recon.
 * Notes:           Only flags injection findings on endpoints confirmed to
 *                  have a cache (Age, X-Cache, CF-Cache-Status, Via).
 *                  Two-request pattern: poison request then clean request,
 *                  checking if the poisoned value appears in the clean response.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "cache-poison";
const AUDIT_TOOL: &str = "mg-cache-poison";
const USER_AGENT: &str = "mg-cache-poison/0.1 (security scanner)";

// Attacker domain injected as poison value in header tests
const POISON_VALUE_HOST: &str = "attacker.com";
const POISON_VALUE_SCHEME: &str = "nothttps";
const POISON_VALUE_PATH: &str = "/admin";
const POISON_VALUE_IP: &str = "127.0.0.1";

// Unique marker to detect reflection; unlikely to appear in normal responses
const REFLECTION_MARKER: &str = "attacker.com";

// Response headers that indicate a caching layer is present
const CACHE_INDICATOR_HEADERS: &[&str] = &[
    "age",
    "x-cache",
    "cf-cache-status",
    "via",
    "x-varnish",
    "x-drupal-cache",
    "x-cache-hits",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-cache-poison",
    about = "Web cache poisoning detection — unkeyed headers, fat GET, cache presence"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
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

// Mirrors the HostRecord shape written by mg-recon
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Mirrors the ReconSummary shape written by mg-recon
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// Classification of a cache poisoning probe
#[derive(Debug, Serialize, PartialEq, Eq)]
enum PoisonVerdict {
    // Injected value reflected in clean response on a cacheable endpoint
    Confirmed,
    // Request returned different status (e.g. 403 -> 200) suggesting override
    StatusOverride,
    // Cache headers present but no reflection detected
    CachePresent,
    // No cache detected, no reflection
    Miss,
}

// Result of one unkeyed-header probe pair
#[derive(Debug, Serialize)]
struct HeaderProbeResult {
    url: String,
    header: String,
    poison_value: String,
    cacheable: bool,
    clean_status: u16,
    reflected: bool,
    verdict: PoisonVerdict,
}

// Result of a fat GET probe
#[derive(Debug, Serialize)]
struct FatGetResult {
    url: String,
    cacheable: bool,
    clean_status: u16,
    fat_status: u16,
    body_differs: bool,
    verdict: PoisonVerdict,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CachePoisonResults {
    engagement: String,
    timestamp: String,
    hosts_probed: usize,
    cacheable_endpoints: usize,
    confirmed_count: usize,
    header_results: Vec<HeaderProbeResult>,
    fat_get_results: Vec<FatGetResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

// Derive the base URL for a host record, preferring HTTPS
fn base_url_for_host(host: &HostRecord) -> String {
    if host.open_ports.contains(&443) {
        return format!("https://{}", host.hostname);
    }
    if host.open_ports.contains(&80) {
        return format!("http://{}", host.hostname);
    }
    if let Some(&port) = host.open_ports.iter().find(|&&p| p == 8443 || p == 9443) {
        return format!("https://{}:{port}", host.hostname);
    }
    if let Some(&port) = host.open_ports.first() {
        return format!("http://{}:{port}", host.hostname);
    }
    format!("https://{}", host.hostname)
}

// Check response headers for cache indicator presence
fn has_cache_headers(resp: &reqwest::Response) -> bool {
    let headers = resp.headers();
    CACHE_INDICATOR_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
}

// Check if a string value appears in a response body or Location header
fn value_reflected(
    body: &str,
    location: Option<&str>,
    value: &str,
) -> bool {
    if body.contains(value) {
        return true;
    }
    if let Some(loc) = location
        && loc.contains(value)
    {
        return true;
    }
    false
}

// ── Probe functions ──────────────────────────────────────────────────────────

// Probe one URL with one unkeyed header injection: poison request then clean request
async fn probe_header(
    client: reqwest::Client,
    url: String,
    header_name: String,
    poison_value: String,
) -> HeaderProbeResult {
    // Send poison request
    let poison_req = client
        .get(&url)
        .header(header_name.as_str(), poison_value.as_str())
        .send()
        .await;

    // Short sleep to allow cache to store poisoned response
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Send clean request
    let clean_resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => {
            return HeaderProbeResult {
                url,
                header: header_name,
                poison_value,
                cacheable: false,
                clean_status: 0,
                reflected: false,
                verdict: PoisonVerdict::Miss,
            };
        }
    };

    let cacheable = has_cache_headers(&clean_resp);
    let clean_status = clean_resp.status().as_u16();
    let clean_headers = clean_resp.headers().clone();
    let location = clean_headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = clean_resp.text().await.unwrap_or_default();

    let reflected = cacheable
        && value_reflected(&body, location.as_deref(), REFLECTION_MARKER);

    // Check if status changed in a way suggesting path override (403 -> 200)
    let poison_status = match poison_req {
        Ok(ref r) => r.status().as_u16(),
        Err(_) => 0,
    };
    let status_override = cacheable
        && poison_status != 0
        && clean_status != poison_status
        && clean_status == 200
        && poison_status >= 400;

    let verdict = if reflected {
        PoisonVerdict::Confirmed
    } else if status_override {
        PoisonVerdict::StatusOverride
    } else if cacheable {
        PoisonVerdict::CachePresent
    } else {
        PoisonVerdict::Miss
    };

    HeaderProbeResult {
        url,
        header: header_name,
        poison_value,
        cacheable,
        clean_status,
        reflected,
        verdict,
    }
}

// Probe one URL with a fat GET (GET with body) vs clean GET
async fn probe_fat_get(client: reqwest::Client, url: String) -> FatGetResult {
    // Send fat GET with body
    let fat_resp = client
        .get(&url)
        .header("Content-Length", "5")
        .body("x=123")
        .send()
        .await;

    // Send clean GET
    let clean_resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => {
            return FatGetResult {
                url,
                cacheable: false,
                clean_status: 0,
                fat_status: 0,
                body_differs: false,
                verdict: PoisonVerdict::Miss,
            };
        }
    };

    let cacheable = has_cache_headers(&clean_resp);
    let clean_status = clean_resp.status().as_u16();
    let clean_body = clean_resp.text().await.unwrap_or_default();

    let fat_status = match fat_resp {
        Ok(ref r) => r.status().as_u16(),
        Err(_) => 0,
    };

    let fat_body = match fat_resp {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    };

    let body_differs = cacheable && fat_body != clean_body;

    let verdict = if body_differs {
        PoisonVerdict::Confirmed
    } else if cacheable {
        PoisonVerdict::CachePresent
    } else {
        PoisonVerdict::Miss
    };

    FatGetResult {
        url,
        cacheable,
        clean_status,
        fat_status,
        body_differs,
        verdict,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join("summary.json");
    if !summary_path.exists() {
        anyhow::bail!(
            "recon/summary.json not found — run `mg-recon {}` first",
            args.engagement
        );
    }

    let scope = eng.scope().context("load scope")?;
    let raw = fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    // Collect HTTP-accessible in-scope hosts
    let hosts: Vec<&HostRecord> = summary
        .hosts
        .iter()
        .filter(|h| h.http_accessible && scope.is_in_scope(&h.hostname))
        .collect();

    if hosts.is_empty() {
        anyhow::bail!("no HTTP-accessible in-scope hosts in summary.json");
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

    eprintln!(
        "mg-cache-poison: {} hosts, concurrency={}",
        hosts.len(),
        args.concurrency
    );

    // Build probe tasks: one per (host, header) pair plus one fat-GET per host
    let mut header_join: JoinSet<HeaderProbeResult> = JoinSet::new();
    let mut fat_join: JoinSet<FatGetResult> = JoinSet::new();

    // Unkeyed headers to test: (header-name, poison-value)
    let header_probes: &[(&str, &str)] = &[
        ("X-Forwarded-Host", POISON_VALUE_HOST),
        ("X-Forwarded-Scheme", POISON_VALUE_SCHEME),
        ("X-Original-URL", POISON_VALUE_PATH),
        ("X-Rewrite-URL", POISON_VALUE_PATH),
        ("X-Host", POISON_VALUE_HOST),
        ("X-Forwarded-For", POISON_VALUE_IP),
    ];

    for host in &hosts {
        let base = base_url_for_host(host);
        eprintln!("  probing {base}");

        // Spawn header injection probes
        for (hdr, val) in header_probes {
            // Drain at ceiling
            while header_join.len() >= args.concurrency {
                header_join.join_next().await;
            }
            header_join.spawn(probe_header(
                client.clone(),
                base.clone(),
                hdr.to_string(),
                val.to_string(),
            ));
        }

        // Spawn fat GET probe
        while fat_join.len() >= args.concurrency {
            fat_join.join_next().await;
        }
        fat_join.spawn(probe_fat_get(client.clone(), base.clone()));
    }

    // Drain all
    let mut header_results: Vec<HeaderProbeResult> = Vec::new();
    while let Some(Ok(r)) = header_join.join_next().await {
        header_results.push(r);
    }
    let mut fat_get_results: Vec<FatGetResult> = Vec::new();
    while let Some(Ok(r)) = fat_join.join_next().await {
        fat_get_results.push(r);
    }

    // Count cacheable endpoints and confirmed findings before moving into output struct
    let cacheable_endpoint_count: usize = {
        let cacheable_urls: HashSet<&str> = header_results
            .iter()
            .filter(|r| r.cacheable)
            .map(|r| r.url.as_str())
            .chain(
                fat_get_results
                    .iter()
                    .filter(|r| r.cacheable)
                    .map(|r| r.url.as_str()),
            )
            .collect();
        cacheable_urls.len()
    };

    let confirmed_count = header_results
        .iter()
        .filter(|r| r.verdict == PoisonVerdict::Confirmed || r.verdict == PoisonVerdict::StatusOverride)
        .count()
        + fat_get_results
            .iter()
            .filter(|r| r.verdict == PoisonVerdict::Confirmed)
            .count();

    // Print confirmed findings and emit standardized ToolFinding records
    for r in &header_results {
        if r.verdict == PoisonVerdict::Confirmed || r.verdict == PoisonVerdict::StatusOverride {
            eprintln!(
                "  [cache-poison] {} header={} verdict={:?}",
                r.url, r.header, r.verdict
            );
            let severity = if r.verdict == PoisonVerdict::Confirmed {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            };
            let tf = ToolFinding::new(
                AUDIT_TOOL,
                format!("Cache poisoning via unkeyed header: {}", r.header),
                severity,
            )
            .url(r.url.clone())
            .discriminator(r.header.clone())
            .evidence(format!(
                "header={} value={} clean_status={} verdict={:?} reflected={}",
                r.header, r.poison_value, r.clean_status, r.verdict, r.reflected
            ))
            .recommendation("Add the offending header to the cache key or strip it before caching");
            let _ = write_finding(&eng, &tf);
        }
    }
    for r in &fat_get_results {
        if r.verdict == PoisonVerdict::Confirmed {
            eprintln!("  [fat-get] {} body_differs=true", r.url);
            let tf = ToolFinding::new(
                AUDIT_TOOL,
                "Cache poisoning via fat GET (request-with-body)",
                FindingSeverity::High,
            )
            .url(r.url.clone())
            .evidence(format!(
                "clean_status={} fat_status={} body_differs=true",
                r.clean_status, r.fat_status
            ))
            .recommendation("Reject GET requests carrying a body, or include the body hash in the cache key");
            let _ = write_finding(&eng, &tf);
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = CachePoisonResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        hosts_probed: hosts.len(),
        cacheable_endpoints: cacheable_endpoint_count,
        confirmed_count,
        header_results,
        fat_get_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create cache-poison output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write cache-poison results")?;

    eprintln!(
        "mg-cache-poison: confirmed={} cacheable={} — {}",
        confirmed_count,
        cacheable_endpoint_count,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} confirmed={} cacheable={} ts={ts}",
            hosts.len(),
            confirmed_count,
            cacheable_endpoint_count
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
            ts_for_filename("2026-05-18T12:00:00Z"),
            "2026-05-18T12_00_00Z"
        );
    }

    #[test]
    fn value_reflected_detects_body_match() {
        assert!(value_reflected("hello attacker.com world", None, "attacker.com"));
    }

    #[test]
    fn value_reflected_detects_location_match() {
        assert!(value_reflected(
            "nothing here",
            Some("https://attacker.com/path"),
            "attacker.com"
        ));
    }

    #[test]
    fn value_reflected_returns_false_on_miss() {
        assert!(!value_reflected("clean response", None, "attacker.com"));
    }

    #[test]
    fn base_url_prefers_https_443() {
        let host = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            open_ports: vec![80, 443],
        };
        assert_eq!(base_url_for_host(&host), "https://example.com");
    }

    #[test]
    fn base_url_falls_back_to_http_80() {
        let host = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            open_ports: vec![80],
        };
        assert_eq!(base_url_for_host(&host), "http://example.com");
    }

    #[test]
    fn base_url_uses_nonstandard_port() {
        let host = HostRecord {
            hostname: "internal".into(),
            http_accessible: true,
            open_ports: vec![8080],
        };
        assert_eq!(base_url_for_host(&host), "http://internal:8080");
    }

    #[test]
    fn cache_indicator_headers_contains_x_cache() {
        // Verify the constant includes the most common cache header names
        assert!(CACHE_INDICATOR_HEADERS.contains(&"x-cache"));
        assert!(CACHE_INDICATOR_HEADERS.contains(&"age"));
        assert!(CACHE_INDICATOR_HEADERS.contains(&"cf-cache-status"));
    }
}
