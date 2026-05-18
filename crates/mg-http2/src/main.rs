/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-http2 — HTTP/2 misconfiguration detection.
 *                  Checks h2c cleartext upgrade, TLS ALPN h2 negotiation,
 *                  rapid reset server-version heuristic, and HPACK header
 *                  size acceptance.
 * Notes:           Rapid reset (CVE-2023-44487) cannot be confirmed without
 *                  raw framing — we flag it as INFO based on server version
 *                  string and require manual verification.
 *                  h2c probe uses raw reqwest with Upgrade header; reqwest
 *                  will follow any 101 but won't speak h2c natively, so
 *                  we treat a 101 response as confirmation of upgrade acceptance.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "http2";
const AUDIT_TOOL: &str = "mg-http2";
const DEFAULT_CONCURRENCY: usize = 5;
const DEFAULT_TIMEOUT: u64 = 10;

// h2c upgrade header values per RFC 7540 §3.2
const H2C_UPGRADE_VALUE: &str = "h2c";
const H2C_SETTINGS_VALUE: &str = "AAMAAABkAAQAAP__";

// Custom header name/value for HPACK size probe — 100 headers of ~100 bytes each
const HPACK_HEADER_COUNT: usize = 100;
const HPACK_HEADER_NAME_PREFIX: &str = "x-geist-hpack-probe-";
// 100-byte value to exercise HPACK table
const HPACK_HEADER_VALUE: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Known vulnerable server substrings for rapid reset heuristic
// nginx < 1.25.3 and Apache < 2.4.58 are unpatched
const RAPID_RESET_VULNERABLE_NGINX: &str = "nginx/";
const RAPID_RESET_SAFE_NGINX_VERSION: (u32, u32, u32) = (1, 25, 3);
const RAPID_RESET_VULNERABLE_APACHE: &str = "Apache/";
const RAPID_RESET_SAFE_APACHE_VERSION: (u32, u32, u32) = (2, 4, 58);

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-http2",
    about = "HTTP/2 misconfiguration detector — h2c upgrade, ALPN, rapid reset heuristic, HPACK size"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Max concurrent probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u64,
}

// ── Input types ───────────────────────────────────────────────────────────────

// Shape of recon/summary.json
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    open_ports: Vec<u16>,
}

// ── Output types ──────────────────────────────────────────────────────────────

// Severity label
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    Medium,
    Low,
    None,
}

// Result for one host
#[derive(Debug, Clone, Serialize)]
struct Http2Result {
    host: String,
    base_url: String,
    h2c_upgrade_accepted: bool,
    h2c_severity: Severity,
    http2_tls_supported: bool,
    server_header: Option<String>,
    rapid_reset_risk: bool,
    rapid_reset_note: String,
    hpack_large_headers_accepted: bool,
    hpack_severity: Severity,
    error: Option<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct Http2Results {
    engagement: String,
    timestamp: String,
    hosts_checked: usize,
    results: Vec<Http2Result>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

// Choose HTTPS base URL, falling back to HTTP for non-TLS hosts
fn base_url(host: &str, open_ports: &[u16]) -> String {
    if open_ports.contains(&443) || open_ports.contains(&8443) {
        format!("https://{host}")
    } else if open_ports.contains(&80) || open_ports.contains(&8080) {
        format!("http://{host}")
    } else {
        format!("https://{host}")
    }
}

// Parse a version string like "1.25.3" into (major, minor, patch)
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = s.splitn(3, '.').collect();
    if parts.len() < 3 {
        return None;
    }
    let maj = parts[0].parse().ok()?;
    let min = parts[1].parse().ok()?;
    // patch may have trailing characters like "-ubuntu"
    let patch: u32 = parts[2].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
    Some((maj, min, patch))
}

// Return true if version tuple is strictly less than the safe threshold
fn version_lt(v: (u32, u32, u32), safe: (u32, u32, u32)) -> bool {
    v < safe
}

// Check server header for known rapid-reset-vulnerable versions
fn check_rapid_reset(server: &str) -> (bool, String) {
    if let Some(rest) = server.strip_prefix(RAPID_RESET_VULNERABLE_NGINX) {
        // extract version — nginx/1.24.0 → "1.24.0 ..."
        let ver_str = rest.split_whitespace().next().unwrap_or("");
        if let Some(ver) = parse_version(ver_str)
            && version_lt(ver, RAPID_RESET_SAFE_NGINX_VERSION)
        {
            return (
                true,
                format!(
                    "nginx/{ver_str} < {}.{}.{} — likely vulnerable to CVE-2023-44487; verify manually",
                    RAPID_RESET_SAFE_NGINX_VERSION.0,
                    RAPID_RESET_SAFE_NGINX_VERSION.1,
                    RAPID_RESET_SAFE_NGINX_VERSION.2
                ),
            );
        }
    }
    if let Some(rest) = server.strip_prefix(RAPID_RESET_VULNERABLE_APACHE) {
        let ver_str = rest.split_whitespace().next().unwrap_or("");
        if let Some(ver) = parse_version(ver_str)
            && version_lt(ver, RAPID_RESET_SAFE_APACHE_VERSION)
        {
            return (
                true,
                format!(
                    "Apache/{ver_str} < {}.{}.{} — likely vulnerable to CVE-2023-44487; verify manually",
                    RAPID_RESET_SAFE_APACHE_VERSION.0,
                    RAPID_RESET_SAFE_APACHE_VERSION.1,
                    RAPID_RESET_SAFE_APACHE_VERSION.2
                ),
            );
        }
    }
    (false, String::new())
}

// Build reqwest client with HTTP/2 and TLS support
fn build_h2_client(timeout_secs: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .context("build HTTP/2 client")
}

// Build standard client for h2c upgrade and HPACK probes
fn build_http1_client(timeout_secs: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        // no http2_prior_knowledge — uses HTTP/1.1 for upgrade probe
        .build()
        .context("build HTTP/1 client")
}

// Probe h2c cleartext upgrade — returns true if server responds 101
async fn probe_h2c_upgrade(client: &reqwest::Client, url: &str) -> bool {
    let resp = client
        .get(url)
        .header("Upgrade", H2C_UPGRADE_VALUE)
        .header("Connection", "Upgrade, HTTP2-Settings")
        .header("HTTP2-Settings", H2C_SETTINGS_VALUE)
        .send()
        .await;
    match resp {
        Ok(r) => r.status().as_u16() == 101,
        Err(_) => false,
    }
}

// Probe HTTP/2 TLS support — returns (h2_supported, server_header)
async fn probe_h2_tls(h2_client: &reqwest::Client, url: &str) -> (bool, Option<String>) {
    let resp = h2_client.get(url).send().await;
    match resp {
        Ok(r) => {
            let server = r
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            // HTTP/2 responses have version HTTP/2.0
            let is_h2 = r.version() == reqwest::Version::HTTP_2;
            (is_h2, server)
        }
        Err(_) => (false, None),
    }
}

// Probe HPACK: send 100 large headers, return true if accepted (no 431)
async fn probe_hpack(client: &reqwest::Client, url: &str) -> bool {
    let mut headers = HeaderMap::new();
    for i in 0..HPACK_HEADER_COUNT {
        let name_str = format!("{HPACK_HEADER_NAME_PREFIX}{i:03}");
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(name_str.as_bytes()),
            HeaderValue::from_str(HPACK_HEADER_VALUE),
        ) {
            headers.insert(name, val);
        }
    }
    let resp = client.get(url).headers(headers).send().await;
    match resp {
        Ok(r) => r.status().as_u16() != 431,
        // connection error could mean server rejected — treat as not accepted
        Err(_) => false,
    }
}

// Run all checks for one host
async fn probe_host(
    host: String,
    open_ports: Vec<u16>,
    timeout_secs: u64,
) -> Http2Result {
    let url = base_url(&host, &open_ports);

    let h1_client = match build_http1_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            return Http2Result {
                host,
                base_url: url,
                h2c_upgrade_accepted: false,
                h2c_severity: Severity::None,
                http2_tls_supported: false,
                server_header: None,
                rapid_reset_risk: false,
                rapid_reset_note: String::new(),
                hpack_large_headers_accepted: false,
                hpack_severity: Severity::None,
                error: Some(format!("build client: {e}")),
            };
        }
    };

    let h2_client = match build_h2_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            return Http2Result {
                host,
                base_url: url,
                h2c_upgrade_accepted: false,
                h2c_severity: Severity::None,
                http2_tls_supported: false,
                server_header: None,
                rapid_reset_risk: false,
                rapid_reset_note: String::new(),
                hpack_large_headers_accepted: false,
                hpack_severity: Severity::None,
                error: Some(format!("build h2 client: {e}")),
            };
        }
    };

    // h2c upgrade probe — HTTP only (cleartext)
    let h2c_url = if url.starts_with("https://") {
        url.replacen("https://", "http://", 1)
    } else {
        url.clone()
    };
    let h2c_upgrade_accepted = probe_h2c_upgrade(&h1_client, &h2c_url).await;
    let h2c_severity = if h2c_upgrade_accepted {
        Severity::Medium
    } else {
        Severity::None
    };

    // HTTP/2 TLS probe
    let (http2_tls_supported, server_header) = probe_h2_tls(&h2_client, &url).await;

    // rapid reset heuristic
    let (rapid_reset_risk, rapid_reset_note) = server_header
        .as_deref()
        .map(check_rapid_reset)
        .unwrap_or((false, String::new()));

    // HPACK large header probe
    let hpack_large_headers_accepted = probe_hpack(&h1_client, &url).await;
    let hpack_severity = if hpack_large_headers_accepted {
        Severity::Low
    } else {
        Severity::None
    };

    Http2Result {
        host,
        base_url: url,
        h2c_upgrade_accepted,
        h2c_severity,
        http2_tls_supported,
        server_header,
        rapid_reset_risk,
        rapid_reset_note,
        hpack_large_headers_accepted,
        hpack_severity,
        error: None,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // load hosts from recon/summary.json
    let summary_path = eng.recon_dir().join("summary.json");
    anyhow::ensure!(
        summary_path.exists(),
        "recon/summary.json not found — run mg-recon first"
    );
    let raw = fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    // only probe HTTP-reachable hosts
    let hosts: Vec<(String, Vec<u16>)> = summary
        .hosts
        .into_iter()
        .filter(|h| {
            h.open_ports.contains(&443)
                || h.open_ports.contains(&80)
                || h.open_ports.contains(&8443)
                || h.open_ports.contains(&8080)
        })
        .map(|h| (h.hostname, h.open_ports))
        .collect();

    eprintln!(
        "mg-http2: {} hosts to probe (concurrency={})",
        hosts.len(),
        args.concurrency
    );

    let timeout = args.timeout;
    let concurrency = args.concurrency;
    let mut set: JoinSet<Http2Result> = JoinSet::new();
    let mut results: Vec<Http2Result> = Vec::new();

    for (host, ports) in hosts {
        // drain when at ceiling
        if set.len() >= concurrency
            && let Some(Ok(r)) = set.join_next().await
        {
            results.push(r);
        }
        set.spawn(async move { probe_host(host, ports, timeout).await });
    }

    // drain remaining
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }

    results.sort_by(|a, b| a.host.cmp(&b.host));

    // print notable results
    for r in &results {
        if r.h2c_upgrade_accepted {
            eprintln!("  [MEDIUM] {} — h2c cleartext upgrade accepted", r.host);
        }
        if r.rapid_reset_risk {
            eprintln!("  [INFO] {} — {}", r.host, r.rapid_reset_note);
        }
        if r.hpack_large_headers_accepted {
            eprintln!("  [LOW] {} — HPACK large headers accepted (100 x 100-byte headers)", r.host);
        }
        if r.http2_tls_supported {
            eprintln!("  [INFO] {} — HTTP/2 over TLS supported", r.host);
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = Http2Results {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        hosts_checked: results.len(),
        results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create http2 output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write http2 results JSON")?;

    eprintln!("mg-http2: written {}", results_path.display());

    // Emit findings for confirmed HTTP/2 issues
    for r in &output.results {
        if r.h2c_upgrade_accepted {
            let tf = ToolFinding::new("mg-http2", "h2c Cleartext Upgrade Accepted", FindingSeverity::Medium)
                .url(r.base_url.clone())
                .evidence(format!(
                    "host={} responded 101 Switching Protocols to h2c Upgrade request — \
                     plaintext HTTP/2 negotiation accepted; traffic is unencrypted",
                    r.host
                ))
                .recommendation(
                    "Disable h2c cleartext upgrade; enforce TLS for all HTTP/2 traffic; \
                     configure server to reject Upgrade: h2c headers"
                );
            let _ = write_finding(&eng, &tf);
        }
        if r.rapid_reset_risk {
            let tf = ToolFinding::new("mg-http2", "HTTP/2 Rapid Reset Vulnerable Version Detected", FindingSeverity::Medium)
                .url(r.base_url.clone())
                .evidence(format!(
                    "host={} server={} — {}",
                    r.host,
                    r.server_header.as_deref().unwrap_or("unknown"),
                    r.rapid_reset_note
                ))
                .recommendation(
                    "Upgrade nginx to >= 1.25.3 or Apache to >= 2.4.58 to patch CVE-2023-44487; \
                     verify patch status with HTTP/2 rapid reset PoC tooling"
                );
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!("hosts={} ts={ts}", output.hosts_checked)),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_standard() {
        assert_eq!(parse_version("1.25.3"), Some((1, 25, 3)));
        assert_eq!(parse_version("2.4.58"), Some((2, 4, 58)));
    }

    #[test]
    fn parse_version_with_suffix() {
        // e.g. "1.24.0-ubuntu" — patch stops at non-digit
        assert_eq!(parse_version("1.24.0-ubuntu"), Some((1, 24, 0)));
    }

    #[test]
    fn parse_version_insufficient_parts() {
        assert!(parse_version("1.25").is_none());
    }

    #[test]
    fn version_lt_correctly_ordered() {
        assert!(version_lt((1, 24, 0), (1, 25, 3)));
        assert!(version_lt((1, 25, 2), (1, 25, 3)));
        assert!(!version_lt((1, 25, 3), (1, 25, 3)));
        assert!(!version_lt((1, 26, 0), (1, 25, 3)));
    }

    #[test]
    fn rapid_reset_flags_old_nginx() {
        let (risk, note) = check_rapid_reset("nginx/1.24.0");
        assert!(risk);
        assert!(note.contains("CVE-2023-44487"));
    }

    #[test]
    fn rapid_reset_does_not_flag_safe_nginx() {
        let (risk, _) = check_rapid_reset("nginx/1.25.3");
        assert!(!risk);
    }

    #[test]
    fn rapid_reset_flags_old_apache() {
        let (risk, note) = check_rapid_reset("Apache/2.4.57");
        assert!(risk);
        assert!(note.contains("CVE-2023-44487"));
    }

    #[test]
    fn rapid_reset_does_not_flag_safe_apache() {
        let (risk, _) = check_rapid_reset("Apache/2.4.58");
        assert!(!risk);
    }

    #[test]
    fn rapid_reset_unrecognized_server() {
        let (risk, _) = check_rapid_reset("caddy/2.7.0");
        assert!(!risk);
    }

    #[test]
    fn base_url_prefers_https() {
        assert_eq!(base_url("example.com", &[80, 443]), "https://example.com");
    }

    #[test]
    fn base_url_http_only() {
        assert_eq!(base_url("example.com", &[80]), "http://example.com");
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T10:30:00Z"), "2026-05-18T10_30_00Z");
    }
}
