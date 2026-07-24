/*******************************************************************
 * Filename:        cors.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-cors-exploit — active CORS misconfiguration testing;
 *                  origin reflection, null-origin, subdomain/pre-domain bypass.
 * Notes:           Reads recon/summary.json for endpoints and scope.json for
 *                  target domain derivation. Concurrency bounded with JoinSet.
 *                  "Exploitable" = credentials allowed; MEDIUM = reflected
 *                  without credentials (still an information leak).
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
use url::Url;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "cors-exploit";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-cors-exploit";

// Fixed attacker origin used in bypass probes
const ATTACKER_ORIGIN: &str = "https://attacker.com";
const ATTACKER_DOMAIN: &str = "attacker.com";

// Header names used in CORS probes
const HEADER_ORIGIN: &str = "Origin";
const HEADER_ACAO: &str = "access-control-allow-origin";
const HEADER_ACAC: &str = "access-control-allow-credentials";

// Severity strings
const SEVERITY_HIGH: &str = "HIGH";
const SEVERITY_MEDIUM: &str = "MEDIUM";

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
}

// ── Data types ───────────────────────────────────────────────────────────────

// One CORS finding
#[derive(Debug, Serialize)]
struct CorsExploitFinding {
    endpoint: String,
    origin_sent: String,
    acao_received: String,
    acac_received: String,
    severity: String,
    check: String,
    exploitable: bool,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CorsExploitResults {
    engagement: String,
    timestamp: String,
    endpoints_tested: usize,
    findings: Vec<CorsExploitFinding>,
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

// Minimal scope.json shape for target domain extraction
#[derive(Deserialize)]
struct ScopeFile {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    roots: Vec<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Build base URL from a host record, preferring HTTPS
fn base_url_for_host(rec: &HostRecord) -> String {
    if rec.open_ports.contains(&443) {
        return format!("https://{}", rec.hostname);
    }
    if rec.open_ports.contains(&80) {
        return format!("http://{}", rec.hostname);
    }
    format!("https://{}", rec.hostname)
}

// Collect HTTP-accessible endpoints from recon/summary.json
fn collect_endpoints(recon_dir: &Path) -> Vec<String> {
    let summary_path = recon_dir.join("summary.json");
    let Ok(raw) = fs::read_to_string(&summary_path) else {
        return Vec::new();
    };
    let Ok(summary) = serde_json::from_str::<ReconSummary>(&raw) else {
        return Vec::new();
    };
    summary
        .hosts
        .iter()
        .filter(|h| h.http_accessible)
        .map(base_url_for_host)
        .collect()
}

// Derive target domain from scope.json, or from first recon host
fn derive_target_domain(eng: &Engagement) -> Option<String> {
    let scope_path = eng.root.join("scope.json");
    if let Ok(raw) = fs::read_to_string(&scope_path)
        && let Ok(scope_file) = serde_json::from_str::<ScopeFile>(&raw)
    {
        // Prefer scope.domains, then scope.roots
        if let Some(d) = scope_file.domains.into_iter().next() {
            return Some(strip_wildcard(&d));
        }
        if let Some(r) = scope_file.roots.into_iter().next() {
            return Some(strip_wildcard(&r));
        }
    }
    // Fall back to first recon host domain
    let endpoints = collect_endpoints(&eng.recon_dir());
    let first = endpoints.into_iter().next()?;
    Url::parse(&first)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

// Strip leading wildcard from a domain pattern like *.example.com
fn strip_wildcard(domain: &str) -> String {
    domain.trim_start_matches("*.").to_string()
}

// Extract ACAO and ACAC header values from a response
fn cors_headers(resp: &reqwest::Response) -> (String, String) {
    let acao = resp
        .headers()
        .get(HEADER_ACAO)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let acac = resp
        .headers()
        .get(HEADER_ACAC)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (acao, acac)
}

// Return true when ACAC header indicates credentials are allowed
fn creds_allowed(acac: &str) -> bool {
    acac.trim().eq_ignore_ascii_case("true")
}

// ── Probe logic ───────────────────────────────────────────────────────────────

// Result of probing one origin against one endpoint
struct ProbeOutcome {
    endpoint: String,
    origin_sent: String,
    acao: String,
    acac: String,
}

// Send one OPTIONS (preflight) request with a crafted Origin and return headers
async fn probe_origin(
    client: &reqwest::Client,
    endpoint: &str,
    origin: &str,
) -> Option<ProbeOutcome> {
    let resp = client
        .request(reqwest::Method::OPTIONS, endpoint)
        .header(HEADER_ORIGIN, origin)
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .ok()?;
    let (acao, acac) = cors_headers(&resp);
    Some(ProbeOutcome {
        endpoint: endpoint.to_string(),
        origin_sent: origin.to_string(),
        acao,
        acac,
    })
}

// Build a CorsExploitFinding from a probe outcome
fn make_finding(
    o: ProbeOutcome,
    check: &str,
    severity: &str,
    exploitable: bool,
) -> CorsExploitFinding {
    CorsExploitFinding {
        endpoint: o.endpoint,
        origin_sent: o.origin_sent,
        acao_received: o.acao,
        acac_received: o.acac,
        severity: severity.to_string(),
        check: check.to_string(),
        exploitable,
    }
}

// Run all CORS checks for a single endpoint, return findings
async fn check_endpoint(
    client: reqwest::Client,
    endpoint: String,
    target_domain: String,
) -> Vec<CorsExploitFinding> {
    let mut findings = Vec::new();

    // Probe a: arbitrary attacker.com
    if let Some(o) = probe_origin(&client, &endpoint, ATTACKER_ORIGIN).await
        && (o.acao == ATTACKER_ORIGIN || o.acao == "*")
    {
        let exploitable = creds_allowed(&o.acac);
        // wildcard alone is not exploitable unless credentials are also allowed
        let sev = if exploitable {
            SEVERITY_HIGH
        } else {
            SEVERITY_MEDIUM
        };
        findings.push(make_finding(
            o,
            "arbitrary_origin_reflection",
            sev,
            exploitable,
        ));
    }

    // Probe b: null origin
    if let Some(o) = probe_origin(&client, &endpoint, "null").await
        && o.acao == "null"
    {
        let exploitable = creds_allowed(&o.acac);
        findings.push(make_finding(
            o,
            "null_origin_reflection",
            SEVERITY_HIGH,
            exploitable,
        ));
    }

    // Probe c: evil.<target_domain> (subdomain of target)
    let evil_sub = format!("https://evil.{target_domain}");
    if let Some(o) = probe_origin(&client, &endpoint, &evil_sub).await
        && o.acao == evil_sub
    {
        let exploitable = creds_allowed(&o.acac);
        let sev = if exploitable {
            SEVERITY_HIGH
        } else {
            SEVERITY_MEDIUM
        };
        findings.push(make_finding(o, "subdomain_bypass", sev, exploitable));
    }

    // Probe d: <target_domain>.attacker.com (pre-domain bypass)
    let pre_domain = format!("https://{target_domain}.{ATTACKER_DOMAIN}");
    if let Some(o) = probe_origin(&client, &endpoint, &pre_domain).await
        && o.acao == pre_domain
    {
        let exploitable = creds_allowed(&o.acac);
        let sev = if exploitable {
            SEVERITY_HIGH
        } else {
            SEVERITY_MEDIUM
        };
        findings.push(make_finding(o, "pre_domain_bypass", sev, exploitable));
    }

    // Probe e: HTTP downgrade of target domain
    let http_origin = format!("http://{target_domain}");
    if let Some(o) = probe_origin(&client, &endpoint, &http_origin).await
        && o.acao == http_origin
    {
        let exploitable = creds_allowed(&o.acac);
        let sev = if exploitable {
            SEVERITY_HIGH
        } else {
            SEVERITY_MEDIUM
        };
        findings.push(make_finding(o, "http_downgrade", sev, exploitable));
    }

    // Probe f: wildcard with credentials (invalid per spec but some servers emit this)
    // Use a benign origin so the server reveals its static ACAO header
    if let Some(o) = probe_origin(&client, &endpoint, "https://check.example.com").await
        && o.acao == "*"
        && creds_allowed(&o.acac)
    {
        findings.push(make_finding(
            o,
            "wildcard_with_credentials",
            SEVERITY_HIGH,
            true,
        ));
    }

    findings
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Load session auth headers
    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    // Build HTTP client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Collect endpoints from recon summary
    let endpoints = collect_endpoints(&eng.recon_dir());
    if endpoints.is_empty() {
        anyhow::bail!(
            "No HTTP-accessible endpoints found in recon/summary.json — run mg-recon first"
        );
    }

    // Derive target domain for bypass probes
    let target_domain = derive_target_domain(&eng).unwrap_or_else(|| eng.meta.target.clone());

    eprintln!(
        "mg-cors-exploit: {} endpoint(s), target_domain={}",
        endpoints.len(),
        target_domain
    );

    // Run checks with bounded concurrency
    let mut join_set: JoinSet<Vec<CorsExploitFinding>> = JoinSet::new();
    let mut all_findings: Vec<CorsExploitFinding> = Vec::new();
    let endpoint_count = endpoints.len();

    for endpoint in endpoints {
        eprintln!("  probing {endpoint}");
        if join_set.len() >= args.concurrency
            && let Some(Ok(batch)) = join_set.join_next().await
        {
            all_findings.extend(batch);
        }
        join_set.spawn(check_endpoint(
            client.clone(),
            endpoint,
            target_domain.clone(),
        ));
    }
    while let Some(Ok(batch)) = join_set.join_next().await {
        all_findings.extend(batch);
    }

    // Print findings
    println!("\n=== CORS Exploit Findings ===");
    for f in &all_findings {
        println!(
            "[{}] {} check={} origin={} acao={}",
            f.severity, f.endpoint, f.check, f.origin_sent, f.acao_received
        );
    }
    println!("Total: {} finding(s)", all_findings.len());

    // Write results JSON
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create cors-exploit output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = CorsExploitResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        endpoints_tested: endpoint_count,
        findings: all_findings,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Emit standardized findings for HIGH/MEDIUM CORS issues
    for f in &results.findings {
        let sev = match f.severity.as_str() {
            "HIGH" => FindingSeverity::High,
            "MEDIUM" => FindingSeverity::Medium,
            _ => continue,
        };
        let tf = ToolFinding::new(AUDIT_TOOL, format!("CORS Misconfiguration: {}", f.check), sev)
            .url(f.endpoint.clone())
            .evidence(format!("Origin sent: {} — ACAO received: {}", f.origin_sent, f.acao_received))
            .recommendation("Validate Origin against an explicit allowlist; never reflect arbitrary origins with credentials");
        let _ = write_finding(&eng, &tf);
    }

    // Audit log
    let detail = format!(
        "endpoints={} findings={}",
        results.endpoints_tested,
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
    fn strip_wildcard_removes_prefix() {
        assert_eq!(strip_wildcard("*.example.com"), "example.com");
        assert_eq!(strip_wildcard("example.com"), "example.com");
    }

    #[test]
    fn creds_allowed_case_insensitive() {
        assert!(creds_allowed("true"));
        assert!(creds_allowed("True"));
        assert!(creds_allowed("TRUE"));
        assert!(!creds_allowed("false"));
        assert!(!creds_allowed(""));
    }

    #[test]
    fn collect_endpoints_returns_empty_for_missing_summary() {
        let result = collect_endpoints(Path::new("/nonexistent/recon"));
        assert!(result.is_empty());
    }

    #[test]
    fn collect_endpoints_parses_summary_json() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = serde_json::json!({
            "hosts": [
                {"hostname": "api.example.com", "http_accessible": true, "open_ports": [443]},
                {"hostname": "internal.example.com", "http_accessible": false, "open_ports": []}
            ]
        });
        fs::write(
            tmp.path().join("summary.json"),
            serde_json::to_string(&summary).unwrap(),
        )
        .unwrap();
        let endpoints = collect_endpoints(tmp.path());
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0], "https://api.example.com");
    }

    #[test]
    fn base_url_for_host_prefers_https_port_443() {
        let rec = HostRecord {
            hostname: "example.com".to_string(),
            http_accessible: true,
            open_ports: vec![80, 443],
        };
        assert_eq!(base_url_for_host(&rec), "https://example.com");
    }

    #[test]
    fn base_url_for_host_falls_back_to_https_when_no_known_ports() {
        let rec = HostRecord {
            hostname: "example.com".to_string(),
            http_accessible: true,
            open_ports: vec![],
        };
        assert_eq!(base_url_for_host(&rec), "https://example.com");
    }
}
