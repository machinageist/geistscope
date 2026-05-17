/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     mg-probe — passive and semi-active security posture checker
 *                  Reads recon/summary.json and crawl/ output, runs checks for
 *                  missing headers, CORS issues, bad cookies, exposed debug paths,
 *                  and stack traces in crawl HTML. Writes finding .md files.
 * Notes:           "Semi-active" means it probes debug paths (real HTTP requests)
 *                  but never modifies state or sends attack payloads.
 *                  All requests respect the engagement scope.
 *                  Rate-limited to 2 req/sec by default.
 *******************************************************************/

mod checks;
mod report;

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

use engagement::Engagement;

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-probe",
    about = "Passive security posture checker — headers, CORS, cookies, exposure"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Minimum milliseconds between requests
    #[arg(long, default_value_t = 500)]
    rate_ms: u64,

    /// HTTP timeout in milliseconds
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,

    /// Skip the exposed-paths probe (faster, no active requests beyond headers/CORS/cookies)
    #[arg(long)]
    passive_only: bool,

    /// Enable low-volume active endpoint probes from crawl endpoints.json
    #[arg(long)]
    active: bool,

    /// Re-run even if probe-report.json is fresh (always overwrites)
    #[arg(long)]
    force: bool,
}

// ── Recon types ──────────────────────────────────────────────────────────────

// Mirrors the HostRecord shape written by mg-recon orchestrator
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[allow(dead_code)] // present in JSON; retained for future scheme-selection logic
    fingerprint: Option<serde_json::Value>,
    #[allow(dead_code)]
    open_ports: Vec<u16>,
}

// Mirrors the ReconSummary shape written by mg-recon orchestrator
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
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

    // skip if already probed and not forced; probe-report.json age is not checked
    // (probe is cheap enough to always re-run if explicitly requested)
    let report_path = eng.recon_dir().join("probe-report.json");
    if !args.force && report_path.exists() {
        eprintln!("probe-report.json exists — use --force to re-run");
        return Ok(());
    }

    // build scope checker for filtering which hosts to probe
    let scope = eng.scope().context("load scope")?;
    let default_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;
    let auth_header_count = default_headers.len();

    // build reqwest client with configured timeout and rate limiting
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout_ms))
        .user_agent("mg-probe/0.1 (security posture scanner)")
        .default_headers(default_headers)
        .build()
        .context("build HTTP client")?;
    let active_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout_ms))
        .user_agent("mg-probe/0.1 (active endpoint checker)")
        .default_headers(session::get_auth_headers(&eng).await?)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build active HTTP client")?;

    // load and parse the recon summary
    let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let http_hosts: Vec<&HostRecord> = summary
        .hosts
        .iter()
        .filter(|h| h.http_accessible && scope.is_in_scope(&h.hostname))
        .collect();

    eprintln!(
        "mg-probe: {} HTTP-accessible hosts, auth_headers={}",
        http_hosts.len(),
        auth_header_count
    );

    let mut all_issues = Vec::new();
    let rate = Duration::from_millis(args.rate_ms);

    // run all checks for each HTTP-accessible in-scope host
    for host_rec in &http_hosts {
        let host = &host_rec.hostname;

        // choose scheme/port from recon so nonstandard HTTP services work
        let base_url = base_url_for_host(host_rec);

        eprintln!("  checking {base_url}");

        // security header check — one GET to root
        let mut h_issues = checks::check_security_headers(&client, &base_url, host).await;
        tokio::time::sleep(rate).await;

        // CORS check — one GET with foreign Origin
        let mut cors_issues = checks::check_cors(&client, &base_url, host).await;
        tokio::time::sleep(rate).await;

        // cookie check — one GET to root
        let mut cookie_issues = checks::check_cookies(&client, &base_url, host).await;
        tokio::time::sleep(rate).await;

        all_issues.append(&mut h_issues);
        all_issues.append(&mut cors_issues);
        all_issues.append(&mut cookie_issues);

        // exposed path probe — multiple GETs, skip if passive-only mode
        if !args.passive_only {
            let mut path_issues = checks::check_exposed_paths(&client, &base_url, host).await;
            tokio::time::sleep(rate).await;
            all_issues.append(&mut path_issues);
        }

        // HTML analysis — reads stored crawl files, no network I/O
        let crawl_host_dir = eng.crawl_dir().join(host);
        if crawl_host_dir.exists() {
            let index_path = crawl_host_dir.join("index.json");
            if index_path.exists() {
                let raw = std::fs::read_to_string(&index_path).unwrap_or_default();
                let index: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
                let mut html_issues = checks::check_html_files(&crawl_host_dir, host, &index);
                all_issues.append(&mut html_issues);
            }
            if args.active {
                let mut active_issues = checks::check_active_endpoint_params(
                    &active_client,
                    &base_url,
                    host,
                    &crawl_host_dir,
                    rate,
                )
                .await;
                all_issues.append(&mut active_issues);
            }
        }
    }

    eprintln!("  {} total issues found", all_issues.len());

    // write findings/ markdown files and probe-report.json
    report::write_report(
        &all_issues,
        &eng.findings_dir(),
        &eng.recon_dir(),
        &args.engagement,
    )
    .context("write report")?;

    // record the run in the audit log
    let _ = eng.audit(
        "mg-probe",
        &eng.meta.target,
        Some(&format!(
            "hosts={} issues={} active={} auth_headers={}",
            http_hosts.len(),
            all_issues.len(),
            args.active,
            auth_header_count
        )),
    );

    eprintln!("  written: {}", report_path.display());
    Ok(())
}

// Choose a base URL from recon ports, preferring HTTPS when available
fn base_url_for_host(host: &HostRecord) -> String {
    if host.open_ports.contains(&443) {
        return format!("https://{}", host.hostname);
    }
    if host.open_ports.contains(&80) {
        return format!("http://{}", host.hostname);
    }
    if let Some(port) = host
        .open_ports
        .iter()
        .copied()
        .find(|port| *port == 8443 || *port == 9443)
    {
        return format!("https://{}:{port}", host.hostname);
    }
    if let Some(port) = host.open_ports.first() {
        return format!("http://{}:{port}", host.hostname);
    }
    format!("https://{}", host.hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_uses_nonstandard_http_port() {
        let host = HostRecord {
            hostname: "localhost".into(),
            http_accessible: true,
            fingerprint: None,
            open_ports: vec![18080],
        };
        assert_eq!(base_url_for_host(&host), "http://localhost:18080");
    }

    #[test]
    fn base_url_prefers_https_default_port() {
        let host = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            fingerprint: None,
            open_ports: vec![80, 443],
        };
        assert_eq!(base_url_for_host(&host), "https://example.com");
    }
}
