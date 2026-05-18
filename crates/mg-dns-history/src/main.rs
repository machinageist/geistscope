/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-dns-history — historical DNS records via SecurityTrails or HackerTarget.
 * Notes:           SecurityTrails requires an API key (--api-key or $MG_SECURITYTRAILS_KEY).
 *                  Without a key, falls back to HackerTarget free tier (subdomain CSV only).
 *                  Old IPs are cross-referenced against recon/summary.json to flag
 *                  IPs that no longer appear in the current scan.
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

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const ST_API_BASE: &str = "https://api.securitytrails.com/v1";
const HT_HOSTSEARCH_URL: &str = "https://api.hackertarget.com/hostsearch/";
const OUTPUT_SUBDIR: &str = "dns-history";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-dns-history";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-dns-history",
    about = "Historical DNS records via SecurityTrails or HackerTarget"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Domain to look up historical DNS for
    #[arg(long)]
    domain: String,

    /// SecurityTrails API key (or set $MG_SECURITYTRAILS_KEY)
    #[arg(long, env = "MG_SECURITYTRAILS_KEY")]
    api_key: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One historical A record entry from SecurityTrails
#[derive(Debug, Deserialize)]
struct StARecord {
    #[serde(default)]
    values: Vec<StAValue>,
}

#[derive(Debug, Deserialize)]
struct StAValue {
    ip: String,
}

// SecurityTrails history response wrapper
#[derive(Debug, Deserialize)]
struct StHistoryResponse {
    #[serde(default)]
    records: Vec<StARecord>,
}

// One historical CNAME record entry from SecurityTrails
#[derive(Debug, Deserialize)]
struct StCnameRecord {
    #[serde(default)]
    values: Vec<StCnameValue>,
}

#[derive(Debug, Deserialize)]
struct StCnameValue {
    hostname: String,
}

// SecurityTrails CNAME history response wrapper
#[derive(Debug, Deserialize)]
struct StCnameHistoryResponse {
    #[serde(default)]
    records: Vec<StCnameRecord>,
}

// SecurityTrails subdomains response
#[derive(Debug, Deserialize)]
struct StSubdomainsResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

// Current host from recon/summary.json — only fields we need
#[derive(Debug, Deserialize)]
struct ReconHost {
    // hostname is in the JSON but we only need the IPs for cross-reference
    #[allow(dead_code)]
    hostname: String,
    #[serde(default)]
    ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReconSummary {
    #[serde(default)]
    hosts: Vec<ReconHost>,
}

// One flagged old IP not seen in current scan
#[derive(Debug, Serialize)]
struct StaleIp {
    ip: String,
    found_in_history: bool,
}

// Top-level output written to disk
#[derive(Serialize)]
struct DnsHistoryResults {
    engagement: String,
    timestamp: String,
    domain: String,
    source: String,
    historical_a_ips: Vec<String>,
    historical_cnames: Vec<String>,
    subdomains: Vec<String>,
    stale_ips: Vec<StaleIp>,
}

// ── SecurityTrails helpers ────────────────────────────────────────────────────

// Fetch historical A records for a domain from SecurityTrails
async fn st_fetch_a_records(
    client: &reqwest::Client,
    domain: &str,
    api_key: &str,
) -> Result<Vec<String>> {
    let url = format!("{ST_API_BASE}/history/{domain}/dns/a");
    let resp = client
        .get(&url)
        .header("apikey", api_key)
        .send()
        .await
        .context("SecurityTrails A history request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("SecurityTrails A history returned {status}: {body}");
    }

    let parsed: StHistoryResponse = resp.json().await.context("parse ST A history JSON")?;
    let mut ips: Vec<String> = parsed
        .records
        .into_iter()
        .flat_map(|r| r.values.into_iter().map(|v| v.ip))
        .collect();
    ips.sort();
    ips.dedup();
    Ok(ips)
}

// Fetch historical CNAME records for a domain from SecurityTrails
async fn st_fetch_cname_records(
    client: &reqwest::Client,
    domain: &str,
    api_key: &str,
) -> Result<Vec<String>> {
    let url = format!("{ST_API_BASE}/history/{domain}/dns/cname");
    let resp = client
        .get(&url)
        .header("apikey", api_key)
        .send()
        .await
        .context("SecurityTrails CNAME history request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("SecurityTrails CNAME history returned {status}: {body}");
    }

    let parsed: StCnameHistoryResponse = resp.json().await.context("parse ST CNAME history JSON")?;
    let mut cnames: Vec<String> = parsed
        .records
        .into_iter()
        .flat_map(|r| r.values.into_iter().map(|v| v.hostname))
        .collect();
    cnames.sort();
    cnames.dedup();
    Ok(cnames)
}

// Fetch subdomain list for a domain from SecurityTrails
async fn st_fetch_subdomains(
    client: &reqwest::Client,
    domain: &str,
    api_key: &str,
) -> Result<Vec<String>> {
    let url = format!("{ST_API_BASE}/domain/{domain}/subdomains");
    let resp = client
        .get(&url)
        .header("apikey", api_key)
        .send()
        .await
        .context("SecurityTrails subdomains request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("SecurityTrails subdomains returned {status}: {body}");
    }

    let parsed: StSubdomainsResponse = resp.json().await.context("parse ST subdomains JSON")?;
    Ok(parsed.subdomains)
}

// ── HackerTarget fallback ─────────────────────────────────────────────────────

// Fetch subdomain+IP pairs from HackerTarget free API, return (subdomains, ips)
async fn ht_hostsearch(
    client: &reqwest::Client,
    domain: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let url = format!("{HT_HOSTSEARCH_URL}?q={domain}");
    let text = client
        .get(&url)
        .send()
        .await
        .context("HackerTarget hostsearch request")?
        .text()
        .await
        .context("HackerTarget response text")?;

    // Response is CSV: subdomain,ip per line
    let mut subdomains = Vec::new();
    let mut ips = Vec::new();
    for line in text.lines() {
        if let Some((sub, ip)) = line.split_once(',') {
            let sub = sub.trim().to_string();
            let ip = ip.trim().to_string();
            if !sub.is_empty() {
                subdomains.push(sub);
            }
            if !ip.is_empty() {
                ips.push(ip);
            }
        }
    }
    subdomains.sort();
    subdomains.dedup();
    ips.sort();
    ips.dedup();
    Ok((subdomains, ips))
}

// ── Cross-reference helper ────────────────────────────────────────────────────

// Compare historical IPs against current recon summary; return IPs not currently seen
fn find_stale_ips(historical: &[String], summary_path: &Path) -> Vec<StaleIp> {
    if !summary_path.exists() {
        return Vec::new();
    }
    let raw = match fs::read_to_string(summary_path) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let summary: ReconSummary = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    // Collect all IPs seen in the current recon scan
    let current_ips: HashSet<String> = summary
        .hosts
        .iter()
        .flat_map(|h| h.ips.iter().cloned())
        .collect();

    historical
        .iter()
        .filter(|ip| !current_ips.contains(*ip))
        .map(|ip| StaleIp {
            ip: ip.clone(),
            found_in_history: true,
        })
        .collect()
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-dns-history: domain={}", args.domain);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-dns-history/0.1")
        .build()
        .context("build HTTP client")?;

    let (source, historical_a_ips, historical_cnames, subdomains) =
        if let Some(ref key) = args.api_key {
            eprintln!("  using SecurityTrails API");
            let a_ips = st_fetch_a_records(&client, &args.domain, key)
                .await
                .unwrap_or_default();
            let cnames = st_fetch_cname_records(&client, &args.domain, key)
                .await
                .unwrap_or_default();
            let subs = st_fetch_subdomains(&client, &args.domain, key)
                .await
                .unwrap_or_default();
            eprintln!(
                "  {} historical IPs, {} CNAMEs, {} subdomains",
                a_ips.len(),
                cnames.len(),
                subs.len()
            );
            ("securitytrails".to_string(), a_ips, cnames, subs)
        } else {
            eprintln!("  no API key — falling back to HackerTarget free API");
            let (subs, ips) = ht_hostsearch(&client, &args.domain)
                .await
                .unwrap_or_default();
            eprintln!("  {} subdomains, {} IPs", subs.len(), ips.len());
            ("hackertarget".to_string(), ips, Vec::new(), subs)
        };

    // Cross-reference against current recon summary
    let summary_path = eng.recon_dir().join("summary.json");
    let stale_ips = find_stale_ips(&historical_a_ips, &summary_path);
    if !stale_ips.is_empty() {
        eprintln!("  {} stale IPs (not in current recon):", stale_ips.len());
        for s in &stale_ips {
            eprintln!("    {}", s.ip);
        }
    }

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create dns-history output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = DnsHistoryResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        domain: args.domain.clone(),
        source,
        historical_a_ips,
        historical_cnames,
        subdomains,
        stale_ips,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    let _ = eng.audit(AUDIT_TOOL, &args.domain, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ht_parse_csv_splits_correctly() {
        // Simulate the CSV parsing logic inline
        let text = "sub.example.com,1.2.3.4\nother.example.com,5.6.7.8\n";
        let mut subs = Vec::new();
        let mut ips = Vec::new();
        for line in text.lines() {
            if let Some((sub, ip)) = line.split_once(',') {
                subs.push(sub.trim().to_string());
                ips.push(ip.trim().to_string());
            }
        }
        assert_eq!(subs, vec!["sub.example.com", "other.example.com"]);
        assert_eq!(ips, vec!["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn find_stale_ips_returns_empty_when_no_summary() {
        let historical = vec!["1.2.3.4".to_string()];
        let path = Path::new("/nonexistent/summary.json");
        let stale = find_stale_ips(&historical, path);
        assert!(stale.is_empty());
    }
}
