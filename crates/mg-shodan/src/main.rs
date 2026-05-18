/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-shodan — Shodan host lookup, DNS resolve, and facet search.
 * Notes:           API key required — --api-key flag or $MG_SHODAN_KEY env var.
 *                  Domain targets are first resolved to IP via hickory-resolver.
 *                  CVEs are printed in red (ANSI) on the terminal.
 *                  All Shodan API calls share one reqwest client instance.
 *******************************************************************/

use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const SHODAN_API_BASE: &str = "https://api.shodan.io";
const OUTPUT_SUBDIR: &str = "shodan";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-shodan";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// ANSI color codes for terminal output
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";
// Max banner preview length to avoid enormous output
const BANNER_PREVIEW_LEN: usize = 200;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-shodan",
    about = "Shodan host lookup and search — requires a Shodan API key"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// IP or domain to look up (default: read from engagement scope)
    #[arg(long)]
    target: Option<String>,

    /// Shodan API key (or set $MG_SHODAN_KEY)
    #[arg(long, env = "MG_SHODAN_KEY")]
    api_key: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Shodan response types ─────────────────────────────────────────────────────

// Per-port service record from Shodan host data
#[derive(Debug, Deserialize, Serialize)]
struct ShodanService {
    port: Option<u16>,
    transport: Option<String>,
    product: Option<String>,
    version: Option<String>,
    #[serde(default)]
    data: String,
}

// Shodan host lookup response (/shodan/host/<ip>)
#[derive(Debug, Deserialize)]
struct ShodanHost {
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    vulns: Option<Vec<String>>,
    #[serde(default)]
    data: Vec<ShodanService>,
}

// Shodan search result match
#[derive(Debug, Deserialize, Serialize)]
struct ShodanSearchMatch {
    ip_str: Option<String>,
    port: Option<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    product: Option<String>,
    version: Option<String>,
}

// Shodan search response (/shodan/host/search)
#[derive(Debug, Deserialize)]
struct ShodanSearchResponse {
    #[serde(default)]
    matches: Vec<ShodanSearchMatch>,
}

// Condensed per-port record for output
#[derive(Debug, Serialize)]
struct ServiceRecord {
    port: u16,
    transport: String,
    product: String,
    version: String,
    banner_preview: String,
}

// Scope JSON subset
#[derive(Deserialize)]
struct ScopeJson {
    target: String,
}

// Top-level output
#[derive(Serialize)]
struct ShodanResults {
    engagement: String,
    timestamp: String,
    target: String,
    ip: String,
    org: Option<String>,
    os: Option<String>,
    ports: Vec<u16>,
    hostnames: Vec<String>,
    cves: Vec<String>,
    services: Vec<ServiceRecord>,
    search_matches: Vec<ShodanSearchMatch>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Resolve a domain name to its first IPv4/IPv6 address
async fn resolve_domain(domain: &str) -> Result<IpAddr> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let response = resolver
        .lookup_ip(domain)
        .await
        .with_context(|| format!("DNS resolve {domain}"))?;
    response
        .iter()
        .next()
        .with_context(|| format!("no addresses for {domain}"))
}

// Return true if the string looks like an IP address (v4 or v6)
fn is_ip_addr(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

// Build a condensed ServiceRecord from a raw Shodan service entry
fn service_record_from(svc: &ShodanService) -> ServiceRecord {
    let preview_end = svc.data.len().min(BANNER_PREVIEW_LEN);
    ServiceRecord {
        port: svc.port.unwrap_or(0),
        transport: svc.transport.clone().unwrap_or_default(),
        product: svc.product.clone().unwrap_or_default(),
        version: svc.version.clone().unwrap_or_default(),
        banner_preview: svc.data[..preview_end].replace('\n', " "),
    }
}

// ── Shodan API calls ──────────────────────────────────────────────────────────

// Fetch host info for a known IP address
async fn shodan_host_lookup(
    client: &reqwest::Client,
    ip: &str,
    api_key: &str,
) -> Result<ShodanHost> {
    let url = format!("{SHODAN_API_BASE}/shodan/host/{ip}?key={api_key}");
    let resp = client
        .get(&url)
        .send()
        .await
        .context("Shodan host lookup request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Shodan host lookup returned {status}: {body}");
    }

    resp.json::<ShodanHost>()
        .await
        .context("parse Shodan host JSON")
}

// Fetch search results for a hostname query
async fn shodan_search(
    client: &reqwest::Client,
    domain: &str,
    api_key: &str,
) -> Result<ShodanSearchResponse> {
    let query = format!("hostname:{domain}");
    let url = format!(
        "{SHODAN_API_BASE}/shodan/host/search?query={query}&key={api_key}"
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .context("Shodan search request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Shodan search returned {status}: {body}");
    }

    resp.json::<ShodanSearchResponse>()
        .await
        .context("parse Shodan search JSON")
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // API key is required; no silent fallback
    let api_key = match args.api_key {
        Some(k) => k,
        None => {
            bail!("Shodan API key required — use --api-key or set $MG_SHODAN_KEY");
        }
    };

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Resolve target
    let target = if let Some(t) = args.target {
        t
    } else {
        let scope_path = eng.root.join("scope.json");
        let raw = fs::read_to_string(&scope_path).context("read scope.json")?;
        let scope_json: ScopeJson = serde_json::from_str(&raw).context("parse scope.json")?;
        scope_json.target
    };

    eprintln!("mg-shodan: target={target}");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-shodan/0.1")
        .build()
        .context("build HTTP client")?;

    // Resolve domain to IP if needed
    let ip = if is_ip_addr(&target) {
        target.clone()
    } else {
        eprintln!("  resolving {target} to IP...");
        let addr = resolve_domain(&target).await?;
        let ip_str = addr.to_string();
        eprintln!("  resolved to {ip_str}");
        ip_str
    };

    // Host lookup
    eprintln!("  querying Shodan host data for {ip}...");
    let host_data = shodan_host_lookup(&client, &ip, &api_key).await?;

    let cves: Vec<String> = host_data.vulns.unwrap_or_default();
    let services: Vec<ServiceRecord> = host_data
        .data
        .iter()
        .map(service_record_from)
        .collect();

    // Hostname-based search (only if target is a domain)
    let search_matches = if !is_ip_addr(&target) {
        eprintln!("  running Shodan hostname search for {target}...");
        shodan_search(&client, &target, &api_key)
            .await
            .map(|r| r.matches)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Print findings
    println!("\n=== Shodan Results: {target} ({ip}) ===");
    if let Some(org) = &host_data.org {
        println!("Org:       {org}");
    }
    if let Some(os) = &host_data.os {
        println!("OS:        {os}");
    }
    if !host_data.ports.is_empty() {
        let ports: Vec<String> = host_data.ports.iter().map(|p| p.to_string()).collect();
        println!("Ports:     {}", ports.join(", "));
    }
    if !host_data.hostnames.is_empty() {
        println!("Hostnames: {}", host_data.hostnames.join(", "));
    }
    if !cves.is_empty() {
        println!("\n{ANSI_RED}CVEs:{ANSI_RESET}");
        for cve in &cves {
            println!("  {ANSI_RED}{cve}{ANSI_RESET}");
        }
    }
    if !services.is_empty() {
        println!("\nServices:");
        for svc in &services {
            println!(
                "  :{}/{}  {} {}",
                svc.port, svc.transport, svc.product, svc.version
            );
        }
    }
    if !search_matches.is_empty() {
        println!("\nSearch matches: {}", search_matches.len());
    }

    // Write findings for each CVE (HIGH) and each versioned service (MEDIUM)
    for cve in &cves {
        let tf = ToolFinding::new(AUDIT_TOOL, format!("Shodan CVE: {cve}"), FindingSeverity::High)
            .url(format!("shodan://{target}"))
            .evidence(format!("CVE {cve} listed in Shodan host data for {ip}"))
            .recommendation("Patch the vulnerable service or restrict access");
        let _ = write_finding(&eng, &tf);
    }
    for svc in &services {
        if !svc.version.is_empty() {
            let tf = ToolFinding::new(
                AUDIT_TOOL,
                format!("Exposed service with version: {} {}", svc.product, svc.version),
                FindingSeverity::Medium,
            )
            .url(format!("shodan://{target}"))
            .evidence(format!("Port {}/{}: {} {}", svc.port, svc.transport, svc.product, svc.version))
            .recommendation("Restrict service exposure and update to a patched version");
            let _ = write_finding(&eng, &tf);
        }
    }

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create shodan output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = ShodanResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        target: target.clone(),
        ip,
        org: host_data.org,
        os: host_data.os,
        ports: host_data.ports,
        hostnames: host_data.hostnames,
        cves,
        services,
        search_matches,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let _ = eng.audit(AUDIT_TOOL, &target, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ip_addr_recognizes_ipv4() {
        assert!(is_ip_addr("192.168.1.1"));
        assert!(is_ip_addr("1.2.3.4"));
        assert!(!is_ip_addr("example.com"));
        assert!(!is_ip_addr("not an ip"));
    }

    #[test]
    fn is_ip_addr_recognizes_ipv6() {
        assert!(is_ip_addr("::1"));
        assert!(is_ip_addr("2001:db8::1"));
        assert!(!is_ip_addr("2001:db8::1:extra_garbage"));
    }

    #[test]
    fn service_record_truncates_banner() {
        let svc = ShodanService {
            port: Some(80),
            transport: Some("tcp".into()),
            product: Some("nginx".into()),
            version: Some("1.18".into()),
            data: "A".repeat(BANNER_PREVIEW_LEN + 100),
        };
        let rec = service_record_from(&svc);
        assert_eq!(rec.banner_preview.len(), BANNER_PREVIEW_LEN);
    }

    #[test]
    fn service_record_replaces_newlines() {
        let svc = ShodanService {
            port: Some(22),
            transport: Some("tcp".into()),
            product: Some("OpenSSH".into()),
            version: Some("8.0".into()),
            data: "line1\nline2\nline3".into(),
        };
        let rec = service_record_from(&svc);
        assert!(!rec.banner_preview.contains('\n'));
    }

    #[test]
    fn service_record_defaults_zero_for_missing_port() {
        let svc = ShodanService {
            port: None,
            transport: None,
            product: None,
            version: None,
            data: String::new(),
        };
        let rec = service_record_from(&svc);
        assert_eq!(rec.port, 0);
    }
}
