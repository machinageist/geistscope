/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-whois — WHOIS, ASN, and BGP prefix lookup for a target.
 * Notes:           WHOIS is done via raw TCP to whois.iana.org:43 to discover
 *                  the authoritative server, then a second TCP connection to
 *                  that server for the full record.
 *                  ASN data comes from ipinfo.io (free tier, no key needed).
 *                  BGP prefixes come from api.bgpview.io (no key needed).
 *                  --target overrides the engagement scope domain.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const WHOIS_IANA_HOST: &str = "whois.iana.org";
const WHOIS_PORT: u16 = 43;
const OUTPUT_SUBDIR: &str = "whois";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-whois";
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const IPINFO_BASE: &str = "https://ipinfo.io";
const BGPVIEW_BASE: &str = "https://api.bgpview.io/asn";
// Maximum bytes to read from a WHOIS TCP connection
const WHOIS_READ_LIMIT: usize = 65_536;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-whois",
    about = "WHOIS, ASN, and BGP prefix lookup for a target domain or IP"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Domain or IP to look up (default: read from engagement scope)
    #[arg(long)]
    target: Option<String>,

    /// HTTP + WHOIS timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Parsed WHOIS fields of interest
#[derive(Debug, Default, Serialize)]
struct WhoisInfo {
    raw: String,
    registrar: Option<String>,
    registrant: Option<String>,
    name_servers: Vec<String>,
    creation_date: Option<String>,
    expiry_date: Option<String>,
}

// Shape of ipinfo.io JSON response
#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    #[serde(default)]
    org: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    ip: String,
}

// ASN + geo info derived from ipinfo.io
#[derive(Debug, Default, Serialize)]
struct AsnInfo {
    asn: Option<String>,
    org: String,
    country: String,
    city: String,
    ip: String,
}

// One prefix entry from bgpview.io
#[derive(Debug, Serialize, Deserialize)]
struct BgpPrefix {
    prefix: String,
}

// Shape of the bgpview.io ASN prefixes response
#[derive(Debug, Deserialize)]
struct BgpViewData {
    #[serde(default)]
    ipv4_prefixes: Vec<BgpPrefix>,
    #[serde(default)]
    ipv6_prefixes: Vec<BgpPrefix>,
}

#[derive(Debug, Deserialize)]
struct BgpViewResponse {
    data: Option<BgpViewData>,
}

// BGP prefix results
#[derive(Debug, Default, Serialize)]
struct BgpInfo {
    ipv4_prefixes: Vec<String>,
    ipv6_prefixes: Vec<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct WhoisResults {
    engagement: String,
    timestamp: String,
    target: String,
    whois: WhoisInfo,
    asn: AsnInfo,
    bgp: BgpInfo,
}

// Scope JSON subset for reading the target domain
#[derive(Deserialize)]
struct ScopeJson {
    target: String,
}

// ── WHOIS helpers ─────────────────────────────────────────────────────────────

// Query a WHOIS server over TCP and return the raw response text
async fn whois_query(server: &str, query: &str, timeout: Duration) -> Result<String> {
    let addr = format!("{server}:{WHOIS_PORT}");
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("connect timeout to {server}"))?
        .with_context(|| format!("connect to {server}"))?;
    let mut tcp = tcp;
    let msg = format!("{query}\r\n");
    tokio::time::timeout(timeout, tcp.write_all(msg.as_bytes()))
        .await
        .context("write timeout")?
        .context("write query")?;

    let mut buf = Vec::with_capacity(4096);
    // Read until EOF, capped at WHOIS_READ_LIMIT
    let _ = tokio::time::timeout(timeout, async {
        let mut tmp = [0u8; 4096];
        loop {
            let n = tcp.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            let remaining = WHOIS_READ_LIMIT.saturating_sub(buf.len());
            buf.extend_from_slice(&tmp[..n.min(remaining)]);
            if buf.len() >= WHOIS_READ_LIMIT {
                break;
            }
        }
    })
    .await;

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// Extract the authoritative WHOIS server from an IANA WHOIS response
fn extract_whois_server(iana_response: &str) -> Option<String> {
    for line in iana_response.lines() {
        let line = line.trim();
        // IANA uses "whois:" field
        if let Some(rest) = line.strip_prefix("whois:") {
            let server = rest.trim().to_lowercase();
            if !server.is_empty() {
                return Some(server);
            }
        }
        // Some registrars use "Registrar WHOIS Server:"
        if let Some(rest) = line
            .to_lowercase()
            .strip_prefix("registrar whois server:")
        {
            let server = rest.trim().to_string();
            if !server.is_empty() {
                return Some(server);
            }
        }
    }
    None
}

// Parse key WHOIS fields from a raw response string
fn parse_whois_fields(raw: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        raw: raw.to_string(),
        ..Default::default()
    };
    for line in raw.lines() {
        let lower = line.to_lowercase();
        // Registrar
        if info.registrar.is_none()
            && let Some(v) = extract_field(&lower, line, "registrar:")
        {
            info.registrar = Some(v);
        }
        // Registrant (org)
        if info.registrant.is_none() {
            if let Some(v) = extract_field(&lower, line, "registrant organization:") {
                info.registrant = Some(v);
            } else if let Some(v) = extract_field(&lower, line, "registrant:") {
                info.registrant = Some(v);
            }
        }
        // Name servers
        if lower.starts_with("name server:")
            && let Some(v) = extract_field(&lower, line, "name server:")
        {
            info.name_servers.push(v.to_lowercase());
        }
        // Creation date
        if info.creation_date.is_none() {
            if let Some(v) = extract_field(&lower, line, "creation date:") {
                info.creation_date = Some(v);
            } else if let Some(v) = extract_field(&lower, line, "created:") {
                info.creation_date = Some(v);
            }
        }
        // Expiry date
        if info.expiry_date.is_none() {
            if let Some(v) = extract_field(&lower, line, "registry expiry date:") {
                info.expiry_date = Some(v);
            } else if let Some(v) = extract_field(&lower, line, "expiry date:") {
                info.expiry_date = Some(v);
            } else if let Some(v) = extract_field(&lower, line, "expires:") {
                info.expiry_date = Some(v);
            }
        }
    }
    // Deduplicate name servers
    info.name_servers.sort();
    info.name_servers.dedup();
    info
}

// Extract value for a key prefix from the original (non-lowercased) line
fn extract_field(lower_line: &str, original_line: &str, lower_key: &str) -> Option<String> {
    if lower_line.starts_with(lower_key) {
        let value = original_line[lower_key.len()..].trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

// ── ASN/BGP helpers ───────────────────────────────────────────────────────────

// Query ipinfo.io for ASN and geo info for a domain or IP
async fn fetch_asn_info(
    client: &reqwest::Client,
    target: &str,
) -> Result<AsnInfo> {
    let url = format!("{IPINFO_BASE}/{target}/json");
    let resp: IpInfoResponse = client
        .get(&url)
        .send()
        .await
        .context("ipinfo.io request")?
        .json()
        .await
        .context("ipinfo.io JSON parse")?;

    // org field looks like "AS12345 Some Corp"
    let asn = resp
        .org
        .split_whitespace()
        .next()
        .filter(|s| s.starts_with("AS"))
        .map(|s| s.to_string());

    Ok(AsnInfo {
        asn,
        org: resp.org,
        country: resp.country,
        city: resp.city,
        ip: resp.ip,
    })
}

// Query bgpview.io for prefix list associated with an ASN number
async fn fetch_bgp_prefixes(
    client: &reqwest::Client,
    asn_str: &str,
) -> Result<BgpInfo> {
    // Strip leading "AS" prefix so the API gets a bare number
    let asn_num = asn_str.trim_start_matches("AS");
    let url = format!("{BGPVIEW_BASE}/{asn_num}/prefixes");
    let resp: BgpViewResponse = client
        .get(&url)
        .send()
        .await
        .context("bgpview.io request")?
        .json()
        .await
        .context("bgpview.io JSON parse")?;

    let mut info = BgpInfo::default();
    if let Some(data) = resp.data {
        info.ipv4_prefixes = data.ipv4_prefixes.into_iter().map(|p| p.prefix).collect();
        info.ipv6_prefixes = data.ipv6_prefixes.into_iter().map(|p| p.prefix).collect();
    }
    Ok(info)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Resolve target: CLI override wins, then engagement scope domain
    let target = if let Some(t) = args.target {
        t
    } else {
        let scope_path = eng.root.join("scope.json");
        let raw = fs::read_to_string(&scope_path).context("read scope.json")?;
        let scope_json: ScopeJson = serde_json::from_str(&raw).context("parse scope.json")?;
        scope_json.target
    };

    eprintln!("mg-whois: target={target}");

    let timeout = Duration::from_secs(args.timeout);

    // Build reqwest client for HTTP calls
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("mg-whois/0.1")
        .build()
        .context("build HTTP client")?;

    // WHOIS: first query IANA for the authoritative server
    eprintln!("  querying IANA WHOIS for authoritative server...");
    let iana_resp = whois_query(WHOIS_IANA_HOST, &target, timeout)
        .await
        .unwrap_or_default();

    let whois_info = if let Some(auth_server) = extract_whois_server(&iana_resp) {
        eprintln!("  querying {auth_server} for full WHOIS record...");
        let full_resp = whois_query(&auth_server, &target, timeout)
            .await
            .unwrap_or_default();
        parse_whois_fields(&full_resp)
    } else {
        eprintln!("  no authoritative WHOIS server found; using IANA response");
        parse_whois_fields(&iana_resp)
    };

    // ASN lookup via ipinfo.io
    eprintln!("  fetching ASN info from ipinfo.io...");
    let asn_info = fetch_asn_info(&client, &target)
        .await
        .unwrap_or_default();

    // BGP prefixes if we have an ASN
    let bgp_info = if let Some(asn) = &asn_info.asn {
        eprintln!("  fetching BGP prefixes for {asn}...");
        fetch_bgp_prefixes(&client, asn).await.unwrap_or_default()
    } else {
        eprintln!("  no ASN found; skipping BGP prefix lookup");
        BgpInfo::default()
    };

    // Print summary
    println!("\n=== WHOIS Summary: {target} ===");
    if let Some(r) = &whois_info.registrar {
        println!("Registrar:    {r}");
    }
    if let Some(r) = &whois_info.registrant {
        println!("Registrant:   {r}");
    }
    if let Some(d) = &whois_info.creation_date {
        println!("Created:      {d}");
    }
    if let Some(d) = &whois_info.expiry_date {
        println!("Expires:      {d}");
    }
    if !whois_info.name_servers.is_empty() {
        println!("Name Servers: {}", whois_info.name_servers.join(", "));
    }
    println!("\n=== ASN Info ===");
    println!("IP:      {}", asn_info.ip);
    println!("Org:     {}", asn_info.org);
    println!("Country: {}", asn_info.country);
    println!("City:    {}", asn_info.city);
    if let Some(asn) = &asn_info.asn {
        println!("ASN:     {asn}");
    }
    println!("\n=== BGP Prefixes ===");
    for p in &bgp_info.ipv4_prefixes {
        println!("  IPv4: {p}");
    }
    for p in &bgp_info.ipv6_prefixes {
        println!("  IPv6: {p}");
    }

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create whois output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = WhoisResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        target: target.clone(),
        whois: whois_info,
        asn: asn_info,
        bgp: bgp_info,
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
    fn extract_whois_server_from_iana_response() {
        let resp = "domain: EXAMPLE\nwhois: whois.example-registry.com\nstatus: ACTIVE\n";
        assert_eq!(
            extract_whois_server(resp),
            Some("whois.example-registry.com".to_string())
        );
    }

    #[test]
    fn extract_whois_server_returns_none_when_missing() {
        let resp = "domain: EXAMPLE\nstatus: ACTIVE\n";
        assert!(extract_whois_server(resp).is_none());
    }

    #[test]
    fn parse_whois_fields_extracts_registrar() {
        let raw = "Domain Name: EXAMPLE.COM\nRegistrar: ACME Registrar Inc.\nCreation Date: 2000-01-01\n";
        let info = parse_whois_fields(raw);
        assert_eq!(info.registrar.as_deref(), Some("ACME Registrar Inc."));
    }

    #[test]
    fn parse_whois_fields_extracts_name_servers() {
        let raw = "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM\n";
        let info = parse_whois_fields(raw);
        assert_eq!(info.name_servers.len(), 2);
        assert!(info.name_servers.contains(&"ns1.example.com".to_string()));
    }

    #[test]
    fn parse_whois_fields_extracts_expiry() {
        let raw = "Registry Expiry Date: 2030-12-31T00:00:00Z\n";
        let info = parse_whois_fields(raw);
        assert_eq!(
            info.expiry_date.as_deref(),
            Some("2030-12-31T00:00:00Z")
        );
    }

    #[test]
    fn parse_whois_fields_deduplicates_name_servers() {
        let raw = "Name Server: ns1.example.com\nName Server: ns1.example.com\n";
        let info = parse_whois_fields(raw);
        assert_eq!(info.name_servers.len(), 1);
    }

    #[test]
    fn extract_field_returns_none_for_no_match() {
        assert!(extract_field("domain: example.com", "domain: example.com", "registrar:").is_none());
    }
}
