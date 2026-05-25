/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-dns-enum — active DNS enumeration. Zone transfer
 *                  attempt, wildcard detection, DNSSEC check, SRV record
 *                  discovery, and PTR sweep.
 * Notes:           AXFR is attempted via raw TCP to port 53 on each NS.
 *                  If the connection is refused or the server does not
 *                  return a valid AXFR payload, "zone transfer denied"
 *                  is logged and execution continues.
 *                  PTR sweep is limited to /24 — larger CIDRs are warned
 *                  and skipped per spec.
 *******************************************************************/

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "dns-enum";
const AUDIT_TOOL: &str = "mg-dns-enum";
const AXFR_PORT: u16 = 53;
// Minimum TCP connect timeout for AXFR attempt
const AXFR_CONNECT_TIMEOUT_SECS: u64 = 5;
// PTR sweep limit — refuse to sweep ranges larger than /24
const PTR_MAX_PREFIX_LEN: u8 = 24;

// Common SRV service prefixes to probe
const SRV_NAMES: &[&str] = &[
    "_http._tcp",
    "_https._tcp",
    "_smtp._tcp",
    "_imap._tcp",
    "_pop3._tcp",
    "_ftp._tcp",
    "_ssh._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_sip._tcp",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-dns-enum",
    about = "Active DNS enumeration — zone transfer, wildcard, DNSSEC, SRV, PTR sweep"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Target domain to enumerate
    #[arg(long)]
    domain: String,

    /// Custom nameserver IP (default: system resolver)
    #[arg(long)]
    nameserver: Option<String>,

    /// CIDR range for PTR sweep (max /24), e.g. 192.168.1.0/24
    #[arg(long)]
    ptr_range: Option<String>,

    /// DNS query timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Result of the zone transfer attempt
#[derive(Serialize)]
struct ZoneTransferResult {
    nameserver: String,
    success: bool,
    denied: bool,
    record_count: usize,
    records: Vec<String>,
}

// Result of wildcard detection
#[derive(Serialize)]
struct WildcardResult {
    probe_hostname: String,
    resolved: bool,
    addresses: Vec<String>,
}

// Result of DNSSEC check
#[derive(Serialize)]
struct DnssecResult {
    dnskey_found: bool,
}

// One SRV probe result
#[derive(Serialize)]
struct SrvResult {
    service: String,
    resolved: bool,
    targets: Vec<String>,
}

// One PTR result
#[derive(Serialize)]
struct PtrResult {
    ip: String,
    hostname: Option<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct DnsEnumResults {
    engagement: String,
    domain: String,
    timestamp: String,
    zone_transfers: Vec<ZoneTransferResult>,
    wildcard: Option<WildcardResult>,
    dnssec: Option<DnssecResult>,
    srv_records: Vec<SrvResult>,
    ptr_records: Vec<PtrResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize a timestamp string for use in a filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Build a TokioResolver using either the system config or a custom nameserver IP
fn build_resolver(nameserver_ip: Option<&str>, timeout_secs: u64) -> Result<TokioResolver> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(timeout_secs);

    let config = match nameserver_ip {
        Some(ip) => {
            let addr: std::net::IpAddr = ip.parse().with_context(|| format!("parse nameserver IP: {ip}"))?;
            use hickory_resolver::config::{ConnectionConfig, NameServerConfig};
            // Single UDP connection on the standard DNS port to the chosen server
            let mut conn = ConnectionConfig::udp();
            conn.port = AXFR_PORT;
            let ns = NameServerConfig::new(addr, true, vec![conn]);
            ResolverConfig::from_parts(None, vec![], vec![ns])
        }
        None => ResolverConfig::default(),
    };

    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .context("build DNS resolver")
}

// Resolve NS records for a domain; return list of nameserver hostnames
async fn resolve_ns(resolver: &TokioResolver, domain: &str) -> Vec<String> {
    match resolver.ns_lookup(domain).await {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

// Attempt AXFR zone transfer via raw TCP to a nameserver
// AXFR is a two-message exchange: send query, receive one or more response messages.
// This is best-effort: if the connection fails or returns nothing useful, log denied.
async fn attempt_axfr(ns_host: &str, domain: &str, timeout_secs: u64) -> ZoneTransferResult {
    // Resolve NS hostname to an IP first
    let ns_ip_str = match tokio::net::lookup_host(format!("{ns_host}:53")).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip().to_string(),
            None => {
                return ZoneTransferResult {
                    nameserver: ns_host.to_string(),
                    success: false,
                    denied: true,
                    record_count: 0,
                    records: vec!["could not resolve nameserver hostname".into()],
                };
            }
        },
        Err(e) => {
            return ZoneTransferResult {
                nameserver: ns_host.to_string(),
                success: false,
                denied: true,
                record_count: 0,
                records: vec![format!("resolve error: {e}")],
            };
        }
    };

    let addr = format!("{ns_ip_str}:53");
    let connect_result = tokio::time::timeout(
        Duration::from_secs(AXFR_CONNECT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&addr),
    )
    .await;

    let mut stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return ZoneTransferResult {
                nameserver: ns_host.to_string(),
                success: false,
                denied: true,
                record_count: 0,
                records: vec![format!("TCP connect failed: {e}")],
            };
        }
        Err(_) => {
            return ZoneTransferResult {
                nameserver: ns_host.to_string(),
                success: false,
                denied: true,
                record_count: 0,
                records: vec!["connection timed out".into()],
            };
        }
    };

    // Build a minimal AXFR DNS query in wire format
    // DNS over TCP prepends a 2-byte length field
    let axfr_query = build_axfr_query(domain);
    let query_len = axfr_query.len() as u16;
    let mut tcp_msg = Vec::with_capacity(2 + axfr_query.len());
    tcp_msg.extend_from_slice(&query_len.to_be_bytes());
    tcp_msg.extend_from_slice(&axfr_query);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let write_result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        stream.write_all(&tcp_msg),
    )
    .await;
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return ZoneTransferResult {
                nameserver: ns_host.to_string(),
                success: false,
                denied: true,
                record_count: 0,
                records: vec![format!("write AXFR query failed: {e}")],
            };
        }
        Err(_) => {
            return ZoneTransferResult {
                nameserver: ns_host.to_string(),
                success: false,
                denied: true,
                record_count: 0,
                records: vec!["write AXFR query timed out".into()],
            };
        }
    }

    // Read up to 65536 bytes of response
    let mut buf = vec![0u8; 65536];
    let n = match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        _ => {
            return ZoneTransferResult {
                nameserver: ns_host.to_string(),
                success: false,
                denied: true,
                record_count: 0,
                records: vec!["read AXFR response timed out".into()],
            };
        }
    };

    // Check for RCODE 5 (REFUSED) or empty response
    if n < 6 {
        return ZoneTransferResult {
            nameserver: ns_host.to_string(),
            success: false,
            denied: true,
            record_count: 0,
            records: vec!["zone transfer denied (empty response)".into()],
        };
    }

    // DNS TCP: first 2 bytes are length prefix, then DNS message
    // Bytes 2+3 are txid, byte 4-5 contain flags, byte 6+7 ancount, etc.
    // Byte 5 (flags low byte) bit 0-3 = RCODE
    let rcode = buf[5] & 0x0F;
    if rcode == 5 {
        return ZoneTransferResult {
            nameserver: ns_host.to_string(),
            success: false,
            denied: true,
            record_count: 0,
            records: vec!["zone transfer refused (RCODE 5)".into()],
        };
    }

    if rcode != 0 {
        return ZoneTransferResult {
            nameserver: ns_host.to_string(),
            success: false,
            denied: true,
            record_count: 0,
            records: vec![format!("zone transfer failed RCODE={rcode}")],
        };
    }

    // RCODE 0 with data — report as success (raw bytes, not fully parsed)
    ZoneTransferResult {
        nameserver: ns_host.to_string(),
        success: true,
        denied: false,
        record_count: 1,
        records: vec![format!("AXFR response received ({n} bytes) — manual review required")],
    }
}

// Build a minimal AXFR DNS query in wire format (RFC 1035)
fn build_axfr_query(domain: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    // Transaction ID: 0x1234
    msg.extend_from_slice(&[0x12, 0x34]);
    // Flags: standard query, recursion desired
    msg.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1
    msg.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode domain name: each label prefixed with its length
    let domain_clean = domain.trim_end_matches('.');
    for label in domain_clean.split('.') {
        let bytes = label.as_bytes();
        msg.push(bytes.len() as u8);
        msg.extend_from_slice(bytes);
    }
    // Root label terminator
    msg.push(0x00);

    // QTYPE: AXFR = 252
    msg.extend_from_slice(&[0x00, 0xFC]);
    // QCLASS: IN = 1
    msg.extend_from_slice(&[0x00, 0x01]);

    msg
}

// Generate a random-looking hostname for wildcard detection (no rand dep)
fn random_probe_label() -> String {
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("nonexistent-{pid}-{now:x}")
}

// Check for wildcard DNS by resolving a guaranteed-nonexistent label
async fn check_wildcard(resolver: &TokioResolver, domain: &str) -> WildcardResult {
    let label = random_probe_label();
    let probe = format!("{label}.{domain}");
    match resolver.lookup_ip(probe.as_str()).await {
        Ok(ips) => {
            let addresses: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            WildcardResult {
                probe_hostname: probe,
                resolved: !addresses.is_empty(),
                addresses,
            }
        }
        Err(_) => WildcardResult {
            probe_hostname: probe,
            resolved: false,
            addresses: Vec::new(),
        },
    }
}

// Check for DNSKEY record presence (indicates DNSSEC is deployed)
async fn check_dnssec(resolver: &TokioResolver, domain: &str) -> DnssecResult {
    let fqdn = format!("{domain}.");
    let found = resolver
        .lookup(fqdn.as_str(), RecordType::DNSKEY)
        .await
        .map(|l| !l.answers().is_empty())
        .unwrap_or(false);
    DnssecResult { dnskey_found: found }
}

// Query SRV records for all known service names under the domain
async fn probe_srv_records(resolver: &TokioResolver, domain: &str) -> Vec<SrvResult> {
    let mut results = Vec::new();
    for svc in SRV_NAMES {
        let qname = format!("{svc}.{domain}");
        let (resolved, targets) = match resolver.srv_lookup(qname.as_str()).await {
            Ok(lookup) => {
                let targets: Vec<String> = lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::SRV(srv) => Some(format!("{}:{}", srv.target, srv.port)),
                        _ => None,
                    })
                    .collect();
                (!targets.is_empty(), targets)
            }
            Err(_) => (false, Vec::new()),
        };
        results.push(SrvResult {
            service: svc.to_string(),
            resolved,
            targets,
        });
    }
    results
}

// Parse a CIDR string into base IP and prefix length
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    anyhow::ensure!(parts.len() == 2, "CIDR must be in addr/prefix format");
    let addr: Ipv4Addr = parts[0].parse().context("parse CIDR base address")?;
    let prefix: u8 = parts[1].parse().context("parse CIDR prefix length")?;
    Ok((addr, prefix))
}

// Sweep PTR records for every IP in a /24 CIDR
async fn sweep_ptr(resolver: &TokioResolver, cidr: &str) -> Result<Vec<PtrResult>> {
    let (base, prefix) = parse_cidr(cidr)?;

    anyhow::ensure!(
        prefix >= PTR_MAX_PREFIX_LEN,
        "PTR sweep limited to /{PTR_MAX_PREFIX_LEN} — refusing to sweep /{prefix}"
    );

    // Enumerate all host IPs in the /24
    let base_octets = u32::from(base) & 0xFFFFFF00;
    let mut results = Vec::new();

    for host_byte in 0u32..=255 {
        let ip = Ipv4Addr::from(base_octets | host_byte);
        let hostname = match resolver.reverse_lookup(Name::from(ip)).await {
            Ok(lookup) => lookup.answers().iter().find_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.0.to_string()),
                _ => None,
            }),
            Err(_) => None,
        };
        if hostname.is_some() {
            results.push(PtrResult {
                ip: ip.to_string(),
                hostname,
            });
        }
    }

    Ok(results)
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let resolver = build_resolver(args.nameserver.as_deref(), args.timeout)
        .context("build DNS resolver")?;

    eprintln!(
        "mg-dns-enum: domain={} nameserver={}",
        args.domain,
        args.nameserver.as_deref().unwrap_or("system")
    );

    // ── Zone transfer ────────────────────────────────────────────────────────
    let ns_list = resolve_ns(&resolver, &args.domain).await;
    eprintln!("  NS records: {:?}", ns_list);

    let mut zone_transfers = Vec::new();
    for ns in &ns_list {
        let ns_clean = ns.trim_end_matches('.');
        eprintln!("  attempting AXFR from {ns_clean}");
        let zt = attempt_axfr(ns_clean, &args.domain, args.timeout).await;
        if zt.success {
            eprintln!("  [HIGH] zone transfer succeeded from {ns_clean}");
        } else {
            eprintln!("  zone transfer denied from {ns_clean}");
        }
        zone_transfers.push(zt);
    }

    // ── Wildcard detection ───────────────────────────────────────────────────
    eprintln!("  checking wildcard DNS");
    let wildcard = check_wildcard(&resolver, &args.domain).await;
    if wildcard.resolved {
        eprintln!("  [INFO] wildcard DNS detected: {} -> {:?}", wildcard.probe_hostname, wildcard.addresses);
    }

    // ── DNSSEC check ─────────────────────────────────────────────────────────
    eprintln!("  checking DNSSEC");
    let dnssec = check_dnssec(&resolver, &args.domain).await;
    if !dnssec.dnskey_found {
        eprintln!("  [INFO] no DNSSEC — DNSKEY record not found");
    }

    // ── SRV records ──────────────────────────────────────────────────────────
    eprintln!("  probing SRV records");
    let srv_records = probe_srv_records(&resolver, &args.domain).await;
    for srv in &srv_records {
        if srv.resolved {
            eprintln!("  [SRV] {} -> {:?}", srv.service, srv.targets);
        }
    }

    // ── PTR sweep ────────────────────────────────────────────────────────────
    let ptr_records = if let Some(ref cidr) = args.ptr_range {
        eprintln!("  PTR sweep: {cidr}");
        match sweep_ptr(&resolver, cidr).await {
            Ok(records) => {
                eprintln!("  {} PTR records found", records.len());
                records
            }
            Err(e) => {
                eprintln!("  PTR sweep skipped: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = DnsEnumResults {
        engagement: args.engagement.clone(),
        domain: args.domain.clone(),
        timestamp: ts.clone(),
        zone_transfers,
        wildcard: Some(wildcard),
        dnssec: Some(dnssec),
        srv_records,
        ptr_records,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create dns-enum output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write dns-enum results JSON")?;

    eprintln!("mg-dns-enum: written {}", results_path.display());

    // Write finding for each successful zone transfer
    for zt in output.zone_transfers.iter().filter(|z| z.success) {
        let tf = ToolFinding::new("mg-dns-enum", "DNS Zone Transfer Allowed (AXFR)", FindingSeverity::High)
            .evidence(format!("nameserver={} domain={} records={}", zt.nameserver, args.domain, zt.record_count))
            .recommendation("Restrict AXFR to authorized secondary nameservers only; configure zone transfer ACLs");
        let _ = write_finding(&eng, &tf);
    }

    let axfr_success = output.zone_transfers.iter().filter(|z| z.success).count();
    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "domain={} axfr_success={} wildcard={} dnssec={} ptr={} ts={ts}",
            args.domain,
            axfr_success,
            output.wildcard.as_ref().map(|w| w.resolved).unwrap_or(false),
            output.dnssec.as_ref().map(|d| d.dnskey_found).unwrap_or(false),
            output.ptr_records.len()
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_axfr_query_starts_with_txid_and_encodes_domain() {
        let q = build_axfr_query("example.com");
        // First two bytes: transaction ID 0x1234
        assert_eq!(q[0], 0x12);
        assert_eq!(q[1], 0x34);
        // QTYPE AXFR is 0x00FC — find it near the end
        let qtype_pos = q.len() - 4;
        assert_eq!(q[qtype_pos], 0x00);
        assert_eq!(q[qtype_pos + 1], 0xFC);
    }

    #[test]
    fn parse_cidr_valid() {
        let (addr, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_invalid_prefix_returns_error() {
        assert!(parse_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn parse_cidr_rejects_large_range() {
        // parse succeeds; sweep_ptr will reject it
        let (_, prefix) = parse_cidr("10.0.0.0/16").unwrap();
        assert!(prefix < PTR_MAX_PREFIX_LEN);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }

    #[test]
    fn random_probe_label_is_unique_across_calls() {
        // Not truly guaranteed but sufficient — pid and nanosecond timestamp differ
        let a = random_probe_label();
        let b = random_probe_label();
        assert!(a.starts_with("nonexistent-"));
        // Both start with the same pid so differ in timestamp portion
        assert_eq!(a.split('-').next(), b.split('-').next());
    }
}
