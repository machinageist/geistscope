/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-udp-scan — UDP port scanner with service fingerprinting.
 *                  Probes common UDP ports and identifies services from response payloads.
 * Notes:           Probes are sent as raw UDP datagrams via tokio::net::UdpSocket.
 *                  Any response (even ICMP-unreachable) means the port is interesting;
 *                  we treat any non-timeout response as "open" since UDP has no SYN/ACK.
 *                  Binding to 0.0.0.0:0 lets the OS assign an ephemeral source port.
 *******************************************************************/

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "udp-scan";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-udp-scan";
const DEFAULT_CONCURRENCY: usize = 50;
const DEFAULT_TIMEOUT_SECS: u64 = 3;
const RECV_BUF_LEN: usize = 4096;

// Default UDP ports to probe when no --ports flag is given
const DEFAULT_UDP_PORTS: &[u16] = &[
    53, 67, 68, 69, 111, 123, 137, 138, 139, 161, 162, 177, 500, 514, 520, 623, 1194, 1900, 4500,
    5353,
];

// ── Service probe payloads (const byte arrays) ───────────────────────────────

// DNS query: standard query for version.bind TXT (CHAOS class)
const PROBE_DNS: &[u8] = &[
    0x00, 0x01, // Transaction ID
    0x00, 0x00, // Flags: standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // QNAME: version.bind (7 bytes "version", 4 bytes "bind", 0 terminator)
    0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
    0x04, b'b', b'i', b'n', b'd',
    0x00, // end of name
    0x00, 0x10, // QTYPE: TXT
    0x00, 0x03, // QCLASS: CHAOS
];

// NTP client request: mode 3 (client), version 3, leap indicator 0
const PROBE_NTP: &[u8] = &[
    0x1b, // LI=0, VN=3, Mode=3
    0x00, 0x00, 0x00, // stratum, poll, precision
    0x00, 0x00, 0x00, 0x00, // root delay
    0x00, 0x00, 0x00, 0x00, // root dispersion
    0x00, 0x00, 0x00, 0x00, // reference identifier
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reference timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originate timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // receive timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // transmit timestamp
];

// SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0), community "public"
const PROBE_SNMP: &[u8] = &[
    0x30, 0x26, // SEQUENCE, length 38
    0x02, 0x01, 0x00, // INTEGER version = 0 (v1)
    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // OCTET STRING "public"
    0xa0, 0x19, // GetRequest PDU, length 25
    0x02, 0x01, 0x01, // request-id = 1
    0x02, 0x01, 0x00, // error-status = 0
    0x02, 0x01, 0x00, // error-index = 0
    0x30, 0x0e, // VarBindList SEQUENCE, length 14
    0x30, 0x0c, // VarBind SEQUENCE, length 12
    0x06, 0x08, // OID, length 8
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // 1.3.6.1.2.1.1.1.0
    0x05, 0x00, // NULL value
];

// mDNS PTR query for _services._dns-sd._udp.local
const PROBE_MDNS: &[u8] = &[
    0x00, 0x00, // Transaction ID: 0 (mDNS uses 0)
    0x00, 0x00, // Flags: standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // _services._dns-sd._udp.local
    0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
    0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
    0x04, b'_', b'u', b'd', b'p',
    0x05, b'l', b'o', b'c', b'a', b'l',
    0x00, // end of name
    0x00, 0x0c, // QTYPE: PTR
    0x00, 0x01, // QCLASS: IN
];

// SSDP/UPnP M-SEARCH discovery
const PROBE_SSDP: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
Host: 239.255.255.250:1900\r\n\
Man: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\
\r\n";

// Generic fallback probe: 4 null bytes
const PROBE_GENERIC: &[u8] = &[0x00, 0x00, 0x00, 0x00];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-udp-scan",
    about = "UDP port scanner with service fingerprinting"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Comma-separated UDP ports to scan (default: common set)
    #[arg(long)]
    ports: Option<String>,

    /// Max concurrent UDP probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Seconds to wait for a UDP response per probe
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Minimal shape from recon/summary.json — only fields we need
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
}

// Top-level recon summary
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// Result for a single host+port probe
#[derive(Debug, Serialize)]
struct PortResult {
    host: String,
    port: u16,
    open: bool,
    service: Option<String>,
    banner: Option<String>,
}

// Top-level output written to the engagement udp-scan dir
#[derive(Serialize)]
struct UdpScanOutput {
    engagement: String,
    scanned_at: String,
    hosts_scanned: usize,
    ports_probed: Vec<u16>,
    open_ports: Vec<PortResult>,
}

// ── Probe selection ──────────────────────────────────────────────────────────

// Return the service name and probe payload for a given port
fn probe_for_port(port: u16) -> (&'static str, &'static [u8]) {
    match port {
        53 => ("dns", PROBE_DNS),
        123 => ("ntp", PROBE_NTP),
        161 | 162 => ("snmp", PROBE_SNMP),
        5353 => ("mdns", PROBE_MDNS),
        1900 => ("ssdp", PROBE_SSDP),
        _ => ("unknown", PROBE_GENERIC),
    }
}

// ── Response parsing ─────────────────────────────────────────────────────────

// Extract a human-readable banner from a UDP response given the probed port
fn parse_banner(port: u16, buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }
    match port {
        // NTP: byte 1 is stratum, extract it
        123 if buf.len() >= 2 => Some(format!("ntp stratum={}", buf[1])),
        // DNS: attempt to extract the answer section as ASCII
        53 => {
            let printable: String = buf
                .iter()
                .filter(|b| b.is_ascii_graphic() || **b == b' ')
                .map(|b| *b as char)
                .collect();
            if printable.is_empty() {
                None
            } else {
                Some(printable.chars().take(120).collect())
            }
        }
        // SSDP/HTTP: treat as text
        1900 => {
            let s = String::from_utf8_lossy(buf);
            Some(s.chars().take(120).collect())
        }
        _ => None,
    }
}

// ── Core probe ───────────────────────────────────────────────────────────────

// Bind a UDP socket, send a service-appropriate probe, and wait for a response
async fn probe_udp(host: &str, port: u16, timeout_secs: u64) -> PortResult {
    let (service_name, payload) = probe_for_port(port);

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            return PortResult {
                host: host.to_string(),
                port,
                open: false,
                service: None,
                banner: None,
            };
        }
    };

    let target: SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => {
            return PortResult {
                host: host.to_string(),
                port,
                open: false,
                service: None,
                banner: None,
            };
        }
    };

    // send probe; ignore error — destination unreachable lands as recv error
    let _ = sock.send_to(payload, target).await;

    let mut buf = vec![0u8; RECV_BUF_LEN];
    let recv_result = timeout(Duration::from_secs(timeout_secs), sock.recv(&mut buf)).await;

    match recv_result {
        Ok(Ok(n)) => {
            let banner = parse_banner(port, &buf[..n]);
            PortResult {
                host: host.to_string(),
                port,
                open: true,
                service: Some(service_name.to_string()),
                banner,
            }
        }
        _ => PortResult {
            host: host.to_string(),
            port,
            open: false,
            service: None,
            banner: None,
        },
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

    // parse ports from --ports flag or use default set
    let ports: Vec<u16> = if let Some(p) = &args.ports {
        p.split(',')
            .map(|s| s.trim().parse::<u16>().context("parse port"))
            .collect::<Result<Vec<_>>>()?
    } else {
        DEFAULT_UDP_PORTS.to_vec()
    };

    let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let hosts: Vec<String> = summary.hosts.iter().map(|h| h.hostname.clone()).collect();

    eprintln!(
        "mg-udp-scan: {} hosts, {} ports, concurrency={}, timeout={}s",
        hosts.len(),
        ports.len(),
        args.concurrency,
        args.timeout
    );

    // build full work list: every (host, port) pair
    let mut work: Vec<(String, u16)> = Vec::new();
    for host in &hosts {
        for &port in &ports {
            work.push((host.clone(), port));
        }
    }

    // drain with bounded JoinSet concurrency
    let mut open_results: Vec<PortResult> = Vec::new();
    let mut set: tokio::task::JoinSet<PortResult> = tokio::task::JoinSet::new();
    let timeout_secs = args.timeout;

    for (host, port) in work {
        // drain if at ceiling
        if set.len() >= args.concurrency
            && let Some(Ok(r)) = set.join_next().await
            && r.open
        {
            eprintln!("  open: {}:{} ({})", r.host, r.port, r.service.as_deref().unwrap_or("?"));
            open_results.push(r);
        }
        set.spawn(async move { probe_udp(&host, port, timeout_secs).await });
    }

    // drain remaining
    while let Some(Ok(r)) = set.join_next().await {
        if r.open {
            eprintln!("  open: {}:{} ({})", r.host, r.port, r.service.as_deref().unwrap_or("?"));
            open_results.push(r);
        }
    }

    eprintln!("mg-udp-scan: {} open UDP ports found", open_results.len());

    // write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&out_dir).context("create udp-scan dir")?;

    let scanned_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let ts_file = scanned_at.replace(':', "-");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = UdpScanOutput {
        engagement: args.engagement.clone(),
        scanned_at,
        hosts_scanned: hosts.len(),
        ports_probed: ports,
        open_ports: open_results,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, json).context("write output")?;

    eprintln!("  written: {}", out_path.display());

    // Emit MEDIUM finding if SNMP port 161 responds (potential info disclosure)
    for pr in &output.open_ports {
        if pr.port == 161 {
            let tf = ToolFinding::new(AUDIT_TOOL, "SNMP Port Open", FindingSeverity::Medium)
                .url(format!("udp://{}:{}", pr.host, pr.port))
                .evidence(format!("Service: {} — response received on port 161", pr.service.as_deref().unwrap_or("snmp")))
                .recommendation("Restrict SNMP access; use SNMPv3 with authentication; change default community strings");
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} open={}",
            output.hosts_scanned,
            output.open_ports.len()
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_for_known_ports_returns_correct_service() {
        assert_eq!(probe_for_port(53).0, "dns");
        assert_eq!(probe_for_port(123).0, "ntp");
        assert_eq!(probe_for_port(161).0, "snmp");
        assert_eq!(probe_for_port(1900).0, "ssdp");
        assert_eq!(probe_for_port(5353).0, "mdns");
        assert_eq!(probe_for_port(9999).0, "unknown");
    }

    #[test]
    fn default_ports_contains_dns_and_snmp() {
        assert!(DEFAULT_UDP_PORTS.contains(&53));
        assert!(DEFAULT_UDP_PORTS.contains(&161));
        assert!(DEFAULT_UDP_PORTS.contains(&123));
        assert!(DEFAULT_UDP_PORTS.contains(&1900));
    }

    #[test]
    fn ntp_banner_extracts_stratum() {
        // NTP response: byte 0 = flags, byte 1 = stratum
        let buf = [0x1c, 0x02, 0x00, 0x00];
        let banner = parse_banner(123, &buf);
        assert_eq!(banner, Some("ntp stratum=2".to_string()));
    }

    #[test]
    fn generic_probe_is_four_null_bytes() {
        assert_eq!(PROBE_GENERIC, &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn parse_banner_empty_returns_none() {
        assert!(parse_banner(53, &[]).is_none());
        assert!(parse_banner(123, &[]).is_none());
    }
}
