/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-snmp — SNMP community string brute force and MIB walk.
 *                  Tests common community strings and extracts system information.
 * Notes:           PDUs are built manually as BER-encoded raw bytes.
 *                  SNMPv1 GetRequest uses message type 0xa0.
 *                  SNMPv2c GetRequest uses the same tag but version byte 0x01.
 *                  GetResponse tag is 0xa2; we check this after recv.
 *                  OID 1.3.6.1.2.1.1.1.0 (sysDescr) = [0x2b,0x06,0x01,0x02,
 *                  0x01,0x01,0x01,0x00] in BER.
 *                  The "both" mode tries v1 first, then v2c on the same host.
 *******************************************************************/

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "snmp";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-snmp";
const DEFAULT_PORT: u16 = 161;
const DEFAULT_TIMEOUT_SECS: u64 = 3;
const DEFAULT_CONCURRENCY: usize = 20;
const RECV_BUF_LEN: usize = 4096;

// SNMPv1 GetRequest PDU tag
const SNMP_GET_REQUEST_TAG: u8 = 0xa0;
// SNMPv2c GetRequest PDU tag (same value)
const SNMP_GET_RESPONSE_TAG: u8 = 0xa2;

// OID bytes for sysDescr (1.3.6.1.2.1.1.1.0)
const OID_SYS_DESCR: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
// OID bytes for sysName (1.3.6.1.2.1.1.5.0)
const OID_SYS_NAME: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
// OID bytes for sysContact (1.3.6.1.2.1.1.4.0)
const OID_SYS_CONTACT: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00];
// OID bytes for sysLocation (1.3.6.1.2.1.1.6.0)
const OID_SYS_LOCATION: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00];

// Built-in community strings to try
const DEFAULT_COMMUNITIES: &[&str] = &[
    "public", "private", "community", "manager", "admin", "snmp", "default", "cisco", "monitor",
    "read", "write", "all", "secret", "password", "test",
];

// Community strings considered write/high-risk
const WRITE_COMMUNITIES: &[&str] = &["private", "write", "manager", "admin", "secret", "password"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum, Serialize)]
enum SnmpVersion {
    V1,
    V2c,
}

#[derive(Parser, Debug)]
#[command(
    name = "mg-snmp",
    about = "SNMP community string brute force and MIB walk"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// SNMP UDP port
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Timeout in seconds per probe
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// Max concurrent SNMP probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Comma-separated community strings (default: built-in list)
    #[arg(long)]
    communities: Option<String>,

    /// SNMP version to try (default: try both)
    #[arg(long, value_enum)]
    version: Option<SnmpVersion>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Minimal shape from recon/summary.json
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
}

// Top-level recon summary
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// Severity of a finding
#[derive(Debug, Clone, Serialize, PartialEq)]
enum Severity {
    High,
    Medium,
}

// A valid community string hit with MIB values
#[derive(Debug, Serialize)]
struct CommunityHit {
    community: String,
    version: SnmpVersion,
    severity: Severity,
    sys_descr: Option<String>,
    sys_name: Option<String>,
    sys_contact: Option<String>,
    sys_location: Option<String>,
}

// Full result for one host
#[derive(Debug, Serialize)]
struct HostResult {
    host: String,
    port: u16,
    valid_communities: Vec<CommunityHit>,
    error: Option<String>,
}

// Top-level output
#[derive(Serialize)]
struct SnmpOutput {
    engagement: String,
    scanned_at: String,
    hosts_scanned: usize,
    total_hits: usize,
    results: Vec<HostResult>,
}

// ── PDU builder ──────────────────────────────────────────────────────────────

// Build a BER-encoded SNMPv1 or v2c GetRequest PDU for a single OID
fn build_get_request(community: &[u8], oid: &[u8], version_byte: u8, request_id: u8) -> Vec<u8> {
    // VarBind: SEQUENCE { OID, NULL }
    // OID TLV: 0x06 + len + bytes
    let oid_tlv = {
        let mut v = vec![0x06, oid.len() as u8];
        v.extend_from_slice(oid);
        v
    };
    // NULL TLV
    let null_tlv = [0x05, 0x00];
    // VarBind SEQUENCE
    let varbind_content_len = oid_tlv.len() + null_tlv.len();
    let varbind = {
        let mut v = vec![0x30, varbind_content_len as u8];
        v.extend_from_slice(&oid_tlv);
        v.extend_from_slice(&null_tlv);
        v
    };
    // VarBindList SEQUENCE
    let varlist = {
        let mut v = vec![0x30, varbind.len() as u8];
        v.extend_from_slice(&varbind);
        v
    };
    // Request-ID, error-status, error-index integers
    let req_id_tlv = [0x02, 0x01, request_id];
    let err_status_tlv = [0x02, 0x01, 0x00];
    let err_index_tlv = [0x02, 0x01, 0x00];

    // GetRequest PDU (0xa0): request-id + error-status + error-index + varlist
    let pdu_content_len =
        req_id_tlv.len() + err_status_tlv.len() + err_index_tlv.len() + varlist.len();
    let pdu = {
        let mut v = vec![SNMP_GET_REQUEST_TAG, pdu_content_len as u8];
        v.extend_from_slice(&req_id_tlv);
        v.extend_from_slice(&err_status_tlv);
        v.extend_from_slice(&err_index_tlv);
        v.extend_from_slice(&varlist);
        v
    };

    // Community OCTET STRING TLV
    let community_tlv = {
        let mut v = vec![0x04, community.len() as u8];
        v.extend_from_slice(community);
        v
    };

    // Version INTEGER TLV
    let version_tlv = [0x02, 0x01, version_byte];

    // Top-level SEQUENCE
    let msg_content_len = version_tlv.len() + community_tlv.len() + pdu.len();
    let mut msg = vec![0x30, msg_content_len as u8];
    msg.extend_from_slice(&version_tlv);
    msg.extend_from_slice(&community_tlv);
    msg.extend_from_slice(&pdu);
    msg
}

// ── Response parsing ─────────────────────────────────────────────────────────

// Check if the response is a valid SNMP GetResponse (tag 0xa2, error-status 0)
fn is_valid_response(buf: &[u8]) -> bool {
    if buf.len() < 8 {
        return false;
    }
    // Top-level must be SEQUENCE (0x30)
    if buf[0] != 0x30 {
        return false;
    }
    // Scan for GetResponse PDU tag 0xa2 in the buffer
    buf.iter().enumerate().any(|(i, &b)| {
        b == SNMP_GET_RESPONSE_TAG && i + 2 < buf.len()
    })
}

// Extract an OCTET STRING value from an SNMP response for a known OID
// Returns the string value of the first OCTET STRING (0x04) found after the OID bytes
fn extract_octet_string(buf: &[u8], oid: &[u8]) -> Option<String> {
    // Find the OID bytes in the buffer
    let pos = buf.windows(oid.len()).position(|w| w == oid)?;
    // After OID TLV: skip the value's tag+length, then OCTET STRING should follow
    let after_oid = pos + oid.len();
    // Look for 0x04 (OCTET STRING tag) within the next 8 bytes
    let search_end = (after_oid + 8).min(buf.len());
    let str_pos = buf[after_oid..search_end]
        .iter()
        .position(|&b| b == 0x04)
        .map(|p| after_oid + p)?;
    if str_pos + 2 > buf.len() {
        return None;
    }
    let str_len = buf[str_pos + 1] as usize;
    let str_start = str_pos + 2;
    if str_start + str_len > buf.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[str_start..str_start + str_len])
        .trim()
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

// ── Core probe ───────────────────────────────────────────────────────────────

// Send one SNMP GetRequest and return the raw response if valid
async fn snmp_get(
    sock: &UdpSocket,
    target: SocketAddr,
    community: &str,
    oid: &[u8],
    version_byte: u8,
    request_id: u8,
    timeout_secs: u64,
) -> Option<Vec<u8>> {
    let pdu = build_get_request(community.as_bytes(), oid, version_byte, request_id);
    sock.send_to(&pdu, target).await.ok()?;

    let mut buf = vec![0u8; RECV_BUF_LEN];
    let n = match timeout(Duration::from_secs(timeout_secs), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    buf.truncate(n);

    if is_valid_response(&buf) {
        Some(buf)
    } else {
        None
    }
}

// Probe all community strings for one host; return a HostResult
async fn probe_host(
    host: String,
    port: u16,
    communities: Vec<String>,
    versions: Vec<(SnmpVersion, u8)>,
    timeout_secs: u64,
) -> HostResult {
    let target_str = format!("{host}:{port}");
    let target: SocketAddr = match target_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return HostResult {
                host,
                port,
                valid_communities: vec![],
                error: Some(e.to_string()),
            };
        }
    };

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            return HostResult {
                host,
                port,
                valid_communities: vec![],
                error: Some(e.to_string()),
            };
        }
    };

    let mut valid_communities: Vec<CommunityHit> = Vec::new();
    let mut request_id: u8 = 1;

    for community in &communities {
        for &(version, version_byte) in &versions {
            // probe with sysDescr OID to test community validity
            if let Some(resp) = snmp_get(
                &sock,
                target,
                community,
                OID_SYS_DESCR,
                version_byte,
                request_id,
                timeout_secs,
            )
            .await
            {
                request_id = request_id.wrapping_add(1);

                let sys_descr = extract_octet_string(&resp, OID_SYS_DESCR);

                // walk additional OIDs
                let sys_name = if let Some(r) = snmp_get(
                    &sock, target, community, OID_SYS_NAME, version_byte,
                    request_id, timeout_secs,
                )
                .await
                {
                    request_id = request_id.wrapping_add(1);
                    extract_octet_string(&r, OID_SYS_NAME)
                } else {
                    None
                };

                let sys_contact = if let Some(r) = snmp_get(
                    &sock, target, community, OID_SYS_CONTACT, version_byte,
                    request_id, timeout_secs,
                )
                .await
                {
                    request_id = request_id.wrapping_add(1);
                    extract_octet_string(&r, OID_SYS_CONTACT)
                } else {
                    None
                };

                let sys_location = if let Some(r) = snmp_get(
                    &sock, target, community, OID_SYS_LOCATION, version_byte,
                    request_id, timeout_secs,
                )
                .await
                {
                    request_id = request_id.wrapping_add(1);
                    extract_octet_string(&r, OID_SYS_LOCATION)
                } else {
                    None
                };

                let severity = if WRITE_COMMUNITIES.contains(&community.as_str()) {
                    Severity::High
                } else {
                    Severity::Medium
                };

                valid_communities.push(CommunityHit {
                    community: community.clone(),
                    version,
                    severity,
                    sys_descr,
                    sys_name,
                    sys_contact,
                    sys_location,
                });
            }
            request_id = request_id.wrapping_add(1);
        }
    }

    HostResult {
        host,
        port,
        valid_communities,
        error: None,
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

    // parse communities from flag or use built-in list
    let communities: Vec<String> = if let Some(c) = &args.communities {
        c.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        DEFAULT_COMMUNITIES.iter().map(|s| s.to_string()).collect()
    };

    // build (version_enum, version_byte) pairs based on --version flag
    let versions: Vec<(SnmpVersion, u8)> = match args.version {
        Some(SnmpVersion::V1) => vec![(SnmpVersion::V1, 0x00)],
        Some(SnmpVersion::V2c) => vec![(SnmpVersion::V2c, 0x01)],
        None => vec![(SnmpVersion::V1, 0x00), (SnmpVersion::V2c, 0x01)],
    };

    let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let hosts: Vec<String> = summary.hosts.iter().map(|h| h.hostname.clone()).collect();
    let port = args.port;

    eprintln!(
        "mg-snmp: {} hosts, {} communities, {} version(s), concurrency={}, timeout={}s",
        hosts.len(),
        communities.len(),
        versions.len(),
        args.concurrency,
        args.timeout
    );

    // bounded JoinSet drain
    let mut set: tokio::task::JoinSet<HostResult> = tokio::task::JoinSet::new();
    let mut results: Vec<HostResult> = Vec::new();
    let timeout_secs = args.timeout;

    for host in hosts {
        if set.len() >= args.concurrency
            && let Some(Ok(r)) = set.join_next().await
        {
            if !r.valid_communities.is_empty() {
                eprintln!(
                    "  {} — {} valid communities: {}",
                    r.host,
                    r.valid_communities.len(),
                    r.valid_communities.iter().map(|h| h.community.as_str()).collect::<Vec<_>>().join(", ")
                );
            }
            results.push(r);
        }
        let c = communities.clone();
        let v = versions.clone();
        set.spawn(async move { probe_host(host, port, c, v, timeout_secs).await });
    }

    while let Some(Ok(r)) = set.join_next().await {
        if !r.valid_communities.is_empty() {
            eprintln!(
                "  {} — {} valid communities: {}",
                r.host,
                r.valid_communities.len(),
                r.valid_communities.iter().map(|h| h.community.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        results.push(r);
    }

    let total_hits: usize = results.iter().map(|r| r.valid_communities.len()).sum();
    eprintln!("mg-snmp: {} community hits across {} hosts", total_hits, results.len());

    // write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&out_dir).context("create snmp dir")?;

    let scanned_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let ts_file = scanned_at.replace(':', "-");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = SnmpOutput {
        engagement: args.engagement.clone(),
        scanned_at,
        hosts_scanned: results.len(),
        total_hits,
        results,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, json).context("write output")?;

    eprintln!("  written: {}", out_path.display());

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} hits={}",
            output.hosts_scanned, output.total_hits
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_get_request_starts_with_sequence_tag() {
        let pdu = build_get_request(b"public", OID_SYS_DESCR, 0x00, 1);
        assert_eq!(pdu[0], 0x30, "top-level BER tag must be SEQUENCE (0x30)");
    }

    #[test]
    fn build_get_request_contains_get_request_tag() {
        let pdu = build_get_request(b"public", OID_SYS_DESCR, 0x00, 1);
        assert!(
            pdu.contains(&SNMP_GET_REQUEST_TAG),
            "PDU must contain GetRequest tag 0xa0"
        );
    }

    #[test]
    fn build_get_request_contains_community_bytes() {
        let pdu = build_get_request(b"mycommunity", OID_SYS_DESCR, 0x00, 1);
        let community_bytes = b"mycommunity";
        assert!(
            pdu.windows(community_bytes.len()).any(|w| w == community_bytes),
            "PDU must contain community string bytes"
        );
    }

    #[test]
    fn is_valid_response_rejects_short_buffer() {
        assert!(!is_valid_response(&[0x30, 0x00]));
        assert!(!is_valid_response(&[]));
    }

    #[test]
    fn is_valid_response_rejects_wrong_top_tag() {
        let buf = [0x31, 0x20, 0x02, 0x01, 0x00, 0x04, 0x06, 0xa2, 0x00];
        assert!(!is_valid_response(&buf));
    }

    #[test]
    fn is_valid_response_accepts_buffer_with_response_tag() {
        // Minimal buffer: SEQUENCE + some content containing 0xa2
        let buf = [0x30, 0x08, 0x02, 0x01, 0x00, 0x04, 0x01, 0xa2, 0x00, 0x00];
        assert!(is_valid_response(&buf));
    }

    #[test]
    fn default_communities_contains_public_and_private() {
        assert!(DEFAULT_COMMUNITIES.contains(&"public"));
        assert!(DEFAULT_COMMUNITIES.contains(&"private"));
    }

    #[test]
    fn write_communities_classified_as_high() {
        assert!(WRITE_COMMUNITIES.contains(&"private"));
        assert!(WRITE_COMMUNITIES.contains(&"write"));
    }

    #[test]
    fn oid_sys_descr_starts_with_0x2b() {
        // BER encoding of 1.3 is always 0x2b
        assert_eq!(OID_SYS_DESCR[0], 0x2b);
        assert_eq!(OID_SYS_DESCR.len(), 8);
    }
}
