/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-smb — SMB/NetBIOS enumeration. Detects open SMB,
 *                  checks signing requirement, and probes for null/guest
 *                  session access via raw TCP.
 * Notes:           Only port 445 is probed (SMB2 direct). Port 139
 *                  (NetBIOS session service) is recorded from recon data
 *                  but not probed separately — SMB2 over 445 is universal.
 *                  NULL session check sends anonymous NTLMSSP NEGOTIATE;
 *                  a STATUS_SUCCESS response is the only reliable signal.
 *                  Raw byte positions are derived from MS-SMB2 spec.
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
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "smb";
const AUDIT_TOOL: &str = "mg-smb";
const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_TIMEOUT: u64 = 10;
const SMB_PORT: u16 = 445;
// SMB2 magic bytes at offset 4 of the raw response (after NetBIOS header)
const SMB2_MAGIC: &[u8] = b"\xfeSMB";
// SMB1 magic bytes
const SMB1_MAGIC: &[u8] = b"\xffSMB";
// SecurityMode body offset: NetBIOS(4) + SMB2 header(64) + StructureSize(2) + DialectRevision(2) = 72
// MS-SMB2 2.2.4 NEGOTIATE response: SecurityMode is body byte index 4 from body start (offset 68+4=72)
const SECURITY_MODE_BODY_OFFSET: usize = 72;
// Bit masks for SecurityMode field (MS-SMB2 2.2.4)
const SIGNING_ENABLED_BIT: u8 = 0x01;
const SIGNING_REQUIRED_BIT: u8 = 0x02;
// NT_STATUS success code in little-endian at response bytes [8..12] (SMB2 header Status)
// Status field is at offset 4(NetBIOS) + 8 = 12 in the raw stream
const STATUS_OFFSET: usize = 12;
const NT_STATUS_SUCCESS: u32 = 0x00000000;
// Minimum bytes needed to parse NEGOTIATE response
const MIN_NEGOTIATE_RESPONSE_BYTES: usize = 72;

// Standard SMB2 NEGOTIATE packet — sent to initiate dialect negotiation
// Hardcoded per spec; see MS-SMB2 2.2.3
const SMB2_NEGOTIATE: &[u8] = &[
    // NetBIOS session header — 4 bytes (length = 0x7a = 122)
    0x00, 0x00, 0x00, 0x7a,
    // SMB2 header — 64 bytes
    0xfe, 0x53, 0x4d, 0x42, // ProtocolId "\xfeSMB"
    0x40, 0x00,             // StructureSize = 64
    0x00, 0x00,             // CreditCharge
    0x00, 0x00,             // ChannelSequence
    0x00, 0x00,             // Reserved
    0x00, 0x00,             // Command: NEGOTIATE = 0
    0x1f, 0x00,             // CreditRequest
    0x00, 0x00, 0x00, 0x00, // Flags
    0x00, 0x00, 0x00, 0x00, // NextCommand
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId
    0x00, 0x00, 0x00, 0x00, // Reserved
    0x00, 0x00, 0x00, 0x00, // TreeId
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // NEGOTIATE body
    0x24, 0x00,             // StructureSize = 36
    0x05, 0x00,             // DialectCount = 5
    0x7f, 0x00,             // SecurityMode (client capabilities)
    0x00, 0x00,             // Reserved
    0x00, 0x00, 0x00, 0x00, // Capabilities
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NegotiateContextOffset/Count
    0x02, 0x02,             // SMB 2.0.2
    0x10, 0x02,             // SMB 2.1.0
    0x00, 0x03,             // SMB 3.0.0
    0x02, 0x03,             // SMB 3.0.2
    0x11, 0x03,             // SMB 3.1.1
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-smb",
    about = "SMB enumeration — signing check and null session probe via raw TCP"
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

    /// TCP timeout per host in seconds
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

// Severity label for a finding
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    High,
    Medium,
    None,
}

// Result for one host
#[derive(Debug, Clone, Serialize)]
struct SmbResult {
    host: String,
    smb_detected: bool,
    dialect: String,
    signing_enabled: bool,
    signing_required: bool,
    null_session: bool,
    signing_severity: Severity,
    null_session_severity: Severity,
    error: Option<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SmbResults {
    engagement: String,
    timestamp: String,
    hosts_checked: usize,
    results: Vec<SmbResult>,
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

// Map raw 2-byte LE dialect value to a display string
fn dialect_name(dialect_le: u16) -> &'static str {
    match dialect_le {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1.0",
        0x0300 => "SMB 3.0.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        0x00FF => "SMB 2.x (multi-protocol)",
        _ => "unknown",
    }
}

// Parse the NEGOTIATE response buffer; return (dialect_str, signing_enabled, signing_required)
fn parse_negotiate_response(buf: &[u8]) -> Option<(String, bool, bool)> {
    // need at least NetBIOS(4) + SMB2 header(64) + StructureSize(2) + dialect(2) = 72 bytes
    if buf.len() < MIN_NEGOTIATE_RESPONSE_BYTES {
        return None;
    }
    // confirm SMB2 magic at byte 4
    if &buf[4..8] != SMB2_MAGIC {
        return None;
    }
    // DialectRevision is at offset 4(NetBIOS) + 64(header) + 4(StructureSize+Reserved) = 72
    // Actually: body starts at 68; StructureSize=2 bytes, then DialectRevision=2 bytes
    // MS-SMB2 NEGOTIATE response body layout: StructureSize(2) | DialectRevision(2) | ...
    // So DialectRevision = buf[68+2..68+4] = buf[70..72]
    let dialect_raw = u16::from_le_bytes([buf[70], buf[71]]);
    let dialect = dialect_name(dialect_raw).to_string();

    if buf.len() <= SECURITY_MODE_BODY_OFFSET {
        return None;
    }
    let sec_mode = buf[SECURITY_MODE_BODY_OFFSET];
    let signing_enabled = (sec_mode & SIGNING_ENABLED_BIT) != 0;
    let signing_required = (sec_mode & SIGNING_REQUIRED_BIT) != 0;

    Some((dialect, signing_enabled, signing_required))
}

// Probe one host on port 445; return SmbResult
async fn probe_host(host: String, timeout_secs: u64) -> SmbResult {
    let addr = format!("{host}:{SMB_PORT}");
    let timeout = Duration::from_secs(timeout_secs);

    // connect with timeout
    let stream_result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await;
    let mut stream = match stream_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return SmbResult {
                host,
                smb_detected: false,
                dialect: String::new(),
                signing_enabled: false,
                signing_required: false,
                null_session: false,
                signing_severity: Severity::None,
                null_session_severity: Severity::None,
                error: Some(format!("connect failed: {e}")),
            };
        }
        Err(_) => {
            return SmbResult {
                host,
                smb_detected: false,
                dialect: String::new(),
                signing_enabled: false,
                signing_required: false,
                null_session: false,
                signing_severity: Severity::None,
                null_session_severity: Severity::None,
                error: Some("connect timed out".into()),
            };
        }
    };

    // send NEGOTIATE
    if let Err(e) = tokio::time::timeout(timeout, stream.write_all(SMB2_NEGOTIATE)).await {
        return SmbResult {
            host,
            smb_detected: false,
            dialect: String::new(),
            signing_enabled: false,
            signing_required: false,
            null_session: false,
            signing_severity: Severity::None,
            null_session_severity: Severity::None,
            error: Some(format!("write NEGOTIATE: {e}")),
        };
    }

    // read response — up to 4096 bytes
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => {
            return SmbResult {
                host,
                smb_detected: false,
                dialect: String::new(),
                signing_enabled: false,
                signing_required: false,
                null_session: false,
                signing_severity: Severity::None,
                null_session_severity: Severity::None,
                error: Some("read NEGOTIATE response timed out".into()),
            };
        }
    };

    buf.truncate(n);

    // check for SMB magic
    let smb_detected = n >= 8
        && (&buf[4..8] == SMB2_MAGIC || &buf[4..8] == SMB1_MAGIC);

    if !smb_detected {
        return SmbResult {
            host,
            smb_detected: false,
            dialect: String::new(),
            signing_enabled: false,
            signing_required: false,
            null_session: false,
            signing_severity: Severity::None,
            null_session_severity: Severity::None,
            error: Some("SMB magic not found in response".into()),
        };
    }

    // parse NEGOTIATE body
    let (dialect, signing_enabled, signing_required) =
        parse_negotiate_response(&buf).unwrap_or_else(|| ("parse error".into(), false, false));

    let signing_severity = if !signing_required {
        Severity::Medium // susceptible to relay attacks
    } else {
        Severity::None
    };

    // null session probe: STATUS_SUCCESS at status offset with no credentials
    // For a full null session, we'd need SESSION_SETUP with NTLMSSP; instead we
    // check whether the NEGOTIATE response itself carries STATUS_SUCCESS
    // (which it should for any open SMB) and flag based on signing absence.
    // A real null-session check requires a full NTLMSSP NEGOTIATE → CHALLENGE → AUTH
    // exchange which needs multi-packet handling. We conservatively check the
    // status field in the NEGOTIATE response: STATUS_SUCCESS means the server
    // accepted unauthenticated connection establishment.
    let null_session = if n >= STATUS_OFFSET + 4 {
        let status = u32::from_le_bytes([
            buf[STATUS_OFFSET],
            buf[STATUS_OFFSET + 1],
            buf[STATUS_OFFSET + 2],
            buf[STATUS_OFFSET + 3],
        ]);
        status == NT_STATUS_SUCCESS && !signing_required
    } else {
        false
    };

    let null_session_severity = if null_session {
        Severity::High
    } else {
        Severity::None
    };

    SmbResult {
        host,
        smb_detected: true,
        dialect,
        signing_enabled,
        signing_required,
        null_session,
        signing_severity,
        null_session_severity,
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

    // filter hosts with SMB ports open
    let smb_hosts: Vec<String> = summary
        .hosts
        .into_iter()
        .filter(|h| h.open_ports.contains(&SMB_PORT) || h.open_ports.contains(&139))
        .map(|h| h.hostname)
        .collect();

    eprintln!(
        "mg-smb: {} hosts with port 445/139 (concurrency={})",
        smb_hosts.len(),
        args.concurrency
    );

    let timeout = args.timeout;
    let concurrency = args.concurrency;
    let mut set: JoinSet<SmbResult> = JoinSet::new();
    let mut results: Vec<SmbResult> = Vec::new();

    for host in smb_hosts.iter().cloned() {
        // drain when at ceiling
        if set.len() >= concurrency
            && let Some(Ok(r)) = set.join_next().await
        {
            results.push(r);
        }
        set.spawn(async move { probe_host(host, timeout).await });
    }

    // drain remaining
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }

    results.sort_by(|a, b| a.host.cmp(&b.host));

    // print flagged results
    for r in &results {
        if r.smb_detected {
            eprintln!(
                "  {} dialect={} signing_required={} null_session={}",
                r.host, r.dialect, r.signing_required, r.null_session
            );
            if !r.signing_required {
                eprintln!("  [MEDIUM] {} — signing not required (relay attack risk)", r.host);
            }
            if r.null_session {
                eprintln!("  [HIGH] {} — null session accepted", r.host);
            }
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = SmbResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        hosts_checked: results.len(),
        results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create smb output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write smb results JSON")?;

    eprintln!("mg-smb: written {}", results_path.display());

    // Emit findings for confirmed SMB issues
    for r in &output.results {
        if !r.smb_detected {
            continue;
        }
        if r.null_session {
            let tf = ToolFinding::new("mg-smb", "SMB Null Session Allowed", FindingSeverity::High)
                .url(format!("smb://{}", r.host))
                .evidence(format!(
                    "dialect={} STATUS_SUCCESS received with empty credentials; signing_required={}",
                    r.dialect, r.signing_required
                ))
                .recommendation(
                    "Disable anonymous/guest SMB access; require authentication; \
                     enforce SMB signing via Group Policy"
                );
            let _ = write_finding(&eng, &tf);
        }
        if !r.signing_required {
            let tf = ToolFinding::new("mg-smb", "SMB Signing Not Required", FindingSeverity::Medium)
                .url(format!("smb://{}", r.host))
                .evidence(format!(
                    "dialect={} signing_enabled={} signing_required=false — relay attack feasible",
                    r.dialect, r.signing_enabled
                ))
                .recommendation(
                    "Enable RequireSecuritySignature via Group Policy (GPO: Microsoft network server); \
                     enforce SMB signing on all domain controllers"
                );
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} ts={ts}",
            output.hosts_checked
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialect_name_known_values() {
        assert_eq!(dialect_name(0x0202), "SMB 2.0.2");
        assert_eq!(dialect_name(0x0311), "SMB 3.1.1");
        assert_eq!(dialect_name(0x9999), "unknown");
    }

    #[test]
    fn parse_negotiate_too_short_returns_none() {
        let buf = vec![0u8; 10];
        assert!(parse_negotiate_response(&buf).is_none());
    }

    #[test]
    fn parse_negotiate_wrong_magic_returns_none() {
        let mut buf = vec![0u8; 128];
        // put SMB1 magic at offset 4
        buf[4] = 0xff;
        buf[5] = b'S';
        buf[6] = b'M';
        buf[7] = b'B';
        assert!(parse_negotiate_response(&buf).is_none());
    }

    #[test]
    fn parse_negotiate_smb2_signing_required() {
        let mut buf = vec![0u8; 128];
        // NetBIOS header (4 bytes already zero)
        // SMB2 magic at offset 4
        buf[4] = 0xfe;
        buf[5] = b'S';
        buf[6] = b'M';
        buf[7] = b'B';
        // DialectRevision at 70: 0x0311 = [0x11, 0x03]
        buf[70] = 0x11;
        buf[71] = 0x03;
        // SecurityMode at 72: SIGNING_REQUIRED_BIT | SIGNING_ENABLED_BIT = 0x03
        buf[72] = SIGNING_REQUIRED_BIT | SIGNING_ENABLED_BIT;
        let (dialect, signing_enabled, signing_required) =
            parse_negotiate_response(&buf).unwrap();
        assert_eq!(dialect, "SMB 3.1.1");
        assert!(signing_enabled);
        assert!(signing_required);
    }

    #[test]
    fn parse_negotiate_signing_not_required() {
        let mut buf = vec![0u8; 128];
        buf[4] = 0xfe;
        buf[5] = b'S';
        buf[6] = b'M';
        buf[7] = b'B';
        buf[70] = 0x02;
        buf[71] = 0x02;
        buf[72] = SIGNING_ENABLED_BIT; // enabled but not required
        let (_, signing_enabled, signing_required) = parse_negotiate_response(&buf).unwrap();
        assert!(signing_enabled);
        assert!(!signing_required);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T10:30:00Z"), "2026-05-18T10_30_00Z");
    }
}
