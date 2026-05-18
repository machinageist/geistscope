/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-ssh-audit — SSH configuration auditor. Connects to SSH
 *                  servers, reads the banner and key exchange, and flags
 *                  deprecated algorithms and weak configurations.
 * Notes:           No SSH library is used. KEXINIT is sent as a raw packet
 *                  and the server's KEXINIT response is parsed from raw bytes.
 *                  KEXINIT packet structure per RFC 4253 §7.1:
 *                    uint32   packet_length
 *                    byte     padding_length
 *                    byte     SSH_MSG_KEXINIT (20)
 *                    byte[16] cookie (random)
 *                    name-list kex_algorithms
 *                    name-list server_host_key_algorithms
 *                    name-list encryption_algorithms_client_to_server
 *                    name-list encryption_algorithms_server_to_client
 *                    name-list mac_algorithms_client_to_server
 *                    ...
 *                  Each name-list is a uint32 length followed by that many bytes.
 *******************************************************************/

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "ssh-audit";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-ssh-audit";
const DEFAULT_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_CONCURRENCY: usize = 10;
const SSH_MSG_KEXINIT: u8 = 20;
const KEXINIT_COOKIE_LEN: usize = 16;
// Maximum bytes to read for banner + KEXINIT
const READ_BUF_LEN: usize = 32_768;
// Our client banner sent to trigger the server's KEXINIT
const CLIENT_BANNER: &[u8] = b"SSH-2.0-mg-ssh-audit_0.1\r\n";

// ── Deprecated algorithm lists ───────────────────────────────────────────────

const WEAK_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
];

const WEAK_CIPHERS: &[&str] = &[
    "arcfour",
    "blowfish-cbc",
    "3des-cbc",
    "aes128-cbc",
    "aes256-cbc",
];

const WEAK_MACS: &[&str] = &["hmac-md5", "hmac-sha1"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-ssh-audit",
    about = "SSH configuration auditor — banner, KEX algorithms, deprecated cipher detection"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// SSH port to audit
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// Max concurrent SSH connections
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Minimal shape from recon/summary.json — only fields we need
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Top-level recon summary
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// Severity of a flagged finding
#[derive(Debug, Clone, Serialize, PartialEq)]
enum Severity {
    High,
    Medium,
}

// A single algorithm or configuration weakness
#[derive(Debug, Clone, Serialize)]
struct Flag {
    severity: Severity,
    category: String,
    value: String,
    reason: String,
}

// Parsed KEXINIT algorithm lists for one host
#[derive(Debug, Default, Serialize)]
struct KexInfo {
    kex_algorithms: Vec<String>,
    server_host_key_algorithms: Vec<String>,
    encryption_algorithms_c2s: Vec<String>,
    mac_algorithms_c2s: Vec<String>,
}

// Full audit result for one host
#[derive(Debug, Serialize)]
struct HostAudit {
    host: String,
    port: u16,
    banner: Option<String>,
    ssh_version: Option<String>,
    kex: Option<KexInfo>,
    flags: Vec<Flag>,
    error: Option<String>,
}

// Top-level output written to the engagement ssh-audit dir
#[derive(Serialize)]
struct SshAuditOutput {
    engagement: String,
    audited_at: String,
    hosts_audited: usize,
    total_flags: usize,
    results: Vec<HostAudit>,
}

// ── KEXINIT parsing ──────────────────────────────────────────────────────────

// Read a 4-byte big-endian length then that many bytes; return as String
fn read_name_list(buf: &[u8], offset: &mut usize) -> Option<Vec<String>> {
    if *offset + 4 > buf.len() {
        return None;
    }
    let len = u32::from_be_bytes(buf[*offset..*offset + 4].try_into().ok()?) as usize;
    *offset += 4;
    if *offset + len > buf.len() {
        return None;
    }
    let s = std::str::from_utf8(&buf[*offset..*offset + len]).ok()?;
    *offset += len;
    Some(s.split(',').map(|a| a.to_string()).filter(|a| !a.is_empty()).collect())
}

// Parse a server KEXINIT payload starting after the SSH binary packet framing
// Returns None if the buffer doesn't contain a valid KEXINIT
fn parse_kexinit(raw: &[u8]) -> Option<KexInfo> {
    // Find the SSH_MSG_KEXINIT (20) in the stream after the banner
    // The server sends its banner then the KEXINIT binary packet.
    // Binary packet: uint32 pkt_len, byte pad_len, byte msg_type, payload, padding
    // We scan for the KEXINIT packet after the banner "\r\n"
    let banner_end = raw.windows(2).position(|w| w == b"\r\n")? + 2;
    let pkt = &raw[banner_end..];

    if pkt.len() < 6 {
        return None;
    }

    // pkt[0..4] = packet_length, pkt[4] = padding_length, pkt[5] = msg_type
    let msg_type = pkt[5];
    if msg_type != SSH_MSG_KEXINIT {
        return None;
    }

    // After msg_type comes 16 bytes of cookie, then the name-lists
    let payload_start = 6 + KEXINIT_COOKIE_LEN;
    if pkt.len() <= payload_start {
        return None;
    }

    let mut offset = payload_start;
    let kex_algorithms = read_name_list(pkt, &mut offset)?;
    let server_host_key_algorithms = read_name_list(pkt, &mut offset)?;
    let encryption_algorithms_c2s = read_name_list(pkt, &mut offset)?;
    // skip encryption_algorithms_s2c
    read_name_list(pkt, &mut offset)?;
    let mac_algorithms_c2s = read_name_list(pkt, &mut offset)?;

    Some(KexInfo {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_c2s,
        mac_algorithms_c2s,
    })
}

// ── Algorithm flagging ───────────────────────────────────────────────────────

// Compare algorithm lists against weak sets and build Flag records
fn flag_algorithms(kex: &KexInfo, banner: Option<&str>) -> Vec<Flag> {
    let mut flags = Vec::new();

    // Flag SSH v1 as HIGH — version string starts with "SSH-1."
    if let Some(b) = banner
        && b.starts_with("SSH-1.")
    {
        flags.push(Flag {
            severity: Severity::High,
            category: "version".to_string(),
            value: b.to_string(),
            reason: "SSH protocol version 1 is cryptographically broken".to_string(),
        });
    }

    // Flag deprecated KEX algorithms
    for alg in &kex.kex_algorithms {
        if WEAK_KEX.contains(&alg.as_str()) {
            flags.push(Flag {
                severity: Severity::High,
                category: "kex".to_string(),
                value: alg.clone(),
                reason: "weak key exchange algorithm".to_string(),
            });
        }
    }

    // Flag deprecated ciphers
    for alg in &kex.encryption_algorithms_c2s {
        if WEAK_CIPHERS.contains(&alg.as_str()) {
            flags.push(Flag {
                severity: Severity::Medium,
                category: "cipher".to_string(),
                value: alg.clone(),
                reason: "deprecated or weak cipher".to_string(),
            });
        }
    }

    // Flag weak MACs
    for alg in &kex.mac_algorithms_c2s {
        if WEAK_MACS.contains(&alg.as_str()) {
            flags.push(Flag {
                severity: Severity::Medium,
                category: "mac".to_string(),
                value: alg.clone(),
                reason: "weak MAC algorithm".to_string(),
            });
        }
    }

    flags
}

// ── Core audit ───────────────────────────────────────────────────────────────

// Connect to one SSH host, read banner + KEXINIT, return audit result
async fn audit_host(host: String, port: u16, timeout_secs: u64) -> HostAudit {
    let connect_result = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(format!("{host}:{port}")),
    )
    .await;

    let mut stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return HostAudit {
                host,
                port,
                banner: None,
                ssh_version: None,
                kex: None,
                flags: Vec::new(),
                error: Some(e.to_string()),
            };
        }
        Err(_) => {
            return HostAudit {
                host,
                port,
                banner: None,
                ssh_version: None,
                kex: None,
                flags: Vec::new(),
                error: Some("connection timeout".to_string()),
            };
        }
    };

    // read server banner (first \n-terminated line)
    let mut raw = vec![0u8; READ_BUF_LEN];
    let n = match timeout(
        Duration::from_secs(timeout_secs),
        stream.read(&mut raw),
    )
    .await
    {
        Ok(Ok(n)) => n,
        _ => {
            return HostAudit {
                host,
                port,
                banner: None,
                ssh_version: None,
                kex: None,
                flags: Vec::new(),
                error: Some("read timeout".to_string()),
            };
        }
    };
    raw.truncate(n);

    // extract banner: first line of the raw buffer
    let banner_line = raw
        .split(|&b| b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).trim_end_matches('\r').to_string());

    let ssh_version = banner_line
        .as_deref()
        .filter(|l| l.starts_with("SSH-"))
        .map(|l| l.to_string());

    // send client banner to trigger server KEXINIT
    if stream.write_all(CLIENT_BANNER).await.is_err() {
        let flags = if let Some(ref v) = ssh_version {
            flag_algorithms(&KexInfo::default(), Some(v.as_str()))
        } else {
            Vec::new()
        };
        return HostAudit {
            host,
            port,
            banner: banner_line,
            ssh_version,
            kex: None,
            flags,
            error: Some("failed to send client banner".to_string()),
        };
    }

    // read server KEXINIT — may arrive in the same buffer or require another read
    let mut kexinit_buf = raw.clone();
    match timeout(
        Duration::from_secs(timeout_secs),
        stream.read(&mut raw),
    )
    .await
    {
        Ok(Ok(n2)) if n2 > 0 => kexinit_buf.extend_from_slice(&raw[..n2]),
        _ => {}
    }

    let kex = parse_kexinit(&kexinit_buf);
    let flags = flag_algorithms(
        kex.as_ref().unwrap_or(&KexInfo::default()),
        ssh_version.as_deref(),
    );

    HostAudit {
        host,
        port,
        banner: banner_line,
        ssh_version,
        kex,
        flags,
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

    let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    // filter to hosts with the target SSH port open
    let ssh_port = args.port;
    let hosts: Vec<String> = summary
        .hosts
        .iter()
        .filter(|h| h.open_ports.contains(&ssh_port))
        .map(|h| h.hostname.clone())
        .collect();

    eprintln!(
        "mg-ssh-audit: {} hosts with port {} open, concurrency={}, timeout={}s",
        hosts.len(),
        ssh_port,
        args.concurrency,
        args.timeout
    );

    // bounded JoinSet drain
    let mut set: tokio::task::JoinSet<HostAudit> = tokio::task::JoinSet::new();
    let mut results: Vec<HostAudit> = Vec::new();
    let timeout_secs = args.timeout;

    for host in hosts {
        if set.len() >= args.concurrency
            && let Some(Ok(r)) = set.join_next().await
        {
            eprintln!(
                "  {} — {} flags{}",
                r.host,
                r.flags.len(),
                r.error.as_deref().map(|e| format!(" (err: {e})")).unwrap_or_default()
            );
            results.push(r);
        }
        set.spawn(async move { audit_host(host, ssh_port, timeout_secs).await });
    }

    while let Some(Ok(r)) = set.join_next().await {
        eprintln!(
            "  {} — {} flags{}",
            r.host,
            r.flags.len(),
            r.error.as_deref().map(|e| format!(" (err: {e})")).unwrap_or_default()
        );
        results.push(r);
    }

    let total_flags: usize = results.iter().map(|r| r.flags.len()).sum();
    eprintln!("mg-ssh-audit: {} total flags across {} hosts", total_flags, results.len());

    // write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&out_dir).context("create ssh-audit dir")?;

    let audited_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let ts_file = audited_at.replace(':', "-");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = SshAuditOutput {
        engagement: args.engagement.clone(),
        audited_at,
        hosts_audited: results.len(),
        total_flags,
        results,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, json).context("write output")?;

    eprintln!("  written: {}", out_path.display());

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} flags={}",
            output.hosts_audited, output.total_flags
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_algorithms_detects_weak_kex() {
        let kex = KexInfo {
            kex_algorithms: vec!["diffie-hellman-group1-sha1".to_string()],
            server_host_key_algorithms: vec![],
            encryption_algorithms_c2s: vec![],
            mac_algorithms_c2s: vec![],
        };
        let flags = flag_algorithms(&kex, None);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, Severity::High);
        assert_eq!(flags[0].category, "kex");
    }

    #[test]
    fn flag_algorithms_detects_weak_cipher() {
        let kex = KexInfo {
            kex_algorithms: vec![],
            server_host_key_algorithms: vec![],
            encryption_algorithms_c2s: vec!["aes128-cbc".to_string(), "aes256-cbc".to_string()],
            mac_algorithms_c2s: vec![],
        };
        let flags = flag_algorithms(&kex, None);
        assert_eq!(flags.len(), 2);
        assert!(flags.iter().all(|f| f.severity == Severity::Medium));
        assert!(flags.iter().all(|f| f.category == "cipher"));
    }

    #[test]
    fn flag_algorithms_detects_weak_mac() {
        let kex = KexInfo {
            kex_algorithms: vec![],
            server_host_key_algorithms: vec![],
            encryption_algorithms_c2s: vec![],
            mac_algorithms_c2s: vec!["hmac-md5".to_string()],
        };
        let flags = flag_algorithms(&kex, None);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, Severity::Medium);
        assert_eq!(flags[0].category, "mac");
    }

    #[test]
    fn flag_algorithms_detects_ssh_v1() {
        let kex = KexInfo::default();
        let flags = flag_algorithms(&kex, Some("SSH-1.99-OpenSSH_7.4"));
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].severity, Severity::High);
        assert_eq!(flags[0].category, "version");
    }

    #[test]
    fn flag_algorithms_clean_server_returns_no_flags() {
        let kex = KexInfo {
            kex_algorithms: vec!["curve25519-sha256".to_string()],
            server_host_key_algorithms: vec!["ssh-ed25519".to_string()],
            encryption_algorithms_c2s: vec!["chacha20-poly1305@openssh.com".to_string()],
            mac_algorithms_c2s: vec!["hmac-sha2-256".to_string()],
        };
        let flags = flag_algorithms(&kex, Some("SSH-2.0-OpenSSH_8.9"));
        assert!(flags.is_empty());
    }

    #[test]
    fn parse_kexinit_returns_none_for_short_buffer() {
        assert!(parse_kexinit(b"SSH-2.0-OpenSSH\r\n").is_none());
    }

    #[test]
    fn read_name_list_parses_comma_separated() {
        // 4-byte big-endian length (6) + "a,b,cd" (6 bytes, no null terminator)
        let buf = [0x00, 0x00, 0x00, 0x06, b'a', b',', b'b', b',', b'c', b'd'];
        let mut off = 0;
        let list = read_name_list(&buf, &mut off).unwrap();
        assert_eq!(list, vec!["a", "b", "cd"]);
        assert_eq!(off, 10);
    }
}
