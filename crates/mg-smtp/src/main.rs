/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-smtp — SMTP enumeration: user enum via VRFY/EXPN,
 *                  open relay test, and header injection check.
 * Notes:           All communication is raw TCP with no SMTP library.
 *                  Header injection test sends a MAIL FROM with an embedded
 *                  CRLF; compliant servers reject this.
 *                  Only hosts with port 25 or 587 in open_ports are probed.
 *******************************************************************/

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "smtp";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-smtp";
const DEFAULT_PORT: u16 = 25;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_CONCURRENCY: usize = 5;
// VRFY response codes: 252 = user probably exists, 550 = does not exist
const VRFY_EXISTS_CODE: &str = "252";
const VRFY_MISSING_CODE: &str = "550";
// SMTP ports considered for scanning when no --port given
const SMTP_PORTS: &[u16] = &[25, 587];

// Built-in username list for VRFY enumeration
const DEFAULT_USERS: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "postmaster",
    "webmaster",
    "info",
    "support",
    "noreply",
    "no-reply",
    "security",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-smtp",
    about = "SMTP enumeration — VRFY/EXPN user enum, open relay test, header injection"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// SMTP port to probe (default: scan both 25 and 587)
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// Max concurrent SMTP sessions
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Comma-separated usernames to VRFY (default: built-in list)
    #[arg(long)]
    users: Option<String>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Minimal shape from recon/summary.json
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

// Severity of a finding
#[derive(Debug, Clone, Serialize, PartialEq)]
enum Severity {
    High,
    Medium,
}

// One enumeration finding
#[derive(Debug, Clone, Serialize)]
struct SmtpFinding {
    severity: Severity,
    category: String,
    detail: String,
}

// Full result for one SMTP host
#[derive(Debug, Serialize)]
struct HostResult {
    host: String,
    port: u16,
    banner: Option<String>,
    ehlo_capabilities: Vec<String>,
    vrfy_users_found: Vec<String>,
    expn_enabled: bool,
    open_relay: bool,
    header_injection: bool,
    findings: Vec<SmtpFinding>,
    error: Option<String>,
}

// Top-level output written to the engagement smtp dir
#[derive(Serialize)]
struct SmtpOutput {
    engagement: String,
    scanned_at: String,
    hosts_scanned: usize,
    total_findings: usize,
    results: Vec<HostResult>,
}

// ── SMTP I/O helpers ─────────────────────────────────────────────────────────

// Read one SMTP response line (may be multi-line; stop when continuation flag clears)
async fn read_response(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    timeout_secs: u64,
) -> String {
    let mut full = String::new();
    loop {
        let mut line = String::new();
        let result = timeout(
            Duration::from_secs(timeout_secs),
            reader.read_line(&mut line),
        )
        .await;
        match result {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {
                full.push_str(&line);
                // multi-line responses have a '-' after the code; single line has ' ' or end
                if line.len() < 4 || line.as_bytes()[3] != b'-' {
                    break;
                }
            }
        }
    }
    full
}

// Send a command and read the response
async fn cmd(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    command: &str,
    timeout_secs: u64,
) -> String {
    let _ = writer.write_all(command.as_bytes()).await;
    read_response(reader, timeout_secs).await
}

// Extract the first 3-digit code from an SMTP response
fn smtp_code(resp: &str) -> &str {
    if resp.len() >= 3 { &resp[..3] } else { "" }
}

// ── Core probe ───────────────────────────────────────────────────────────────

// Connect to one SMTP host and run all enumeration checks
async fn probe_smtp(host: String, port: u16, timeout_secs: u64, users: Vec<String>) -> HostResult {
    let connect_result = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(format!("{host}:{port}")),
    )
    .await;

    let stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return HostResult {
                host,
                port,
                banner: None,
                ehlo_capabilities: vec![],
                vrfy_users_found: vec![],
                expn_enabled: false,
                open_relay: false,
                header_injection: false,
                findings: vec![],
                error: Some(e.to_string()),
            };
        }
        Err(_) => {
            return HostResult {
                host,
                port,
                banner: None,
                ehlo_capabilities: vec![],
                vrfy_users_found: vec![],
                expn_enabled: false,
                open_relay: false,
                header_injection: false,
                findings: vec![],
                error: Some("connection timeout".to_string()),
            };
        }
    };

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    // read greeting banner
    let banner_resp = read_response(&mut reader, timeout_secs).await;
    let banner = Some(banner_resp.lines().next().unwrap_or("").to_string());

    // send EHLO and collect capabilities
    let ehlo_resp = cmd(&mut wr, &mut reader, "EHLO scanner.test\r\n", timeout_secs).await;
    let ehlo_capabilities: Vec<String> = ehlo_resp
        .lines()
        .skip(1)
        .map(|l| {
            l.trim_start_matches(|c: char| c.is_ascii_digit() || c == '-' || c == ' ')
                .to_string()
        })
        .filter(|l| !l.is_empty())
        .collect();

    // extract domain from banner for VRFY addresses
    let domain = banner
        .as_deref()
        .and_then(|b| b.split_whitespace().nth(1))
        .unwrap_or("target.test");

    let mut vrfy_users_found: Vec<String> = Vec::new();
    let mut expn_enabled = false;
    let mut findings: Vec<SmtpFinding> = Vec::new();

    // VRFY user enumeration
    for user in &users {
        let resp = cmd(
            &mut wr,
            &mut reader,
            &format!("VRFY {user}@{domain}\r\n"),
            timeout_secs,
        )
        .await;
        let code = smtp_code(&resp);
        if code == VRFY_EXISTS_CODE {
            vrfy_users_found.push(user.clone());
        }
        // 252 and non-550 both suggest the server doesn't refuse VRFY
        if code != VRFY_MISSING_CODE && code != "500" && code != "502" && !code.is_empty() {
            // only record VRFY-enabled finding once
            if vrfy_users_found.len() == 1
                || (code == VRFY_EXISTS_CODE && vrfy_users_found.len() == 1)
            {
                findings.push(SmtpFinding {
                    severity: Severity::Medium,
                    category: "vrfy".to_string(),
                    detail: format!("VRFY enabled; user '{user}' likely exists"),
                });
            }
        }
    }

    // EXPN enumeration — check first user, flag if 250
    if !users.is_empty() {
        let expn_resp = cmd(
            &mut wr,
            &mut reader,
            &format!("EXPN {}\r\n", users[0]),
            timeout_secs,
        )
        .await;
        if smtp_code(&expn_resp) == "250" {
            expn_enabled = true;
            findings.push(SmtpFinding {
                severity: Severity::Medium,
                category: "expn".to_string(),
                detail: "EXPN command enabled — mailing list disclosure possible".to_string(),
            });
        }
    }

    // reset state before relay test
    let _ = cmd(&mut wr, &mut reader, "RSET\r\n", timeout_secs).await;

    // open relay test: MAIL FROM external, RCPT TO external
    let mail_resp = cmd(
        &mut wr,
        &mut reader,
        "MAIL FROM:<test@evil-scanner.test>\r\n",
        timeout_secs,
    )
    .await;
    let rcpt_resp = cmd(
        &mut wr,
        &mut reader,
        "RCPT TO:<target@victim-scanner.test>\r\n",
        timeout_secs,
    )
    .await;
    let open_relay = smtp_code(&mail_resp) == "250" && smtp_code(&rcpt_resp) == "250";
    if open_relay {
        findings.push(SmtpFinding {
            severity: Severity::High,
            category: "open_relay".to_string(),
            detail: "server accepted RCPT TO for external domain — open relay".to_string(),
        });
    }

    // reset before header injection test
    let _ = cmd(&mut wr, &mut reader, "RSET\r\n", timeout_secs).await;

    // header injection: MAIL FROM with embedded CRLF in address
    let inject_resp = cmd(
        &mut wr,
        &mut reader,
        "MAIL FROM:<test@evil-scanner.test\r\nBcc: victim@victim-scanner.test>\r\n",
        timeout_secs,
    )
    .await;
    let header_injection = smtp_code(&inject_resp) == "250";
    if header_injection {
        findings.push(SmtpFinding {
            severity: Severity::High,
            category: "header_injection".to_string(),
            detail: "server accepted MAIL FROM with embedded CRLF — header injection".to_string(),
        });
    }

    // clean up session
    let _ = cmd(&mut wr, &mut reader, "QUIT\r\n", timeout_secs).await;

    HostResult {
        host,
        port,
        banner,
        ehlo_capabilities,
        vrfy_users_found,
        expn_enabled,
        open_relay,
        header_injection,
        findings,
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

    // parse user list from --users flag or use built-in default
    let users: Vec<String> = if let Some(u) = &args.users {
        u.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        DEFAULT_USERS.iter().map(|s| s.to_string()).collect()
    };

    let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    // filter to hosts with SMTP ports open
    let target_port = args.port;
    let hosts: Vec<(String, u16)> = summary
        .hosts
        .iter()
        .flat_map(|h| {
            SMTP_PORTS
                .iter()
                .filter(|&&p| h.open_ports.contains(&p))
                .map(|&p| (h.hostname.clone(), p))
                .collect::<Vec<_>>()
        })
        .filter(|(_, p)| *p == target_port || args.port == DEFAULT_PORT)
        .collect();

    eprintln!(
        "mg-smtp: {} host/port pairs, concurrency={}, timeout={}s, users={}",
        hosts.len(),
        args.concurrency,
        args.timeout,
        users.len()
    );

    // bounded JoinSet drain
    let mut set: tokio::task::JoinSet<HostResult> = tokio::task::JoinSet::new();
    let mut results: Vec<HostResult> = Vec::new();
    let timeout_secs = args.timeout;

    for (host, port) in hosts {
        if set.len() >= args.concurrency
            && let Some(Ok(r)) = set.join_next().await
        {
            eprintln!(
                "  {}:{} — {} findings, relay={}, inject={}",
                r.host,
                r.port,
                r.findings.len(),
                r.open_relay,
                r.header_injection
            );
            results.push(r);
        }
        let u = users.clone();
        set.spawn(async move { probe_smtp(host, port, timeout_secs, u).await });
    }

    while let Some(Ok(r)) = set.join_next().await {
        eprintln!(
            "  {}:{} — {} findings, relay={}, inject={}",
            r.host,
            r.port,
            r.findings.len(),
            r.open_relay,
            r.header_injection
        );
        results.push(r);
    }

    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    eprintln!(
        "mg-smtp: {} total findings across {} results",
        total_findings,
        results.len()
    );

    // write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&out_dir).context("create smtp dir")?;

    let scanned_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let ts_file = scanned_at.replace(':', "-");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = SmtpOutput {
        engagement: args.engagement.clone(),
        scanned_at,
        hosts_scanned: results.len(),
        total_findings,
        results,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, json).context("write output")?;

    eprintln!("  written: {}", out_path.display());

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} findings={}",
            output.hosts_scanned, output.total_findings
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_code_extracts_first_three_chars() {
        assert_eq!(smtp_code("250 OK"), "250");
        assert_eq!(smtp_code("550 User unknown"), "550");
        assert_eq!(smtp_code(""), "");
    }

    #[test]
    fn smtp_code_returns_empty_for_short_string() {
        // fewer than 3 chars has no valid SMTP code
        assert_eq!(smtp_code("25"), "");
        assert_eq!(smtp_code("2"), "");
    }

    #[test]
    fn default_users_includes_admin_and_root() {
        assert!(DEFAULT_USERS.contains(&"admin"));
        assert!(DEFAULT_USERS.contains(&"root"));
        assert!(DEFAULT_USERS.contains(&"postmaster"));
    }

    #[test]
    fn smtp_ports_includes_25_and_587() {
        assert!(SMTP_PORTS.contains(&25));
        assert!(SMTP_PORTS.contains(&587));
    }

    #[test]
    fn vrfy_exists_code_is_252() {
        assert_eq!(VRFY_EXISTS_CODE, "252");
    }
}
