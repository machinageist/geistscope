/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-tls-scan — TLS/SSL configuration auditor. Connects to
 *                  HTTPS hosts from an engagement's recon summary, inspects the
 *                  negotiated TLS parameters, cert validity, and cipher suites.
 * Notes:           Uses rustls 0.23 + tokio-rustls 0.26 for direct TLS
 *                  handshake inspection — not routed through reqwest.
 *                  x509-parser 0.16 is used for DER certificate parsing.
 *                  x509_parser::prelude::* re-exports a `time` module, so
 *                  the `time` crate is imported with `::time` prefix to avoid
 *                  the ambiguity.
 *                  TLS 1.0/1.1 probing is advisory: rustls 0.23 only speaks
 *                  TLS 1.2+, so version flags come from negotiated_protocol_version().
 *                  Weak-cipher detection covers the rustls SupportedCipherSuite name.
 *******************************************************************/

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;
// Explicit crate-root prefix required because x509_parser::prelude::* also exports `time`
use ::time::OffsetDateTime;
use ::time::format_description::well_known::Rfc3339;
use x509_parser::prelude::*;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const HTTPS_PORT: u16 = 443;
const OUTPUT_SUBDIR: &str = "tls";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-tls-scan";
// Seconds before certificate expiry that triggers a HIGH flag (30 days)
const CERT_EXPIRY_WARN_SECS: i64 = 30 * 24 * 60 * 60;
// Cipher suite name substrings considered HIGH severity
const HIGH_CIPHERS: &[&str] = &["RC4", "3DES", "NULL", "EXPORT", "ANON"];
// Cipher suite name substrings considered LOW severity (when not already HIGH)
const LOW_CIPHERS: &[&str] = &["CBC"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-tls-scan",
    about = "TLS/SSL configuration auditor — version, cipher, cert, chain checks"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Max concurrent TLS probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// TCP connect + TLS handshake timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Input types ───────────────────────────────────────────────────────────────

// Shape of recon/summary.json (written by mg-recon orchestrator)
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<SummaryHostRecord>,
}

#[derive(Deserialize)]
struct SummaryHostRecord {
    hostname: String,
    open_ports: Vec<u16>,
}

// ── Output types ──────────────────────────────────────────────────────────────

// Severity levels for individual findings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    Info,
    Low,
    Medium,
    High,
}

// One check result for a single finding on a host
#[derive(Debug, Clone, Serialize)]
struct CheckFinding {
    severity: Severity,
    check: String,
    detail: String,
}

// Per-host TLS scan result
#[derive(Debug, Clone, Serialize)]
struct HostResult {
    hostname: String,
    port: u16,
    tls_version: String,
    cipher_suite: String,
    cert_subject: String,
    cert_issuer: String,
    cert_not_after: String,
    cert_not_before: String,
    cert_sans: Vec<String>,
    cert_chain_len: usize,
    findings: Vec<CheckFinding>,
    error: Option<String>,
}

// Top-level output written to tls/results-<ts>.json
#[derive(Serialize)]
struct TlsScanOutput {
    engagement: String,
    generated_at: String,
    hosts_scanned: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    results: Vec<HostResult>,
}

// ── Host loading ──────────────────────────────────────────────────────────────

// Extract unique HTTPS hosts from summary.json
fn load_https_hosts(recon_dir: &Path) -> Result<Vec<(String, u16)>> {
    let summary_path = recon_dir.join("summary.json");
    if !summary_path.exists() {
        anyhow::bail!("recon/summary.json not found — run mg-recon first");
    }
    let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let mut hosts: Vec<(String, u16)> = Vec::new();
    for h in summary.hosts {
        if h.open_ports.contains(&HTTPS_PORT) {
            hosts.push((h.hostname.clone(), HTTPS_PORT));
        }
        // also include common alternate HTTPS ports
        for &port in &h.open_ports {
            if port == 8443 || port == 9443 {
                hosts.push((h.hostname.clone(), port));
            }
        }
    }

    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

// ── Certificate parsing ───────────────────────────────────────────────────────

// Parse a DER leaf cert; run expiry + self-signed + hostname checks; return fields
fn parse_and_check_cert(
    der: &[u8],
    hostname: &str,
    findings: &mut Vec<CheckFinding>,
) -> (String, String, String, String, Vec<String>, bool) {
    let Ok((_, cert)) = parse_x509_certificate(der) else {
        findings.push(CheckFinding {
            severity: Severity::Medium,
            check: "certificate parse error".into(),
            detail: "could not parse DER certificate".into(),
        });
        return (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Vec::new(),
            false,
        );
    };

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let not_after_ts = cert.validity().not_after.timestamp();
    let is_self_signed = subject == issuer;

    // timestamp-based expiry check
    check_cert_expiry_ts(not_after_ts, findings);

    // extract DNS SANs
    let mut sans: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(name) = gn {
                    sans.push(name.to_string());
                }
            }
        }
    }

    // check hostname match
    check_hostname_match(hostname, &subject, &sans, findings);

    (subject, issuer, not_before, not_after, sans, is_self_signed)
}

// ── Individual checks ─────────────────────────────────────────────────────────

// Flag weak or deprecated TLS versions
fn check_tls_version(version_str: &str, findings: &mut Vec<CheckFinding>) {
    // rustls 0.23 only negotiates TLS 1.2 and 1.3; older versions never appear
    // in practice but the check is retained for completeness
    if version_str.contains("1_0") || version_str.contains("TLS1_0") {
        findings.push(CheckFinding {
            severity: Severity::High,
            check: "deprecated TLS version".into(),
            detail: format!("TLS 1.0 negotiated ({version_str}) — upgrade to TLS 1.3"),
        });
    } else if version_str.contains("1_1") || version_str.contains("TLS1_1") {
        findings.push(CheckFinding {
            severity: Severity::High,
            check: "deprecated TLS version".into(),
            detail: format!("TLS 1.1 negotiated ({version_str}) — upgrade to TLS 1.3"),
        });
    } else if version_str.contains("1_2")
        || version_str.contains("TLS1_2")
        || version_str.contains("TLSv1_2")
    {
        findings.push(CheckFinding {
            severity: Severity::Info,
            check: "TLS 1.2 in use".into(),
            detail: "TLS 1.2 acceptable; TLS 1.3 recommended for improved security".into(),
        });
    }
}

// Flag weak cipher suites by name substring
fn check_cipher_suite(suite_name: &str, findings: &mut Vec<CheckFinding>) {
    let upper = suite_name.to_uppercase();
    for bad in HIGH_CIPHERS {
        if upper.contains(bad) {
            findings.push(CheckFinding {
                severity: Severity::High,
                check: "weak cipher suite".into(),
                detail: format!("cipher suite {suite_name} is cryptographically weak"),
            });
            return;
        }
    }
    for low in LOW_CIPHERS {
        if upper.contains(low) {
            findings.push(CheckFinding {
                severity: Severity::Low,
                check: "deprecated cipher mode".into(),
                detail: format!("cipher suite {suite_name} uses CBC mode (prefer AEAD)"),
            });
            return;
        }
    }
}

// Flag certificates expiring within 30 days or already expired
fn check_cert_expiry_ts(not_after_ts: i64, findings: &mut Vec<CheckFinding>) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if not_after_ts < now {
        findings.push(CheckFinding {
            severity: Severity::High,
            check: "certificate expired".into(),
            detail: "certificate not_after is in the past".into(),
        });
    } else if not_after_ts < now + CERT_EXPIRY_WARN_SECS {
        let days_left = (not_after_ts - now) / 86400;
        findings.push(CheckFinding {
            severity: Severity::High,
            check: "certificate expiring soon".into(),
            detail: format!("certificate expires in {days_left} days"),
        });
    }
}

// Check whether hostname matches any SAN (exact or wildcard) or subject CN
fn check_hostname_match(
    hostname: &str,
    subject: &str,
    sans: &[String],
    findings: &mut Vec<CheckFinding>,
) {
    let hostname_lower = hostname.to_lowercase();

    if sans.is_empty() {
        // no SANs — fall back to CN check
        let cn_match = subject
            .to_lowercase()
            .contains(&format!("cn={hostname_lower}"));
        if !cn_match {
            findings.push(CheckFinding {
                severity: Severity::High,
                check: "hostname mismatch".into(),
                detail: format!("hostname {hostname} does not match certificate CN"),
            });
        }
        return;
    }

    let matched = sans.iter().any(|san| {
        let san_lower = san.to_lowercase();
        if san_lower == hostname_lower {
            return true;
        }
        if let Some(wildcard_suffix) = san_lower.strip_prefix("*.")
            && let Some(stripped) = hostname_lower.strip_suffix(wildcard_suffix)
        {
            // wildcard covers exactly one label: "api." is valid, "api.v2." is not
            return stripped.ends_with('.') && !stripped[..stripped.len() - 1].contains('.');
        }
        false
    });

    if !matched {
        findings.push(CheckFinding {
            severity: Severity::High,
            check: "hostname mismatch".into(),
            detail: format!("hostname {hostname} does not match any SAN in the certificate"),
        });
    }
}

// ── TLS handshake ─────────────────────────────────────────────────────────────

// Perform TLS handshake and build a HostResult with all checks applied
async fn do_tls_handshake(
    hostname: &str,
    port: u16,
    connector: &TlsConnector,
) -> Result<HostResult> {
    let addr = format!("{hostname}:{port}");
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;

    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {hostname}"))?;

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {addr}"))?;

    let (_, conn) = tls_stream.get_ref();

    let tls_version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| cs.suite().as_str().unwrap_or("unknown").to_string())
        .unwrap_or_else(|| "unknown".into());

    let peer_certs = conn.peer_certificates().unwrap_or(&[]);
    let cert_chain_len = peer_certs.len();

    let mut findings: Vec<CheckFinding> = Vec::new();

    check_tls_version(&tls_version, &mut findings);
    check_cipher_suite(&cipher_suite, &mut findings);

    let (cert_subject, cert_issuer, cert_not_before, cert_not_after, cert_sans, is_self_signed) =
        if let Some(leaf_der) = peer_certs.first() {
            parse_and_check_cert(leaf_der.as_ref(), hostname, &mut findings)
        } else {
            findings.push(CheckFinding {
                severity: Severity::High,
                check: "no certificate returned".into(),
                detail: "server sent no peer certificates".into(),
            });
            (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                false,
            )
        };

    if is_self_signed {
        findings.push(CheckFinding {
            severity: Severity::High,
            check: "self-signed certificate".into(),
            detail: format!("subject == issuer: {cert_subject}"),
        });
    }

    if cert_chain_len == 1 {
        findings.push(CheckFinding {
            severity: Severity::Medium,
            check: "incomplete certificate chain".into(),
            detail: "only leaf certificate sent; intermediate CA missing".into(),
        });
    }

    Ok(HostResult {
        hostname: hostname.to_string(),
        port,
        tls_version,
        cipher_suite,
        cert_subject,
        cert_issuer,
        cert_not_after,
        cert_not_before,
        cert_sans,
        cert_chain_len,
        findings,
        error: None,
    })
}

// Probe one host with timeout + error wrapping
async fn probe_host(
    hostname: String,
    port: u16,
    connector: Arc<TlsConnector>,
    timeout: Duration,
) -> HostResult {
    match tokio::time::timeout(timeout, do_tls_handshake(&hostname, port, &connector)).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => error_result(hostname, port, e.to_string()),
        Err(_) => error_result(
            hostname,
            port,
            format!("timeout after {}s", timeout.as_secs()),
        ),
    }
}

// Build an error HostResult for a failed probe
fn error_result(hostname: String, port: u16, msg: String) -> HostResult {
    HostResult {
        hostname,
        port,
        tls_version: String::new(),
        cipher_suite: String::new(),
        cert_subject: String::new(),
        cert_issuer: String::new(),
        cert_not_after: String::new(),
        cert_not_before: String::new(),
        cert_sans: Vec::new(),
        cert_chain_len: 0,
        findings: Vec::new(),
        error: Some(msg),
    }
}

// ── Summary table printing ─────────────────────────────────────────────────────

// ANSI color codes for terminal output
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_CYAN: &str = "\x1b[36m";
const ANSI_RESET: &str = "\x1b[0m";

// Print a color-coded summary table to stdout
fn print_summary_table(results: &[HostResult]) {
    println!("\n{:-<72}", "");
    println!("{:<35} {:<10} {:<15} FINDINGS", "HOST", "PORT", "TLS");
    println!("{:-<72}", "");

    for r in results {
        let host_col = if r.hostname.len() > 33 {
            format!("{}...", &r.hostname[..30])
        } else {
            r.hostname.clone()
        };

        if let Some(ref err) = r.error {
            println!("{:<35} {:<10} {:<15} ERROR: {}", host_col, r.port, "-", err);
            continue;
        }

        let highest = r.findings.iter().max_by_key(|f| &f.severity);
        let (color, label) = match highest {
            Some(f) if f.severity == Severity::High => (ANSI_RED, "HIGH"),
            Some(f) if f.severity == Severity::Medium => (ANSI_YELLOW, "MEDIUM"),
            Some(f) if f.severity == Severity::Low => (ANSI_CYAN, "LOW"),
            _ => ("", "OK"),
        };

        println!(
            "{:<35} {:<10} {:<15} {}{}{}",
            host_col, r.port, r.tls_version, color, label, ANSI_RESET
        );

        for f in &r.findings {
            let (fc, fl) = match f.severity {
                Severity::High => (ANSI_RED, "HIGH  "),
                Severity::Medium => (ANSI_YELLOW, "MEDIUM"),
                Severity::Low => (ANSI_CYAN, "LOW   "),
                Severity::Info => ("", "INFO  "),
            };
            println!("  [{}{}{}] {}: {}", fc, fl, ANSI_RESET, f.check, f.detail);
        }
    }
    println!("{:-<72}", "");
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let hosts = load_https_hosts(&eng.recon_dir()).context("load HTTPS hosts")?;

    if hosts.is_empty() {
        eprintln!("mg-tls-scan: no HTTPS hosts found in recon/summary.json");
        return Ok(());
    }

    eprintln!(
        "mg-tls-scan: {} HTTPS host:port pairs (concurrency={})",
        hosts.len(),
        args.concurrency
    );

    // build TLS connector backed by system root CAs
    let root_store = rustls::RootCertStore {
        roots: TLS_SERVER_ROOTS.to_vec(),
    };
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let tls_connector = Arc::new(TlsConnector::from(Arc::new(tls_config)));

    let timeout = Duration::from_secs(args.timeout);
    let concurrency = args.concurrency.max(1);
    let mut set: JoinSet<HostResult> = JoinSet::new();
    let mut results: Vec<HostResult> = Vec::new();

    for (hostname, port) in hosts.iter().cloned() {
        // drain one result before spawning when at the concurrency ceiling
        while set.len() >= concurrency {
            if let Some(Ok(r)) = set.join_next().await {
                eprintln!("  scanned {}:{}", r.hostname, r.port);
                results.push(r);
            }
        }
        let connector = Arc::clone(&tls_connector);
        set.spawn(async move { probe_host(hostname, port, connector, timeout).await });
    }

    // drain remaining in-flight tasks
    while let Some(Ok(r)) = set.join_next().await {
        eprintln!("  scanned {}:{}", r.hostname, r.port);
        results.push(r);
    }

    results.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.port.cmp(&b.port)));

    print_summary_table(&results);

    let high_count = results
        .iter()
        .filter(|r| r.findings.iter().any(|f| f.severity == Severity::High))
        .count();
    let medium_count = results
        .iter()
        .filter(|r| r.findings.iter().any(|f| f.severity == Severity::Medium))
        .count();
    let low_count = results
        .iter()
        .filter(|r| r.findings.iter().any(|f| f.severity == Severity::Low))
        .count();

    // write output file
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&out_dir).context("create tls dir")?;

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;
    let ts_file = generated_at.replace(':', "-");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = TlsScanOutput {
        engagement: args.engagement.clone(),
        generated_at,
        hosts_scanned: results.len(),
        high_count,
        medium_count,
        low_count,
        results,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, &json).context("write output file")?;

    println!(
        "mg-tls-scan: {}/{} hosts with HIGH findings",
        output.high_count, output.hosts_scanned
    );
    println!("  results: {}", out_path.display());

    // Write findings for each HIGH and MEDIUM TLS issue per host
    for r in &output.results {
        for f in &r.findings {
            let sev = match f.severity {
                Severity::High => FindingSeverity::High,
                Severity::Medium => FindingSeverity::Medium,
                _ => continue,
            };
            let tf = ToolFinding::new("mg-tls-scan", &f.check, sev)
                .url(format!("https://{}:{}", r.hostname, r.port))
                .evidence(f.detail.clone())
                .recommendation(
                    "Upgrade TLS configuration; refer to Mozilla SSL Configuration Generator",
                );
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "hosts={} high={} medium={} low={}",
            output.hosts_scanned, output.high_count, output.medium_count, output.low_count
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Write summary.json into a temp recon dir; return (TempDir guard, recon path)
    fn tmp_recon_with_summary(content: &str) -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        let recon = tmp.path().join("recon");
        std::fs::create_dir_all(&recon).unwrap();
        std::fs::write(recon.join("summary.json"), content).unwrap();
        (tmp, recon)
    }

    #[test]
    fn load_https_hosts_extracts_port_443() {
        let json = r#"{"engagement":"t","target":"example.com","generated_at":"","host_count":2,"hosts":[{"hostname":"a.example.com","ips":[],"source":"ct","http_accessible":true,"fingerprint":null,"open_ports":[80,443],"services":[]},{"hostname":"b.example.com","ips":[],"source":"ct","http_accessible":false,"fingerprint":null,"open_ports":[80],"services":[]}]}"#;
        let (_tmp, recon) = tmp_recon_with_summary(json);
        let hosts = load_https_hosts(&recon).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], ("a.example.com".to_string(), 443));
    }

    #[test]
    fn load_https_hosts_includes_alt_tls_ports() {
        let json = r#"{"engagement":"t","target":"example.com","generated_at":"","host_count":1,"hosts":[{"hostname":"c.example.com","ips":[],"source":"ct","http_accessible":true,"fingerprint":null,"open_ports":[8443],"services":[]}]}"#;
        let (_tmp, recon) = tmp_recon_with_summary(json);
        let hosts = load_https_hosts(&recon).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].1, 8443);
    }

    #[test]
    fn load_https_hosts_errors_without_summary_json() {
        let tmp = TempDir::new().unwrap();
        let recon = tmp.path().join("recon");
        std::fs::create_dir_all(&recon).unwrap();
        assert!(load_https_hosts(&recon).is_err());
    }

    #[test]
    fn check_tls_version_flags_12_as_info() {
        let mut findings = Vec::new();
        check_tls_version("TLSv1_2", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn check_tls_version_flags_10_as_high() {
        let mut findings = Vec::new();
        check_tls_version("TLS1_0", &mut findings);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn check_cipher_suite_flags_rc4_as_high() {
        let mut findings = Vec::new();
        check_cipher_suite("TLS_RSA_WITH_RC4_128_SHA", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn check_cipher_suite_flags_cbc_as_low() {
        let mut findings = Vec::new();
        check_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn check_cipher_suite_no_finding_for_aead() {
        let mut findings = Vec::new();
        check_cipher_suite("TLS13_AES_128_GCM_SHA256", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn check_cert_expiry_ts_flags_past_expiry() {
        let mut findings = Vec::new();
        check_cert_expiry_ts(0, &mut findings); // unix epoch = long expired
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn check_cert_expiry_ts_no_finding_for_far_future() {
        let mut findings = Vec::new();
        let far_future = OffsetDateTime::now_utc().unix_timestamp() + 365 * 86400;
        check_cert_expiry_ts(far_future, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn hostname_mismatch_flagged_when_not_in_sans() {
        let mut findings = Vec::new();
        check_hostname_match(
            "evil.example.com",
            "CN=other.example.com",
            &["a.example.com".to_string()],
            &mut findings,
        );
        assert!(findings.iter().any(|f| f.check == "hostname mismatch"));
    }

    #[test]
    fn hostname_wildcard_san_accepted() {
        let mut findings = Vec::new();
        check_hostname_match(
            "api.example.com",
            "CN=example.com",
            &["*.example.com".to_string()],
            &mut findings,
        );
        assert!(findings.iter().all(|f| f.check != "hostname mismatch"));
    }

    #[test]
    fn hostname_exact_san_accepted() {
        let mut findings = Vec::new();
        check_hostname_match(
            "api.example.com",
            "CN=example.com",
            &["api.example.com".to_string()],
            &mut findings,
        );
        assert!(findings.iter().all(|f| f.check != "hostname mismatch"));
    }
}
