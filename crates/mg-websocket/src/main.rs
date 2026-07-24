/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-websocket — WebSocket security tester
 *                  Detects WebSocket endpoints, tests CSWSH via foreign Origin,
 *                  checks unauthenticated access, and optionally fuzzes messages.
 * Notes:           Uses tokio-tungstenite for handshake + framing.
 *                  CSWSH is detected when a 101 is returned with Origin:
 *                  https://attacker.com — no cookie or auth header sent.
 *                  Fuzz payloads sent as text frames; responses are recorded.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::time::timeout;
use tokio_tungstenite::connect_async_tls_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "websocket";
const AUDIT_TOOL: &str = "mg-websocket";

// Foreign origin used for CSWSH detection
const ATTACKER_ORIGIN: &str = "https://attacker.com";

// Text frames sent during fuzz mode
const FUZZ_PAYLOADS: &[&str] = &[
    r#"{"type":"ping"}"#,
    "<script>alert(1)</script>",
    "'; DROP TABLE users; --",
    r#"{"__proto__":{"polluted":"true"}}"#,
    "../../../etc/passwd",
];

// Receive timeout per frame during fuzz (seconds)
const FUZZ_RECV_TIMEOUT_SECS: u64 = 3;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-websocket",
    about = "WebSocket security tester — CSWSH, unauth, fuzz"
)]
struct Args {
    /// Engagement name (must have engagement.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Explicit WebSocket endpoint URL (ws:// or wss://)
    #[arg(long)]
    endpoint: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Send fuzz payloads after connecting
    #[arg(long)]
    fuzz: bool,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Crawl corpus URL entry (simplified — we only need the url field)
#[derive(Deserialize)]
struct CrawlEntry {
    url: String,
}

// Finding attached to a WebSocket endpoint result
#[derive(Debug, Serialize)]
struct Finding {
    kind: String,
    severity: String,
    detail: String,
}

// Fuzz response recorded for one payload
#[derive(Debug, Serialize)]
struct FuzzResponse {
    payload: String,
    response: Option<String>,
}

// Result for one WebSocket endpoint
#[derive(Debug, Serialize)]
struct WsResult {
    endpoint: String,
    cswsh_vulnerable: bool,
    cswsh_acao_header: Option<String>,
    unauth_accessible: bool,
    fuzz_responses: Vec<FuzzResponse>,
    findings: Vec<Finding>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct WebsocketResults {
    engagement: String,
    timestamp: String,
    endpoints_tested: usize,
    findings_count: usize,
    results: Vec<WsResult>,
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

// Collect WebSocket endpoint URLs from the crawl corpus directory
fn collect_from_crawl(crawl_dir: &Path) -> Vec<String> {
    let mut endpoints = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return endpoints;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        // Read the corpus index for ws:// / wss:// URLs
        let index_path = entry.path().join("index.json");
        let Ok(raw) = fs::read_to_string(&index_path) else {
            continue;
        };
        let Ok(entries): Result<Vec<CrawlEntry>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for e in entries {
            if e.url.starts_with("ws://") || e.url.starts_with("wss://") {
                endpoints.push(e.url);
            }
        }
        // Also scan HTML files for new WebSocket( patterns
        let html_dir = entry.path().join("html");
        let Ok(html_files) = fs::read_dir(&html_dir) else {
            continue;
        };
        for hf in html_files.flatten() {
            let Ok(content) = fs::read_to_string(hf.path()) else {
                continue;
            };
            // Extract URL string from new WebSocket("wss://...")
            for line in content.lines() {
                if let Some(idx) = line.find("new WebSocket(") {
                    let rest = &line[idx + 14..];
                    // Strip leading quote
                    let rest = rest.trim_start_matches(['"', '\'']);
                    if let Some(end) = rest.find(['"', '\'', ')']) {
                        let url = &rest[..end];
                        if url.starts_with("ws://") || url.starts_with("wss://") {
                            endpoints.push(url.to_string());
                        }
                    }
                }
            }
        }
    }
    endpoints
}

// Test one WebSocket endpoint for CSWSH, unauth access, and optionally fuzz
async fn test_endpoint(endpoint: String, timeout_secs: u64, fuzz: bool) -> WsResult {
    let mut result = WsResult {
        endpoint: endpoint.clone(),
        cswsh_vulnerable: false,
        cswsh_acao_header: None,
        unauth_accessible: false,
        fuzz_responses: Vec::new(),
        findings: Vec::new(),
    };

    let connect_timeout = Duration::from_secs(timeout_secs);

    // ── CSWSH test: connect with foreign Origin, no auth ────────────────────
    let cswsh_result = {
        let mut req = match endpoint.as_str().into_client_request() {
            Ok(r) => r,
            Err(_) => return result,
        };
        req.headers_mut()
            .insert("Origin", ATTACKER_ORIGIN.parse().unwrap());
        timeout(
            connect_timeout,
            connect_async_tls_with_config(req, None, false, None),
        )
        .await
    };

    match cswsh_result {
        Ok(Ok((mut ws_stream, http_resp))) => {
            // 101 returned with foreign origin → CSWSH possible
            result.cswsh_vulnerable = true;
            result.cswsh_acao_header = http_resp
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            result.findings.push(Finding {
                kind: "cswsh".into(),
                severity: "HIGH".into(),
                detail: format!(
                    "WebSocket handshake accepted with Origin: {ATTACKER_ORIGIN}; acao={:?}",
                    result.cswsh_acao_header
                ),
            });

            // ── Fuzz: send payloads over the already-open CSWSH connection ──
            if fuzz {
                for &payload in FUZZ_PAYLOADS {
                    let send_result = ws_stream.send(Message::Text(payload.into())).await;
                    if send_result.is_err() {
                        result.fuzz_responses.push(FuzzResponse {
                            payload: payload.to_string(),
                            response: None,
                        });
                        continue;
                    }
                    let response_text = match timeout(
                        Duration::from_secs(FUZZ_RECV_TIMEOUT_SECS),
                        ws_stream.next(),
                    )
                    .await
                    {
                        Ok(Some(Ok(Message::Text(t)))) => Some(t.to_string()),
                        Ok(Some(Ok(Message::Binary(b)))) => {
                            Some(format!("<binary {} bytes>", b.len()))
                        }
                        _ => None,
                    };
                    result.fuzz_responses.push(FuzzResponse {
                        payload: payload.to_string(),
                        response: response_text,
                    });
                }
            }

            let _ = ws_stream.close(None).await;
        }
        _ => {
            // CSWSH not confirmed
        }
    }

    // ── Unauth check: connect without any credentials ────────────────────────
    // Only test if CSWSH didn't already prove we can connect
    if !result.cswsh_vulnerable {
        let unauth_result = {
            let req = match endpoint.as_str().into_client_request() {
                Ok(r) => r,
                Err(_) => return result,
            };
            timeout(
                connect_timeout,
                connect_async_tls_with_config(req, None, false, None),
            )
            .await
        };

        if let Ok(Ok((mut ws_stream, _))) = unauth_result {
            // Connection succeeded without any auth
            result.unauth_accessible = true;
            result.findings.push(Finding {
                kind: "unauth-websocket".into(),
                severity: "HIGH".into(),
                detail: "WebSocket connection established without authentication".into(),
            });

            // ── Fuzz on unauth connection ────────────────────────────────────
            if fuzz {
                for &payload in FUZZ_PAYLOADS {
                    let send_result = ws_stream.send(Message::Text(payload.into())).await;
                    if send_result.is_err() {
                        result.fuzz_responses.push(FuzzResponse {
                            payload: payload.to_string(),
                            response: None,
                        });
                        continue;
                    }
                    let response_text = match timeout(
                        Duration::from_secs(FUZZ_RECV_TIMEOUT_SECS),
                        ws_stream.next(),
                    )
                    .await
                    {
                        Ok(Some(Ok(Message::Text(t)))) => Some(t.to_string()),
                        Ok(Some(Ok(Message::Binary(b)))) => {
                            Some(format!("<binary {} bytes>", b.len()))
                        }
                        _ => None,
                    };
                    result.fuzz_responses.push(FuzzResponse {
                        payload: payload.to_string(),
                        response: response_text,
                    });
                }
            }

            let _ = ws_stream.close(None).await;
        }
    }

    result
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Collect endpoints: explicit flag takes priority, then crawl corpus
    let mut endpoints: Vec<String> = Vec::new();
    if let Some(ep) = &args.endpoint {
        endpoints.push(ep.clone());
    } else {
        endpoints.extend(collect_from_crawl(&eng.crawl_dir()));
    }

    // Deduplicate
    let mut seen: HashSet<String> = HashSet::new();
    endpoints.retain(|e| seen.insert(e.clone()));

    if endpoints.is_empty() {
        anyhow::bail!("no WebSocket endpoints found — run mg-crawl first or provide --endpoint");
    }

    eprintln!(
        "mg-websocket: {} endpoints, fuzz={}, timeout={}s",
        endpoints.len(),
        args.fuzz,
        args.timeout
    );

    let mut all_results: Vec<WsResult> = Vec::new();
    for endpoint in &endpoints {
        eprintln!("  testing {endpoint}");
        let r = test_endpoint(endpoint.clone(), args.timeout, args.fuzz).await;
        if r.cswsh_vulnerable {
            eprintln!("    [HIGH] CSWSH confirmed");
            let tf = ToolFinding::new(
                AUDIT_TOOL,
                "Cross-site WebSocket hijacking (CSWSH)",
                FindingSeverity::High,
            )
            .url(r.endpoint.clone())
            .evidence("Handshake accepted with attacker-controlled Origin header")
            .recommendation(
                "Validate the Origin header on WebSocket upgrade and reject untrusted origins",
            );
            let _ = write_finding(&eng, &tf);
        }
        if r.unauth_accessible {
            eprintln!("    [HIGH] unauthenticated access confirmed");
            let tf = ToolFinding::new(
                AUDIT_TOOL,
                "Unauthenticated WebSocket endpoint",
                FindingSeverity::High,
            )
            .url(r.endpoint.clone())
            .discriminator("unauth")
            .evidence("WebSocket upgrade succeeded without auth cookies or tokens")
            .recommendation("Require authenticated session on WebSocket upgrade");
            let _ = write_finding(&eng, &tf);
        }
        all_results.push(r);
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);
    let findings_count: usize = all_results.iter().map(|r| r.findings.len()).sum();

    let output = WebsocketResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        endpoints_tested: all_results.len(),
        findings_count,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create websocket output dir")?;

    let out_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &out_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write results JSON")?;

    eprintln!(
        "mg-websocket: {} endpoints tested, {} findings — {}",
        output.endpoints_tested,
        output.findings_count,
        out_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "endpoints={} findings={} fuzz={} ts={ts}",
            output.endpoints_tested, output.findings_count, args.fuzz
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-18T10:30:00Z"),
            "2026-05-18T10_30_00Z"
        );
    }

    #[test]
    fn fuzz_payloads_non_empty() {
        assert!(!FUZZ_PAYLOADS.is_empty());
    }

    #[test]
    fn collect_from_crawl_empty_dir_returns_empty() {
        let dir = std::env::temp_dir().join("mg_ws_test_no_crawl");
        let result = collect_from_crawl(&dir);
        assert!(result.is_empty());
    }
}
