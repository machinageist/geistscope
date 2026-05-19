/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-oob — out-of-band HTTP callback listener for blind
 *                  SSRF/XXE/CMDi/SQLi detection. Generates unique tokens,
 *                  captures inbound callbacks, writes results to engagement.
 * Notes:           DNS listener is a future enhancement — HTTP only for now.
 *                  Tokens are 32-char lowercase hex (UUID v4, hyphens stripped).
 *******************************************************************/

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_PORT: u16 = 8765;
const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const BODY_TRUNCATE_BYTES: usize = 2048;
const OUTPUT_SUBDIR: &str = "oob";
const OUTPUT_FILE_PREFIX: &str = "callbacks-";
const AUDIT_TOOL: &str = "mg-oob";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-oob",
    about = "Out-of-band HTTP callback listener — blind SSRF/XXE/CMDi detection"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// TCP port to listen on
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Interface address to bind
    #[arg(long, default_value = DEFAULT_HOST)]
    host: String,

    /// Seconds of no new hits before auto-exit (0 = wait for Ctrl-C only)
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// Additional known token to mark as a hit (may repeat)
    #[arg(long = "token")]
    extra_tokens: Vec<String>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One captured inbound callback request
#[derive(Debug, Clone, Serialize)]
struct Callback {
    timestamp: String,
    source_ip: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body_preview: String,
    hit: bool,
}

// Top-level output written to the engagement oob dir
#[derive(Serialize)]
struct OobOutput {
    engagement: String,
    listener_url: String,
    auto_token: String,
    started_at: String,
    ended_at: String,
    total_callbacks: usize,
    hits: usize,
    callbacks: Vec<Callback>,
}

// Shared state handed to each axum handler
#[derive(Clone)]
struct AppState {
    callbacks: Arc<Mutex<Vec<Callback>>>,
    known_tokens: Arc<HashSet<String>>,
    last_hit_tx: tokio::sync::watch::Sender<()>,
}

// ── Axum handler ─────────────────────────────────────────────────────────────

// Capture every inbound request; mark hits when path matches a known token
async fn handle_request(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> impl IntoResponse {
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into());

    let method = req.method().as_str().to_uppercase();
    let path = req.uri().path().to_string();

    // strip leading slash to compare against bare tokens
    let token_candidate = path.trim_start_matches('/');
    let is_hit = state.known_tokens.contains(token_candidate);

    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("<binary>").to_string(),
            )
        })
        .collect();

    // consume body, truncate to limit
    let body_bytes = axum::body::to_bytes(req.into_body(), BODY_TRUNCATE_BYTES * 2)
        .await
        .unwrap_or_default();
    let body_preview = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(BODY_TRUNCATE_BYTES)]).into_owned();

    let cb = Callback {
        timestamp: ts,
        source_ip: peer.ip().to_string(),
        method: method.clone(),
        path: path.clone(),
        headers,
        body_preview,
        hit: is_hit,
    };

    // print to stdout for real-time visibility
    if is_hit {
        println!("[HIT]  {} {} from {}", method, path, peer.ip());
        let _ = state.last_hit_tx.send(());
    } else {
        println!("[RECV] {} {} from {}", method, path, peer.ip());
    }

    state.callbacks.lock().unwrap().push(cb);

    StatusCode::OK
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // generate auto token: UUID v4 with hyphens stripped
    let auto_token = Uuid::new_v4().simple().to_string();

    // build full known-token set: auto-generated + any --token flags
    let mut token_set: HashSet<String> = args.extra_tokens.iter().cloned().collect();
    token_set.insert(auto_token.clone());
    let known_tokens = Arc::new(token_set);

    let bind_addr = format!("{}:{}", args.host, args.port);
    let listener_url = format!("http://{}:{}/{}", args.host, args.port, auto_token);

    println!("mg-oob: engagement={}", args.engagement);
    println!("  listener URL : {listener_url}");
    println!("  auto token   : {auto_token}");
    if !args.extra_tokens.is_empty() {
        println!("  extra tokens : {}", args.extra_tokens.join(", "));
    }
    println!("  timeout      : {}s after last hit (0 = Ctrl-C only)", args.timeout);
    println!("Waiting for callbacks…");

    let callbacks: Arc<Mutex<Vec<Callback>>> = Arc::new(Mutex::new(Vec::new()));
    let (hit_tx, mut hit_rx) = tokio::sync::watch::channel(());

    let state = AppState {
        callbacks: Arc::clone(&callbacks),
        known_tokens,
        last_hit_tx: hit_tx,
    };

    let router = Router::new()
        .route("/{*path}", any(handle_request))
        .route("/", any(handle_request))
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind {bind_addr}"))?;

    let started_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format start timestamp")?;

    // run server; terminate on Ctrl-C or inactivity timeout
    let timeout_secs = args.timeout;
    tokio::select! {
        _ = axum::serve(listener, router) => {},
        _ = tokio::signal::ctrl_c() => {
            println!("\nmg-oob: Ctrl-C received, shutting down");
        },
        _ = async {
            if timeout_secs == 0 {
                // wait forever; only Ctrl-C exits
                std::future::pending::<()>().await;
            } else {
                // reset deadline on every hit; exit when quiet for timeout_secs
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                            println!("\nmg-oob: {}s inactivity timeout, shutting down", timeout_secs);
                            break;
                        }
                        _ = hit_rx.changed() => {
                            // got a hit — reset the inactivity timer by continuing the loop
                        }
                    }
                }
            }
        } => {},
    }

    let ended_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format end timestamp")?;

    let captured: Vec<Callback> = callbacks.lock().unwrap().clone();
    let hit_count = captured.iter().filter(|c| c.hit).count();

    // write output file
    let oob_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&oob_dir).context("create oob dir")?;

    let ts_file = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "ts".into())
        .replace(':', "-");
    let out_path = oob_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = OobOutput {
        engagement: args.engagement.clone(),
        listener_url: listener_url.clone(),
        auto_token: auto_token.clone(),
        started_at,
        ended_at,
        total_callbacks: captured.len(),
        hits: hit_count,
        callbacks: captured,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, json).context("write output file")?;

    println!(
        "mg-oob: {} callbacks ({} hits) written to {}",
        output.total_callbacks,
        output.hits,
        out_path.display()
    );

    // Write a finding for each confirmed OOB hit callback
    for cb in output.callbacks.iter().filter(|c| c.hit) {
        let tf = ToolFinding::new("mg-oob", "OOB Callback Received", FindingSeverity::High)
            .evidence(format!("method={} path={} from={}", cb.method, cb.path, cb.source_ip))
            .recommendation("Investigate the injected parameter that triggered the callback; confirms blind SSRF/XXE/CMDi");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "callbacks={} hits={} token={} port={}",
            output.total_callbacks, output.hits, auto_token, args.port
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_token_is_32_hex_chars() {
        let token = Uuid::new_v4().simple().to_string();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn known_token_set_includes_auto_and_extras() {
        let auto = "abc123".to_string();
        let extras = ["tok1".to_string(), "tok2".to_string()];
        let mut set: HashSet<String> = extras.iter().cloned().collect();
        set.insert(auto.clone());
        assert!(set.contains("abc123"));
        assert!(set.contains("tok1"));
        assert!(set.contains("tok2"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn body_truncate_constant_is_2kb() {
        assert_eq!(BODY_TRUNCATE_BYTES, 2048);
    }
}
