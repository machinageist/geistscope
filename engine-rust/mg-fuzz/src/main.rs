/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     mg-fuzz — Burp Intruder-style HTTP fuzzer with four attack modes:
 *                  sniper, battering-ram, pitchfork, cluster-bomb
 *                  Reads a raw HTTP request template with §position§ markers,
 *                  substitutes payloads, sends each request, diffs the response,
 *                  and writes a full JSON report.
 * Notes:           The Host header in the template sets the target unless
 *                  --host overrides it. HTTPS is used by default; use --no-tls
 *                  to force HTTP or --insecure for test targets with bad certs.
 *                  Rate is configurable; defaults to 500ms/req.
 *******************************************************************/

mod attack;
mod diff;
mod payload;
mod report;
mod template;

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

use crate::diff::ResponseRecord;
use crate::report::{FuzzReport, FuzzResult};

const MAX_CAPTURED_BODY_BYTES: usize = 256 * 1024;

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(ValueEnum, Clone, Debug)]
enum AttackMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

#[derive(Parser, Debug)]
#[command(
    name = "mg-fuzz",
    about = "HTTP fuzzer — Burp Intruder-style payload injection"
)]
struct Args {
    /// Engagement name (engagement.json must exist)
    engagement: String,

    /// Path to the raw HTTP request template file (§position§ markers)
    #[arg(long)]
    template: String,

    /// Payload spec(s): builtin name, numbers:N-M, or /path/to/file.txt
    /// Provide once per position (pitchfork/cluster-bomb); single list for sniper/battering-ram
    #[arg(long = "payloads", required = true, num_args = 1..)]
    payload_specs: Vec<String>,

    /// Attack mode
    #[arg(long, default_value = "sniper")]
    mode: AttackMode,

    /// Override the target host (default: Host header from template)
    #[arg(long)]
    host: Option<String>,

    /// Override the target port (default: 443 for HTTPS, 80 for HTTP)
    #[arg(long)]
    port: Option<u16>,

    /// Use HTTP instead of HTTPS
    #[arg(long)]
    no_tls: bool,

    /// Accept invalid TLS certificates
    #[arg(long)]
    insecure: bool,

    /// Milliseconds between requests
    #[arg(long, default_value_t = 500)]
    rate_ms: u64,

    /// HTTP timeout in milliseconds
    #[arg(long, default_value_t = 15_000)]
    timeout_ms: u64,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Only print interesting responses during the run (status change, body delta > 50B, timing)
    #[arg(long)]
    interesting_only: bool,
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // read and parse the request template
    let tmpl_raw = std::fs::read_to_string(&args.template)
        .with_context(|| format!("read template {}", args.template))?;
    let tmpl = template::RequestTemplate::parse(&tmpl_raw).context("parse template")?;

    eprintln!(
        "mg-fuzz: {} positions: {:?}",
        tmpl.positions.len(),
        tmpl.positions
    );

    if tmpl.positions.is_empty() {
        anyhow::bail!("template has no §markers§ — nothing to fuzz");
    }

    // load all payload lists
    let payload_lists: Vec<Vec<String>> = args
        .payload_specs
        .iter()
        .map(|spec| payload::load(spec).with_context(|| format!("load payload '{spec}'")))
        .collect::<Result<_>>()?;

    // generate the attack request sequence based on mode
    let attack_reqs = match args.mode {
        AttackMode::Sniper => attack::sniper(&tmpl.positions, &payload_lists),
        AttackMode::BatteringRam => attack::battering_ram(&tmpl.positions, &payload_lists),
        AttackMode::Pitchfork => attack::pitchfork(&tmpl.positions, &payload_lists),
        AttackMode::ClusterBomb => attack::cluster_bomb(&tmpl.positions, &payload_lists),
    };

    eprintln!("  {} requests queued", attack_reqs.len());

    // determine target host from CLI override or Host header in template
    let host = if let Some(h) = &args.host {
        h.clone()
    } else {
        tmpl.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| eng.meta.target.clone())
    };

    let scheme = if args.no_tls { "http" } else { "https" };
    let port = args.port.map(|p| format!(":{p}")).unwrap_or_default();
    let base_url = format!("{scheme}://{host}{port}");

    // build reqwest client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(args.timeout_ms))
        .user_agent("mg-fuzz/0.1 (security research)")
        .danger_accept_invalid_certs(args.insecure)
        .build()
        .context("build HTTP client")?;

    let rate = Duration::from_millis(args.rate_ms);
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    // take a baseline response using the first request from the list (all-empty payloads)
    let empty_payloads: Vec<&str> = tmpl.positions.iter().map(|_| "").collect();
    let baseline_req = tmpl.inject(&empty_payloads);
    eprintln!("  taking baseline...");
    let baseline = send_request(&client, &base_url, &baseline_req)
        .await
        .context("baseline request failed")?;
    eprintln!(
        "  baseline: {} {} bytes",
        baseline.status, baseline.body_len
    );

    report::print_header();

    // main fuzzing loop: send each attack request, diff against baseline
    let mut results: Vec<FuzzResult> = Vec::new();
    for attack_req in &attack_reqs {
        let payload_refs: Vec<&str> = attack_req.payloads.iter().map(String::as_str).collect();
        let injected = tmpl.inject(&payload_refs);
        tokio::time::sleep(rate).await;

        let response = match send_request(&client, &base_url, &injected).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [err] {}: {e}", attack_req.label);
                continue;
            }
        };

        let diff_result = diff::diff(&baseline, &response);
        let result = FuzzResult {
            label: attack_req.label.clone(),
            payloads: attack_req.payloads.clone(),
            response,
            diff: diff_result,
        };

        // print live feedback, filtered if --interesting-only
        if !args.interesting_only || result.diff.interesting {
            report::print_result(&result);
        }
        results.push(result);
    }

    let interesting_count = results.iter().filter(|r| r.diff.interesting).count();
    eprintln!(
        "  {} interesting / {} total",
        interesting_count,
        results.len()
    );

    // write the full report to the engagement recon directory
    let mode_str = format!("{:?}", args.mode).to_lowercase();
    let fuzz_report = FuzzReport {
        engagement: args.engagement.clone(),
        template: args.template.clone(),
        attack_mode: mode_str,
        generated_at: ts,
        total_requests: results.len(),
        interesting_count,
        results,
    };
    report::write_report(&fuzz_report, &eng.recon_dir()).context("write report")?;

    // record the run in the audit log
    let _ = eng.audit(
        "mg-fuzz",
        &host,
        Some(&format!(
            "requests={} interesting={}",
            fuzz_report.total_requests, interesting_count
        )),
    );

    Ok(())
}

// ── HTTP dispatch ─────────────────────────────────────────────────────────────

// Send an InjectedRequest to the target and return a ResponseRecord
async fn send_request(
    client: &reqwest::Client,
    base_url: &str,
    req: &template::InjectedRequest,
) -> Result<ResponseRecord> {
    let url = format!("{base_url}{}", req.path);
    let t0 = Instant::now();

    // build the request with the correct method
    let mut builder = match req.method.as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        m => client.request(
            reqwest::Method::from_bytes(m.as_bytes()).unwrap_or(reqwest::Method::GET),
            &url,
        ),
    };

    // apply headers from the injected request (skip Host — reqwest sets it from URL)
    for (k, v) in &req.headers {
        if !k.eq_ignore_ascii_case("host") {
            builder = builder.header(k.as_str(), v.as_str());
        }
    }

    // attach body if present
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    let resp = builder.send().await.context("send request")?;
    let elapsed_ms = t0.elapsed().as_millis() as u64;

    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let body = read_limited_text(resp, MAX_CAPTURED_BODY_BYTES).await?;

    Ok(ResponseRecord::new(
        status,
        body,
        elapsed_ms,
        content_type,
        location,
    ))
}

// Read at most `limit` bytes so a single large response cannot exhaust memory or bloat reports
async fn read_limited_text(mut resp: reqwest::Response, limit: usize) -> Result<String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("read response chunk")? {
        let remaining = limit.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}
