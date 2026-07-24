/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-vhost — virtual host enumeration and host-header injection
 *                  Probes a target IP/domain with candidate Host headers derived
 *                  from a built-in wordlist or caller-supplied file.
 * Notes:           Baseline is established against the bare base-domain header.
 *                  A candidate flags when status or body length diverges enough.
 *                  Host injection test sends attacker.com to catch misconfigured
 *                  reverse proxies that forward arbitrary Host values.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "vhost";
const AUDIT_TOOL: &str = "mg-vhost";

// Body-length difference threshold to flag a candidate as interesting
const BODY_LEN_DIFF_THRESHOLD: usize = 200;

// Host injection test value
const INJECTION_HOST: &str = "attacker.com";

// Built-in prefix wordlist — 50 entries
const BUILTIN_WORDLIST: &[&str] = &[
    "dev",
    "staging",
    "test",
    "api",
    "admin",
    "internal",
    "intranet",
    "vpn",
    "mail",
    "smtp",
    "ftp",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "jira",
    "confluence",
    "wiki",
    "docs",
    "portal",
    "dashboard",
    "monitor",
    "metrics",
    "grafana",
    "kibana",
    "elastic",
    "db",
    "database",
    "mysql",
    "redis",
    "rabbitmq",
    "kafka",
    "mq",
    "proxy",
    "gateway",
    "auth",
    "sso",
    "login",
    "app",
    "beta",
    "preview",
    "sandbox",
    "uat",
    "qa",
    "prod",
    "secure",
    "cdn",
    "static",
    "assets",
    "media",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-vhost",
    about = "Virtual host enumeration and host-header injection detection"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Target IP or domain to send requests to
    #[arg(long)]
    target: String,

    /// Base domain for Host header construction
    #[arg(long)]
    base_domain: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Path to custom prefix wordlist (one prefix per line)
    #[arg(long)]
    wordlist: Option<String>,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 20)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Target port
    #[arg(long, default_value_t = 80)]
    port: u16,

    /// Use HTTPS
    #[arg(long)]
    https: bool,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Baseline response characteristics
struct Baseline {
    status: u16,
    body_len: usize,
}

// Classification of a vhost probe result
#[derive(Debug, Serialize, PartialEq, Eq)]
enum VhostVerdict {
    Interesting,
    Miss,
}

// Result for one candidate Host header
#[derive(Debug, Serialize)]
struct VhostResult {
    host_header: String,
    status: u16,
    body_len: usize,
    verdict: VhostVerdict,
    reason: String,
}

// Host injection test outcome
#[derive(Debug, Serialize)]
struct InjectionResult {
    injected_host: String,
    status: u16,
    reflects_host: bool,
    flagged: bool,
}

// Top-level output written to disk
#[derive(Serialize)]
struct VhostResults {
    engagement: String,
    timestamp: String,
    target: String,
    base_domain: String,
    baseline_status: u16,
    baseline_body_len: usize,
    total_candidates: usize,
    interesting: usize,
    results: Vec<VhostResult>,
    injection: Option<InjectionResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for use in filename
fn ts_for_filename(ts: &str) -> String {
    ts.chars().map(|c| if c == ':' { '_' } else { c }).collect()
}

// Build the request URL from target, port, and scheme
fn build_url(target: &str, port: u16, https: bool) -> String {
    let scheme = if https { "https" } else { "http" };
    if (https && port == 443) || (!https && port == 80) {
        format!("{scheme}://{target}/")
    } else {
        format!("{scheme}://{target}:{port}/")
    }
}

// Load wordlist from file, one prefix per line, ignoring blanks and comments
fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path).with_context(|| format!("read wordlist {path}"))?;
    let words = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();
    Ok(words)
}

// Probe one Host header and return a VhostResult
async fn probe_host(
    client: reqwest::Client,
    url: String,
    host_header: String,
    baseline: Baseline,
) -> VhostResult {
    let resp = client.get(&url).header("Host", &host_header).send().await;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            let body_len = body.len();
            let status_diff = status != baseline.status;
            let len_diff = body_len.abs_diff(baseline.body_len) > BODY_LEN_DIFF_THRESHOLD;
            let (verdict, reason) = if status_diff || len_diff {
                let r = if status_diff && len_diff {
                    format!(
                        "status {} (baseline {}) and body_len {} (baseline {})",
                        status, baseline.status, body_len, baseline.body_len
                    )
                } else if status_diff {
                    format!("status {} (baseline {})", status, baseline.status)
                } else {
                    format!("body_len {} (baseline {})", body_len, baseline.body_len)
                };
                (VhostVerdict::Interesting, r)
            } else {
                (VhostVerdict::Miss, String::new())
            };
            VhostResult {
                host_header,
                status,
                body_len,
                verdict,
                reason,
            }
        }
        Err(_) => VhostResult {
            host_header,
            status: 0,
            body_len: 0,
            verdict: VhostVerdict::Miss,
            reason: String::new(),
        },
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let url = build_url(&args.target, args.port, args.https);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(true)
        // Disable redirect following so we see the raw response per Host
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client")?;

    // Establish baseline with the bare base-domain Host header
    let baseline_resp = client
        .get(&url)
        .header("Host", &args.base_domain)
        .send()
        .await
        .context("baseline request failed")?;
    let baseline_status = baseline_resp.status().as_u16();
    let baseline_body = baseline_resp.text().await.unwrap_or_default();
    let baseline_body_len = baseline_body.len();

    eprintln!("mg-vhost: baseline status={baseline_status} body_len={baseline_body_len}");

    // Load prefix list
    let prefixes: Vec<String> = if let Some(wl_path) = &args.wordlist {
        load_wordlist(wl_path)?
    } else {
        BUILTIN_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    eprintln!(
        "mg-vhost: {} prefixes, concurrency={}",
        prefixes.len(),
        args.concurrency
    );

    let mut join_set: JoinSet<VhostResult> = JoinSet::new();
    let mut all_results: Vec<VhostResult> = Vec::new();

    for prefix in &prefixes {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(r)) = join_set.join_next().await
        {
            all_results.push(r);
        }

        let host_header = format!("{prefix}.{}", args.base_domain);
        let c = client.clone();
        let u = url.clone();
        let bl = Baseline {
            status: baseline_status,
            body_len: baseline_body_len,
        };
        join_set.spawn(probe_host(c, u, host_header, bl));
    }

    // Drain remaining tasks
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    // Host injection test
    let injection = {
        let inj_resp = client.get(&url).header("Host", INJECTION_HOST).send().await;
        match inj_resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let reflects_host = body.contains(INJECTION_HOST);
                let flagged = status == 200 || reflects_host;
                if flagged {
                    eprintln!(
                        "  [INJECT] Host: {INJECTION_HOST} — status={status} reflects={}",
                        reflects_host
                    );
                }
                Some(InjectionResult {
                    injected_host: INJECTION_HOST.into(),
                    status,
                    reflects_host,
                    flagged,
                })
            }
            Err(_) => None,
        }
    };

    // Print interesting hits
    for r in &all_results {
        if r.verdict == VhostVerdict::Interesting {
            eprintln!("  [VHOST] {} — {}", r.host_header, r.reason);
        }
    }

    let interesting_count = all_results
        .iter()
        .filter(|r| r.verdict == VhostVerdict::Interesting)
        .count();

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = VhostResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        target: args.target.clone(),
        base_domain: args.base_domain.clone(),
        baseline_status,
        baseline_body_len,
        total_candidates: all_results.len(),
        interesting: interesting_count,
        results: all_results,
        injection,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create vhost output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write vhost results JSON")?;

    eprintln!(
        "mg-vhost: {} candidates, {} interesting — {}",
        output.total_candidates,
        output.interesting,
        results_path.display()
    );

    // Write finding for each discovered (interesting) virtual host
    for r in output
        .results
        .iter()
        .filter(|r| r.verdict == VhostVerdict::Interesting)
    {
        let tf = ToolFinding::new("mg-vhost", "Virtual Host Discovered", FindingSeverity::Medium)
            .url(format!("http://{}", r.host_header))
            .evidence(format!("host_header={} status={} body_len={} reason={}", r.host_header, r.status, r.body_len, r.reason))
            .recommendation("Review whether this virtual host should be publicly accessible; apply access controls if internal");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "candidates={} interesting={} ts={ts}",
            output.total_candidates, output.interesting
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_omits_default_http_port() {
        assert_eq!(build_url("192.168.1.1", 80, false), "http://192.168.1.1/");
    }

    #[test]
    fn build_url_omits_default_https_port() {
        assert_eq!(build_url("example.com", 443, true), "https://example.com/");
    }

    #[test]
    fn build_url_includes_nonstandard_port() {
        assert_eq!(
            build_url("192.168.1.1", 8080, false),
            "http://192.168.1.1:8080/"
        );
    }

    #[test]
    fn builtin_wordlist_has_fifty_entries() {
        assert_eq!(BUILTIN_WORDLIST.len(), 50);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-17T12:00:00Z"),
            "2026-05-17T12_00_00Z"
        );
    }
}
