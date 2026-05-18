/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-cname-chain — full CNAME chain resolver for engagement
 *                  subdomains. Detects circular references, NXDOMAIN
 *                  intermediates, external CNAMEs, and long chains.
 * Notes:           Reads recon/subdomain-enum.json first; falls back to
 *                  recon/summary.json. Uses JoinSet with bounded concurrency.
 *                  NXDOMAIN at any intermediate hop (not just final) signals
 *                  a potentially hijackable dangling CNAME.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "cname-chain";
const AUDIT_TOOL: &str = "mg-cname-chain";
const DEFAULT_CONCURRENCY: usize = 20;
const DEFAULT_TIMEOUT: u64 = 5;
const DEFAULT_MAX_HOPS: usize = 10;
// Long chain threshold — flag as INFO for DNS performance
const LONG_CHAIN_THRESHOLD: usize = 5;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-cname-chain",
    about = "CNAME chain resolver — follows every hop, detects circular refs and hijackable intermediates"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Max concurrent DNS probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// DNS timeout in seconds per query
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u64,

    /// Max CNAME hops before stopping
    #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
    max_hops: usize,
}

// ── Input types ───────────────────────────────────────────────────────────────

// Shape of recon/subdomain-enum.json
#[derive(Deserialize)]
struct SubdomainEnumOutput {
    subdomains: Vec<SubdomainEntry>,
}

#[derive(Deserialize)]
struct SubdomainEntry {
    name: String,
}

// Shape of recon/summary.json
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
}

// ── Output types ──────────────────────────────────────────────────────────────

// Anomaly category for a CNAME chain
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum AnomalyKind {
    Circular,              // loop detected in chain
    NxdomainIntermediate,  // intermediate hop returned NXDOMAIN
    ExternalCname,         // chain passes through an out-of-scope domain
    LongChain,             // chain exceeds LONG_CHAIN_THRESHOLD hops
}

// Result for one subdomain
#[derive(Debug, Clone, Serialize)]
struct ChainResult {
    subdomain: String,
    chain: Vec<String>,
    final_resolution: String,
    anomalies: Vec<AnomalyKind>,
    external_domains: Vec<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CnameChainResults {
    engagement: String,
    timestamp: String,
    subdomains_checked: usize,
    anomaly_count: usize,
    results: Vec<ChainResult>,
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

// Extract the registrable domain (last two labels) to detect external CNAMEs
fn apex_domain(fqdn: &str) -> String {
    let clean = fqdn.trim_end_matches('.');
    let labels: Vec<&str> = clean.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        clean.to_string()
    }
}

// Load subdomain list; prefers subdomain-enum.json, falls back to summary.json
fn load_subdomains(recon_dir: &Path) -> Result<Vec<String>> {
    let enum_path = recon_dir.join("subdomain-enum.json");
    if enum_path.exists() {
        let raw = fs::read_to_string(&enum_path).context("read subdomain-enum.json")?;
        let out: SubdomainEnumOutput =
            serde_json::from_str(&raw).context("parse subdomain-enum.json")?;
        return Ok(out.subdomains.into_iter().map(|e| e.name).collect());
    }
    let summary_path = recon_dir.join("summary.json");
    if summary_path.exists() {
        let raw = fs::read_to_string(&summary_path).context("read summary.json")?;
        let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;
        return Ok(summary.hosts.into_iter().map(|h| h.hostname).collect());
    }
    anyhow::bail!(
        "neither recon/subdomain-enum.json nor recon/summary.json found — run mg-recon first"
    )
}

// Build a TokioAsyncResolver with the given timeout
fn build_resolver(timeout_secs: u64) -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(timeout_secs);
    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
}

// Follow the CNAME chain for a single subdomain up to max_hops
// Returns (chain, final_resolution_label, anomalies, external_domains)
async fn resolve_chain(
    resolver: &TokioAsyncResolver,
    start: &str,
    max_hops: usize,
    origin_apex: &str,
) -> ChainResult {
    let mut chain: Vec<String> = vec![start.to_string()];
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(start.to_lowercase());

    let mut current = start.to_string();
    let mut anomalies: Vec<AnomalyKind> = Vec::new();
    let mut external_domains: Vec<String> = Vec::new();
    let mut final_resolution = "unresolved".to_string();

    for _ in 0..max_hops {
        match resolver.lookup_ip(current.as_str()).await {
            Ok(ips) => {
                // resolved to an IP — chain ends here
                let first_ip = ips.iter().next().map(|ip| ip.to_string()).unwrap_or_else(|| "no-ip".into());
                final_resolution = first_ip;
                break;
            }
            Err(ref e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
                // could be NXDOMAIN or NOERROR/NXDOMAIN — try CNAME lookup
                match resolver
                    .lookup(current.as_str(), hickory_resolver::proto::rr::RecordType::CNAME)
                    .await
                {
                    Ok(cname_lookup) => {
                        let targets: Vec<String> = cname_lookup
                            .records()
                            .iter()
                            .filter_map(|r| {
                                if let Some(hickory_resolver::proto::rr::RData::CNAME(c)) =
                                    r.data()
                                {
                                    Some(c.0.to_string())
                                } else {
                                    None
                                }
                            })
                            .collect();

                        if targets.is_empty() {
                            // no CNAME and no A — NXDOMAIN intermediate
                            if chain.len() > 1 {
                                anomalies.push(AnomalyKind::NxdomainIntermediate);
                            }
                            final_resolution = "NXDOMAIN".to_string();
                            break;
                        }

                        let next = targets.into_iter().next().unwrap();
                        let next_lower = next.to_lowercase();

                        // circular reference check
                        if seen.contains(&next_lower) {
                            anomalies.push(AnomalyKind::Circular);
                            final_resolution = "circular".to_string();
                            chain.push(next);
                            break;
                        }

                        // external CNAME check
                        let next_apex = apex_domain(&next);
                        if next_apex != origin_apex {
                            external_domains.push(next_apex.clone());
                            anomalies.push(AnomalyKind::ExternalCname);
                        }

                        seen.insert(next_lower);
                        chain.push(next.clone());
                        current = next;
                    }
                    Err(_) => {
                        // intermediate NXDOMAIN — potentially hijackable
                        if chain.len() > 1 {
                            anomalies.push(AnomalyKind::NxdomainIntermediate);
                        }
                        final_resolution = "NXDOMAIN".to_string();
                        break;
                    }
                }
            }
            Err(_) => {
                final_resolution = "error".to_string();
                break;
            }
        }
    }

    // long chain flag — checked after walk completes
    if chain.len() > LONG_CHAIN_THRESHOLD {
        anomalies.push(AnomalyKind::LongChain);
    }

    // deduplicate anomalies (ExternalCname can appear per-hop)
    anomalies.dedup_by(|a, b| {
        std::mem::discriminant(a) == std::mem::discriminant(b)
    });

    ChainResult {
        subdomain: start.to_string(),
        chain,
        final_resolution,
        anomalies,
        external_domains,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let subdomains = load_subdomains(&eng.recon_dir())
        .context("load subdomains from recon dir")?;

    eprintln!(
        "mg-cname-chain: {} subdomains (concurrency={} max_hops={})",
        subdomains.len(),
        args.concurrency,
        args.max_hops,
    );

    let resolver = Arc::new(build_resolver(args.timeout));
    let max_hops = args.max_hops;
    let concurrency = args.concurrency;

    // derive origin apex from engagement target for external-CNAME detection
    let origin_apex = Arc::new(apex_domain(&eng.meta.target));

    let mut set: JoinSet<ChainResult> = JoinSet::new();
    let mut results: Vec<ChainResult> = Vec::new();

    for subdomain in subdomains.iter() {
        // drain when at ceiling
        if set.len() >= concurrency
            && let Some(Ok(r)) = set.join_next().await
        {
            results.push(r);
        }
        let resolver = Arc::clone(&resolver);
        let apex = Arc::clone(&origin_apex);
        let subdomain = subdomain.clone();
        set.spawn(async move {
            resolve_chain(&resolver, &subdomain, max_hops, &apex).await
        });
    }

    // drain remaining
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }

    // sort for deterministic output
    results.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

    let anomaly_count = results.iter().filter(|r| !r.anomalies.is_empty()).count();

    // print flagged entries to stderr
    for r in &results {
        if !r.anomalies.is_empty() {
            eprintln!("  [FLAG] {} chain={:?} anomalies={:?}", r.subdomain, r.chain, r.anomalies);
        }
    }
    eprintln!(
        "mg-cname-chain: {} checked, {} with anomalies",
        results.len(),
        anomaly_count
    );

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = CnameChainResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        subdomains_checked: results.len(),
        anomaly_count,
        results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create cname-chain output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write cname-chain results JSON")?;

    eprintln!("mg-cname-chain: written {}", results_path.display());

    // Emit HIGH finding for each subdomain with an NXDOMAIN intermediate (hijackable CNAME)
    for r in &output.results {
        let has_nxdomain = r.anomalies.iter().any(|a| matches!(a, AnomalyKind::NxdomainIntermediate));
        if has_nxdomain {
            let chain_str = r.chain.join(" -> ");
            let tf = ToolFinding::new("mg-cname-chain", "Hijackable CNAME Chain Detected", FindingSeverity::High)
                .url(format!("dns://{}", r.subdomain))
                .evidence(format!("chain: {chain_str} — intermediate resolves to NXDOMAIN (unclaimed resource)"))
                .recommendation(
                    "Remove the dangling CNAME record or claim the target resource before an attacker does"
                );
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "subdomains={} anomalies={anomaly_count} ts={ts}",
            output.subdomains_checked
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn apex_domain_two_labels() {
        assert_eq!(apex_domain("example.com"), "example.com");
    }

    #[test]
    fn apex_domain_subdomain() {
        assert_eq!(apex_domain("foo.bar.example.com"), "example.com");
    }

    #[test]
    fn apex_domain_strips_trailing_dot() {
        assert_eq!(apex_domain("example.com."), "example.com");
    }

    #[test]
    fn apex_domain_single_label() {
        assert_eq!(apex_domain("localhost"), "localhost");
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T10:30:00Z"), "2026-05-18T10_30_00Z");
    }

    #[test]
    fn load_subdomains_from_enum_json() {
        let dir = tempfile::tempdir().unwrap();
        let recon = dir.path().join("recon");
        fs::create_dir_all(&recon).unwrap();
        let mut f = fs::File::create(recon.join("subdomain-enum.json")).unwrap();
        write!(
            f,
            r#"{{"domain":"example.com","subdomains":[{{"name":"a.example.com","ips":[],"source":"ct_log"}},{{"name":"b.example.com","ips":[],"source":"brute"}}],"elapsed_ms":100}}"#
        )
        .unwrap();
        let names = load_subdomains(&recon).unwrap();
        assert_eq!(names, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn load_subdomains_falls_back_to_summary_json() {
        let dir = tempfile::tempdir().unwrap();
        let recon = dir.path().join("recon");
        fs::create_dir_all(&recon).unwrap();
        let mut f = fs::File::create(recon.join("summary.json")).unwrap();
        write!(
            f,
            r#"{{"hosts":[{{"hostname":"x.example.com","http_accessible":true,"open_ports":[443]}}]}}"#
        )
        .unwrap();
        let names = load_subdomains(&recon).unwrap();
        assert_eq!(names, vec!["x.example.com"]);
    }

    #[test]
    fn load_subdomains_errors_when_neither_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let recon = dir.path().join("recon");
        fs::create_dir_all(&recon).unwrap();
        assert!(load_subdomains(&recon).is_err());
    }
}
