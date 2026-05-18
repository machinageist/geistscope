/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-takeover — subdomain takeover detector. Reads enumerated
 *                  subdomains from the engagement workspace, resolves CNAME chains,
 *                  matches against known-vulnerable service fingerprints.
 * Notes:           Reads recon/subdomain-enum.json first; falls back to
 *                  recon/summary.json if the former is absent.
 *                  HTTP body check is best-effort; CNAME match alone is
 *                  flagged as "potential" if HTTP probe fails.
 *******************************************************************/

mod fingerprints;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_CONCURRENCY: usize = 20;
const OUTPUT_SUBDIR: &str = "takeover";
const OUTPUT_FILE_PREFIX: &str = "results-";
const HTTP_TIMEOUT_SECS: u64 = 10;
const AUDIT_TOOL: &str = "mg-takeover";
const CNAME_FOLLOW_LIMIT: usize = 10;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-takeover",
    about = "Subdomain takeover detector — checks CNAME chains against known-vulnerable services"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Max concurrent DNS+HTTP probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,
}

// ── Input types ───────────────────────────────────────────────────────────────

// Shape of recon/subdomain-enum.json (written by subdomain-enum crate)
#[derive(Deserialize)]
struct SubdomainEnumOutput {
    subdomains: Vec<SubdomainEntry>,
}

#[derive(Deserialize)]
struct SubdomainEntry {
    name: String,
}

// Shape of recon/summary.json (written by mg-recon orchestrator)
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
}

// ── Output types ──────────────────────────────────────────────────────────────

// Confidence level for a takeover finding
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
enum Confidence {
    Confirmed,  // CNAME match + body signature present
    Potential,  // CNAME match but HTTP probe failed or no body sig
}

// One takeover finding entry
#[derive(Debug, Clone, Serialize)]
struct TakeoverResult {
    subdomain: String,
    cname_chain: Vec<String>,
    final_cname: String,
    service: String,
    confidence: Confidence,
    body_snippet: String,
}

// Top-level output written to takeover/results-<ts>.json
#[derive(Serialize)]
struct TakeoverOutput {
    engagement: String,
    generated_at: String,
    subdomains_checked: usize,
    vulnerable_count: usize,
    results: Vec<TakeoverResult>,
}

// ── DNS helpers ───────────────────────────────────────────────────────────────

// Resolve CNAME chain for a hostname; return (chain, final_target)
async fn resolve_cname_chain(
    resolver: &TokioAsyncResolver,
    hostname: &str,
) -> (Vec<String>, String) {
    let mut chain: Vec<String> = Vec::new();
    let mut current = hostname.trim_end_matches('.').to_string();

    for _ in 0..CNAME_FOLLOW_LIMIT {
        match resolver.lookup_ip(current.as_str()).await {
            Ok(_) => break,
            Err(_) => {
                // try explicit CNAME lookup to follow the chain
            }
        }

        match resolver
            .lookup(
                current.as_str(),
                hickory_resolver::proto::rr::RecordType::CNAME,
            )
            .await
        {
            Ok(lookup) => {
                let mut found_cname = false;
                for record in lookup.iter() {
                    if let Some(cname) = record.as_cname() {
                        let target = cname.to_string();
                        let target = target.trim_end_matches('.').to_string();
                        chain.push(current.clone());
                        current = target;
                        found_cname = true;
                        break;
                    }
                }
                if !found_cname {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let final_cname = current;
    (chain, final_cname)
}

// Check whether a CNAME target is NXDOMAIN (no A/AAAA records)
async fn is_nxdomain(resolver: &TokioAsyncResolver, target: &str) -> bool {
    resolver.lookup_ip(target).await.is_err()
}

// ── HTTP body check ───────────────────────────────────────────────────────────

// Fetch the HTTP body for a hostname and return up to 4KB for signature matching
async fn fetch_body(client: &reqwest::Client, hostname: &str) -> String {
    let url = format!("http://{hostname}");
    match client.get(&url).send().await {
        Ok(resp) => resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(4096)
            .collect(),
        Err(_) => String::new(),
    }
}

// ── Per-subdomain probe ───────────────────────────────────────────────────────

// Probe one subdomain: resolve CNAME chain, match fingerprints, check body
async fn probe_subdomain(
    subdomain: String,
    resolver: Arc<TokioAsyncResolver>,
    client: Arc<reqwest::Client>,
) -> Option<TakeoverResult> {
    let (chain, final_cname) = resolve_cname_chain(&resolver, &subdomain).await;

    // only investigate if there is at least one CNAME hop
    if chain.is_empty() {
        return None;
    }

    let fp = fingerprints::match_cname(&final_cname)?;

    // confirm the final target has no A/AAAA (dangling CNAME)
    let dangling = is_nxdomain(&resolver, &final_cname).await;

    // regardless of NXDOMAIN, try the HTTP body check against the original subdomain
    let body = fetch_body(&client, &subdomain).await;
    let body_lower = body.to_lowercase();
    let sig_lower = fp.body_signature.to_lowercase();
    let body_match = body_lower.contains(&sig_lower);

    let confidence = if body_match {
        Confidence::Confirmed
    } else if dangling {
        Confidence::Potential
    } else {
        // CNAME matched the suffix but it's not dangling and body doesn't confirm — skip
        return None;
    };

    let body_snippet = if body_match {
        let start = body_lower.find(&sig_lower).unwrap_or(0);
        let end = (start + 100).min(body.len());
        body[start..end].to_string()
    } else {
        String::new()
    };

    Some(TakeoverResult {
        subdomain,
        cname_chain: chain,
        final_cname,
        service: fp.service.to_string(),
        confidence,
        body_snippet,
    })
}

// ── Input loading ─────────────────────────────────────────────────────────────

// Load subdomain list from recon dir; tries subdomain-enum.json then summary.json
fn load_subdomains(recon_dir: &Path) -> Result<Vec<String>> {
    let enum_path = recon_dir.join("subdomain-enum.json");
    if enum_path.exists() {
        let raw = std::fs::read_to_string(&enum_path).context("read subdomain-enum.json")?;
        let out: SubdomainEnumOutput =
            serde_json::from_str(&raw).context("parse subdomain-enum.json")?;
        return Ok(out.subdomains.into_iter().map(|e| e.name).collect());
    }

    let summary_path = recon_dir.join("summary.json");
    if summary_path.exists() {
        let raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
        let summary: ReconSummary =
            serde_json::from_str(&raw).context("parse summary.json")?;
        return Ok(summary.hosts.into_iter().map(|h| h.hostname).collect());
    }

    anyhow::bail!(
        "neither recon/subdomain-enum.json nor recon/summary.json found — run mg-recon first"
    );
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let subdomains = load_subdomains(&eng.recon_dir())
        .context("load subdomain list")?;

    eprintln!(
        "mg-takeover: {} subdomains to check (concurrency={})",
        subdomains.len(),
        args.concurrency
    );

    // build shared DNS resolver with system defaults
    let resolver = Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
    );

    // build shared HTTP client — short timeout, follow no redirects for body check
    let http_client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("mg-takeover/0.1")
            .build()
            .context("build HTTP client")?,
    );

    let concurrency = args.concurrency.max(1);
    let mut set: JoinSet<Option<TakeoverResult>> = JoinSet::new();
    let mut results: Vec<TakeoverResult> = Vec::new();

    for subdomain in subdomains.iter().cloned() {
        // drain one result before spawning when at concurrency ceiling
        while set.len() >= concurrency {
            if let Some(Ok(Some(finding))) = set.join_next().await {
                print_finding(&finding);
                results.push(finding);
            }
        }
        let res = Arc::clone(&resolver);
        let cli = Arc::clone(&http_client);
        set.spawn(async move { probe_subdomain(subdomain, res, cli).await });
    }

    // drain remaining in-flight tasks
    while let Some(Ok(maybe)) = set.join_next().await {
        if let Some(finding) = maybe {
            print_finding(&finding);
            results.push(finding);
        }
    }

    // write output file
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    std::fs::create_dir_all(&out_dir).context("create takeover dir")?;

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;
    let ts_file = generated_at.replace(':', "-");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = TakeoverOutput {
        engagement: args.engagement.clone(),
        generated_at,
        subdomains_checked: subdomains.len(),
        vulnerable_count: results.len(),
        results,
    };

    let json = serde_json::to_string_pretty(&output).context("serialize output")?;
    std::fs::write(&out_path, &json).context("write output file")?;

    // print summary table
    println!("\n{:-<60}", "");
    println!(
        "mg-takeover: {}/{} potentially takeable",
        output.vulnerable_count, output.subdomains_checked
    );
    println!("  results: {}", out_path.display());

    // Write a finding for each confirmed takeover result
    for r in &output.results {
        if matches!(r.confidence, Confidence::Confirmed) {
            let tf = ToolFinding::new("mg-takeover", "Subdomain Takeover", FindingSeverity::High)
                .url(format!("https://{}", r.subdomain))
                .evidence(format!("service={} cname={} snippet={}", r.service, r.final_cname, r.body_snippet))
                .recommendation("Remove or reclaim the dangling CNAME record; update DNS before the service is claimed");
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "checked={} vulnerable={}",
            output.subdomains_checked, output.vulnerable_count
        )),
    );

    Ok(())
}

// Print one finding to stdout in real time
fn print_finding(r: &TakeoverResult) {
    println!(
        "[{:?}] {} → {} ({})",
        r.confidence, r.subdomain, r.final_cname, r.service
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // Write a file and return its path
    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn load_subdomains_from_enum_json() {
        let tmp = TempDir::new().unwrap();
        let recon = tmp.path().join("recon");
        std::fs::create_dir_all(&recon).unwrap();
        write_file(
            &recon,
            "subdomain-enum.json",
            r#"{"domain":"example.com","subdomains":[{"name":"a.example.com","ips":[],"source":"ct_log"},{"name":"b.example.com","ips":[],"source":"brute"}],"elapsed_ms":100}"#,
        );
        let names = load_subdomains(&recon).unwrap();
        assert_eq!(names, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn load_subdomains_falls_back_to_summary_json() {
        let tmp = TempDir::new().unwrap();
        let recon = tmp.path().join("recon");
        std::fs::create_dir_all(&recon).unwrap();
        write_file(
            &recon,
            "summary.json",
            r#"{"engagement":"test","target":"example.com","generated_at":"","host_count":1,"hosts":[{"hostname":"c.example.com","ips":[],"source":"ct_log","http_accessible":true,"fingerprint":null,"open_ports":[],"services":[]}]}"#,
        );
        let names = load_subdomains(&recon).unwrap();
        assert_eq!(names, vec!["c.example.com"]);
    }

    #[test]
    fn load_subdomains_errors_when_neither_file_exists() {
        let tmp = TempDir::new().unwrap();
        let recon = tmp.path().join("recon");
        std::fs::create_dir_all(&recon).unwrap();
        assert!(load_subdomains(&recon).is_err());
    }
}
