/*******************************************************************
 * Filename:        orchestrator.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Four-stage recon pipeline — subdomains → fingerprint → port scan → summary
 * Notes:           Each stage is resumable: if the output file exists and --force is not set,
 *                  the stage loads the cache instead of re-running.
 *                  Fingerprinting is sequential to avoid overwhelming the target; port scanning
 *                  is sequential per host but async within each host.
 *******************************************************************/

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, Scope};
use fingerprint::Fingerprint;
use mg_scan::{scan_ports, PortState, ScanConfig};
use subdomain_enum::{brute, ct_logs, output::{make_output, ScanOutput, SubdomainEntry}};
use http_client::{Client, ClientConfig};

// Configuration for a single recon run
pub struct RunConfig {
    pub engagement_name: String,
    pub eng_root: PathBuf,
    pub force: bool,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub port_start: u16,
    pub port_end: u16,
}

// Aggregate record for one discovered host in summary.json
#[derive(Serialize, Deserialize)]
pub struct HostRecord {
    pub hostname: String,
    pub ips: Vec<String>,
    pub source: String,
    pub http_accessible: bool,
    pub fingerprint: Option<Fingerprint>,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
}

// Top-level structure written to recon/summary.json
#[derive(Serialize, Deserialize)]
pub struct ReconSummary {
    pub engagement: String,
    pub target: String,
    pub generated_at: String,
    pub host_count: usize,
    pub hosts: Vec<HostRecord>,
}

// Entrypoint: load the engagement, run all four stages, write summary.json
pub async fn run(cfg: RunConfig) -> Result<()> {
    // fail fast if the engagement directory does not exist
    let eng = Engagement::load(&cfg.eng_root)
        .with_context(|| format!("load engagement {} at {}", cfg.engagement_name, cfg.eng_root.display()))?;

    let scope = eng.scope().context("load scope.json")?;

    eprintln!("=== mg-recon: {} → {} ===", cfg.engagement_name, eng.meta.target);

    // stage 1: discover subdomains
    let subdomains = stage_subdomains(&cfg, &eng, &scope).await?;
    if subdomains.is_empty() {
        eprintln!("no subdomains found — stopping");
        return Ok(());
    }

    // stage 2: fingerprint each discovered host over HTTPS
    let fingerprints = stage_fingerprint(&cfg, &eng, &subdomains).await?;

    // stage 3: port scan each host that resolved to at least one IP
    let scan_map = stage_portscan(&cfg, &eng, &subdomains).await?;

    // stage 4: merge all three data sources and write summary.json
    stage_summarise(&cfg, &eng, &subdomains, &fingerprints, &scan_map).await?;

    eprintln!("=== done — see {}/recon/summary.json ===", cfg.eng_root.display());
    Ok(())
}

// Stage 1: CT log query + DNS brute force, scope-filtered, written to recon/subdomain-enum.json
async fn stage_subdomains(cfg: &RunConfig, eng: &Engagement, scope: &Scope) -> Result<Vec<SubdomainEntry>> {
    let path = eng.recon_dir().join("subdomain-enum.json");

    // skip enumeration if cached output exists and --force was not passed
    if path.exists() && !cfg.force {
        eprintln!("[1/4] subdomain-enum — loading cache");
        let raw = std::fs::read_to_string(&path).context("read cached subdomain-enum.json")?;
        let out: ScanOutput = serde_json::from_str(&raw).context("parse subdomain-enum.json")?;
        eprintln!("[1/4] {} cached subdomains", out.subdomains.len());
        return Ok(out.subdomains);
    }

    eprintln!("[1/4] subdomain-enum — {} (CT logs + brute force)", eng.meta.target);
    let start = Instant::now();
    // accumulate unique entries from both sources, deduplicating by hostname
    let mut merged: HashMap<String, SubdomainEntry> = HashMap::new();

    // query CT logs for historically issued certificates (passive, no active probing)
    match ct_logs::query_ct_logs(&eng.meta.target, cfg.timeout_ms).await {
        Ok(names) => {
            eprintln!("  ct_logs: {} names returned", names.len());
            // resolve IPs concurrently, bounded by the configured concurrency limit
            let mut set: JoinSet<(String, Vec<IpAddr>)> = JoinSet::new();
            for name in names {
                // drain one result when at ceiling to avoid unbounded task growth
                while set.len() >= cfg.concurrency {
                    // drain one result when at ceiling to avoid unbounded task growth
                    if let Some(Ok((n, ips))) = set.join_next().await
                        && scope.is_in_scope(&n)
                    {
                        merged.insert(n.clone(), SubdomainEntry {
                            name: n,
                            ips: ips.iter().map(|i| i.to_string()).collect(),
                            source: "ct_log".into(),
                        });
                    }
                }
                let t = cfg.timeout_ms;
                set.spawn(async move {
                    // resolve with a deadline so stale DNS doesn't stall the pipeline
                    let ips = match tokio::time::timeout(
                        Duration::from_millis(t),
                        tokio::net::lookup_host(format!("{name}:0")),
                    ).await {
                        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
                        _ => vec![],
                    };
                    (name, ips)
                });
            }
            // drain any remaining in-flight resolutions
            while let Some(Ok((n, ips))) = set.join_next().await {
                if scope.is_in_scope(&n) {
                    merged.insert(n.clone(), SubdomainEntry {
                        name: n,
                        ips: ips.iter().map(|i| i.to_string()).collect(),
                        source: "ct_log".into(),
                    });
                }
            }
        }
        Err(e) => eprintln!("  ct_logs: failed — {e}"),
    }

    // brute-force DNS by trying wordlist prefixes; resolves IPs internally
    let brute_results = brute::brute_force(&eng.meta.target, None, cfg.concurrency, cfg.timeout_ms).await;
    eprintln!("  brute force: {} resolved", brute_results.len());
    for r in brute_results {
        if !scope.is_in_scope(&r.name) { continue; }
        if let Some(entry) = merged.get_mut(&r.name) {
            // host was already seen in CT logs — upgrade source tag and union IPs
            entry.source = "ct_log+brute".into();
            for ip in &r.ips {
                let s = ip.to_string();
                if !entry.ips.contains(&s) { entry.ips.push(s); }
            }
        } else {
            merged.insert(r.name.clone(), SubdomainEntry {
                name: r.name,
                ips: r.ips.iter().map(|i| i.to_string()).collect(),
                source: "brute".into(),
            });
        }
    }

    let elapsed = start.elapsed();
    let subdomains: Vec<SubdomainEntry> = merged.into_values().collect();
    // make_output sorts alphabetically and attaches elapsed time
    let out = make_output(&eng.meta.target, subdomains, elapsed);

    let json = serde_json::to_string_pretty(&out).context("serialize subdomain output")?;
    std::fs::write(&path, json).context("write subdomain-enum.json")?;
    let _ = eng.audit("subdomain-enum", &eng.meta.target, Some(&format!("count={}", out.subdomains.len())));

    eprintln!("[1/4] done — {} in-scope subdomains in {:.1}s", out.subdomains.len(), elapsed.as_secs_f32());
    Ok(out.subdomains)
}

// Stage 2: HTTPS fingerprint each host; results merged into recon/fingerprint.json
async fn stage_fingerprint(
    cfg: &RunConfig,
    eng: &Engagement,
    subdomains: &[SubdomainEntry],
) -> Result<HashMap<String, Fingerprint>> {
    let path = eng.recon_dir().join("fingerprint.json");

    // skip if cached output exists
    if path.exists() && !cfg.force {
        eprintln!("[2/4] fingerprint — loading cache");
        let raw = std::fs::read_to_string(&path).context("read cached fingerprint.json")?;
        let map: HashMap<String, Fingerprint> = serde_json::from_str(&raw).context("parse fingerprint.json")?;
        eprintln!("[2/4] {} cached fingerprints", map.len());
        return Ok(map);
    }

    eprintln!("[2/4] fingerprint — probing {} hosts", subdomains.len());

    // shared HTTP client with UA rotation; one instance reused across all probes
    let client = Client::new(ClientConfig {
        timeout_ms: cfg.timeout_ms,
        rate_limit_ms: None,
        max_retries: 1,
        rotate_ua: true,
        max_redirects: 5,
    }).context("build HTTP client")?;

    let mut map: HashMap<String, Fingerprint> = HashMap::new();

    // probe each host sequentially to avoid hammering the target
    for entry in subdomains {
        let url = format!("https://{}", entry.name);
        match fingerprint::fingerprint_url(&client, &url).await {
            Ok(fp) => {
                eprintln!("  {} — ok", entry.name);
                map.insert(entry.name.clone(), fp);
            }
            // connection refused and TLS errors are expected for non-HTTP hosts
            Err(e) => eprintln!("  {} — {e}", entry.name),
        }
    }

    let json = serde_json::to_string_pretty(&map).context("serialize fingerprints")?;
    std::fs::write(&path, json).context("write fingerprint.json")?;
    let _ = eng.audit(
        "mg-fingerprint",
        &eng.meta.target,
        Some(&format!("accessible={}/{}", map.len(), subdomains.len())),
    );

    eprintln!("[2/4] done — {}/{} hosts HTTP-accessible", map.len(), subdomains.len());
    Ok(map)
}

// Per-host port scan result stored in the orchestrator's own format
#[derive(Serialize, Deserialize)]
struct HostScan {
    hostname: String,
    ip: String,
    open_ports: Vec<u16>,
    services: Vec<String>,
}

// Stage 3: port scan each host that has a resolvable IP; writes recon/mg-scan.json
async fn stage_portscan(
    cfg: &RunConfig,
    eng: &Engagement,
    subdomains: &[SubdomainEntry],
) -> Result<HashMap<String, HostScan>> {
    let path = eng.recon_dir().join("mg-scan.json");

    // skip if cached
    if path.exists() && !cfg.force {
        eprintln!("[3/4] port scan — loading cache");
        let raw = std::fs::read_to_string(&path).context("read cached mg-scan.json")?;
        let scans: Vec<HostScan> = serde_json::from_str(&raw).context("parse mg-scan.json")?;
        let count = scans.len();
        let map: HashMap<String, HostScan> = scans.into_iter().map(|s| (s.hostname.clone(), s)).collect();
        eprintln!("[3/4] {} cached scan results", count);
        return Ok(map);
    }

    eprintln!("[3/4] port scan — ports {}-{} on {} hosts", cfg.port_start, cfg.port_end, subdomains.len());

    let scan_cfg = ScanConfig {
        port_start: cfg.port_start,
        port_end: cfg.port_end,
        timeout_ms: 1500,
        concurrency: 500,
        randomise: false,
        delay_ms: 0,
        jitter_ms: 0,
        source_port: None,
    };

    let mut results: Vec<HostScan> = Vec::new();
    let mut map: HashMap<String, HostScan> = HashMap::new();

    for entry in subdomains {
        // skip hosts that did not resolve to any IP during enumeration
        let ip_str = match entry.ips.first() {
            Some(ip) => ip.clone(),
            None => {
                eprintln!("  {} — no IP, skipping", entry.name);
                continue;
            }
        };

        // parse the stored IP string; skip on malformed entry
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("  {} — unparseable IP {ip_str}, skipping", entry.name);
                continue;
            }
        };

        eprintln!("  scanning {} ({})", entry.name, ip);
        let port_results = scan_ports(ip, &scan_cfg).await;

        // collect only open ports for the summary
        let open_ports: Vec<u16> = port_results.iter()
            .filter(|r| r.state == PortState::Open)
            .map(|r| r.port)
            .collect();
        let services: Vec<String> = port_results.iter()
            .filter(|r| r.state == PortState::Open)
            .map(|r| r.service.to_string())
            .collect();

        eprintln!("  {} — {} open ports", entry.name, open_ports.len());

        let hs = HostScan {
            hostname: entry.name.clone(),
            ip: ip_str,
            open_ports,
            services,
        };
        results.push(hs);
    }

    let json = serde_json::to_string_pretty(&results).context("serialize scan results")?;
    std::fs::write(&path, json).context("write mg-scan.json")?;
    let _ = eng.audit("mg-scan", &eng.meta.target, Some(&format!("hosts={}", results.len())));

    // move results into map after writing
    for hs in results {
        map.insert(hs.hostname.clone(), hs);
    }

    eprintln!("[3/4] done — {} hosts scanned", map.len());
    Ok(map)
}

// Stage 4: merge subdomains, fingerprints, and port scans into one summary file
async fn stage_summarise(
    cfg: &RunConfig,
    eng: &Engagement,
    subdomains: &[SubdomainEntry],
    fingerprints: &HashMap<String, Fingerprint>,
    scan_map: &HashMap<String, HostScan>,
) -> Result<()> {
    eprintln!("[4/4] building summary.json");

    let generated_at = OffsetDateTime::now_utc().format(&Rfc3339)
        .context("format timestamp")?;

    // one HostRecord per subdomain, joined with fingerprint and scan data
    let hosts: Vec<HostRecord> = subdomains.iter().map(|sub| {
        let fp = fingerprints.get(&sub.name).cloned();
        let http_accessible = fp.is_some();
        let (open_ports, services) = if let Some(hs) = scan_map.get(&sub.name) {
            (hs.open_ports.clone(), hs.services.clone())
        } else {
            (vec![], vec![])
        };

        HostRecord {
            hostname: sub.name.clone(),
            ips: sub.ips.clone(),
            source: sub.source.clone(),
            http_accessible,
            fingerprint: fp,
            open_ports,
            services,
        }
    }).collect();

    let summary = ReconSummary {
        engagement: cfg.engagement_name.clone(),
        target: eng.meta.target.clone(),
        generated_at,
        host_count: hosts.len(),
        hosts,
    };

    let path = eng.recon_dir().join("summary.json");
    let json = serde_json::to_string_pretty(&summary).context("serialize summary")?;
    std::fs::write(&path, json).context("write summary.json")?;

    eprintln!("[4/4] summary.json written — {} hosts", summary.host_count);
    Ok(())
}
