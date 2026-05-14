/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Entry point — orchestrates CT log + DNS brute force enumeration
 * Notes:           When --engagement is set, results are scope-filtered and written to
 *                  recon/subdomain-enum.json before stdout output
 *******************************************************************/
mod cli;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use subdomain_enum::{brute, ct_logs, output};
use time::OffsetDateTime;
use tokio::task::JoinSet;

// Resolve a hostname to IPs concurrently; returns empty vec on failure or timeout
async fn resolve_name(name: String, timeout: Duration) -> (String, Vec<IpAddr>) {
    let ips =
        match tokio::time::timeout(timeout, tokio::net::lookup_host(format!("{name}:0"))).await {
            Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
            _ => vec![],
        };
    (name, ips)
}

#[tokio::main]
async fn main() {
    let args = cli::get_args();
    let date_time = OffsetDateTime::now_utc();
    let concurrency = args.concurrency.max(1);
    eprintln!("Starting subdomain-enum at {date_time}");
    eprintln!("Target: {}", args.domain);

    let timeout = Duration::from_millis(args.timeout_ms);
    let start = Instant::now();

    // accumulate unique names from both sources, deduplicating by hostname
    let mut merged: HashMap<String, output::SubdomainEntry> = HashMap::new();

    // Passive: query CT logs for historically observed subdomains, then resolve IPs
    if matches!(args.mode, cli::Mode::Passive | cli::Mode::All) {
        eprintln!("Querying CT logs (crt.sh)...");
        match ct_logs::query_ct_logs(&args.domain, args.timeout_ms).await {
            Ok(names) => {
                eprintln!("CT logs: {} unique subdomains found", names.len());
                // bounded JoinSet drains at concurrency limit so we don't spawn thousands of tasks at once
                let mut set: JoinSet<(String, Vec<IpAddr>)> = JoinSet::new();

                for name in names {
                    // drain one result before spawning when at the concurrency ceiling
                    while set.len() >= concurrency {
                        if let Some(Ok((n, ips))) = set.join_next().await {
                            merged.insert(
                                n.clone(),
                                output::SubdomainEntry {
                                    name: n,
                                    ips: ips.iter().map(|ip| ip.to_string()).collect(),
                                    source: "ct_log".into(),
                                },
                            );
                        }
                    }
                    let t = timeout;
                    set.spawn(async move { resolve_name(name, t).await });
                }

                // drain remaining in-flight resolution tasks
                while let Some(Ok((n, ips))) = set.join_next().await {
                    merged.insert(
                        n.clone(),
                        output::SubdomainEntry {
                            name: n,
                            ips: ips.iter().map(|ip| ip.to_string()).collect(),
                            source: "ct_log".into(),
                        },
                    );
                }
            }
            Err(e) => eprintln!("CT log query failed: {e}"),
        }
    }

    // Active: brute-force DNS by trying wordlist prefixes under the target domain
    if matches!(args.mode, cli::Mode::Active | cli::Mode::All) {
        eprintln!("Running DNS brute force (concurrency={concurrency})...");
        let results = brute::brute_force(
            &args.domain,
            args.wordlist.as_deref(),
            concurrency,
            args.timeout_ms,
        )
        .await;
        eprintln!("Brute force: {} subdomains resolved", results.len());

        // merge brute-force hits, tagging entries found by both sources
        for r in results {
            if let Some(entry) = merged.get_mut(&r.name) {
                // mark dual-source discovery and union the IP lists
                entry.source = "ct_log+brute".into();
                for ip in &r.ips {
                    let s = ip.to_string();
                    if !entry.ips.contains(&s) {
                        entry.ips.push(s);
                    }
                }
            } else {
                merged.insert(
                    r.name.clone(),
                    output::SubdomainEntry {
                        name: r.name,
                        ips: r.ips.iter().map(|ip| ip.to_string()).collect(),
                        source: "brute".into(),
                    },
                );
            }
        }
    }

    let elapsed = start.elapsed();
    // flatten map to vec; scope-filter is applied below if engagement is set
    let mut subdomains: Vec<output::SubdomainEntry> = merged.into_values().collect();

    // Engagement mode: drop out-of-scope hosts before output
    let eng_opt = if let Some(ref name) = args.engagement {
        match engagement::Engagement::load_named(std::path::Path::new(&args.engagements_dir), name)
        {
            Ok(eng) => {
                match eng.scope() {
                    Ok(scope) => {
                        let before = subdomains.len();
                        // retain only hosts explicitly allowed by scope.json
                        subdomains.retain(|s| scope.is_in_scope(&s.name));
                        let dropped = before - subdomains.len();
                        if dropped > 0 {
                            eprintln!("scope: dropped {dropped} out-of-scope entries");
                        }
                        Some(eng)
                    }
                    Err(e) => {
                        eprintln!("warning: could not load scope for {name}: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("warning: could not load engagement {name}: {e}");
                None
            }
        }
    } else {
        None
    };

    // sort alphabetically and attach elapsed time
    let out = output::make_output(&args.domain, subdomains, elapsed);

    // print to stdout in the requested format
    match args.format {
        cli::OutputFormat::Table => output::print_table(&out),
        cli::OutputFormat::Json => output::print_json(&out),
    }

    // write JSON to engagement recon dir and append audit log entry
    if let Some(eng) = eng_opt {
        let recon_path = eng.recon_dir().join("subdomain-enum.json");
        match serde_json::to_string_pretty(&out) {
            Ok(json) => match std::fs::write(&recon_path, json) {
                Ok(()) => eprintln!(
                    "wrote {} subdomains to {}",
                    out.subdomains.len(),
                    recon_path.display()
                ),
                Err(e) => eprintln!("warning: could not write recon file: {e}"),
            },
            Err(e) => eprintln!("warning: JSON serialization failed: {e}"),
        }
        // record tool invocation in the append-only audit log
        let detail = format!("count={} mode={:?}", out.subdomains.len(), args.mode);
        let _ = eng.audit("subdomain-enum", &args.domain, Some(&detail));
    }
}
