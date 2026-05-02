/*******************************************************************
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     Entry point — orchestrates CT log + DNS brute force enumeration
 *******************************************************************/
mod cli;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::task::JoinSet;
use subdomain_enum::{brute, ct_logs, output};

// Resolve a hostname to IPs; returns empty vec on failure or timeout
async fn resolve_name(name: String, timeout: Duration) -> (String, Vec<IpAddr>) {
    let ips = match tokio::time::timeout(timeout, tokio::net::lookup_host(format!("{name}:0"))).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => vec![],
    };
    (name, ips)
}

#[tokio::main]
async fn main() {
    let args = cli::get_args();
    let date_time = OffsetDateTime::now_local().unwrap();
    eprintln!("Starting subdomain-enum at {date_time}");
    eprintln!("Target: {}", args.domain);

    let timeout = Duration::from_millis(args.timeout_ms);
    let start = Instant::now();

    let mut merged: HashMap<String, output::SubdomainEntry> = HashMap::new();

    // Passive: CT log query
    if matches!(args.mode, cli::Mode::Passive | cli::Mode::All) {
        eprintln!("Querying CT logs (crt.sh)...");
        match ct_logs::query_ct_logs(&args.domain, args.timeout_ms).await {
            Ok(names) => {
                eprintln!("CT logs: {} unique subdomains found", names.len());
                let mut set: JoinSet<(String, Vec<IpAddr>)> = JoinSet::new();

                for name in names {
                    while set.len() >= args.concurrency {
                        if let Some(Ok((n, ips))) = set.join_next().await {
                            merged.insert(n.clone(), output::SubdomainEntry {
                                name: n,
                                ips: ips.iter().map(|ip| ip.to_string()).collect(),
                                source: "ct_log".into(),
                            });
                        }
                    }
                    let t = timeout;
                    set.spawn(async move { resolve_name(name, t).await });
                }

                while let Some(Ok((n, ips))) = set.join_next().await {
                    merged.insert(n.clone(), output::SubdomainEntry {
                        name: n,
                        ips: ips.iter().map(|ip| ip.to_string()).collect(),
                        source: "ct_log".into(),
                    });
                }
            }
            Err(e) => eprintln!("CT log query failed: {e}"),
        }
    }

    // Active: DNS brute force
    if matches!(args.mode, cli::Mode::Active | cli::Mode::All) {
        eprintln!("Running DNS brute force (concurrency={})...", args.concurrency);
        let results = brute::brute_force(
            &args.domain,
            args.wordlist.as_deref(),
            args.concurrency,
            args.timeout_ms,
        )
        .await;
        eprintln!("Brute force: {} subdomains resolved", results.len());

        for r in results {
            if let Some(entry) = merged.get_mut(&r.name) {
                entry.source = "ct_log+brute".into();
                for ip in &r.ips {
                    let s = ip.to_string();
                    if !entry.ips.contains(&s) {
                        entry.ips.push(s);
                    }
                }
            } else {
                merged.insert(r.name.clone(), output::SubdomainEntry {
                    name: r.name,
                    ips: r.ips.iter().map(|ip| ip.to_string()).collect(),
                    source: "brute".into(),
                });
            }
        }
    }

    let elapsed = start.elapsed();
    let subdomains: Vec<output::SubdomainEntry> = merged.into_values().collect();
    let out = output::make_output(&args.domain, subdomains, elapsed);

    match args.format {
        cli::OutputFormat::Table => output::print_table(&out),
        cli::OutputFormat::Json => output::print_json(&out),
    }
}
