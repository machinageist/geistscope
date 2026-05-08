/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Entry point — resolves targets and orchestrates scan
 * Notes:           When --engagement is set, targets are scope-checked before probing
 *                  and all results are written to recon/mg-scan.json regardless of stdout format
 *******************************************************************/
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;
use ipnet::IpNet;
use time::OffsetDateTime;

mod cli;

use mg_scan::{output, scanner, PortState};

// Expand a host string to a list of (display_name, IpAddr) pairs
// Accepts CIDR notation, a bare IP address, or a hostname
async fn resolve_targets(host: &str) -> Vec<(String, IpAddr)> {
    // CIDR range — expand each host address individually
    if let Ok(net) = host.parse::<IpNet>() {
        return net.hosts().map(|ip| (ip.to_string(), ip)).collect();
    }

    // Bare IP — use directly, no lookup needed
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![(ip.to_string(), ip)];
    }

    // Hostname — async DNS lookup so the executor is not blocked
    match tokio::net::lookup_host(format!("{host}:0")).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                vec![(host.to_string(), addr.ip())]
            } else {
                eprintln!("Could not resolve host: {host}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("DNS resolution failed: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let args = cli::get_args();
    let date_time = OffsetDateTime::now_local().unwrap();

    eprintln!("Starting mg-scan at {date_time}");

    if let Some(src_port) = args.source_port {
        eprintln!("Source port: {src_port} (note: ports < 1024 require elevated privileges)");
    }

    let targets = resolve_targets(&args.host).await;

    if targets.is_empty() {
        eprintln!("No targets found for: {}", args.host);
        std::process::exit(1);
    }

    // load engagement and scope if --engagement was provided
    let eng_opt = if let Some(ref name) = args.engagement {
        let eng_root = Path::new(&args.engagements_dir).join(name);
        match engagement::Engagement::load(&eng_root) {
            Ok(eng) => match eng.scope() {
                Ok(scope) => Some((eng, scope)),
                Err(e) => {
                    eprintln!("warning: could not load scope for {name}: {e}");
                    None
                }
            },
            Err(e) => {
                eprintln!("warning: could not load engagement {name}: {e}");
                None
            }
        }
    } else {
        None
    };

    // always collect JSON structs so we can write the engagement file even in table mode
    let mut json_results: Vec<output::ScanResult> = Vec::new();
    // (hostname, open-port count) pairs for the audit log
    let mut audit_notes: Vec<(String, usize)> = Vec::new();

    for (display_name, ip) in &targets {
        // scope-check hostnames before probing; raw IPs pass through (scope uses hostname patterns)
        if let Some((_, ref scope)) = eng_opt {
            let is_ip = display_name.parse::<IpAddr>().is_ok();
            if !is_ip && !scope.is_in_scope(display_name) {
                eprintln!("scope: skipping out-of-scope target {display_name}");
                continue;
            }
        }

        eprintln!(
            "Scanning {} ({}) ports {}-{}",
            display_name, ip, args.port_start, args.port_end
        );
        let start = Instant::now();

        let cfg = scanner::ScanConfig {
            port_start: args.port_start,
            port_end: args.port_end,
            timeout_ms: args.timeout_ms,
            concurrency: args.concurrency,
            randomise: args.randomise,
            delay_ms: args.delay_ms,
            jitter_ms: args.jitter_ms,
            source_port: args.source_port,
        };
        let results = scanner::scan_ports(*ip, &cfg).await;
        let elapsed = start.elapsed();

        // count open ports before consuming results into the formatted struct
        let open_count = results.iter().filter(|r| r.state == PortState::Open).count();
        audit_notes.push((display_name.clone(), open_count));

        // table output is printed immediately per host; JSON is batched for end-of-run emit
        if matches!(args.format, cli::OutputFormat::Table) {
            output::print_table(&results, display_name, *ip, elapsed);
        }
        // always build the JSON struct — needed for both engagement file and Json stdout
        json_results.push(output::make_result(results, display_name, *ip, elapsed));
    }

    // JSON stdout: emit the full array once after all hosts are scanned
    if matches!(args.format, cli::OutputFormat::Json) {
        output::print_json(&json_results);
    }

    // write to engagement recon dir and audit each scanned host
    if let Some((eng, _)) = eng_opt {
        let recon_path = eng.recon_dir().join("mg-scan.json");
        match serde_json::to_string_pretty(&json_results) {
            Ok(json) => match std::fs::write(&recon_path, json) {
                Ok(()) => eprintln!("wrote scan results to {}", recon_path.display()),
                Err(e) => eprintln!("warning: could not write recon file: {e}"),
            },
            Err(e) => eprintln!("warning: JSON serialization failed: {e}"),
        }
        // one audit line per host scanned
        for (host, open) in &audit_notes {
            let detail = format!("open={open}");
            let _ = eng.audit("mg-scan", host, Some(&detail));
        }
    }
}
