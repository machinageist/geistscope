/*******************************************************************
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     Entry point — resolves targets and orchestrates scan
 *******************************************************************/
use std::net::IpAddr;
use std::time::Instant;
use ipnet::IpNet;
use time::OffsetDateTime;

mod cli;

use mg_scan::{output, scanner};

// Resolve a host string to a list of (display_name, IpAddr) pairs
// Accepts CIDR notation, a bare IP address, or a hostname
async fn resolve_targets(host: &str) -> Vec<(String, IpAddr)> {
    // CIDR range — expand to all host addresses in the block
    if let Ok(net) = host.parse::<IpNet>() {
        return net.hosts().map(|ip| (ip.to_string(), ip)).collect();
    }

    // Single IP address — use directly without DNS lookup
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![(ip.to_string(), ip)];
    }

    // Hostname — async DNS lookup via tokio so the executor thread is not blocked
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

    let mut json_results: Vec<output::ScanResult> = Vec::new();

    // Scan each target and collect or print results
    for (display_name, ip) in &targets {
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

        match args.format {
            cli::OutputFormat::Table => output::print_table(&results, display_name, *ip, elapsed),
            cli::OutputFormat::Json => {
                json_results.push(output::make_result(results, display_name, *ip, elapsed));
            }
        }
    }

    // JSON output is collected across all targets and emitted once
    if matches!(args.format, cli::OutputFormat::Json) {
        output::print_json(&json_results);
    }
}
