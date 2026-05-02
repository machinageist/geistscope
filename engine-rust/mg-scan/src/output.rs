/*************************************************************
 * Filename:        output.rs
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     Table and JSON output formatting
 *************************************************************/
use std::net::IpAddr;
use std::time::Duration;
use serde::Serialize;

use crate::scanner::{PortResult, PortState};

const BANNER_TABLE_MAX: usize = 60;

// JSON representation of a single port result
#[derive(Serialize)]
struct PortEntry {
    port: u16,
    state: &'static str,
    service: &'static str,
    banner: Option<String>,
}

// JSON representation of one host's full scan
#[derive(Serialize)]
pub struct ScanResult {
    host: String,
    ip: String,
    ports: Vec<PortEntry>,
    elapsed_ms: u64,
}

// Convert PortState to its wire string
pub fn state_str(state: &PortState) -> &'static str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
    }
}

// Build ScanResult from raw scan output for JSON serialization
pub fn make_result(ports: Vec<PortResult>, host: &str, ip: IpAddr, elapsed: Duration) -> ScanResult {
    ScanResult {
        host: host.to_string(),
        ip: ip.to_string(),
        ports: ports
            .into_iter()
            .map(|r| PortEntry {
                port: r.port,
                state: state_str(&r.state),
                service: r.service,
                banner: r.banner,
            })
            .collect(),
        elapsed_ms: elapsed.as_millis() as u64,
    }
}

// Print scan results as a formatted table; closed ports hidden to reduce noise
pub fn print_table(ports: &[PortResult], host: &str, ip: IpAddr, elapsed: Duration) {
    println!("\nmg-scan report for {} ({})", host, ip);
    println!("{:<10} {:<10} {:<20} BANNER", "PORT", "STATE", "SERVICE");
    println!("{}", "-".repeat(80));

    for r in ports {
        // Closed ports are noise in interactive output; JSON includes them
        if r.state == PortState::Closed {
            continue;
        }

        let banner_preview = match &r.banner {
            Some(b) => {
                let chars: String = b.chars().take(BANNER_TABLE_MAX).collect();
                if b.chars().count() > BANNER_TABLE_MAX {
                    format!("{chars}…")
                } else {
                    chars
                }
            }
            None => String::new(),
        };

        println!(
            "{:<10} {:<10} {:<20} {}",
            format!("{}/tcp", r.port),
            state_str(&r.state),
            r.service,
            banner_preview
        );
    }

    let open = ports.iter().filter(|r| r.state == PortState::Open).count();
    let filtered = ports.iter().filter(|r| r.state == PortState::Filtered).count();
    let closed = ports.iter().filter(|r| r.state == PortState::Closed).count();

    println!(
        "\n{} open, {} filtered, {} closed (hidden) — scanned in {:?}",
        open, filtered, closed, elapsed
    );
}

// Serialize and print collected scan results as a JSON array
pub fn print_json(results: &[ScanResult]) {
    match serde_json::to_string_pretty(results) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("JSON serialization error: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_strings() {
        assert_eq!(state_str(&PortState::Open), "open");
        assert_eq!(state_str(&PortState::Closed), "closed");
        assert_eq!(state_str(&PortState::Filtered), "filtered");
    }
}
