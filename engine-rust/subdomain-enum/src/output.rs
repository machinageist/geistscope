// Author: Jeff
// Date: 2026-05-01
// Description: Output formatting for subdomain-enum (table and JSON)

use serde::Serialize;
use std::time::Duration;

#[derive(Serialize, Clone)]
pub struct SubdomainEntry {
    pub name: String,
    pub ips: Vec<String>,
    pub source: String,
}

#[derive(Serialize)]
pub struct ScanOutput {
    pub domain: String,
    pub subdomains: Vec<SubdomainEntry>,
    pub elapsed_ms: u128,
}

// Build output struct; sorts subdomains alphabetically
pub fn make_output(domain: &str, mut subdomains: Vec<SubdomainEntry>, elapsed: Duration) -> ScanOutput {
    subdomains.sort_by(|a, b| a.name.cmp(&b.name));
    ScanOutput {
        domain: domain.to_string(),
        subdomains,
        elapsed_ms: elapsed.as_millis(),
    }
}

pub fn print_table(out: &ScanOutput) {
    println!("\nSubdomains for {}:", out.domain);
    println!("{:<50} {:<40} {}", "SUBDOMAIN", "IPs", "SOURCE");
    println!("{}", "-".repeat(100));
    for s in &out.subdomains {
        println!("{:<50} {:<40} {}", s.name, s.ips.join(", "), s.source);
    }
    println!(
        "\n{} subdomain(s) found in {:.2}s",
        out.subdomains.len(),
        out.elapsed_ms as f64 / 1000.0
    );
}

pub fn print_json(out: &ScanOutput) {
    println!("{}", serde_json::to_string_pretty(out).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_output_sorts_alphabetically() {
        let subs = vec![
            SubdomainEntry { name: "z.example.com".into(), ips: vec![], source: "brute".into() },
            SubdomainEntry { name: "a.example.com".into(), ips: vec![], source: "ct_log".into() },
            SubdomainEntry { name: "m.example.com".into(), ips: vec![], source: "brute".into() },
        ];
        let out = make_output("example.com", subs, Duration::from_secs(1));
        assert_eq!(out.subdomains[0].name, "a.example.com");
        assert_eq!(out.subdomains[1].name, "m.example.com");
        assert_eq!(out.subdomains[2].name, "z.example.com");
        assert_eq!(out.elapsed_ms, 1000);
    }

    #[test]
    fn make_output_empty_is_fine() {
        let out = make_output("example.com", vec![], Duration::from_millis(42));
        assert!(out.subdomains.is_empty());
        assert_eq!(out.domain, "example.com");
    }
}
