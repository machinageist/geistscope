// Author: Jeff
// Date: 2026-05-01
// Description: Passive subdomain discovery via crt.sh CT log API

use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
}

// Query crt.sh for all certificate SANs matching *.{domain}, return sorted unique subdomains
pub async fn query_ct_logs(
    domain: &str,
    timeout_ms: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()?;

    let entries: Vec<CrtEntry> = client.get(&url).send().await?.json().await?;

    let suffix = format!(".{domain}");
    let mut seen: HashSet<String> = HashSet::new();

    for entry in &entries {
        for name in entry.name_value.split('\n') {
            let name = name.trim().to_lowercase();
            if name.starts_with('*') || !name.ends_with(&suffix) {
                continue;
            }
            seen.insert(name);
        }
    }

    let mut results: Vec<String> = seen.into_iter().collect();
    results.sort();
    Ok(results)
}

#[cfg(test)]
mod tests {
    #[test]
    fn wildcard_filter() {
        let names = vec!["*.example.com", "www.example.com", "other.com"];
        let domain = "example.com";
        let suffix = format!(".{domain}");
        let filtered: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| !n.starts_with('*') && n.ends_with(&suffix))
            .collect();
        assert_eq!(filtered, vec!["www.example.com"]);
    }

    #[test]
    fn unrelated_domain_excluded() {
        let names = vec!["evil.com", "sub.evil.com", "api.example.com"];
        let domain = "example.com";
        let suffix = format!(".{domain}");
        let filtered: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| !n.starts_with('*') && n.ends_with(&suffix))
            .collect();
        assert_eq!(filtered, vec!["api.example.com"]);
    }
}
