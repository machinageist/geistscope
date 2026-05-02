// Author: Jeff
// Date: 2026-05-01
// Description: Active DNS brute-force subdomain discovery

use std::net::IpAddr;
use std::time::Duration;
use tokio::task::JoinSet;

const DEFAULT_WORDLIST: &str = include_str!("wordlists/common.txt");

pub struct BruteResult {
    pub name: String,
    pub ips: Vec<IpAddr>,
}

// Brute-force subdomains via concurrent DNS; returns only names that resolve
pub async fn brute_force(
    domain: &str,
    wordlist_path: Option<&str>,
    concurrency: usize,
    timeout_ms: u64,
) -> Vec<BruteResult> {
    let words = load_wordlist(wordlist_path);
    let timeout = Duration::from_millis(timeout_ms);
    let mut set: JoinSet<Option<BruteResult>> = JoinSet::new();
    let mut results: Vec<BruteResult> = Vec::new();

    for word in words {
        let name = format!("{word}.{domain}");

        while set.len() >= concurrency {
            if let Some(Ok(Some(r))) = set.join_next().await {
                results.push(r);
            }
        }

        set.spawn(async move { resolve(name, timeout).await });
    }

    while let Some(Ok(Some(r))) = set.join_next().await {
        results.push(r);
    }

    results
}

// Resolve a hostname; returns None on NXDOMAIN or timeout
async fn resolve(name: String, timeout: Duration) -> Option<BruteResult> {
    match tokio::time::timeout(timeout, tokio::net::lookup_host(format!("{name}:0"))).await {
        Ok(Ok(addrs)) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                None
            } else {
                Some(BruteResult { name, ips })
            }
        }
        _ => None,
    }
}

// Load wordlist from file path or fall back to embedded default
fn load_wordlist(path: Option<&str>) -> Vec<String> {
    let content = match path {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|_| DEFAULT_WORDLIST.to_string()),
        None => DEFAULT_WORDLIST.to_string(),
    };
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::load_wordlist;

    #[test]
    fn strips_comments_and_blank_lines() {
        // load_wordlist with None exercises the embedded wordlist parsing path
        let words = load_wordlist(None);
        // embedded list is non-empty and contains no comment lines
        assert!(!words.is_empty());
        assert!(!words.iter().any(|w| w.starts_with('#')));
    }

    #[test]
    fn custom_wordlist_filters_correctly() {
        let tmp = tempfile_content("# comment\nwww\nmail\n\n  api  \n");
        let words = load_wordlist(Some(&tmp));
        assert_eq!(words, vec!["www", "mail", "api"]);
    }

    // Write content to a temp file and return its path
    fn tempfile_content(content: &str) -> String {
        use std::io::Write;
        let path = std::env::temp_dir().join("subdomain_enum_test_wordlist.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path.to_string_lossy().to_string()
    }
}
