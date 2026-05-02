// Author: Jeff
// Date: 2026-05-01
// Description: Mine crt.sh CT logs for subdomains across a domain list

use http_client::{Client, ClientConfig};
use serde::Deserialize;
use std::collections::HashSet;

use crate::store::Corpus;

#[derive(Deserialize)]
struct CrtEntry {
    name_value: String,
}

// Mine crt.sh for all certificate SANs for each domain; store results in corpus
pub async fn mine_ct_logs(domains: &[String], corpus: &mut Corpus, rate_limit_ms: u64) {
    let client = Client::new(ClientConfig {
        timeout_ms: 30_000,
        rate_limit_ms: Some(rate_limit_ms),
        max_retries: 2,
        rotate_ua: false,
    })
    .expect("failed to build HTTP client");

    for domain in domains {
        match fetch_ct(domain, &client).await {
            Ok(subs) => {
                eprintln!("[ct] {domain}: {} subdomains", subs.len());
                if let Err(e) = corpus.insert_subdomains_batch(domain, &subs, "ct_log") {
                    eprintln!("[ct] store error: {e}");
                }
            }
            Err(e) => eprintln!("[ct] {domain}: {e}"),
        }
    }
}

async fn fetch_ct(
    domain: &str,
    client: &Client,
) -> Result<Vec<String>, http_client::HttpError> {
    let raw_q = format!("%.{domain}");
    let q = urlencoding::encode(&raw_q);
    let url = format!("https://crt.sh/?q={q}&output=json");
    let entries: Vec<CrtEntry> = client.get_json(&url).await?;

    let suffix = format!(".{domain}");
    let mut seen: HashSet<String> = HashSet::new();

    for entry in &entries {
        for name in entry.name_value.split('\n') {
            let name = name.trim().to_lowercase();
            if !name.starts_with('*') && name.ends_with(&suffix) {
                seen.insert(name);
            }
        }
    }

    let mut results: Vec<String> = seen.into_iter().collect();
    results.sort();
    Ok(results)
}
