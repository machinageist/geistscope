// Author: Jeff
// Date: 2026-05-01
// Description: Mine Wayback Machine CDX API for historical paths

use http_client::{Client, ClientConfig};
use std::collections::HashSet;
use url::Url;

use crate::store::Corpus;

// Mine Wayback CDX for paths under each domain; store unique paths in corpus
pub async fn mine_wayback(domains: &[String], corpus: &Corpus, rate_limit_ms: u64) {
    let client = Client::new(ClientConfig {
        timeout_ms: 60_000,
        rate_limit_ms: Some(rate_limit_ms),
        max_retries: 1,
        rotate_ua: false,
    })
    .expect("failed to build HTTP client");

    for domain in domains {
        match fetch_paths(domain, &client).await {
            Ok(paths) => {
                eprintln!("[wayback] {domain}: {} paths", paths.len());
                for path in &paths {
                    if let Err(e) = corpus.insert_path(domain, path) {
                        eprintln!("[wayback] store error: {e}");
                    }
                }
            }
            Err(e) => eprintln!("[wayback] {domain}: {e}"),
        }
    }
}

async fn fetch_paths(
    domain: &str,
    client: &Client,
) -> Result<Vec<String>, http_client::HttpError> {
    // CDX API: returns JSON array-of-arrays; first row is header ["original"]
    let cdx_url = format!(
        "http://web.archive.org/cdx/search/cdx\
         ?url=*.{domain}/*&output=json&fl=original&collapse=urlkey\
         &filter=statuscode:200&limit=50000"
    );

    let raw: Vec<Vec<String>> = client.get_json(&cdx_url).await?;
    let mut seen: HashSet<String> = HashSet::new();

    // Skip header row (index 0 = ["original"])
    for row in raw.iter().skip(1) {
        if let Some(raw_url) = row.first() {
            if let Ok(parsed) = Url::parse(raw_url) {
                let path = parsed.path().to_string();
                if path.len() > 1 {
                    seen.insert(path);
                }
            }
        }
    }

    let mut paths: Vec<String> = seen.into_iter().collect();
    paths.sort();
    Ok(paths)
}
