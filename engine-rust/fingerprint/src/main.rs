/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     mg-fingerprint binary — probe a URL and report its tech stack
 * Notes:           When --engagement is set, the result is merged into
 *                  recon/fingerprint.json (keyed by hostname) so mg-recon can skip re-probing
 *******************************************************************/
mod cli;

use anyhow::{Context, Result};
use fingerprint::fingerprint_url;
use http_client::{Client, ClientConfig};
use std::collections::HashMap;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::get_args();

    // build a shared HTTP client with UA rotation and the requested timeout
    let client = Client::new(ClientConfig {
        timeout_ms: args.timeout_ms,
        rate_limit_ms: None,
        max_retries: 1,
        rotate_ua: true,
        max_redirects: 5,
        ..Default::default()
    })
    .context("build HTTP client")?;

    // extract the hostname for scope-checking and as the fingerprint map key
    let hostname = url_hostname(&args.url);

    // if engagement set, verify the target is in scope before probing
    if let Some(ref name) = args.engagement {
        let eng = engagement::Engagement::load_named(Path::new(&args.engagements_dir), name)
            .with_context(|| format!("load engagement {name}"))?;
        let scope = eng.scope().context("load scope")?;
        if !scope.is_in_scope(&hostname) {
            anyhow::bail!("{hostname} is out of scope for engagement {name}");
        }
    }

    eprintln!("Fingerprinting {}...", args.url);
    // send the HTTP probe and classify headers + body
    let fp = fingerprint_url(&client, &args.url)
        .await
        .with_context(|| format!("fingerprint {}", args.url))?;

    // print the result as pretty JSON to stdout
    println!("{}", serde_json::to_string_pretty(&fp)?);

    // write into the engagement fingerprint map and audit
    if let Some(ref name) = args.engagement {
        let eng = engagement::Engagement::load_named(Path::new(&args.engagements_dir), name)
            .with_context(|| format!("load engagement {name}"))?;

        let fp_path = eng.recon_dir().join("fingerprint.json");

        // load existing map so we can merge without clobbering other hosts' entries
        let mut map: HashMap<String, fingerprint::Fingerprint> = if fp_path.exists() {
            let raw = std::fs::read_to_string(&fp_path).context("read fingerprint.json")?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            HashMap::new()
        };

        // upsert this host's fingerprint then write the full map back atomically
        map.insert(hostname.clone(), fp);
        let json = serde_json::to_string_pretty(&map)?;
        std::fs::write(&fp_path, json).context("write fingerprint.json")?;
        let _ = eng.audit("mg-fingerprint", &hostname, None);
        eprintln!("wrote fingerprint to {}", fp_path.display());
    }

    Ok(())
}

// Extract the hostname component from a URL string; falls back to the whole string
fn url_hostname(url: &str) -> String {
    // strip scheme prefix, then cut at first slash to isolate the authority
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // drop any path/query after the host
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}
