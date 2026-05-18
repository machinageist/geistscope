/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-cloud-enum — cloud storage bucket enumeration.
 *                  Generates candidate bucket names from a target name
 *                  and checks S3, GCS, and Azure Blob for public access.
 * Notes:           Three outcomes per candidate: public_listing (HIGH),
 *                  exists_private (INFO), not_found. Public listings are
 *                  printed to stderr in a distinct format for visibility.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "cloud-enum";
const AUDIT_TOOL: &str = "mg-cloud-enum";
const USER_AGENT: &str = "mg-cloud-enum/0.1 (geistscope security scanner)";
// Suffixes appended to the base target name
const SUFFIXES: &[&str] = &[
    "-dev", "-staging", "-prod", "-backup", "-data", "-assets",
    "-static", "-files", "-uploads", "-public", "-private",
    "-internal", "-logs", "-archive", "-store",
];

// Prefixes prepended to the base target name
const PREFIXES: &[&str] = &[
    "dev-", "staging-", "prod-", "backup-", "data-", "assets-",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-cloud-enum",
    about = "Cloud storage bucket enumeration — S3, GCS, and Azure Blob"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Base name for bucket guesses (e.g. "acme")
    #[arg(long)]
    target: String,

    /// Maximum concurrent bucket checks
    #[arg(long, default_value_t = 20)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Result classification for one bucket candidate
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BucketStatus {
    PublicListing,
    ExistsPrivate,
    NotFound,
}

// Result of one cloud provider check for one bucket name
#[derive(Debug, Clone, Serialize)]
struct BucketResult {
    provider: String,
    bucket: String,
    url: String,
    status: BucketStatus,
    http_status: u16,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CloudEnumResults {
    engagement: String,
    target: String,
    timestamp: String,
    candidates_checked: usize,
    public_listings: usize,
    exists_private: usize,
    results: Vec<BucketResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize a timestamp string for use in a filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Generate all candidate bucket names from the base target name
fn generate_candidates(target: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates = Vec::new();

    // Closure to add unique candidates
    let mut push = |name: String| {
        if seen.insert(name.clone()) {
            candidates.push(name);
        }
    };

    push(target.to_string());
    for s in SUFFIXES {
        push(format!("{target}{s}"));
    }
    for p in PREFIXES {
        push(format!("{p}{target}"));
    }

    candidates
}

// Classify an S3 XML body: detect ListBucketResult vs error codes
fn classify_s3_body(body: &str) -> BucketStatus {
    if body.contains("<ListBucketResult") {
        return BucketStatus::PublicListing;
    }
    if body.contains("<Code>NoSuchBucket</Code>") {
        return BucketStatus::NotFound;
    }
    if body.contains("<Code>AccessDenied</Code>") {
        return BucketStatus::ExistsPrivate;
    }
    BucketStatus::NotFound
}

// Check one S3 bucket by name
async fn check_s3(client: Arc<reqwest::Client>, bucket: String) -> BucketResult {
    let url = format!("https://{bucket}.s3.amazonaws.com/");
    let status = match client.get(&url).send().await {
        Ok(resp) => {
            let http_status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let bucket_status = match http_status {
                200 => classify_s3_body(&body),
                403 => BucketStatus::ExistsPrivate,
                404 => classify_s3_body(&body),
                _ => BucketStatus::NotFound,
            };
            (bucket_status, http_status)
        }
        Err(_) => (BucketStatus::NotFound, 0),
    };
    BucketResult {
        provider: "s3".into(),
        bucket: bucket.clone(),
        url,
        status: status.0,
        http_status: status.1,
    }
}

// Check one GCS bucket by name
async fn check_gcs(client: Arc<reqwest::Client>, bucket: String) -> BucketResult {
    let url = format!("https://storage.googleapis.com/storage/v1/b/{bucket}/o");
    let status = match client.get(&url).send().await {
        Ok(resp) => {
            let http_status = resp.status().as_u16();
            let bucket_status = match http_status {
                200 => BucketStatus::PublicListing,
                403 => BucketStatus::ExistsPrivate,
                404 => BucketStatus::NotFound,
                _ => BucketStatus::NotFound,
            };
            (bucket_status, http_status)
        }
        Err(_) => (BucketStatus::NotFound, 0),
    };
    BucketResult {
        provider: "gcs".into(),
        bucket: bucket.clone(),
        url,
        status: status.0,
        http_status: status.1,
    }
}

// Check one Azure Blob container by name
async fn check_azure(client: Arc<reqwest::Client>, bucket: String) -> BucketResult {
    let url = format!(
        "https://{bucket}.blob.core.windows.net/{bucket}?restype=container&comp=list"
    );
    let status = match client.get(&url).send().await {
        Ok(resp) => {
            let http_status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let bucket_status = match http_status {
                200 => BucketStatus::PublicListing,
                403 => BucketStatus::ExistsPrivate,
                404 => {
                    // ResourceNotFound in the body means it doesn't exist
                    if body.contains("ResourceNotFound") || body.contains("ContainerNotFound") {
                        BucketStatus::NotFound
                    } else {
                        BucketStatus::ExistsPrivate
                    }
                }
                _ => BucketStatus::NotFound,
            };
            (bucket_status, http_status)
        }
        Err(_) => (BucketStatus::NotFound, 0),
    };
    BucketResult {
        provider: "azure".into(),
        bucket: bucket.clone(),
        url,
        status: status.0,
        http_status: status.1,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let candidates = generate_candidates(&args.target);
    // Three providers per candidate
    let total_checks = candidates.len() * 3;

    eprintln!(
        "mg-cloud-enum: target={} candidates={} checks={} concurrency={}",
        args.target,
        candidates.len(),
        total_checks,
        args.concurrency
    );

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout))
            .user_agent(USER_AGENT)
            .build()
            .context("build HTTP client")?,
    );

    let mut join_set: JoinSet<BucketResult> = JoinSet::new();
    let mut all_results: Vec<BucketResult> = Vec::new();

    // Spawn one task per (provider, candidate) pair, drain at concurrency ceiling
    for candidate in &candidates {
        for provider_idx in 0..3usize {
            if join_set.len() >= args.concurrency
                && let Some(Ok(r)) = join_set.join_next().await
            {
                all_results.push(r);
            }
            let c = Arc::clone(&client);
            let name = candidate.clone();
            match provider_idx {
                0 => join_set.spawn(check_s3(c, name)),
                1 => join_set.spawn(check_gcs(c, name)),
                _ => join_set.spawn(check_azure(c, name)),
            };
        }
    }
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    let public_count = all_results
        .iter()
        .filter(|r| r.status == BucketStatus::PublicListing)
        .count();
    let private_count = all_results
        .iter()
        .filter(|r| r.status == BucketStatus::ExistsPrivate)
        .count();

    // Print public listing hits prominently
    for r in &all_results {
        if r.status == BucketStatus::PublicListing {
            eprintln!("  [PUBLIC LISTING] {} {} {}", r.provider, r.bucket, r.url);
        } else if r.status == BucketStatus::ExistsPrivate {
            eprintln!("  [exists-private] {} {}", r.provider, r.bucket);
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = CloudEnumResults {
        engagement: args.engagement.clone(),
        target: args.target.clone(),
        timestamp: ts.clone(),
        candidates_checked: candidates.len(),
        public_listings: public_count,
        exists_private: private_count,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create cloud-enum output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write cloud-enum results JSON")?;

    eprintln!(
        "mg-cloud-enum: {} public listings, {} private — {}",
        public_count,
        private_count,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "target={} candidates={} public={} private={} ts={ts}",
            args.target,
            output.candidates_checked,
            public_count,
            private_count
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_candidates_includes_exact_and_variants() {
        let candidates = generate_candidates("acme");
        // exact name
        assert!(candidates.contains(&"acme".to_string()));
        // suffix variant
        assert!(candidates.contains(&"acme-dev".to_string()));
        assert!(candidates.contains(&"acme-prod".to_string()));
        // prefix variant
        assert!(candidates.contains(&"dev-acme".to_string()));
        // 1 + 15 suffixes + 6 prefixes = 22
        assert_eq!(candidates.len(), 22);
    }

    #[test]
    fn generate_candidates_no_duplicates() {
        let candidates = generate_candidates("test");
        let unique: HashSet<_> = candidates.iter().collect();
        assert_eq!(candidates.len(), unique.len());
    }

    #[test]
    fn classify_s3_body_detects_public_listing() {
        let body = r#"<?xml version="1.0"?><ListBucketResult><Name>test</Name></ListBucketResult>"#;
        assert_eq!(classify_s3_body(body), BucketStatus::PublicListing);
    }

    #[test]
    fn classify_s3_body_detects_no_such_bucket() {
        let body = r#"<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>"#;
        assert_eq!(classify_s3_body(body), BucketStatus::NotFound);
    }

    #[test]
    fn classify_s3_body_detects_access_denied() {
        let body = r#"<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>"#;
        assert_eq!(classify_s3_body(body), BucketStatus::ExistsPrivate);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }
}
