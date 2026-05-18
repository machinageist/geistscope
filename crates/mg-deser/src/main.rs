/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-deser — deserialization vulnerability detector from crawl corpus.
 * Notes:           Scans crawl corpus JSON for serialized data magic bytes and
 *                  patterns. Java: ysoserial command strings generated for manual use.
 *                  PHP: sends harmless stdClass payload, checks for 500 error.
 *                  Python: notes candidate for manual inspection.
 *                  Does NOT execute Java/Python payloads — only PHP test payload is sent.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "deser";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-deser";
const DEFAULT_TIMEOUT_SECS: u64 = 20;
const DEFAULT_CONCURRENCY: usize = 5;

// Java serialized object magic bytes (hex AC ED 00 05)
const JAVA_MAGIC: &[u8] = b"\xac\xed\x00\x05";
// PHP serialized object prefix
const PHP_OBJECT_PREFIX: &str = "O:";
// Base64-encoded Java serialized object prefix (rO0A == base64 of AC ED 00 05...)
const JAVA_B64_PREFIX: &str = "rO0";
// Content-Type that signals Java serialized objects
const JAVA_CONTENT_TYPE: &str = "application/x-java-serialized-object";
// Harmless PHP stdClass payload for error-based detection
const PHP_TEST_PAYLOAD: &str = "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-deser",
    about = "Detect deserialization vulnerabilities from crawl corpus"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent HTTP probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// OOB callback URL (embedded in ysoserial command strings)
    #[arg(long)]
    oob_url: Option<String>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Classification of a deserialization finding
// ConfirmedOob is reserved for callers that integrate an OOB server callback;
// auto-detection via polling is out of scope for this binary
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum DeserClass {
    // Magic bytes or patterns found — manual verification needed
    Candidate,
    // Server returned 500 on PHP test payload
    ErrorBased,
    // OOB callback received
    ConfirmedOob,
}

// One detected deserialization candidate
#[derive(Debug, Serialize)]
struct DeserFinding {
    url: String,
    lang: String,
    classification: DeserClass,
    detail: String,
    manual_payload: Option<String>,
}

// Crawl endpoint record — minimal fields we need
#[derive(Debug, Deserialize)]
struct CrawlEndpoint {
    url: String,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    response_body: String,
}

// Crawl index shape
#[derive(Debug, Deserialize)]
struct CrawlIndex {
    #[serde(default)]
    endpoints: Vec<CrawlEndpoint>,
}

// Top-level output
#[derive(Serialize)]
struct DeserResults {
    engagement: String,
    timestamp: String,
    endpoints_scanned: usize,
    findings: Vec<DeserFinding>,
}

// ── Corpus helpers ────────────────────────────────────────────────────────────

// Collect all endpoints from crawl index files
fn collect_endpoints(crawl_dir: &Path) -> Vec<CrawlEndpoint> {
    let mut endpoints = Vec::new();
    if !crawl_dir.exists() {
        return endpoints;
    }
    let Ok(entries) = fs::read_dir(crawl_dir) else {
        return endpoints;
    };
    for entry in entries.flatten() {
        let index_path = entry.path().join("index.json");
        if !index_path.exists() {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&index_path) else {
            continue;
        };
        let Ok(index) = serde_json::from_str::<CrawlIndex>(&raw) else {
            continue;
        };
        endpoints.extend(index.endpoints);
    }
    endpoints
}

// ── Detection logic ───────────────────────────────────────────────────────────

// Check an endpoint's recorded data for deserialization indicators
fn detect_static(ep: &CrawlEndpoint, oob_url: Option<&str>) -> Vec<DeserFinding> {
    let mut findings = Vec::new();
    let combined = format!("{} {}", ep.body, ep.response_body);

    // Java magic bytes in body content (base64-encoded in JSON)
    if combined.contains(JAVA_B64_PREFIX) {
        // Verify it actually decodes to Java magic
        let is_java = combined
            .split_whitespace()
            .filter(|tok| tok.starts_with(JAVA_B64_PREFIX))
            .any(|tok| {
                base64::engine::general_purpose::STANDARD
                    .decode(tok)
                    .map(|decoded| decoded.starts_with(JAVA_MAGIC))
                    .unwrap_or(false)
            });

        if is_java {
            let oob = oob_url.unwrap_or("http://your-oob-server.com");
            let cmd = format!(
                "java -jar ysoserial.jar URLDNS \"{oob}\"",
            );
            findings.push(DeserFinding {
                url: ep.url.clone(),
                lang: "java".to_string(),
                classification: DeserClass::Candidate,
                detail: "Base64-encoded Java serialized object detected in body".to_string(),
                manual_payload: Some(cmd),
            });
        }
    }

    // Java Content-Type header
    if ep.content_type.contains(JAVA_CONTENT_TYPE) {
        let oob = oob_url.unwrap_or("http://your-oob-server.com");
        let cmd = format!("java -jar ysoserial.jar URLDNS \"{oob}\"");
        findings.push(DeserFinding {
            url: ep.url.clone(),
            lang: "java".to_string(),
            classification: DeserClass::Candidate,
            detail: format!("Content-Type: {JAVA_CONTENT_TYPE}"),
            manual_payload: Some(cmd),
        });
    }

    // PHP object prefix in body
    if combined.contains(PHP_OBJECT_PREFIX) {
        findings.push(DeserFinding {
            url: ep.url.clone(),
            lang: "php".to_string(),
            classification: DeserClass::Candidate,
            detail: "PHP serialized object prefix 'O:' found in body".to_string(),
            manual_payload: Some(PHP_TEST_PAYLOAD.to_string()),
        });
    }

    // Python pickle — note as candidate, no auto-probe
    if combined.contains("pickle") || combined.contains("cPickle") {
        findings.push(DeserFinding {
            url: ep.url.clone(),
            lang: "python".to_string(),
            classification: DeserClass::Candidate,
            detail: "Python pickle reference found in body — manual verification required".to_string(),
            manual_payload: Some("import pickle; pickle.loads(<payload>)".to_string()),
        });
    }

    findings
}

// Send PHP test payload and check for 500 error
async fn probe_php(client: &reqwest::Client, url: &str) -> bool {
    let resp = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("data={PHP_TEST_PAYLOAD}"))
        .send()
        .await;

    matches!(resp, Ok(r) if r.status().as_u16() == 500)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-deser: scanning crawl corpus");

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-deser/0.1")
        .default_headers(auth_headers)
        .build()
        .context("build HTTP client")?;

    let endpoints = collect_endpoints(&eng.crawl_dir());
    let endpoints_scanned = endpoints.len();
    eprintln!("  {endpoints_scanned} endpoints to scan");

    let oob_url = args.oob_url.as_deref();
    let mut findings: Vec<DeserFinding> = Vec::new();

    // Static scan first — no network
    let mut php_candidates: Vec<String> = Vec::new();
    for ep in &endpoints {
        let detected = detect_static(ep, oob_url);
        for f in &detected {
            if f.lang == "php" {
                php_candidates.push(ep.url.clone());
            }
        }
        findings.extend(detected);
    }

    // Active PHP probe — bounded concurrency
    let mut join_set = tokio::task::JoinSet::new();
    let mut active_count = 0usize;
    let mut error_based: Vec<String> = Vec::new();

    for url in php_candidates {
        while join_set.len() >= args.concurrency {
            if let Some(Ok((u, is_500))) = join_set.join_next().await
                && is_500
            {
                error_based.push(u);
            }
        }
        let client = client.clone();
        let url_clone = url.clone();
        join_set.spawn(async move {
            let result = probe_php(&client, &url_clone).await;
            (url_clone, result)
        });
        active_count += 1;
    }
    while let Some(Ok((u, is_500))) = join_set.join_next().await {
        if is_500 { error_based.push(u); }
    }

    eprintln!("  {} PHP endpoints probed; {} returned 500", active_count, error_based.len());

    // Upgrade candidate findings to error_based where confirmed
    for f in &mut findings {
        if f.lang == "php" && error_based.contains(&f.url) {
            f.classification = DeserClass::ErrorBased;
            f.detail = "PHP test payload returned HTTP 500".to_string();
        }
    }

    eprintln!("  {} total findings", findings.len());

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create deser output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = DeserResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        endpoints_scanned,
        findings,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Emit findings — HIGH for error_based, MEDIUM for candidates
    for f in &output.findings {
        let (sev, title) = match f.classification {
            DeserClass::ErrorBased | DeserClass::ConfirmedOob => (
                FindingSeverity::High,
                format!("{} Deserialization Confirmed (Error-Based)", f.lang.to_uppercase()),
            ),
            DeserClass::Candidate => (
                FindingSeverity::Medium,
                format!("{} Deserialization Candidate Detected", f.lang.to_uppercase()),
            ),
        };
        let tf = ToolFinding::new("mg-deser", title, sev)
            .url(f.url.clone())
            .evidence(format!("lang={} detail={}", f.lang, f.detail))
            .recommendation(
                "Avoid deserializing untrusted data; use safer alternatives (JSON, Protobuf); \
                 implement type-safe deserialization with an allowlist; \
                 consider RASP/WAF rules to block serialized object patterns"
            );
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ep(url: &str, content_type: &str, body: &str, response_body: &str) -> CrawlEndpoint {
        CrawlEndpoint {
            url: url.to_string(),
            content_type: content_type.to_string(),
            body: body.to_string(),
            response_body: response_body.to_string(),
        }
    }

    #[test]
    fn detect_static_finds_php_prefix() {
        let ep = make_ep("https://x.com/deser", "", "O:8:\"stdClass\":0:{}", "");
        let findings = detect_static(&ep, None);
        assert!(findings.iter().any(|f| f.lang == "php"));
    }

    #[test]
    fn detect_static_finds_java_content_type() {
        let ep = make_ep(
            "https://x.com/java",
            "application/x-java-serialized-object",
            "",
            "",
        );
        let findings = detect_static(&ep, None);
        assert!(findings.iter().any(|f| f.lang == "java"));
    }

    #[test]
    fn detect_static_includes_ysoserial_command() {
        let ep = make_ep(
            "https://x.com/java",
            "application/x-java-serialized-object",
            "",
            "",
        );
        let findings = detect_static(&ep, Some("http://oob.test"));
        let java_finding = findings.iter().find(|f| f.lang == "java").unwrap();
        let payload = java_finding.manual_payload.as_deref().unwrap_or("");
        assert!(payload.contains("ysoserial"));
        assert!(payload.contains("oob.test"));
    }

    #[test]
    fn detect_static_finds_python_pickle() {
        let ep = make_ep("https://x.com/py", "", "pickle.loads(data)", "");
        let findings = detect_static(&ep, None);
        assert!(findings.iter().any(|f| f.lang == "python"));
    }

    #[test]
    fn detect_static_clean_endpoint_returns_empty() {
        let ep = make_ep("https://x.com/clean", "text/html", "hello world", "");
        let findings = detect_static(&ep, None);
        assert!(findings.is_empty());
    }
}
