/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-openapi — OpenAPI spec parser and security prober
 *                  Fetches/reads an OpenAPI spec, builds minimal requests
 *                  for every endpoint, flags auth bypass, sensitive exposure,
 *                  and slow endpoint findings.
 * Notes:           Supports JSON specs only (YAML conversion out of scope).
 *                  --unauthenticated replays each endpoint without auth headers
 *                  to detect missing access controls.
 *                  Param substitution uses 1 for numeric-looking names, test otherwise.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "openapi";
const AUDIT_TOOL: &str = "mg-openapi";
const NUMERIC_PARAM_SUBSTITUTE: &str = "1";
const STRING_PARAM_SUBSTITUTE: &str = "test";
const SENSITIVE_KEYWORDS: &[&str] = &[
    "password",
    "token",
    "secret",
    "key",
    "ssn",
    "dob",
    "credit_card",
];
const SLOW_THRESHOLD_MS: u128 = 5000;
const NUMERIC_PARAM_NAMES: &[&str] = &["id", "user_id", "item_id", "account_id", "order_id"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-openapi",
    about = "OpenAPI spec parser and security prober — auth bypass, data exposure, slow endpoints"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// URL or filesystem path to the OpenAPI JSON spec
    #[arg(long)]
    spec: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Override base URL for requests (defaults to servers[0].url in spec)
    #[arg(long)]
    base_url: Option<String>,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Also replay each endpoint without auth headers
    #[arg(long)]
    unauthenticated: bool,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One parameter parsed from the spec
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpecParam {
    name: String,
    #[serde(rename = "in")]
    location: String,
    #[serde(default)]
    required: bool,
}

// One endpoint parsed from the spec
#[derive(Debug, Clone, Serialize)]
struct SpecEndpoint {
    path_template: String,
    method: String,
    params: Vec<SpecParam>,
    has_request_body: bool,
}

// Finding category
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum FindingKind {
    AuthBypass,
    SensitiveExposure,
    SlowEndpoint,
}

// One security finding
#[derive(Debug, Serialize)]
struct OpenApiFinding {
    endpoint: String,
    method: String,
    kind: FindingKind,
    detail: String,
}

// Probe result for one endpoint
#[derive(Debug, Serialize)]
struct EndpointProbe {
    path_template: String,
    resolved_url: String,
    method: String,
    status: u16,
    body_len: usize,
    elapsed_ms: u128,
    unauthenticated_status: Option<u16>,
}

// Top-level output for inventory file
#[derive(Serialize)]
struct EndpointInventory {
    engagement: String,
    timestamp: String,
    spec: String,
    endpoints: Vec<SpecEndpoint>,
}

// Top-level output for findings file
#[derive(Serialize)]
struct OpenApiResults {
    engagement: String,
    timestamp: String,
    total_probes: usize,
    findings: Vec<OpenApiFinding>,
    probes: Vec<EndpointProbe>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for use in filename
fn ts_for_filename(ts: &str) -> String {
    ts.chars().map(|c| if c == ':' { '_' } else { c }).collect()
}

// Fetch spec from URL or read from filesystem
async fn load_spec(spec: &str) -> Result<Value> {
    if spec.starts_with("http://") || spec.starts_with("https://") {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        let body = client
            .get(spec)
            .send()
            .await
            .with_context(|| format!("fetch spec from {spec}"))?
            .text()
            .await
            .context("read spec response body")?;
        serde_json::from_str(&body).context("parse spec JSON")
    } else {
        let raw = fs::read_to_string(spec).with_context(|| format!("read spec file {spec}"))?;
        serde_json::from_str(&raw).context("parse spec JSON")
    }
}

// Parse endpoints from the spec paths object
fn parse_endpoints(spec: &Value) -> Vec<SpecEndpoint> {
    let mut endpoints = Vec::new();
    let Some(paths) = spec["paths"].as_object() else {
        return endpoints;
    };

    for (path_template, methods_val) in paths {
        let Some(methods) = methods_val.as_object() else {
            continue;
        };
        for (method, op_val) in methods {
            // Skip non-HTTP-method keys like "parameters" or "summary"
            let method_upper = method.to_uppercase();
            if !matches!(
                method_upper.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
            ) {
                continue;
            }

            // Collect parameters from operation and path-level merged
            let op_params = op_val["parameters"].as_array();
            let path_params = methods_val["parameters"].as_array();
            let mut params: Vec<SpecParam> = Vec::new();

            for arr in [path_params, op_params].into_iter().flatten() {
                for p in arr {
                    if let Ok(sp) = serde_json::from_value::<SpecParam>(p.clone()) {
                        // Deduplicate by name
                        if !params.iter().any(|existing| existing.name == sp.name) {
                            params.push(sp);
                        }
                    }
                }
            }

            let has_request_body = !op_val["requestBody"].is_null();

            endpoints.push(SpecEndpoint {
                path_template: path_template.clone(),
                method: method_upper,
                params,
                has_request_body,
            });
        }
    }
    endpoints
}

// Resolve path template: substitute {param} with a sensible value
fn resolve_path(template: &str, params: &[SpecParam]) -> String {
    let mut path = template.to_string();
    for param in params {
        if param.location == "path" {
            let placeholder = format!("{{{}}}", param.name);
            let value = if NUMERIC_PARAM_NAMES.contains(&param.name.as_str()) {
                NUMERIC_PARAM_SUBSTITUTE
            } else {
                STRING_PARAM_SUBSTITUTE
            };
            path = path.replace(&placeholder, value);
        }
    }
    // Replace any remaining {param} tokens with 1
    while let Some(start) = path.find('{') {
        if let Some(end) = path[start..].find('}') {
            let token = &path[start..start + end + 1];
            path = path.replace(token, NUMERIC_PARAM_SUBSTITUTE);
        } else {
            break;
        }
    }
    path
}

// Append required query params to a URL
fn append_query_params(url: &str, params: &[SpecParam]) -> String {
    let query_params: Vec<String> = params
        .iter()
        .filter(|p| p.location == "query" && p.required)
        .map(|p| {
            let value = if NUMERIC_PARAM_NAMES.contains(&p.name.as_str()) {
                NUMERIC_PARAM_SUBSTITUTE
            } else {
                STRING_PARAM_SUBSTITUTE
            };
            format!("{}={}", p.name, value)
        })
        .collect();
    if query_params.is_empty() {
        url.to_string()
    } else {
        format!("{}?{}", url, query_params.join("&"))
    }
}

// Check response body for sensitive keywords
fn has_sensitive_keywords(body: &str) -> bool {
    SENSITIVE_KEYWORDS.iter().any(|kw| body.contains(kw))
}

// Probe one endpoint with the given client, optionally also replay unauthenticated
async fn probe_endpoint(
    auth_client: reqwest::Client,
    unauth_client: Option<reqwest::Client>,
    base_url: String,
    endpoint: SpecEndpoint,
) -> (EndpointProbe, Vec<OpenApiFinding>) {
    let resolved = resolve_path(&endpoint.path_template, &endpoint.params);
    let url_with_params = append_query_params(&format!("{base_url}{resolved}"), &endpoint.params);

    let mut req = match endpoint.method.as_str() {
        "POST" | "PUT" | "PATCH" => {
            let mut b = auth_client.request(
                reqwest::Method::from_bytes(endpoint.method.as_bytes()).unwrap(),
                &url_with_params,
            );
            if endpoint.has_request_body {
                b = b
                    .header("Content-Type", "application/json")
                    .body(r#"{"test":"value"}"#);
            }
            b
        }
        _ => auth_client.request(
            reqwest::Method::from_bytes(endpoint.method.as_bytes()).unwrap(),
            &url_with_params,
        ),
    };

    // GET/HEAD/DELETE don't need a body modifier
    let _ = &mut req;

    let start = Instant::now();
    let resp = auth_client
        .request(
            reqwest::Method::from_bytes(endpoint.method.as_bytes()).unwrap(),
            &url_with_params,
        )
        .send()
        .await;
    let elapsed_ms = start.elapsed().as_millis();

    let (status, body_len, body) = match resp {
        Ok(r) => {
            let s = r.status().as_u16();
            let b = r.text().await.unwrap_or_default();
            let l = b.len();
            (s, l, b)
        }
        Err(_) => (0, 0, String::new()),
    };

    // Replay without auth headers if requested
    let unauth_status = if let Some(ref uc) = unauth_client {
        let ur = uc
            .request(
                reqwest::Method::from_bytes(endpoint.method.as_bytes()).unwrap(),
                &url_with_params,
            )
            .send()
            .await;
        ur.ok().map(|r| r.status().as_u16())
    } else {
        None
    };

    let mut findings: Vec<OpenApiFinding> = Vec::new();

    // Flag auth bypass: unauthenticated 200/201
    if let Some(us) = unauth_status
        && (us == 200 || us == 201)
    {
        findings.push(OpenApiFinding {
            endpoint: url_with_params.clone(),
            method: endpoint.method.clone(),
            kind: FindingKind::AuthBypass,
            detail: format!("unauthenticated {us}"),
        });
    }

    // Flag sensitive keyword exposure
    if has_sensitive_keywords(&body) {
        findings.push(OpenApiFinding {
            endpoint: url_with_params.clone(),
            method: endpoint.method.clone(),
            kind: FindingKind::SensitiveExposure,
            detail: "response body contains sensitive keyword".into(),
        });
    }

    // Flag slow endpoints
    if elapsed_ms > SLOW_THRESHOLD_MS {
        findings.push(OpenApiFinding {
            endpoint: url_with_params.clone(),
            method: endpoint.method.clone(),
            kind: FindingKind::SlowEndpoint,
            detail: format!("{elapsed_ms}ms"),
        });
    }

    let probe = EndpointProbe {
        path_template: endpoint.path_template.clone(),
        resolved_url: url_with_params,
        method: endpoint.method.clone(),
        status,
        body_len,
        elapsed_ms,
        unauthenticated_status: unauth_status,
    };

    (probe, findings)
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-openapi: loading spec from {}", args.spec);
    let spec = load_spec(&args.spec).await.context("load spec")?;

    let endpoints = parse_endpoints(&spec);
    if endpoints.is_empty() {
        anyhow::bail!("no endpoints found in spec — check that paths are present");
    }

    // Resolve base URL from CLI or spec
    let base_url = if let Some(ref b) = args.base_url {
        b.trim_end_matches('/').to_string()
    } else {
        spec["servers"][0]["url"]
            .as_str()
            .unwrap_or("")
            .trim_end_matches('/')
            .to_string()
    };

    if base_url.is_empty() {
        anyhow::bail!("no base URL — pass --base-url or ensure spec has servers[0].url");
    }

    eprintln!(
        "mg-openapi: {} endpoints, base_url={base_url}, concurrency={}",
        endpoints.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let auth_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build auth HTTP client")?;

    let unauth_client = if args.unauthenticated {
        Some(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(args.timeout))
                .danger_accept_invalid_certs(true)
                .build()
                .context("build unauth HTTP client")?,
        )
    } else {
        None
    };

    let mut join_set: JoinSet<(EndpointProbe, Vec<OpenApiFinding>)> = JoinSet::new();
    let mut all_probes: Vec<EndpointProbe> = Vec::new();
    let mut all_findings: Vec<OpenApiFinding> = Vec::new();

    for ep in endpoints.clone() {
        if join_set.len() >= args.concurrency
            && let Some(Ok((probe, findings))) = join_set.join_next().await
        {
            all_probes.push(probe);
            all_findings.extend(findings);
        }

        let ac = auth_client.clone();
        let uc = unauth_client.clone();
        let bu = base_url.clone();
        join_set.spawn(probe_endpoint(ac, uc, bu, ep));
    }

    while let Some(Ok((probe, findings))) = join_set.join_next().await {
        all_probes.push(probe);
        all_findings.extend(findings);
    }

    // Print findings
    for f in &all_findings {
        eprintln!(
            "  [{:?}] {} {} — {}",
            f.kind, f.method, f.endpoint, f.detail
        );
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create openapi output dir")?;

    // Write endpoint inventory
    let inventory = EndpointInventory {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        spec: args.spec.clone(),
        endpoints,
    };
    let inventory_path = output_dir.join(format!("endpoints-{ts_file}.json"));
    fs::write(
        &inventory_path,
        serde_json::to_string_pretty(&inventory).unwrap_or_default(),
    )
    .context("write endpoint inventory JSON")?;

    // Write findings
    let total_probes = all_probes.len();
    let findings_count = all_findings.len();
    let results = OpenApiResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        total_probes,
        findings: all_findings,
        probes: all_probes,
    };
    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&results).unwrap_or_default(),
    )
    .context("write openapi results JSON")?;

    eprintln!(
        "mg-openapi: {} probes, {} findings — {}",
        total_probes,
        findings_count,
        results_path.display()
    );

    // Write findings for auth bypass (HIGH) and sensitive exposure (MEDIUM)
    for f in &results.findings {
        let (title, sev, rec) = match f.kind {
            FindingKind::AuthBypass => (
                "API Endpoint Authentication Bypass",
                FindingSeverity::High,
                "Enforce authentication on all API endpoints; verify auth middleware is applied globally",
            ),
            FindingKind::SensitiveExposure => (
                "API Response Contains Sensitive Keywords",
                FindingSeverity::Medium,
                "Audit API responses for unintended sensitive data exposure; apply field-level access controls",
            ),
            FindingKind::SlowEndpoint => continue,
        };
        let tf = ToolFinding::new("mg-openapi", title, sev)
            .url(f.endpoint.clone())
            .evidence(format!("method={} detail={}", f.method, f.detail))
            .recommendation(rec);
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "probes={total_probes} findings={findings_count} ts={ts}"
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_endpoints_extracts_paths_and_methods() {
        let spec = json!({
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            { "name": "id", "in": "path", "required": true }
                        ]
                    },
                    "post": {
                        "requestBody": { "content": {} }
                    }
                }
            }
        });
        let endpoints = parse_endpoints(&spec);
        assert_eq!(endpoints.len(), 2);
        let get_ep = endpoints.iter().find(|e| e.method == "GET").unwrap();
        assert_eq!(get_ep.path_template, "/users/{id}");
        assert_eq!(get_ep.params.len(), 1);
        assert_eq!(get_ep.params[0].name, "id");
    }

    #[test]
    fn parse_endpoints_returns_empty_for_no_paths() {
        let spec = json!({ "info": { "title": "empty" } });
        assert!(parse_endpoints(&spec).is_empty());
    }

    #[test]
    fn resolve_path_substitutes_numeric_id() {
        let params = vec![SpecParam {
            name: "id".into(),
            location: "path".into(),
            required: true,
        }];
        assert_eq!(resolve_path("/users/{id}", &params), "/users/1");
    }

    #[test]
    fn resolve_path_substitutes_string_param() {
        let params = vec![SpecParam {
            name: "slug".into(),
            location: "path".into(),
            required: true,
        }];
        assert_eq!(resolve_path("/posts/{slug}", &params), "/posts/test");
    }

    #[test]
    fn append_query_params_includes_required_only() {
        let params = vec![
            SpecParam {
                name: "q".into(),
                location: "query".into(),
                required: true,
            },
            SpecParam {
                name: "page".into(),
                location: "query".into(),
                required: false,
            },
        ];
        let result = append_query_params("https://api.example.com/search", &params);
        assert!(result.contains("q=test"));
        assert!(!result.contains("page="));
    }

    #[test]
    fn has_sensitive_keywords_detects_token() {
        assert!(has_sensitive_keywords("response contains token abc"));
        assert!(!has_sensitive_keywords("clean response body here"));
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-17T08:00:00Z"),
            "2026-05-17T08_00_00Z"
        );
    }
}
