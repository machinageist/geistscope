/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-graphql — GraphQL deep tester
 *                  Detects GraphQL endpoints, runs introspection, extracts
 *                  schema, flags dangerous mutations, tests batching abuse
 *                  and depth-limit absence.
 * Notes:           Endpoint candidates come from --endpoint flag, crawl
 *                  endpoints.json (graphql:true or path suffix), or recon
 *                  summary hosts.  All requests carry session auth headers.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "graphql";
const AUDIT_TOOL: &str = "mg-graphql";

// URL path suffixes that suggest a GraphQL endpoint
const GRAPHQL_PATH_SUFFIXES: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
];

// Mutation name substrings that suggest a dangerous operation
const DANGEROUS_MUTATION_KEYWORDS: &[&str] = &[
    "delete", "remove", "update", "create", "set", "reset", "modify",
];

// Standard GraphQL introspection query
const INTROSPECTION_QUERY: &str = r#"{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }"}"#;

// Deeply nested query to test for absent depth limits (10 levels)
const DEPTH_TEST_QUERY: &str = r#"{"query":"{ __type(name: \"Query\") { fields { type { fields { type { fields { type { fields { type { fields { name } } } } } } } } } } }"}"#;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-graphql",
    about = "GraphQL deep tester — introspection, batching, depth-limit checks"
)]
struct Args {
    /// Engagement name (must have engagement.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Explicit GraphQL endpoint URL (skips discovery)
    #[arg(long)]
    endpoint: Option<String>,

    /// Run introspection on each candidate (default: true)
    #[arg(long, default_value_t = true)]
    introspect: bool,

    /// Test for GraphQL batching support
    #[arg(long)]
    batch_test: bool,

    /// Test for missing query depth limits
    #[arg(long)]
    depth_test: bool,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 5)]
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
    graphql: bool,
}

// Mirrors the HostRecord shape from recon/summary.json
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Top-level recon summary
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// Extracted schema from introspection
#[derive(Debug, Serialize, Deserialize, Default)]
struct GraphqlSchema {
    query_type: Option<String>,
    mutation_type: Option<String>,
    subscription_type: Option<String>,
    type_names: Vec<String>,
    query_names: Vec<String>,
    mutation_names: Vec<String>,
}

// One finding produced during testing
#[derive(Debug, Serialize)]
struct Finding {
    endpoint: String,
    kind: String,
    detail: String,
}

// Per-endpoint result written to findings JSON
#[derive(Debug, Serialize)]
struct EndpointResult {
    endpoint: String,
    introspection_succeeded: bool,
    schema: Option<GraphqlSchema>,
    dangerous_mutations: Vec<String>,
    batching_enabled: bool,
    no_depth_limit: bool,
    findings: Vec<Finding>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct GraphqlResults {
    engagement: String,
    timestamp: String,
    endpoints_tested: usize,
    findings_count: usize,
    results: Vec<EndpointResult>,
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

// Build base URL for a recon host, preferring HTTPS
fn base_url_for_host(rec: &HostRecord) -> String {
    if rec.open_ports.contains(&443) {
        return format!("https://{}", rec.hostname);
    }
    if rec.open_ports.contains(&80) {
        return format!("http://{}", rec.hostname);
    }
    format!("https://{}", rec.hostname)
}

// Collect GraphQL endpoint candidates from crawl host directories
fn collect_from_crawl(crawl_dir: &Path) -> Vec<String> {
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
            // Include endpoints explicitly tagged as GraphQL or whose path suffix matches
            let is_graphql_path = GRAPHQL_PATH_SUFFIXES
                .iter()
                .any(|suffix| ep.path.ends_with(suffix));
            if ep.graphql || is_graphql_path {
                endpoints.push(ep.path.clone());
            }
        }
    }
    endpoints
}

// Collect GraphQL candidate URLs from recon summary (appending known path suffixes)
fn collect_from_recon(recon_dir: &Path) -> Vec<String> {
    let summary_path = recon_dir.join("summary.json");
    let Ok(raw) = fs::read_to_string(&summary_path) else {
        return Vec::new();
    };
    let Ok(summary): Result<ReconSummary, _> = serde_json::from_str(&raw) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for host in &summary.hosts {
        if !host.http_accessible {
            continue;
        }
        let base = base_url_for_host(host);
        for suffix in GRAPHQL_PATH_SUFFIXES {
            candidates.push(format!("{base}{suffix}"));
        }
    }
    candidates
}

// Parse introspection JSON response into a GraphqlSchema
fn parse_schema(json: &serde_json::Value) -> GraphqlSchema {
    let mut schema = GraphqlSchema::default();
    let Some(data) = json.get("data").and_then(|d| d.get("__schema")) else {
        return schema;
    };

    schema.query_type = data
        .get("queryType")
        .and_then(|t| t.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());

    schema.mutation_type = data
        .get("mutationType")
        .and_then(|t| t.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());

    schema.subscription_type = data
        .get("subscriptionType")
        .and_then(|t| t.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());

    if let Some(types) = data.get("types").and_then(|t| t.as_array()) {
        for ty in types {
            if let Some(name) = ty.get("name").and_then(|n| n.as_str()) {
                schema.type_names.push(name.to_string());

                // Extract field names for types tagged as the query/mutation root
                let is_query = schema.query_type.as_deref() == Some(name);
                let is_mutation = schema.mutation_type.as_deref() == Some(name);

                if let Some(fields) = ty.get("fields").and_then(|f| f.as_array()) {
                    for field in fields {
                        if let Some(fname) = field.get("name").and_then(|n| n.as_str()) {
                            if is_query {
                                schema.query_names.push(fname.to_string());
                            }
                            if is_mutation {
                                schema.mutation_names.push(fname.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    schema
}

// Check whether a mutation name contains a dangerous keyword
fn is_dangerous_mutation(name: &str) -> bool {
    let lower = name.to_lowercase();
    DANGEROUS_MUTATION_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

// Test one GraphQL endpoint: introspect, batch, depth
async fn test_endpoint(
    client: reqwest::Client,
    endpoint: String,
    run_introspect: bool,
    run_batch: bool,
    run_depth: bool,
) -> EndpointResult {
    let mut result = EndpointResult {
        endpoint: endpoint.clone(),
        introspection_succeeded: false,
        schema: None,
        dangerous_mutations: Vec::new(),
        batching_enabled: false,
        no_depth_limit: false,
        findings: Vec::new(),
    };

    // ── Introspection ────────────────────────────────────────────────────────
    if run_introspect {
        let resp = client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(INTROSPECTION_QUERY)
            .send()
            .await;

        if let Ok(resp) = resp
            && let Ok(json) = resp.json::<serde_json::Value>().await
            && json.get("data").is_some()
        {
            result.introspection_succeeded = true;
            let schema = parse_schema(&json);

            // Flag dangerous mutations
            for name in &schema.mutation_names {
                if is_dangerous_mutation(name) {
                    result.dangerous_mutations.push(name.clone());
                    result.findings.push(Finding {
                        endpoint: endpoint.clone(),
                        kind: "dangerous-mutation".into(),
                        detail: format!("mutation '{name}' matches dangerous keyword"),
                    });
                }
            }

            result.findings.push(Finding {
                endpoint: endpoint.clone(),
                kind: "introspection-enabled".into(),
                detail: format!(
                    "types={} queries={} mutations={}",
                    schema.type_names.len(),
                    schema.query_names.len(),
                    schema.mutation_names.len()
                ),
            });

            result.schema = Some(schema);
        }
    }

    // ── Batch test ───────────────────────────────────────────────────────────
    if run_batch {
        // Send two identical introspection queries as a JSON array
        let batch_body = format!("[{INTROSPECTION_QUERY},{INTROSPECTION_QUERY}]");
        let resp = client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(batch_body)
            .send()
            .await;

        if let Ok(resp) = resp
            && let Ok(json) = resp.json::<serde_json::Value>().await
        {
            // Batching is confirmed if we get an array of two data responses
            if let Some(arr) = json.as_array() {
                let data_count = arr
                    .iter()
                    .filter(|v| v.get("data").is_some())
                    .count();
                if data_count >= 2 {
                    result.batching_enabled = true;
                    result.findings.push(Finding {
                        endpoint: endpoint.clone(),
                        kind: "batching-enabled".into(),
                        detail: "server accepted and responded to a batched request array".into(),
                    });
                }
            }
        }
    }

    // ── Depth test ───────────────────────────────────────────────────────────
    if run_depth {
        let resp = client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(DEPTH_TEST_QUERY)
            .send()
            .await;

        if let Ok(resp) = resp
            && let Ok(json) = resp.json::<serde_json::Value>().await
        {
            // No depth limit if we get data back rather than an error
            let has_data = json.get("data").is_some();
            let has_error = json
                .get("errors")
                .and_then(|e| e.as_array())
                .map(|e| !e.is_empty())
                .unwrap_or(false);
            if has_data && !has_error {
                result.no_depth_limit = true;
                result.findings.push(Finding {
                    endpoint: endpoint.clone(),
                    kind: "no-depth-limit".into(),
                    detail: "10-level nested query returned data without error".into(),
                });
            }
        }
    }

    result
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Build the endpoint candidate list
    let mut candidates: Vec<String> = Vec::new();
    if let Some(ep) = &args.endpoint {
        candidates.push(ep.clone());
    } else {
        let crawl_candidates = collect_from_crawl(&eng.crawl_dir());
        if !crawl_candidates.is_empty() {
            candidates.extend(crawl_candidates);
        } else {
            eprintln!("mg-graphql: no crawl data — falling back to recon suffix probing");
            candidates.extend(collect_from_recon(&eng.recon_dir()));
        }
    }

    // Deduplicate candidates
    let seen: HashSet<String> = HashSet::new();
    let mut seen = seen;
    candidates.retain(|c| seen.insert(c.clone()));

    if candidates.is_empty() {
        anyhow::bail!(
            "no GraphQL candidates found — run mg-crawl first or provide --endpoint"
        );
    }

    eprintln!(
        "mg-graphql: {} endpoint candidates, concurrency={}",
        candidates.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    // Build reqwest client with timeout and auth headers
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Test all candidates with bounded concurrency
    let mut join_set: JoinSet<EndpointResult> = JoinSet::new();
    let mut all_results: Vec<EndpointResult> = Vec::new();

    let run_introspect = args.introspect;
    let run_batch = args.batch_test;
    let run_depth = args.depth_test;

    for endpoint in candidates {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(r)) = join_set.join_next().await
        {
            all_results.push(r);
        }
        let c = client.clone();
        join_set.spawn(test_endpoint(c, endpoint, run_introspect, run_batch, run_depth));
    }

    // Drain remaining tasks
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);
    let findings_count: usize = all_results.iter().map(|r| r.findings.len()).sum();

    // Print summary
    for result in &all_results {
        if result.introspection_succeeded {
            eprintln!("  [introspection] {}", result.endpoint);
            for m in &result.dangerous_mutations {
                eprintln!("    [dangerous-mutation] {m}");
            }
        }
        if result.batching_enabled {
            eprintln!("  [batching-enabled] {}", result.endpoint);
        }
        if result.no_depth_limit {
            eprintln!("  [no-depth-limit] {}", result.endpoint);
        }
    }

    // Write schema and findings to disk
    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create graphql output dir")?;

    let schemas: Vec<serde_json::Value> = all_results
        .iter()
        .filter_map(|r| {
            r.schema.as_ref().map(|s| {
                json!({
                    "endpoint": r.endpoint,
                    "schema": s,
                })
            })
        })
        .collect();

    let schema_path = output_dir.join(format!("schema-{ts_file}.json"));
    fs::write(
        &schema_path,
        serde_json::to_string_pretty(&schemas).unwrap_or_default(),
    )
    .context("write schema JSON")?;

    let output = GraphqlResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        endpoints_tested: all_results.len(),
        findings_count,
        results: all_results,
    };

    let findings_path = output_dir.join(format!("findings-{ts_file}.json"));
    fs::write(
        &findings_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write findings JSON")?;

    eprintln!(
        "mg-graphql: {} endpoints tested, {} findings — {}",
        output.endpoints_tested,
        output.findings_count,
        findings_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "endpoints={} findings={} ts={ts}",
            output.endpoints_tested, output.findings_count
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_mutation_matches_keywords() {
        assert!(is_dangerous_mutation("deleteUser"));
        assert!(is_dangerous_mutation("removeAccount"));
        assert!(is_dangerous_mutation("updateProfile"));
        assert!(is_dangerous_mutation("createPost"));
        assert!(!is_dangerous_mutation("fetchData"));
        assert!(!is_dangerous_mutation("getUser"));
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        let ts = "2026-05-17T12:00:00Z";
        assert_eq!(ts_for_filename(ts), "2026-05-17T12_00_00Z");
    }

    #[test]
    fn parse_schema_extracts_type_names() {
        let json = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": { "name": "Mutation" },
                    "subscriptionType": null,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [{ "name": "getUser" }]
                        },
                        {
                            "name": "Mutation",
                            "kind": "OBJECT",
                            "fields": [{ "name": "deleteUser" }, { "name": "createPost" }]
                        }
                    ]
                }
            }
        });
        let schema = parse_schema(&json);
        assert_eq!(schema.query_type.as_deref(), Some("Query"));
        assert_eq!(schema.mutation_type.as_deref(), Some("Mutation"));
        assert!(schema.query_names.contains(&"getUser".to_string()));
        assert!(schema.mutation_names.contains(&"deleteUser".to_string()));
        assert!(schema.mutation_names.contains(&"createPost".to_string()));
    }
}
