/*******************************************************************
 * Filename:        js_analyzer.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Static JS analyzer for endpoints, GraphQL, libraries, and internal refs
 * Notes:           Regex-first implementation for bundled/minified assets.
 *                  Keep findings conservative and evidence-linked.
 *******************************************************************/

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::analyze::{EndpointMatch, find_endpoints};

// Aggregated static-analysis output for one JS source
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct JsAnalysis {
    pub endpoints: Vec<EndpointMatch>,
    pub internal_refs: Vec<InternalRef>,
    pub vulnerable_libraries: Vec<VulnerableLibrary>,
    pub graphql_candidates: Vec<GraphqlCandidate>,
}

// Internal network reference extracted from JS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InternalRef {
    pub value: String,
    pub kind: String,
    pub source_url: String,
}

// Vulnerable library/version finding extracted from JS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct VulnerableLibrary {
    pub library: String,
    pub version: String,
    pub vulnerable_below: String,
    pub cve_ids: Vec<String>,
    pub source_url: String,
}

// GraphQL endpoint or schema signal extracted from JS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GraphqlCandidate {
    pub endpoint: String,
    pub source_url: String,
    pub evidence: String,
}

// Compiled regex catalog for static JS analysis
struct JsCatalog {
    fetch_call: Regex,
    axios_call: Regex,
    xhr_open: Regex,
    ajax_url: Regex,
    string_url: Regex,
    internal_domain: Regex,
    internal_ip: Regex,
    libraries: Vec<LibraryPattern>,
}

// One vulnerable library detection rule
struct LibraryPattern {
    library: &'static str,
    vulnerable_below: &'static str,
    cve_ids: &'static [&'static str],
    regex: Regex,
}

static JS_CATALOG: OnceLock<JsCatalog> = OnceLock::new();

// Analyze one JS source string
pub fn analyze_js(js: &str, source_url: &str) -> JsAnalysis {
    let cat = catalog();
    let mut analysis = JsAnalysis {
        endpoints: Vec::new(),
        internal_refs: extract_internal_refs(cat, js, source_url),
        vulnerable_libraries: extract_vulnerable_libraries(cat, js, source_url),
        graphql_candidates: Vec::new(),
    };

    let json_body = js.contains("JSON.stringify") || js.contains("JSON.parse");
    let form_body = js.contains("new FormData") || js.contains(".serialize()");

    for cap in cat.fetch_call.captures_iter(js) {
        if let Some(raw) = cap.get(1).map(|m| m.as_str()) {
            let method = infer_fetch_method(js, cap.get(0).map(|m| m.end()).unwrap_or(0));
            push_endpoint(
                &mut analysis,
                raw,
                source_url,
                &method,
                "js_fetch",
                json_body,
                form_body,
            );
        }
    }

    for cap in cat.axios_call.captures_iter(js) {
        let Some(method) = cap.get(1).map(|m| m.as_str().to_ascii_uppercase()) else {
            continue;
        };
        if let Some(raw) = cap.get(2).map(|m| m.as_str()) {
            push_endpoint(
                &mut analysis,
                raw,
                source_url,
                &method,
                "js_axios",
                json_body,
                form_body,
            );
        }
    }

    for cap in cat.xhr_open.captures_iter(js) {
        let Some(method) = cap.get(1).map(|m| m.as_str().to_ascii_uppercase()) else {
            continue;
        };
        if let Some(raw) = cap.get(2).map(|m| m.as_str()) {
            push_endpoint(
                &mut analysis,
                raw,
                source_url,
                &method,
                "js_xhr",
                json_body,
                form_body,
            );
        }
    }

    for cap in cat.ajax_url.captures_iter(js) {
        if let Some(raw) = cap.get(1).map(|m| m.as_str()) {
            push_endpoint(
                &mut analysis,
                raw,
                source_url,
                "GET",
                "js_ajax",
                json_body,
                form_body,
            );
        }
    }

    for cap in cat.string_url.captures_iter(js) {
        if let Some(raw) = cap.get(1).map(|m| m.as_str()) {
            push_endpoint(
                &mut analysis,
                raw,
                source_url,
                "GET",
                "js_string",
                json_body,
                form_body,
            );
        }
    }

    // Keep legacy high-precision patterns as fallback after richer call-site rows
    analysis.endpoints.extend(find_endpoints(js, source_url));

    if has_graphql_signal(js) {
        if !analysis.endpoints.iter().any(|endpoint| endpoint.graphql) {
            analysis.endpoints.push(EndpointMatch::with_details(
                "/graphql",
                source_url,
                "POST",
                "js_graphql_signal",
                Some("json".into()),
                true,
            ));
        }
        for endpoint in analysis
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.graphql)
        {
            analysis.graphql_candidates.push(GraphqlCandidate {
                endpoint: endpoint.path.clone(),
                source_url: source_url.into(),
                evidence: "graphql token or __schema string in JavaScript".into(),
            });
        }
    }

    dedup_analysis(&mut analysis);
    analysis
}

// Initialize JS regex catalog once
fn catalog() -> &'static JsCatalog {
    JS_CATALOG.get_or_init(|| JsCatalog {
        fetch_call: Regex::new(r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        axios_call: Regex::new(r#"axios\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        xhr_open: Regex::new(
            r#"\.open\s*\(\s*["'`](GET|POST|PUT|PATCH|DELETE)["'`]\s*,\s*["'`]([^"'`]+)["'`]"#,
        )
        .unwrap(),
        ajax_url: Regex::new(r#"\$\.ajax\s*\(\s*\{[^}]{0,800}?url\s*:\s*["'`]([^"'`]+)["'`]"#)
            .unwrap(),
        string_url: Regex::new(r#"["'`]((?:https?://[^"'`\s]+)|(?:/[A-Za-z0-9_./?=&%:-]{2,}))["'`]"#)
            .unwrap(),
        internal_domain: Regex::new(r#"(?i)\b[a-z0-9][a-z0-9.-]*\.(?:internal|corp|local)\b"#)
            .unwrap(),
        internal_ip: Regex::new(
            r#"\b10(?:\.\d{1,3}){3}\b|\b172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b|\b192\.168(?:\.\d{1,3}){2}\b"#,
        )
        .unwrap(),
        libraries: vec![
            LibraryPattern {
                library: "jquery",
                vulnerable_below: "3.5.0",
                cve_ids: &["CVE-2020-11022", "CVE-2020-11023"],
                regex: Regex::new(
                    r#"(?i)(?:jquery(?: JavaScript Library)?[ @v-]*|jQuery\.fn\.jquery\s*=\s*["'])(\d+\.\d+\.\d+)"#,
                )
                .unwrap(),
            },
            LibraryPattern {
                library: "lodash",
                vulnerable_below: "4.17.21",
                cve_ids: &["CVE-2021-23337"],
                regex: Regex::new(
                    r#"(?i)(?:lodash[ @v-]*|_\.VERSION\s*=\s*["'])(\d+\.\d+\.\d+)"#,
                )
                .unwrap(),
            },
            LibraryPattern {
                library: "moment",
                vulnerable_below: "2.29.2",
                cve_ids: &["CVE-2022-24785"],
                regex: Regex::new(
                    r#"(?i)(?:moment(?:\.js)?[ @v-]*|moment\.version\s*=\s*["'])(\d+\.\d+\.\d+)"#,
                )
                .unwrap(),
            },
            LibraryPattern {
                library: "handlebars",
                vulnerable_below: "4.7.7",
                cve_ids: &["CVE-2021-23369"],
                regex: Regex::new(
                    r#"(?i)(?:handlebars(?:\.runtime)?[ @v-]*|Handlebars\.VERSION\s*=\s*["'])(\d+\.\d+\.\d+)"#,
                )
                .unwrap(),
            },
        ],
    })
}

// Add one endpoint if it looks useful for testing
fn push_endpoint(
    analysis: &mut JsAnalysis,
    raw: &str,
    source_url: &str,
    method: &str,
    source: &str,
    json_body: bool,
    form_body: bool,
) {
    let Some(path) = normalize_endpoint(raw, source_url) else {
        return;
    };
    let graphql = is_graphql_path(&path);
    let body_format = if graphql || json_body {
        Some("json".into())
    } else if form_body {
        Some("form".into())
    } else {
        None
    };
    analysis.endpoints.push(EndpointMatch::with_details(
        path,
        source_url,
        method,
        source,
        body_format,
        graphql,
    ));
}

// Infer fetch method from nearby options object
fn infer_fetch_method(js: &str, start: usize) -> String {
    let end = (start + 300).min(js.len());
    let window = &js[start..end];
    let method_re =
        Regex::new(r#"(?i)method\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE)["'`]"#).unwrap();
    method_re
        .captures(window)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_ascii_uppercase())
        .unwrap_or_else(|| "GET".into())
}

// Normalize a raw JS string into an endpoint path or URL
fn normalize_endpoint(raw: &str, source_url: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with("data:")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with('#')
    {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let endpoint = Url::parse(trimmed).ok()?;
        let source = Url::parse(source_url).ok()?;
        if endpoint.host_str() != source.host_str() {
            return None;
        }
        return Some(path_with_query(&endpoint));
    }
    if trimmed.starts_with('/') {
        return Some(trimmed.into());
    }
    None
}

// Return path plus query for a same-host absolute URL
fn path_with_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

// Return true for likely GraphQL endpoints
fn is_graphql_path(path: &str) -> bool {
    path.to_ascii_lowercase().contains("graphql")
}

// Return true when JS contains GraphQL query/schema signals
fn has_graphql_signal(js: &str) -> bool {
    let lower = js.to_ascii_lowercase();
    lower.contains("gql`")
        || lower.contains("__schema")
        || lower.contains("query {")
        || lower.contains("mutation {")
        || lower.contains("/graphql")
}

// Extract internal hostnames and RFC1918 IPs from JS
fn extract_internal_refs(cat: &JsCatalog, js: &str, source_url: &str) -> Vec<InternalRef> {
    let mut refs = Vec::new();
    for cap in cat.internal_domain.captures_iter(js) {
        if let Some(value) = cap.get(0).map(|m| m.as_str().to_ascii_lowercase()) {
            refs.push(InternalRef {
                value,
                kind: "hostname".into(),
                source_url: source_url.into(),
            });
        }
    }
    for cap in cat.internal_ip.captures_iter(js) {
        if let Some(value) = cap.get(0).map(|m| m.as_str().to_string()) {
            refs.push(InternalRef {
                value,
                kind: "rfc1918_ip".into(),
                source_url: source_url.into(),
            });
        }
    }
    refs
}

// Extract vulnerable library versions from JS banners and version assignments
fn extract_vulnerable_libraries(
    cat: &JsCatalog,
    js: &str,
    source_url: &str,
) -> Vec<VulnerableLibrary> {
    let mut libraries = Vec::new();
    for pattern in &cat.libraries {
        for cap in pattern.regex.captures_iter(js) {
            let Some(version) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            if semver_lt(version, pattern.vulnerable_below) {
                libraries.push(VulnerableLibrary {
                    library: pattern.library.into(),
                    version: version.into(),
                    vulnerable_below: pattern.vulnerable_below.into(),
                    cve_ids: pattern.cve_ids.iter().map(|cve| (*cve).into()).collect(),
                    source_url: source_url.into(),
                });
            }
        }
    }
    libraries
}

// Compare dotted numeric versions using missing components as zero
fn semver_lt(left: &str, right: &str) -> bool {
    let parse = |value: &str| -> [u64; 3] {
        let mut out = [0, 0, 0];
        for (idx, part) in value.split('.').take(3).enumerate() {
            out[idx] = part.parse::<u64>().unwrap_or(0);
        }
        out
    };
    parse(left) < parse(right)
}

// Deduplicate analysis rows while preserving first-seen order
fn dedup_analysis(analysis: &mut JsAnalysis) {
    let mut endpoint_seen = HashSet::new();
    analysis.endpoints.retain(|endpoint| {
        endpoint_seen.insert((endpoint.path.clone(), endpoint.source_url.clone()))
    });
    let mut ref_seen = HashSet::new();
    analysis
        .internal_refs
        .retain(|entry| ref_seen.insert(entry.clone()));
    let mut lib_seen = HashSet::new();
    analysis
        .vulnerable_libraries
        .retain(|entry| lib_seen.insert(entry.clone()));
    let mut gql_seen = HashSet::new();
    analysis
        .graphql_candidates
        .retain(|entry| gql_seen.insert(entry.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_graphql_endpoint_with_json_body() {
        let js = r#"fetch("/graphql", { method: "POST", body: JSON.stringify({query:"{__schema{types{name}}}"}) });"#;
        let analysis = analyze_js(js, "https://example.com/app.js");
        let endpoint = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.path == "/graphql")
            .unwrap();
        assert_eq!(endpoint.method, "POST");
        assert_eq!(endpoint.body_format.as_deref(), Some("json"));
        assert!(endpoint.graphql);
        assert_eq!(analysis.graphql_candidates.len(), 1);
    }

    #[test]
    fn detects_vulnerable_jquery() {
        let js = "/*! jQuery JavaScript Library v3.4.1 */";
        let analysis = analyze_js(js, "https://example.com/jquery.js");
        assert!(
            analysis
                .vulnerable_libraries
                .iter()
                .any(|lib| lib.library == "jquery" && lib.version == "3.4.1")
        );
    }

    #[test]
    fn detects_internal_refs() {
        let js = r#"const a = "api.internal"; const b = "http://10.1.2.3/admin";"#;
        let analysis = analyze_js(js, "https://example.com/app.js");
        assert!(
            analysis
                .internal_refs
                .iter()
                .any(|r| r.value == "api.internal")
        );
        assert!(analysis.internal_refs.iter().any(|r| r.value == "10.1.2.3"));
    }

    #[test]
    fn external_absolute_urls_are_not_endpoint_rows() {
        let js =
            r#"const a = "https://other.example/api"; const b = "https://example.com/api?x=1";"#;
        let analysis = analyze_js(js, "https://example.com/app.js");
        assert!(analysis.endpoints.iter().any(|e| e.path == "/api?x=1"));
        assert!(
            !analysis
                .endpoints
                .iter()
                .any(|e| e.path.contains("other.example"))
        );
    }
}
