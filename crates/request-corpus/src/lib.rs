// Author: Jeff
// Date: 2026-05-29
// Description: Request corpus candidate model for safe autonomous hunting
// Notes: Builds inert candidate metadata only; replay/execution belongs to later gated crates

use std::collections::{BTreeMap, BTreeSet};

use browser_lab::client_side::{ClientSideObservation, MessageRiskClass, SourceType};
use engagement::TrafficRecord;
use serde::{Deserialize, Serialize};

// Candidate builders group local traffic and browser observations without executing requests
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CandidateBuilder {
    enabled_analyzers: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusCandidate {
    pub id: String,
    pub kind: CandidateKind,
    pub source: CandidateSource,
    pub safety: CandidateSafety,
    pub state_change: CandidateStateChange,
    pub autonomous_safe: bool,
    #[serde(default)]
    pub record_ids: Vec<String>,
    #[serde(default)]
    pub observation_ids: Vec<String>,
    #[serde(default)]
    pub injection_params: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    CrossTenantRead,
    StateChangingOperation,
    DomXssCandidate,
    ClientSideOriginCandidate,
    ServerSideRequestTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    Traffic,
    ClientSideObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSafety {
    ReadOnlyProof,
    BrowserOnlyProof,
    RequiresApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStateChange {
    ReadOnly,
    BrowserObservationOnly,
    StateChanging,
}

impl CandidateBuilder {
    // Return analyzer names that are explicitly enabled for this builder
    pub fn enabled_analyzers(&self) -> &[&'static str] {
        &self.enabled_analyzers
    }

    // Build authorization candidates from already-captured traffic metadata
    pub fn from_traffic_records(&self, records: &[TrafficRecord]) -> Vec<CorpusCandidate> {
        let mut candidates = Vec::new();
        let mut comparable_reads: BTreeMap<String, Vec<&TrafficRecord>> = BTreeMap::new();

        for record in records {
            if is_read_only_method(&record.method) {
                comparable_reads
                    .entry(comparison_key(record))
                    .or_default()
                    .push(record);
            } else {
                candidates.push(state_changing_candidate(record));
            }
            // Flag server-side request sinks regardless of method, gated behind approval
            if let Some(candidate) = server_side_request_candidate(record) {
                candidates.push(candidate);
            }
        }

        for grouped_records in comparable_reads.values() {
            if has_multiple_tenants(grouped_records) && grouped_records.len() >= 2 {
                candidates.push(cross_tenant_read_candidate(grouped_records));
            }
        }

        candidates
    }

    // Build browser/client-side candidates from local observations only
    pub fn from_client_side_observations(
        &self,
        observations: &[ClientSideObservation],
    ) -> Vec<CorpusCandidate> {
        let mut candidates = Vec::new();

        for (index, observation) in observations.iter().enumerate() {
            match observation {
                ClientSideObservation::Dom(dom) if is_attacker_controllable(&dom.source_type) => {
                    candidates.push(CorpusCandidate {
                        id: format!("client-side-dom-{index}"),
                        kind: CandidateKind::DomXssCandidate,
                        source: CandidateSource::ClientSideObservation,
                        safety: CandidateSafety::BrowserOnlyProof,
                        state_change: CandidateStateChange::BrowserObservationOnly,
                        autonomous_safe: true,
                        record_ids: Vec::new(),
                        observation_ids: vec![format!("observation-{index}")],
                        injection_params: Vec::new(),
                        summary: format!(
                            "attacker-controllable {:?} reaches {:?} at {}",
                            dom.source_type, dom.sink_type, dom.selector_path
                        ),
                    });
                }
                ClientSideObservation::Dom(_) => {}
                ClientSideObservation::PostMessage(message)
                    if message.target_origin == "*"
                        || message.risk_class == MessageRiskClass::TrustsWildcardOrigin =>
                {
                    candidates.push(CorpusCandidate {
                        id: format!("client-side-origin-{index}"),
                        kind: CandidateKind::ClientSideOriginCandidate,
                        source: CandidateSource::ClientSideObservation,
                        safety: CandidateSafety::BrowserOnlyProof,
                        state_change: CandidateStateChange::BrowserObservationOnly,
                        autonomous_safe: true,
                        record_ids: Vec::new(),
                        observation_ids: vec![format!("observation-{index}")],
                        injection_params: Vec::new(),
                        summary: format!(
                            "postMessage target origin `{}` requires origin-bound validation",
                            message.target_origin
                        ),
                    });
                }
                _ => {}
            }
        }

        candidates
    }
}

// Optional analyzers live outside the core candidate grouping path
pub mod analyzers {
    pub mod graphql {
        use base64::{Engine as _, engine::general_purpose};
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct GraphQlGlobalId {
            pub scheme: String,
            pub object_type: String,
            pub object_id: String,
        }

        // Decode a Relay-style GraphQL global ID without enabling the analyzer by default
        pub fn decode_global_id(value: &str) -> Option<GraphQlGlobalId> {
            let decoded = if value.starts_with("gid://") {
                value.to_string()
            } else {
                let bytes = general_purpose::STANDARD.decode(value).ok()?;
                String::from_utf8(bytes).ok()?
            };
            let raw = decoded.strip_prefix("gid://")?;
            let mut parts = raw.split('/');
            let scheme = parts.next()?.to_string();
            let object_type = parts.next()?.to_string();
            let object_id = parts.next()?.to_string();

            if object_type.is_empty() || object_id.is_empty() {
                return None;
            }

            Some(GraphQlGlobalId {
                scheme,
                object_type,
                object_id,
            })
        }
    }
}

// Decide whether an HTTP method is read-only for candidate grouping
fn is_read_only_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

// Create a stable comparable traffic key for same endpoint observations
fn comparison_key(record: &TrafficRecord) -> String {
    format!(
        "{} {}://{}{}?{}",
        record.method.to_ascii_uppercase(),
        record.scheme,
        record.host,
        record.path,
        record.query.clone().unwrap_or_default()
    )
}

// Check whether grouped records cross controlled tenant labels
fn has_multiple_tenants(records: &[&TrafficRecord]) -> bool {
    records
        .iter()
        .filter_map(|record| record.tenant_id.as_deref())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

// Create a read-only cross-tenant candidate from comparable traffic records
fn cross_tenant_read_candidate(records: &[&TrafficRecord]) -> CorpusCandidate {
    let record_ids = records
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();

    CorpusCandidate {
        id: format!("cross-tenant-read-{}", stable_suffix(&record_ids)),
        kind: CandidateKind::CrossTenantRead,
        source: CandidateSource::Traffic,
        safety: CandidateSafety::ReadOnlyProof,
        state_change: CandidateStateChange::ReadOnly,
        autonomous_safe: true,
        record_ids,
        observation_ids: Vec::new(),
        injection_params: Vec::new(),
        summary: "comparable read-only traffic crosses controlled tenant labels".into(),
    }
}

// Create a non-autonomous state-changing candidate for operator review
fn state_changing_candidate(record: &TrafficRecord) -> CorpusCandidate {
    CorpusCandidate {
        id: format!("state-changing-{}", record.id),
        kind: CandidateKind::StateChangingOperation,
        source: CandidateSource::Traffic,
        safety: CandidateSafety::RequiresApproval,
        state_change: CandidateStateChange::StateChanging,
        autonomous_safe: false,
        record_ids: vec![record.id.clone()],
        observation_ids: Vec::new(),
        injection_params: Vec::new(),
        summary: format!(
            "{} {} is state-changing and requires explicit approval before replay",
            record.method.to_ascii_uppercase(),
            record.path
        ),
    }
}

// Parameter names that commonly carry a server-fetched URL or host
const SSRF_PRONE_PARAM_NAMES: &[&str] = &[
    "url",
    "uri",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return_url",
    "returnto",
    "next",
    "continue",
    "callback",
    "webhook",
    "fetch",
    "feed",
    "host",
    "domain",
    "site",
    "target",
    "remote",
    "proxy",
    "image",
    "image_url",
    "imageurl",
    "img",
    "load",
    "file_url",
];

// Build a server-side request target candidate when a record exposes SSRF-prone input
fn server_side_request_candidate(record: &TrafficRecord) -> Option<CorpusCandidate> {
    let injection_params = ssrf_injection_params(record);
    if injection_params.is_empty() {
        return None;
    }
    // Mirror the record method so a mutating replay still surfaces as state-changing
    let state_change = if is_read_only_method(&record.method) {
        CandidateStateChange::ReadOnly
    } else {
        CandidateStateChange::StateChanging
    };
    let summary = format!(
        "{} {} exposes server-fetched input on [{}]; requires approval before an SSRF probe",
        record.method.to_ascii_uppercase(),
        record.path,
        injection_params.join(", ")
    );
    Some(CorpusCandidate {
        id: format!("ssrf-{}", record.id),
        kind: CandidateKind::ServerSideRequestTarget,
        source: CandidateSource::Traffic,
        safety: CandidateSafety::RequiresApproval,
        state_change,
        autonomous_safe: false,
        record_ids: vec![record.id.clone()],
        observation_ids: Vec::new(),
        injection_params,
        summary,
    })
}

// Collect distinct SSRF-prone parameter names from a record's query and param names
fn ssrf_injection_params(record: &TrafficRecord) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    // Query pairs expose values, so match on a prone name or a URL-shaped value
    if let Ok(parsed) = url::Url::parse(&record.url) {
        for (name, value) in parsed.query_pairs() {
            if is_ssrf_prone_name(&name) || value_looks_like_url(&value) {
                names.insert(name.into_owned());
            }
        }
    }
    // Param-name list also covers body parameters whose values were not captured
    for name in &record.params {
        if is_ssrf_prone_name(name) {
            names.insert(name.clone());
        }
    }
    names.into_iter().collect()
}

// Check whether a parameter name is a known server-side request sink
fn is_ssrf_prone_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    SSRF_PRONE_PARAM_NAMES.contains(&lowered.as_str())
}

// Check whether a parameter value looks like an absolute or scheme-relative URL
fn value_looks_like_url(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("//")
        || trimmed.contains("://")
}

// Check whether a browser source can be controlled by an attacker/test marker
fn is_attacker_controllable(source_type: &SourceType) -> bool {
    matches!(
        source_type,
        SourceType::QueryParam
            | SourceType::Fragment
            | SourceType::PostMessage
            | SourceType::Storage
    )
}

// Build a deterministic candidate suffix without hashing dependencies
fn stable_suffix(values: &[String]) -> String {
    values.join("+").replace('/', "-")
}

#[cfg(test)]
mod tests {
    use browser_lab::client_side::{
        ClientSideObservation, DomObservation, MessageRiskClass, PostMessageObservation, SinkType,
        SourceType,
    };
    use engagement::{AuthState, TrafficRecord, TrafficRiskClass};

    use crate::{
        CandidateBuilder, CandidateKind, CandidateSafety, CandidateSource, CandidateStateChange,
        analyzers,
    };

    #[test]
    fn comparable_ab_gets_become_cross_tenant_read_candidate() {
        let records = vec![
            traffic_record(
                "alice-read",
                "GET",
                "https://app.example.test/api/projects/123",
                Some("alice"),
                Some("tenant-a"),
            ),
            traffic_record(
                "bob-read",
                "GET",
                "https://app.example.test/api/projects/123",
                Some("bob"),
                Some("tenant-b"),
            ),
        ];

        let candidates = CandidateBuilder::default().from_traffic_records(&records);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::CrossTenantRead);
        assert_eq!(candidates[0].safety, CandidateSafety::ReadOnlyProof);
        assert_eq!(candidates[0].state_change, CandidateStateChange::ReadOnly);
        assert_eq!(candidates[0].source, CandidateSource::Traffic);
        assert_eq!(candidates[0].record_ids, vec!["alice-read", "bob-read"]);
    }

    #[test]
    fn post_product_creation_is_state_changing_and_not_autonomous() {
        let records = vec![traffic_record(
            "create-product",
            "POST",
            "https://app.example.test/api/products",
            Some("alice"),
            Some("tenant-a"),
        )];

        let candidates = CandidateBuilder::default().from_traffic_records(&records);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::StateChangingOperation);
        assert_eq!(
            candidates[0].state_change,
            CandidateStateChange::StateChanging
        );
        assert_eq!(candidates[0].safety, CandidateSafety::RequiresApproval);
        assert!(!candidates[0].autonomous_safe);
    }

    #[test]
    fn graphql_global_ids_are_optional_analyzer_not_core_logic() {
        let encoded = "Z2lkOi8vZXhhbXBsZS9Qcm9kdWN0LzQy";
        let analysis = analyzers::graphql::decode_global_id(encoded).unwrap();

        assert_eq!(analysis.object_type, "Product");
        assert_eq!(analysis.object_id, "42");
        assert!(
            !CandidateBuilder::default()
                .enabled_analyzers()
                .contains(&"graphql")
        );
    }

    #[test]
    fn attacker_controllable_dom_sink_becomes_dom_xss_candidate() {
        let observations = vec![ClientSideObservation::dom(DomObservation::new(
            "https://app.example.test/search?q=marker",
            "https://app.example.test",
            "#results",
            SinkType::InnerHtml,
            SourceType::QueryParam,
            "marker",
        ))];

        let candidates = CandidateBuilder::default().from_client_side_observations(&observations);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::DomXssCandidate);
        assert_eq!(candidates[0].safety, CandidateSafety::BrowserOnlyProof);
        assert!(candidates[0].autonomous_safe);
    }

    #[test]
    fn non_attacker_controllable_dom_sink_is_not_candidate() {
        let observations = vec![ClientSideObservation::dom(DomObservation::new(
            "https://app.example.test/dashboard",
            "https://app.example.test",
            "#server-rendered",
            SinkType::InnerHtml,
            SourceType::NetworkResponse,
            "server controlled",
        ))];

        let candidates = CandidateBuilder::default().from_client_side_observations(&observations);

        assert!(candidates.is_empty());
    }

    #[test]
    fn wildcard_post_message_origin_becomes_client_side_origin_candidate() {
        let observations = vec![ClientSideObservation::post_message(
            PostMessageObservation::new(
                "https://app.example.test",
                "*",
                vec!["action".into(), "token".into()],
                MessageRiskClass::TrustsWildcardOrigin,
            ),
        )];

        let candidates = CandidateBuilder::default().from_client_side_observations(&observations);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::ClientSideOriginCandidate);
        assert_eq!(candidates[0].safety, CandidateSafety::BrowserOnlyProof);
    }

    #[test]
    fn ssrf_prone_url_param_becomes_server_side_request_target_candidate() {
        let records = vec![traffic_record_with_params(
            "fetch-image",
            "GET",
            "https://app.example.test/api/fetch?url=http://169.254.169.254/latest/meta-data/",
            &["url"],
        )];

        let candidates = CandidateBuilder::default().from_traffic_records(&records);
        let ssrf: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate.kind == CandidateKind::ServerSideRequestTarget)
            .collect();

        assert_eq!(ssrf.len(), 1);
        assert_eq!(ssrf[0].safety, CandidateSafety::RequiresApproval);
        assert!(!ssrf[0].autonomous_safe);
        assert_eq!(ssrf[0].injection_params, vec!["url".to_string()]);
        assert_eq!(ssrf[0].record_ids, vec!["fetch-image".to_string()]);
    }

    #[test]
    fn ssrf_prone_param_detected_by_value_even_with_unremarkable_name() {
        let records = vec![traffic_record_with_params(
            "next-redirect",
            "GET",
            "https://app.example.test/go?next=https://internal.svc.local/admin",
            &["next"],
        )];

        let candidates = CandidateBuilder::default().from_traffic_records(&records);
        let ssrf: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate.kind == CandidateKind::ServerSideRequestTarget)
            .collect();

        assert_eq!(ssrf.len(), 1);
        assert_eq!(ssrf[0].injection_params, vec!["next".to_string()]);
    }

    #[test]
    fn benign_search_param_is_not_ssrf_candidate() {
        let records = vec![traffic_record_with_params(
            "search",
            "GET",
            "https://app.example.test/search?q=hello",
            &["q"],
        )];

        let candidates = CandidateBuilder::default().from_traffic_records(&records);

        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.kind != CandidateKind::ServerSideRequestTarget)
        );
    }

    fn traffic_record_with_params(
        id: &str,
        method: &str,
        url: &str,
        params: &[&str],
    ) -> TrafficRecord {
        let mut record = traffic_record(id, method, url, None, None);
        record.params = params.iter().map(|param| param.to_string()).collect();
        record
    }

    fn traffic_record(
        id: &str,
        method: &str,
        url: &str,
        identity_id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> TrafficRecord {
        let parsed = url::Url::parse(url).unwrap();
        TrafficRecord {
            id: id.into(),
            source: "test".into(),
            source_file: None,
            captured_at: "2026-05-29T00:00:00Z".into(),
            imported_at: "2026-05-29T00:00:00Z".into(),
            method: method.into(),
            url: url.into(),
            host: parsed.host_str().unwrap().into(),
            path: parsed.path().into(),
            scheme: parsed.scheme().into(),
            port: parsed.port(),
            query: parsed.query().map(str::to_owned),
            session_id: identity_id.map(|id| format!("session-{id}")),
            identity_id: identity_id.map(str::to_owned),
            role_id: None,
            tenant_id: tenant_id.map(str::to_owned),
            operation: None,
            scope_decision: Some("in_scope".into()),
            risk_class: TrafficRiskClass::Authorization,
            tags: Vec::new(),
            request_sha256: String::new(),
            response_sha256: String::new(),
            params: Vec::new(),
            request_headers: Vec::new(),
            request_body: None,
            response: None,
            auth_state: AuthState::Authenticated,
        }
    }
}
