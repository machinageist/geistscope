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
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    CrossTenantRead,
    StateChangingOperation,
    DomXssCandidate,
    ClientSideOriginCandidate,
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
        summary: format!(
            "{} {} is state-changing and requires explicit approval before replay",
            record.method.to_ascii_uppercase(),
            record.path
        ),
    }
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
