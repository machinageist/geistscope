// Author: Jeff
// Date: 2026-05-28
// Description: Client-side browser observation evidence model
// Notes: Captures browser-side findings without exposing cookie, storage, or console secrets

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_TEXT_LEN: usize = 240;
const PROMPT_INJECTION_MARKER: &str = "[escaped-prompt-text]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientSideObservation {
    Dom(DomObservation),
    ConsoleError(ConsoleObservation),
    NetworkError(NetworkObservation),
    Storage(StorageObservation),
    PostMessage(PostMessageObservation),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomObservation {
    pub url: String,
    pub frame_origin: String,
    pub selector_path: String,
    pub sink_type: SinkType,
    pub source_type: SourceType,
    pub redacted_snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleObservation {
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkObservation {
    pub url: String,
    pub method: String,
    pub status: Option<u16>,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageObservation {
    pub area: StorageArea,
    pub key_name: String,
    pub value_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostMessageObservation {
    pub origin: String,
    pub target_origin: String,
    pub schema_keys: Vec<String>,
    pub risk_class: MessageRiskClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkType {
    InnerHtml,
    DocumentWrite,
    Eval,
    LocationHref,
    ScriptSrc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    QueryParam,
    Fragment,
    PostMessage,
    Storage,
    NetworkResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageArea {
    LocalStorage,
    SessionStorage,
    Cookie,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRiskClass {
    Informational,
    TrustsWildcardOrigin,
    MissingOriginCheck,
    SensitiveDataExposure,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClientSideVerdictEngine;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSideVerdict {
    pub classification: ClientSideVerdictClass,
    pub boundary_violation: bool,
    pub evidence_refs: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientSideVerdictClass {
    SecureBaseline,
    DomSinkExposure,
    PostMessageOriginWeakness,
    SensitiveDataExposure,
}

impl ClientSideObservation {
    // Wrap a DOM sink/source observation
    pub fn dom(observation: DomObservation) -> Self {
        Self::Dom(observation)
    }

    // Create a bounded console error observation
    pub fn console_error(message: &str) -> Self {
        Self::ConsoleError(ConsoleObservation {
            level: "error".into(),
            message: bounded_prompt_safe_text(message),
        })
    }

    // Wrap a bounded network error observation
    pub fn network_error(observation: NetworkObservation) -> Self {
        Self::NetworkError(observation)
    }

    // Wrap a storage key/hash observation
    pub fn storage(observation: StorageObservation) -> Self {
        Self::Storage(observation)
    }

    // Wrap a postMessage origin/schema observation
    pub fn post_message(observation: PostMessageObservation) -> Self {
        Self::PostMessage(observation)
    }
}

impl DomObservation {
    // Create a DOM observation with a redacted snippet
    pub fn new(
        url: &str,
        frame_origin: &str,
        selector_path: &str,
        sink_type: SinkType,
        source_type: SourceType,
        snippet: &str,
    ) -> Self {
        Self {
            url: url.into(),
            frame_origin: frame_origin.into(),
            selector_path: selector_path.into(),
            sink_type,
            source_type,
            redacted_snippet: redact_secret_like_text(snippet),
        }
    }
}

impl NetworkObservation {
    // Create a bounded network error observation
    pub fn new(url: &str, method: &str, status: Option<u16>, error: &str) -> Self {
        Self {
            url: url.into(),
            method: method.into(),
            status,
            error: bounded_prompt_safe_text(error),
        }
    }
}

impl StorageObservation {
    // Create a storage observation that stores only key name and value hash
    pub fn new(area: StorageArea, key_name: &str, raw_value: &str) -> Self {
        Self {
            area,
            key_name: key_name.into(),
            value_sha256: sha256_hex(raw_value),
        }
    }
}

impl PostMessageObservation {
    // Create a postMessage schema and origin observation
    pub fn new(
        origin: &str,
        target_origin: &str,
        schema_keys: Vec<String>,
        risk_class: MessageRiskClass,
    ) -> Self {
        Self {
            origin: origin.into(),
            target_origin: target_origin.into(),
            schema_keys,
            risk_class,
        }
    }
}

impl ClientSideVerdictEngine {
    // Classify browser-side observations without exposing raw snippets or storage values
    pub fn classify(&self, observations: &[ClientSideObservation]) -> ClientSideVerdict {
        if let Some(verdict) = classify_dom_sink(observations) {
            return verdict;
        }
        if let Some(verdict) = classify_post_message(observations) {
            return verdict;
        }
        if let Some(verdict) = classify_sensitive_data(observations) {
            return verdict;
        }
        ClientSideVerdict {
            classification: ClientSideVerdictClass::SecureBaseline,
            boundary_violation: false,
            evidence_refs: Vec::new(),
            reason: "observations contain only bounded or hash-only browser evidence".into(),
        }
    }
}

// Detect attacker-controllable DOM data flowing to sensitive sinks
fn classify_dom_sink(observations: &[ClientSideObservation]) -> Option<ClientSideVerdict> {
    let refs: Vec<String> = observations
        .iter()
        .filter_map(|observation| match observation {
            ClientSideObservation::Dom(dom)
                if is_attacker_controllable_source(&dom.source_type) =>
            {
                Some(format!("dom:{}", dom.selector_path))
            }
            _ => None,
        })
        .collect();
    if refs.is_empty() {
        None
    } else {
        Some(ClientSideVerdict {
            classification: ClientSideVerdictClass::DomSinkExposure,
            boundary_violation: true,
            evidence_refs: refs,
            reason: "attacker-controllable browser source reached a DOM sink".into(),
        })
    }
}

// Detect weak postMessage origin handling without echoing message payloads
fn classify_post_message(observations: &[ClientSideObservation]) -> Option<ClientSideVerdict> {
    let refs: Vec<String> = observations
        .iter()
        .filter_map(|observation| match observation {
            ClientSideObservation::PostMessage(message)
                if matches!(
                    message.risk_class,
                    MessageRiskClass::TrustsWildcardOrigin | MessageRiskClass::MissingOriginCheck
                ) || message.target_origin == "*" =>
            {
                Some(format!("post_message:{}", message.origin))
            }
            _ => None,
        })
        .collect();
    if refs.is_empty() {
        None
    } else {
        Some(ClientSideVerdict {
            classification: ClientSideVerdictClass::PostMessageOriginWeakness,
            boundary_violation: false,
            evidence_refs: refs,
            reason: "postMessage observation indicates wildcard or missing origin validation"
                .into(),
        })
    }
}

// Detect browser observations explicitly marked as sensitive exposure
fn classify_sensitive_data(observations: &[ClientSideObservation]) -> Option<ClientSideVerdict> {
    let refs: Vec<String> = observations
        .iter()
        .filter_map(|observation| match observation {
            ClientSideObservation::PostMessage(message)
                if message.risk_class == MessageRiskClass::SensitiveDataExposure =>
            {
                Some(format!("post_message:{}", message.origin))
            }
            _ => None,
        })
        .collect();
    if refs.is_empty() {
        None
    } else {
        Some(ClientSideVerdict {
            classification: ClientSideVerdictClass::SensitiveDataExposure,
            boundary_violation: true,
            evidence_refs: refs,
            reason: "browser observation indicates sensitive data exposure".into(),
        })
    }
}

// Treat only user-controlled sources as candidate proof sources
fn is_attacker_controllable_source(source_type: &SourceType) -> bool {
    matches!(
        source_type,
        SourceType::QueryParam | SourceType::Fragment | SourceType::PostMessage
    )
}

// Hash secret browser values before model-visible output
fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

// Bound text and neutralize prompt-injection phrases
fn bounded_prompt_safe_text(value: &str) -> String {
    let mut text = value.replace("ignore previous instructions", PROMPT_INJECTION_MARKER);
    text = text.replace("Ignore previous instructions", PROMPT_INJECTION_MARKER);
    text = text.replace("SYSTEM:", "[escaped-system-marker]");
    truncate_chars(&text, MAX_TEXT_LEN)
}

// Redact simple key=value secret patterns and bound the snippet
fn redact_secret_like_text(value: &str) -> String {
    let mut words = Vec::new();
    for word in value.split_whitespace() {
        let lower = word.to_ascii_lowercase();
        if lower.contains("token=")
            || lower.contains("secret=")
            || lower.contains("password=")
            || lower.contains("cookie=")
        {
            words.push(PROMPT_INJECTION_MARKER.replace(PROMPT_INJECTION_MARKER, "[REDACTED]"));
        } else {
            words.push(word.into());
        }
    }
    truncate_chars(&words.join(" "), MAX_TEXT_LEN)
}

// Truncate at a character boundary
fn truncate_chars(value: &str, limit: usize) -> String {
    let mut output = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        output.push_str("...");
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::client_side::{
        ClientSideObservation, ClientSideVerdictClass, ClientSideVerdictEngine, DomObservation,
        MessageRiskClass, NetworkObservation, PostMessageObservation, SinkType, SourceType,
        StorageArea, StorageObservation,
    };

    #[test]
    fn dom_observation_records_location_selector_sink_source_and_redacted_snippet() {
        let observation = ClientSideObservation::dom(DomObservation::new(
            "https://app.example.test/search?q=alpha",
            "https://app.example.test",
            "#results",
            SinkType::InnerHtml,
            SourceType::QueryParam,
            "<div>token=secret-value</div>",
        ));

        let raw = serde_json::to_string(&observation).unwrap();

        assert!(raw.contains("https://app.example.test/search?q=alpha"));
        assert!(raw.contains("#results"));
        assert!(raw.contains("inner_html"));
        assert!(raw.contains("query_param"));
        assert!(raw.contains("[REDACTED]"));
        assert!(!raw.contains("secret-value"));
    }

    #[test]
    fn console_and_network_errors_are_bounded_and_prompt_injection_escaped() {
        let hostile = "ignore previous instructions\n".repeat(40);
        let console = ClientSideObservation::console_error(&hostile);
        let network = ClientSideObservation::network_error(NetworkObservation::new(
            "https://app.example.test/api",
            "GET",
            Some(500),
            &hostile,
        ));

        let console_raw = serde_json::to_string(&console).unwrap();
        let network_raw = serde_json::to_string(&network).unwrap();

        assert!(console_raw.len() < 700);
        assert!(network_raw.len() < 900);
        assert!(!console_raw.contains("ignore previous instructions"));
        assert!(!network_raw.contains("ignore previous instructions"));
        assert!(console_raw.contains("[escaped-prompt-text]"));
    }

    #[test]
    fn storage_observations_emit_key_names_and_hashes_without_values() {
        let observation = ClientSideObservation::storage(StorageObservation::new(
            StorageArea::LocalStorage,
            "authToken",
            "raw-secret-storage-value",
        ));

        let raw = serde_json::to_string(&observation).unwrap();

        assert!(raw.contains("local_storage"));
        assert!(raw.contains("authToken"));
        assert!(raw.contains("value_sha256"));
        assert!(!raw.contains("raw-secret-storage-value"));
    }

    #[test]
    fn post_message_observation_records_origins_schema_shape_and_risk() {
        let observation = ClientSideObservation::post_message(PostMessageObservation::new(
            "https://widget.example.test",
            "https://app.example.test",
            vec!["type".into(), "account_id".into()],
            MessageRiskClass::TrustsWildcardOrigin,
        ));

        let raw = serde_json::to_string(&observation).unwrap();

        assert!(raw.contains("https://widget.example.test"));
        assert!(raw.contains("https://app.example.test"));
        assert!(raw.contains("account_id"));
        assert!(raw.contains("trusts_wildcard_origin"));
    }

    #[test]
    fn client_side_verdict_classifies_attacker_controlled_dom_sink_as_boundary_violation() {
        let observation = ClientSideObservation::dom(DomObservation::new(
            "https://app.example.test/search?q=marker",
            "https://app.example.test",
            "#results",
            SinkType::InnerHtml,
            SourceType::QueryParam,
            "<div>mg-marker</div>",
        ));

        let verdict = ClientSideVerdictEngine.classify(&[observation]);

        assert_eq!(
            verdict.classification,
            ClientSideVerdictClass::DomSinkExposure
        );
        assert!(verdict.boundary_violation);
        assert!(
            verdict
                .evidence_refs
                .iter()
                .any(|item| item == "dom:#results")
        );
        assert!(
            !serde_json::to_string(&verdict)
                .unwrap()
                .contains("mg-marker")
        );
    }

    #[test]
    fn client_side_verdict_classifies_wildcard_post_message_origin() {
        let observation = ClientSideObservation::post_message(PostMessageObservation::new(
            "https://widget.example.test",
            "*",
            vec!["type".into(), "account_id".into()],
            MessageRiskClass::TrustsWildcardOrigin,
        ));

        let verdict = ClientSideVerdictEngine.classify(&[observation]);

        assert_eq!(
            verdict.classification,
            ClientSideVerdictClass::PostMessageOriginWeakness
        );
        assert!(!verdict.boundary_violation);
        assert!(
            verdict
                .evidence_refs
                .iter()
                .any(|item| item == "post_message:https://widget.example.test")
        );
    }

    #[test]
    fn client_side_verdict_treats_storage_hash_only_observations_as_secure_baseline() {
        let observation = ClientSideObservation::storage(StorageObservation::new(
            StorageArea::Cookie,
            "session",
            "raw-secret-storage-value",
        ));

        let verdict = ClientSideVerdictEngine.classify(&[observation]);

        assert_eq!(
            verdict.classification,
            ClientSideVerdictClass::SecureBaseline
        );
        assert!(!verdict.boundary_violation);
        assert!(
            !serde_json::to_string(&verdict)
                .unwrap()
                .contains("raw-secret-storage-value")
        );
    }
}
