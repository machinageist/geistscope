// Author: Jeff
// Date: 2026-05-28
// Description: Proxy capture library skeleton for autonomous hunting traffic collection
// Notes: Safe scaffolding only; CONNECT/MITM behavior waits for CA lifecycle and policy gates

use ed25519_dalek::{Signer, SigningKey};
use engagement::{
    ArtifactStore, ArtifactWriteRecord, CaptureProvenanceError, CaptureVerifier, Engagement,
    EngagementError, SignedCaptureClaims, SignedCapturedRequestEvidence,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use zeroize::Zeroizing;

const DEFAULT_PROXY_PORT: u16 = 8080;
const LABEL_PREFIX: &str = "x-mg-";
const ARTIFACT_DIR: &str = "traffic/proxy-captures";
const PROVENANCE_ARTIFACT_DIR: &str = "traffic/capture-provenance";
const ED25519_SECRET_KEY_LENGTH: usize = 32;

// Hold the private Ed25519 capability available only to trusted proxy capture integration
pub struct CaptureSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl CaptureSigner {
    // Load one signing capability from trusted process configuration
    pub fn from_bytes(
        key_id: impl Into<String>,
        secret_key: &[u8],
    ) -> Result<Self, CaptureSigningError> {
        let key_id = key_id.into();
        if secret_key.len() != ED25519_SECRET_KEY_LENGTH {
            return Err(CaptureSigningError::MalformedSecretKey);
        }
        let mut seed = Zeroizing::new([0_u8; ED25519_SECRET_KEY_LENGTH]);
        seed.copy_from_slice(secret_key);
        let signing_key = SigningKey::from_bytes(&seed);
        CaptureVerifier::from_bytes(&key_id, signing_key.verifying_key().as_bytes())?;
        Ok(Self {
            key_id,
            signing_key,
        })
    }

    // Export only the public verification capability for trusted process configuration
    pub fn verifier(&self) -> Result<CaptureVerifier, CaptureSigningError> {
        Ok(CaptureVerifier::from_bytes(
            &self.key_id,
            self.signing_key.verifying_key().as_bytes(),
        )?)
    }

    // Sign one newly captured exact GET request with a random 128-bit capture identifier
    pub fn sign_request(
        &self,
        engagement_id: impl Into<String>,
        request_id: impl Into<String>,
        canonical_url: impl Into<String>,
    ) -> Result<SignedCapturedRequestEvidence, CaptureSigningError> {
        let capture_id = uuid::Uuid::new_v4().simple().to_string();
        let claims = SignedCaptureClaims::new(
            engagement_id,
            &self.key_id,
            capture_id,
            request_id,
            canonical_url,
        )?;
        self.sign_claims(claims)
    }

    // Sign validated claims deterministically for stable capture retries and test vectors
    pub fn sign_claims(
        &self,
        claims: SignedCaptureClaims,
    ) -> Result<SignedCapturedRequestEvidence, CaptureSigningError> {
        if claims.authority_key_id() != self.key_id {
            return Err(CaptureSigningError::AuthorityMismatch);
        }
        let signature = self.signing_key.sign(&claims.signing_bytes()?);
        Ok(SignedCapturedRequestEvidence::from_signature(
            claims,
            signature.to_bytes(),
        ))
    }
}

// Report capture-signing failures without formatting private key material
#[derive(Debug, thiserror::Error)]
pub enum CaptureSigningError {
    #[error("capture signing key is malformed")]
    MalformedSecretKey,
    #[error("capture claims authority does not match signer")]
    AuthorityMismatch,
    #[error("capture provenance is invalid")]
    Provenance(#[from] CaptureProvenanceError),
    #[error("capture provenance artifact could not be written")]
    Artifact(#[from] EngagementError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub allow_non_loopback: bool,
}

impl Default for ProxyConfig {
    // Create safe proxy defaults for local browser wiring only
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PROXY_PORT),
            allow_non_loopback: false,
        }
    }
}

impl ProxyConfig {
    // Validate listener exposure before any socket bind happens
    pub fn validate(&self) -> Result<(), EngagementError> {
        if !self.listen_addr.ip().is_loopback() && !self.allow_non_loopback {
            return Err(EngagementError::Invalid(
                "non-loopback proxy listener requires approval".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyHeader {
    pub name: String,
    pub value: String,
}

impl ProxyHeader {
    // Construct a proxy header record without normalizing away original value
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    // Check whether this header is an internal GeistScope label
    pub fn is_label(&self) -> bool {
        self.name.to_ascii_lowercase().starts_with(LABEL_PREFIX)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyLabelMetadata {
    pub session_id: Option<String>,
    pub identity_id: Option<String>,
    pub role_id: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserProfileMetadata {
    pub profile_id: String,
    pub session_id: String,
    pub identity_id: String,
    pub role_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<ProxyHeader>,
    pub body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_profile: Option<BrowserProfileMetadata>,
}

impl ProxyRequest {
    // Create a captured browser request before upstream forwarding
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        headers: Vec<ProxyHeader>,
        body: Vec<u8>,
        browser_profile: Option<BrowserProfileMetadata>,
    ) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers,
            body,
            browser_profile,
        }
    }

    // Strip internal labels from the upstream request and keep metadata locally
    pub fn prepare_upstream(&self) -> PreparedUpstreamRequest {
        let mut labels = ProxyLabelMetadata::default();
        let mut headers = Vec::new();

        for header in &self.headers {
            if header.is_label() {
                apply_label(&mut labels, header);
            } else {
                headers.push(header.clone());
            }
        }

        if let Some(profile) = &self.browser_profile {
            labels
                .session_id
                .get_or_insert_with(|| profile.session_id.clone());
            labels
                .identity_id
                .get_or_insert_with(|| profile.identity_id.clone());
            labels
                .role_id
                .get_or_insert_with(|| profile.role_id.clone());
            labels
                .tenant_id
                .get_or_insert_with(|| profile.tenant_id.clone());
        }

        PreparedUpstreamRequest {
            upstream: UpstreamRequest {
                method: self.method.clone(),
                url: self.url.clone(),
                headers,
                body: self.body.clone(),
            },
            labels,
            browser_profile: self.browser_profile.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<ProxyHeader>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedUpstreamRequest {
    pub upstream: UpstreamRequest,
    pub labels: ProxyLabelMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_profile: Option<BrowserProfileMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<ProxyHeader>,
    pub body: Vec<u8>,
}

impl ProxyResponse {
    // Create a captured response paired with a proxy request
    pub fn new(status: u16, headers: Vec<ProxyHeader>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCapture {
    pub request: ProxyRequest,
    pub response: ProxyResponse,
}

impl ProxyCapture {
    // Create a request/response capture pair
    pub fn new(request: ProxyRequest, response: ProxyResponse) -> Self {
        Self { request, response }
    }

    // Write raw capture artifacts under the engagement root
    pub fn write_artifacts(
        &self,
        engagement: &Engagement,
        capture_id: &str,
    ) -> Result<ProxyCaptureArtifacts, EngagementError> {
        validate_capture_id(capture_id)?;
        let store = ArtifactStore::new(&engagement.root)?;
        let request = write_raw_artifact(
            &store,
            &format!("{ARTIFACT_DIR}/{capture_id}/request.raw"),
            &self.request.body,
        )?;
        let response = write_raw_artifact(
            &store,
            &format!("{ARTIFACT_DIR}/{capture_id}/response.raw"),
            &self.response.body,
        )?;

        Ok(ProxyCaptureArtifacts { request, response })
    }

    // Authenticate and persist one exact captured GET request beneath the engagement root
    pub fn write_authenticated_request_evidence(
        &self,
        engagement: &Engagement,
        signer: &CaptureSigner,
        request_id: &str,
    ) -> Result<ArtifactWriteRecord, CaptureSigningError> {
        if self.request.method != "GET" {
            return Err(CaptureProvenanceError::MalformedClaims.into());
        }
        let evidence = signer.sign_request(&engagement.meta.name, request_id, &self.request.url)?;
        let relative = format!(
            "{PROVENANCE_ARTIFACT_DIR}/{}.json",
            evidence.claims().capture_id()
        );
        Ok(ArtifactStore::new(&engagement.root)?.atomic_json_write(&relative, &evidence)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyCaptureArtifacts {
    pub request: ArtifactWriteRecord,
    pub response: ArtifactWriteRecord,
}

// Copy recognized internal labels into local metadata
fn apply_label(labels: &mut ProxyLabelMetadata, header: &ProxyHeader) {
    match header.name.to_ascii_lowercase().as_str() {
        "x-mg-session-id" => labels.session_id = Some(header.value.clone()),
        "x-mg-identity-id" => labels.identity_id = Some(header.value.clone()),
        "x-mg-role-id" => labels.role_id = Some(header.value.clone()),
        "x-mg-tenant-id" => labels.tenant_id = Some(header.value.clone()),
        _ => {}
    }
}

// Write raw bytes through the engagement artifact path guard
fn write_raw_artifact(
    store: &ArtifactStore,
    relative: &str,
    bytes: &[u8],
) -> Result<ArtifactWriteRecord, EngagementError> {
    let path = store.resolve_relative(relative)?;
    let parent = path
        .parent()
        .ok_or_else(|| EngagementError::Invalid("artifact path has no parent directory".into()))?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(&path, bytes)?;

    Ok(ArtifactWriteRecord {
        path,
        sha256: hex::encode(Sha256::digest(bytes)),
        bytes: bytes.len(),
    })
}

// Reject path-like capture IDs before artifact writes
fn validate_capture_id(capture_id: &str) -> Result<(), EngagementError> {
    if capture_id.trim().is_empty()
        || capture_id.contains('/')
        || capture_id.contains('\\')
        || Path::new(capture_id).is_absolute()
        || capture_id.chars().any(char::is_control)
    {
        return Err(EngagementError::Invalid(
            "capture id must be a safe path component".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::{CaptureTrustStore, Engagement, EngagementMeta, SignedCaptureClaims};
    use static_assertions::assert_not_impl_any;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_engagement() -> Engagement {
        let tmp = tempfile::tempdir().unwrap().keep();
        Engagement::init(
            &tmp,
            EngagementMeta {
                name: "acme".into(),
                target: "example.com".into(),
                created_at: String::new(),
                platform: None,
                url: None,
                tags: Vec::new(),
            },
        )
        .unwrap()
    }

    assert_not_impl_any!(CaptureSigner: std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned);

    #[test]
    fn ed25519_signatures_are_deterministic_for_identical_versioned_claims() {
        let signer = CaptureSigner::from_bytes("capture-key-1", &[7; 32]).unwrap();
        let claims = SignedCaptureClaims::new(
            "acme",
            "capture-key-1",
            "0123456789abcdef0123456789abcdef",
            "request-1",
            "https://app.example.com/fetch?url=https%3A%2F%2Fa.test%2F",
        )
        .unwrap();

        let first = signer.sign_claims(claims.clone()).unwrap();
        let second = signer.sign_claims(claims).unwrap();

        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        CaptureTrustStore::new([signer.verifier().unwrap()])
            .unwrap()
            .verify(
                &first,
                "acme",
                "request-1",
                "GET",
                "https://app.example.com/fetch?url=https%3A%2F%2Fa.test%2F",
            )
            .unwrap();
    }

    #[test]
    fn trusted_capture_integration_writes_hash_bound_signed_evidence_without_signer_material() {
        let engagement = test_engagement();
        let signer = CaptureSigner::from_bytes("capture-key-1", &[7; 32]).unwrap();
        let capture = ProxyCapture::new(
            ProxyRequest::new(
                "GET",
                "https://app.example.com/fetch?url=https%3A%2F%2Fa.test%2F",
                Vec::new(),
                Vec::new(),
                None,
            ),
            ProxyResponse::new(200, Vec::new(), Vec::new()),
        );

        let record = capture
            .write_authenticated_request_evidence(&engagement, &signer, "request-1")
            .unwrap();
        let bytes = std::fs::read(&record.path).unwrap();
        let evidence: SignedCapturedRequestEvidence = serde_json::from_slice(&bytes).unwrap();

        assert!(record.path.starts_with(&engagement.root));
        assert!(
            record
                .path
                .to_string_lossy()
                .contains("traffic/capture-provenance")
        );
        assert_eq!(record.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(record.bytes, bytes.len());
        assert_eq!(evidence.claims().capture_id().len(), 32);
        assert!(!String::from_utf8_lossy(&bytes).contains(&hex::encode([7; 32])));
        CaptureTrustStore::new([signer.verifier().unwrap()])
            .unwrap()
            .verify(
                &evidence,
                "acme",
                "request-1",
                "GET",
                "https://app.example.com/fetch?url=https%3A%2F%2Fa.test%2F",
            )
            .unwrap();
    }

    #[test]
    fn generated_capture_ids_are_high_entropy_and_distinct() {
        let signer = CaptureSigner::from_bytes("capture-key-1", &[7; 32]).unwrap();
        let first = signer
            .sign_request("acme", "request-1", "https://app.example.com/")
            .unwrap();
        let second = signer
            .sign_request("acme", "request-1", "https://app.example.com/")
            .unwrap();

        assert_ne!(first.claims().capture_id(), second.claims().capture_id());
        assert!(
            first
                .claims()
                .capture_id()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[test]
    fn default_listener_is_loopback_only() {
        let config = ProxyConfig::default();

        assert!(config.listen_addr.ip().is_loopback());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn non_loopback_listener_requires_explicit_approval() {
        let config = ProxyConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            allow_non_loopback: false,
        };

        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("non-loopback proxy listener requires approval")
        );

        let approved = ProxyConfig {
            allow_non_loopback: true,
            ..config
        };
        assert!(approved.validate().is_ok());
    }

    #[test]
    fn mg_label_headers_are_recorded_locally_and_stripped_before_forwarding() {
        let request = ProxyRequest::new(
            "GET",
            "https://app.example.com/orders",
            vec![
                ProxyHeader::new("Host", "app.example.com"),
                ProxyHeader::new("X-Mg-Session-Id", "session-alice"),
                ProxyHeader::new("X-Mg-Identity-Id", "alice"),
                ProxyHeader::new("X-Mg-Role-Id", "admin"),
                ProxyHeader::new("X-Mg-Tenant-Id", "tenant-a"),
                ProxyHeader::new("User-Agent", "GeistScope"),
            ],
            Vec::new(),
            Some(BrowserProfileMetadata {
                profile_id: "profile-alice".into(),
                session_id: "session-alice".into(),
                identity_id: "alice".into(),
                role_id: "admin".into(),
                tenant_id: "tenant-a".into(),
                container_id: Some("container-1".into()),
            }),
        );

        let prepared = request.prepare_upstream();

        assert!(
            prepared
                .upstream
                .headers
                .iter()
                .all(|header| !header.name.to_ascii_lowercase().starts_with("x-mg-"))
        );
        assert_eq!(prepared.labels.session_id.as_deref(), Some("session-alice"));
        assert_eq!(prepared.labels.identity_id.as_deref(), Some("alice"));
        assert_eq!(prepared.labels.role_id.as_deref(), Some("admin"));
        assert_eq!(prepared.labels.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(
            prepared.browser_profile.as_ref().unwrap().profile_id,
            "profile-alice"
        );
    }

    #[test]
    fn browser_profile_metadata_is_recorded_locally_but_not_forwarded_upstream() {
        let request = ProxyRequest::new(
            "GET",
            "https://app.example.com/profile",
            vec![ProxyHeader::new("User-Agent", "GeistScope")],
            Vec::new(),
            Some(BrowserProfileMetadata {
                profile_id: "profile-alice".into(),
                session_id: "session-alice".into(),
                identity_id: "alice".into(),
                role_id: "admin".into(),
                tenant_id: "tenant-a".into(),
                container_id: Some("container-1".into()),
            }),
        );

        let prepared = request.prepare_upstream();
        let upstream_json = serde_json::to_string(&prepared.upstream).unwrap();

        assert!(prepared.browser_profile.is_some());
        assert!(!upstream_json.contains("profile-alice"));
        assert!(!upstream_json.contains("session-alice"));
        assert!(!upstream_json.contains("container-1"));
    }

    #[test]
    fn raw_request_and_response_artifacts_are_written_under_engagement_root() {
        let engagement = test_engagement();
        let capture = ProxyCapture::new(
            ProxyRequest::new(
                "POST",
                "https://api.example.com/orders",
                vec![ProxyHeader::new("Content-Type", "application/json")],
                br#"{"order":1}"#.to_vec(),
                None,
            ),
            ProxyResponse::new(
                200,
                vec![ProxyHeader::new("Content-Type", "application/json")],
                br#"{"ok":true}"#.to_vec(),
            ),
        );

        let artifacts = capture.write_artifacts(&engagement, "capture-1").unwrap();

        assert!(artifacts.request.path.starts_with(&engagement.root));
        assert!(artifacts.response.path.starts_with(&engagement.root));
        assert_eq!(artifacts.request.bytes, br#"{"order":1}"#.len());
        assert_eq!(artifacts.response.bytes, br#"{"ok":true}"#.len());
        assert_eq!(artifacts.request.sha256.len(), 64);
        assert_eq!(artifacts.response.sha256.len(), 64);
    }
}
