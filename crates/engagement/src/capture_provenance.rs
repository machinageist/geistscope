// Author: Jeff
// Date: 2026-08-06
// Description: Public-key-only verification for signed captured-request provenance
// Notes: Signing authority belongs to trusted capture integrations, never engagement artifacts

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const CLAIMS_SCHEMA: &str = "geistscope.capture_claims";
const CLAIMS_VERSION: u16 = 1;
const EVIDENCE_SCHEMA: &str = "geistscope.signed_captured_request";
const EVIDENCE_VERSION: u16 = 1;
const SIGNING_DOMAIN: &[u8] = b"geistscope.capture-provenance.ed25519\0";
const CAPTURE_ID_HEX_LENGTH: usize = 32;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;

// Bind one trusted capture to its authority, engagement, and exact observed GET request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCaptureClaims {
    schema: String,
    version: u16,
    engagement_id: String,
    authority_key_id: String,
    capture_id: String,
    request_id: String,
    method: String,
    canonical_url: String,
}

impl SignedCaptureClaims {
    // Create validated version-one claims before a trusted capture integration signs them
    pub fn new(
        engagement_id: impl Into<String>,
        authority_key_id: impl Into<String>,
        capture_id: impl Into<String>,
        request_id: impl Into<String>,
        canonical_url: impl Into<String>,
    ) -> Result<Self, CaptureProvenanceError> {
        let claims = Self {
            schema: CLAIMS_SCHEMA.to_string(),
            version: CLAIMS_VERSION,
            engagement_id: engagement_id.into(),
            authority_key_id: authority_key_id.into(),
            capture_id: capture_id.into(),
            request_id: request_id.into(),
            method: "GET".to_string(),
            canonical_url: canonical_url.into(),
        };
        claims.validate()?;
        Ok(claims)
    }

    // Return the trusted authority key identifier bound into the signature
    pub fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    // Return the engagement identifier bound into the signature
    pub fn engagement_id(&self) -> &str {
        &self.engagement_id
    }

    // Return the high-entropy capture identifier bound into the signature
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }

    // Return the exact captured request identifier bound into the signature
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    // Return the fixed safe method bound into the signature
    pub fn method(&self) -> &str {
        &self.method
    }

    // Return the exact canonical captured URL bound into the signature
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    // Encode claims with explicit versioning, field tags, and big-endian lengths
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CaptureProvenanceError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&CLAIMS_VERSION.to_be_bytes());
        append_field(&mut bytes, 1, &self.schema)?;
        append_field(&mut bytes, 2, &self.engagement_id)?;
        append_field(&mut bytes, 3, &self.authority_key_id)?;
        append_field(&mut bytes, 4, &self.capture_id)?;
        append_field(&mut bytes, 5, &self.request_id)?;
        append_field(&mut bytes, 6, &self.method)?;
        append_field(&mut bytes, 7, &self.canonical_url)?;
        Ok(bytes)
    }

    // Reject malformed, ambiguous, state-changing, or non-canonical claim values
    fn validate(&self) -> Result<(), CaptureProvenanceError> {
        if self.schema != CLAIMS_SCHEMA || self.version != CLAIMS_VERSION {
            return Err(CaptureProvenanceError::MalformedClaims);
        }
        if !is_identifier(&self.engagement_id, 128)
            || !is_key_identifier(&self.authority_key_id)
            || !is_lower_hex(&self.capture_id, CAPTURE_ID_HEX_LENGTH)
            || !is_identifier(&self.request_id, 128)
            || self.method != "GET"
        {
            return Err(CaptureProvenanceError::MalformedClaims);
        }
        let url =
            Url::parse(&self.canonical_url).map_err(|_| CaptureProvenanceError::MalformedClaims)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.as_str() != self.canonical_url
        {
            return Err(CaptureProvenanceError::MalformedClaims);
        }
        Ok(())
    }
}

// Store signed claims as hash-bindable engagement-root evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCapturedRequestEvidence {
    schema: String,
    version: u16,
    claims: SignedCaptureClaims,
    signature: String,
}

impl SignedCapturedRequestEvidence {
    // Assemble a signed evidence envelope from trusted capture output
    pub fn from_signature(
        claims: SignedCaptureClaims,
        signature: [u8; ED25519_SIGNATURE_LENGTH],
    ) -> Self {
        Self {
            schema: EVIDENCE_SCHEMA.to_string(),
            version: EVIDENCE_VERSION,
            claims,
            signature: hex::encode(signature),
        }
    }

    // Return claims only after callers have separately established signature trust
    pub fn claims(&self) -> &SignedCaptureClaims {
        &self.claims
    }

    // Parse and validate the versioned evidence envelope
    fn signature(&self) -> Result<Signature, CaptureProvenanceError> {
        if self.schema != EVIDENCE_SCHEMA || self.version != EVIDENCE_VERSION {
            return Err(CaptureProvenanceError::MalformedEvidence);
        }
        self.claims.validate()?;
        let bytes =
            hex::decode(&self.signature).map_err(|_| CaptureProvenanceError::MalformedSignature)?;
        let bytes: [u8; ED25519_SIGNATURE_LENGTH] = bytes
            .try_into()
            .map_err(|_| CaptureProvenanceError::MalformedSignature)?;
        Ok(Signature::from_bytes(&bytes))
    }
}

// Hold one configured Ed25519 public key without any signing capability
#[derive(Clone)]
pub struct CaptureVerifier {
    key_id: String,
    key: VerifyingKey,
}

impl std::fmt::Debug for CaptureVerifier {
    // Expose only the non-secret configured key identifier
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureVerifier")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl CaptureVerifier {
    // Parse one trusted Ed25519 public key from process configuration
    pub fn from_bytes(
        key_id: impl Into<String>,
        public_key: &[u8],
    ) -> Result<Self, CaptureProvenanceError> {
        let key_id = key_id.into();
        if !is_key_identifier(&key_id) {
            return Err(CaptureProvenanceError::InvalidKeyId);
        }
        let public_key: [u8; ED25519_PUBLIC_KEY_LENGTH] = public_key
            .try_into()
            .map_err(|_| CaptureProvenanceError::MalformedPublicKey)?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CaptureProvenanceError::MalformedPublicKey)?;
        Ok(Self { key_id, key })
    }

    // Return the process-configured authority identifier
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

// Support trusted-key rotation while making missing and revoked authorities explicit
#[derive(Clone, Default)]
pub struct CaptureTrustStore {
    verifiers: BTreeMap<String, CaptureVerifier>,
    revoked: BTreeSet<String>,
}

impl std::fmt::Debug for CaptureTrustStore {
    // Report counts only so configuration identifiers do not drift into routine logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureTrustStore")
            .field("trusted_key_count", &self.verifiers.len())
            .field("revoked_key_count", &self.revoked.len())
            .finish()
    }
}

impl CaptureTrustStore {
    // Build a public-key-only trust store and reject duplicate configured authority IDs
    pub fn new<I>(verifiers: I) -> Result<Self, CaptureProvenanceError>
    where
        I: IntoIterator<Item = CaptureVerifier>,
    {
        let mut store = Self::default();
        for verifier in verifiers {
            if store
                .verifiers
                .insert(verifier.key_id.clone(), verifier)
                .is_some()
            {
                return Err(CaptureProvenanceError::DuplicateKeyId);
            }
        }
        Ok(store)
    }

    // Mark an authority identifier revoked even if its public key is no longer configured
    pub fn revoke(&mut self, key_id: impl Into<String>) -> Result<(), CaptureProvenanceError> {
        let key_id = key_id.into();
        if !is_key_identifier(&key_id) {
            return Err(CaptureProvenanceError::InvalidKeyId);
        }
        self.revoked.insert(key_id);
        Ok(())
    }

    // Verify trust, signature, engagement, and the exact expected observation tuple
    pub fn verify(
        &self,
        evidence: &SignedCapturedRequestEvidence,
        expected_engagement_id: &str,
        expected_request_id: &str,
        expected_method: &str,
        expected_canonical_url: &str,
    ) -> Result<(), CaptureProvenanceError> {
        let signature = evidence.signature()?;
        let claims = evidence.claims();
        let key_id = claims.authority_key_id();
        if self.revoked.contains(key_id) {
            return Err(CaptureProvenanceError::RevokedKey);
        }
        let verifier = self
            .verifiers
            .get(key_id)
            .ok_or(CaptureProvenanceError::UnknownKey)?;
        verifier
            .key
            .verify_strict(&claims.signing_bytes()?, &signature)
            .map_err(|_| CaptureProvenanceError::InvalidSignature)?;
        if claims.engagement_id() != expected_engagement_id {
            return Err(CaptureProvenanceError::EngagementMismatch);
        }
        if claims.request_id() != expected_request_id
            || claims.method() != expected_method
            || claims.canonical_url() != expected_canonical_url
        {
            return Err(CaptureProvenanceError::ObservationMismatch);
        }
        Ok(())
    }
}

// Report provenance failures without embedding claim, key, path, or URL values
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CaptureProvenanceError {
    #[error("capture claims are malformed")]
    MalformedClaims,
    #[error("signed capture evidence is malformed")]
    MalformedEvidence,
    #[error("capture authority key id is invalid")]
    InvalidKeyId,
    #[error("capture authority public key is malformed")]
    MalformedPublicKey,
    #[error("capture signature is malformed")]
    MalformedSignature,
    #[error("capture authority key id is duplicated")]
    DuplicateKeyId,
    #[error("capture authority key is not trusted")]
    UnknownKey,
    #[error("capture authority key is revoked")]
    RevokedKey,
    #[error("capture signature is invalid")]
    InvalidSignature,
    #[error("capture engagement does not match trusted context")]
    EngagementMismatch,
    #[error("capture observation does not match the plan")]
    ObservationMismatch,
}

// Append one unambiguous tagged length-prefixed UTF-8 field
fn append_field(bytes: &mut Vec<u8>, tag: u8, value: &str) -> Result<(), CaptureProvenanceError> {
    let length = u32::try_from(value.len()).map_err(|_| CaptureProvenanceError::MalformedClaims)?;
    bytes.push(tag);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

// Accept stable ASCII identifiers used by engagements and observed requests
fn is_identifier(value: &str, max_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

// Accept stable process-configured key identifiers
fn is_key_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

// Require fixed-length lowercase hexadecimal IDs
fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_encoding_is_stable_and_field_boundaries_are_unambiguous() {
        let claims = SignedCaptureClaims::new(
            "engagement-1",
            "capture-key-1",
            "0123456789abcdef0123456789abcdef",
            "request-1",
            "https://target.example.test/fetch?url=https%3A%2F%2Fa.test%2F",
        )
        .unwrap();
        let first = claims.signing_bytes().unwrap();
        let second = claims.signing_bytes().unwrap();

        assert_eq!(first, second);
        assert!(first.starts_with(SIGNING_DOMAIN));
        assert_ne!(
            first,
            SignedCaptureClaims::new(
                "engagement-1",
                "capture-key-1",
                "0123456789abcdef0123456789abcdef",
                "request-2",
                "https://target.example.test/fetch?url=https%3A%2F%2Fa.test%2F",
            )
            .unwrap()
            .signing_bytes()
            .unwrap()
        );
    }

    #[test]
    fn malformed_public_keys_fail_closed() {
        assert_eq!(
            CaptureVerifier::from_bytes("capture-key-1", &[1; 31]).unwrap_err(),
            CaptureProvenanceError::MalformedPublicKey
        );
    }
}
