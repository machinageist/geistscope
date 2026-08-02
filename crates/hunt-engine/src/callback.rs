// Author: Jeff
// Date: 2026-07-31
// Description: Plan-bound callback registration, recording, and deterministic correlation
// Notes: Records retain bounded redacted metadata and hashes, never raw tokens or bodies

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const CALLBACK_TOKEN_HEX_LENGTH: usize = 32;
const MAX_CALLBACK_BODY_BYTES: usize = 2_048;
const MAX_HEADER_NAME_BYTES: usize = 128;
const MAX_HEADER_VALUE_BYTES: usize = 512;
const MAX_CALLBACK_HEADERS: usize = 32;
const MAX_AGGREGATE_HEADER_BYTES: usize = 8_192;
const MAX_PEER_BYTES: usize = 128;
const MAX_METHOD_BYTES: usize = 16;
const MAX_PATH_BYTES: usize = 2_048;
const CALLBACK_ROUTE_PREFIX: &str = "/callbacks/";
const REDACTED_VALUE: &str = "<redacted>";
const REDACTED_TOKEN: &str = "<callback-token>";

// Hold a validated high-entropy callback token
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallbackToken(String);

impl CallbackToken {
    // Generate one random 128-bit lowercase hexadecimal token
    pub fn generate() -> Self {
        Self(Uuid::new_v4().simple().to_string())
    }

    // Parse a callback token received from a worker boundary
    pub fn parse(value: impl Into<String>) -> Result<Self, CallbackContractError> {
        let value = value.into();
        if !is_callback_token(&value) {
            return Err(CallbackContractError::InvalidToken);
        }
        Ok(Self(value))
    }

    // Parse the token from an exact `/callbacks/{token}` worker route only
    pub fn from_callback_path(path: &str) -> Result<Self, CallbackContractError> {
        let rest = path
            .strip_prefix(CALLBACK_ROUTE_PREFIX)
            .ok_or(CallbackContractError::InvalidToken)?;
        if rest.contains(['/', '?', '#']) {
            return Err(CallbackContractError::InvalidToken);
        }
        Self::parse(rest)
    }

    // Return the token for controlled callback URL construction
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Bind one callback token to one immutable plan and expiration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackRegistration {
    token: CallbackToken,
    plan_hash: String,
    expires_at_ms: u64,
}

impl CallbackRegistration {
    // Create a registration validated when inserted into a recorder
    pub fn new(token: CallbackToken, plan_hash: String, expires_at_ms: u64) -> Self {
        Self {
            token,
            plan_hash,
            expires_at_ms,
        }
    }
}

// Store one bounded redacted HTTP header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackHeader {
    name: String,
    value: String,
}

// Carry transient worker input until the recorder removes raw token-bearing path data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackRequest {
    method: String,
    path: String,
    headers: Vec<CallbackHeader>,
    headers_truncated: bool,
    source_peer: Option<String>,
    body_sha256: String,
    body_bytes: usize,
    body_truncated: bool,
    received_at_ms: u64,
}

impl CallbackRequest {
    // Validate and sanitize one callback request at the worker boundary
    pub fn new<I, N, V, B>(
        method: impl Into<String>,
        path: impl Into<String>,
        headers: I,
        body: B,
        source_peer: Option<&str>,
        received_at_ms: u64,
    ) -> Result<Self, CallbackContractError>
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
        B: Into<Vec<u8>>,
    {
        let method = method.into().to_ascii_uppercase();
        let path = path.into();
        if method.is_empty()
            || method.len() > MAX_METHOD_BYTES
            || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(CallbackContractError::InvalidMethod);
        }
        if path.is_empty()
            || path.len() > MAX_PATH_BYTES
            || !path.starts_with('/')
            || path.chars().any(char::is_control)
        {
            return Err(CallbackContractError::InvalidPath);
        }

        // Bound header count and aggregate bytes, not just individual fields
        let mut collected = Vec::new();
        let mut aggregate = 0usize;
        let mut headers_truncated = false;
        for (name, value) in headers {
            if collected.len() >= MAX_CALLBACK_HEADERS {
                headers_truncated = true;
                break;
            }
            let header = sanitize_header(name.into(), value.into())?;
            aggregate += header.name.len() + header.value.len();
            if aggregate > MAX_AGGREGATE_HEADER_BYTES {
                headers_truncated = true;
                break;
            }
            collected.push(header);
        }
        let body = body.into();

        Ok(Self {
            method,
            path,
            headers: collected,
            headers_truncated,
            source_peer: source_peer.map(bounded_peer),
            body_sha256: hex::encode(Sha256::digest(&body)),
            body_bytes: body.len(),
            body_truncated: body.len() > MAX_CALLBACK_BODY_BYTES,
            received_at_ms,
        })
    }
}

// Preserve callback proof metadata without raw token or body content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackRecord {
    plan_hash: String,
    token_sha256: String,
    received_at_ms: u64,
    method: String,
    path: String,
    headers: Vec<CallbackHeader>,
    headers_truncated: bool,
    source_peer: Option<String>,
    body_sha256: String,
    body_bytes: usize,
    body_truncated: bool,
}

impl CallbackRecord {
    // Return the immutable callback-body digest
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    // Return whether the callback headers were bounded before storage
    pub fn headers_truncated(&self) -> bool {
        self.headers_truncated
    }

    // Return the observed callback body byte count within the worker cap
    pub fn body_bytes(&self) -> usize {
        self.body_bytes
    }

    // Return whether the callback body exceeded the redaction cap
    pub fn body_truncated(&self) -> bool {
        self.body_truncated
    }
}

// Report callback recording without treating rejected input as proof
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackRecordOutcome {
    Accepted(CallbackRecord),
    InvalidToken,
    UnknownToken,
    Expired,
    Reused,
}

// Report deterministic plan correlation outcomes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackCorrelation {
    Matched(CallbackRecord),
    Missing,
    UnknownToken,
    PlanMismatch,
    Expired,
    Reused,
}

// Own plan-bound callback registrations and accepted records
#[derive(Debug, Default)]
pub struct CallbackRecorder {
    entries: BTreeMap<String, CallbackEntry>,
}

#[derive(Debug)]
struct CallbackEntry {
    plan_hash: String,
    expires_at_ms: u64,
    record: Option<CallbackRecord>,
    reused: bool,
    late: bool,
}

impl CallbackRecorder {
    // Register one unique token for one immutable plan
    pub fn register(
        &mut self,
        registration: CallbackRegistration,
    ) -> Result<(), CallbackContractError> {
        if !is_sha256(&registration.plan_hash) {
            return Err(CallbackContractError::InvalidPlanHash);
        }
        if registration.expires_at_ms == 0 {
            return Err(CallbackContractError::InvalidExpiration);
        }
        if self.entries.contains_key(registration.token.as_str()) {
            return Err(CallbackContractError::DuplicateRegistration);
        }

        self.entries.insert(
            registration.token.0,
            CallbackEntry {
                plan_hash: registration.plan_hash,
                expires_at_ms: registration.expires_at_ms,
                record: None,
                reused: false,
                late: false,
            },
        );
        Ok(())
    }

    // Record one callback only when its token is known, live, and unused
    pub fn record(
        &mut self,
        token: &CallbackToken,
        request: CallbackRequest,
    ) -> CallbackRecordOutcome {
        if !is_callback_token(token.as_str()) {
            return CallbackRecordOutcome::InvalidToken;
        }
        let Some(entry) = self.entries.get_mut(token.as_str()) else {
            return CallbackRecordOutcome::UnknownToken;
        };
        if request.received_at_ms > entry.expires_at_ms {
            entry.late = true;
            return CallbackRecordOutcome::Expired;
        }
        if entry.record.is_some() {
            entry.reused = true;
            return CallbackRecordOutcome::Reused;
        }

        let record = CallbackRecord {
            plan_hash: entry.plan_hash.clone(),
            token_sha256: hex::encode(Sha256::digest(token.as_str().as_bytes())),
            received_at_ms: request.received_at_ms,
            method: request.method,
            path: request.path.replace(token.as_str(), REDACTED_TOKEN),
            headers: request.headers,
            headers_truncated: request.headers_truncated,
            source_peer: request.source_peer,
            body_sha256: request.body_sha256,
            body_bytes: request.body_bytes,
            body_truncated: request.body_truncated,
        };
        entry.record = Some(record.clone());
        CallbackRecordOutcome::Accepted(record)
    }

    // Correlate a recorded callback with the exact live immutable plan
    pub fn correlate(
        &self,
        token: &CallbackToken,
        plan_hash: &str,
        evaluated_at_ms: u64,
    ) -> CallbackCorrelation {
        let Some(entry) = self.entries.get(token.as_str()) else {
            return CallbackCorrelation::UnknownToken;
        };
        if entry.plan_hash != plan_hash {
            return CallbackCorrelation::PlanMismatch;
        }
        if entry.reused {
            return CallbackCorrelation::Reused;
        }
        // A callback recorded within its lease proves regardless of when correlation runs
        if let Some(record) = &entry.record {
            return CallbackCorrelation::Matched(record.clone());
        }
        if entry.late || evaluated_at_ms > entry.expires_at_ms {
            return CallbackCorrelation::Expired;
        }
        CallbackCorrelation::Missing
    }
}

// Report callback contract failures without returning captured content
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CallbackContractError {
    #[error("callback token must be 32 lowercase hexadecimal characters")]
    InvalidToken,
    #[error("callback plan hash must be a lowercase SHA-256 value")]
    InvalidPlanHash,
    #[error("callback expiration must be non-zero")]
    InvalidExpiration,
    #[error("callback token is already registered")]
    DuplicateRegistration,
    #[error("callback method is invalid")]
    InvalidMethod,
    #[error("callback path is invalid")]
    InvalidPath,
    #[error("callback header is invalid")]
    InvalidHeader,
}

// Sanitize sensitive and oversized header values before storage
fn sanitize_header(name: String, value: String) -> Result<CallbackHeader, CallbackContractError> {
    let name = name.to_ascii_lowercase();
    if name.is_empty()
        || name.len() > MAX_HEADER_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CallbackContractError::InvalidHeader);
    }

    let value = if is_sensitive_header(&name) {
        REDACTED_VALUE.to_string()
    } else {
        value.chars().take(MAX_HEADER_VALUE_BYTES).collect()
    };
    Ok(CallbackHeader { name, value })
}

// Bound untrusted peer metadata before it enters a stored callback record
fn bounded_peer(peer: &str) -> String {
    peer.chars()
        .filter(|character| !character.is_control())
        .take(MAX_PEER_BYTES)
        .collect()
}

// Identify headers that can contain credentials, sessions, or private transport metadata
fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
    )
}

// Validate callback token format at every process boundary
fn is_callback_token(value: &str) -> bool {
    value.len() == CALLBACK_TOKEN_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Validate canonical lowercase SHA-256 text
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
