// Author: Jeff
// Date: 2026-07-31
// Description: Bounded, permit-gated single-request executor for callback-only SSRF probes
// Notes: Executes one authorized GET, enforces budgets fail-closed, leaks no secrets or bodies

use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{ExecutionPermit, HttpMethod, SsrfInputLocation, SsrfProbePlan};

const USER_AGENT: &str = "GeistScope/0.1 (+hunt-engine)";
const MAX_RECORDED_HEADERS: usize = 32;
const REDACTED_VALUE: &str = "<redacted>";

// Classify the deterministic result of one bounded probe execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorOutcome {
    Completed,
    RateLimited,
    ServerError,
    ResponseTooLarge,
    Timeout,
    ConnectionFailed,
    TlsFailed,
}

// Hold one bounded, sanitized request/response transaction with no secrets or body
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpTransactionRecord {
    plan_hash: String,
    candidate_id: String,
    method: HttpMethod,
    target_origin: String,
    target_path: String,
    input_location: SsrfInputLocation,
    elapsed_ms: u64,
    status_code: Option<u16>,
    response_headers: Vec<TransactionHeader>,
    response_body_sha256: String,
    response_body_bytes: u64,
    response_body_truncated: bool,
    outcome: ExecutorOutcome,
}

impl HttpTransactionRecord {
    // Return the plan hash the transaction was executed for
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return the deterministic executor outcome
    pub fn outcome(&self) -> ExecutorOutcome {
        self.outcome
    }

    // Return the response status code when one was received
    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    // Return the observed response byte count within budget
    pub fn response_body_bytes(&self) -> u64 {
        self.response_body_bytes
    }

    // Return whether the response exceeded the byte budget
    pub fn response_body_truncated(&self) -> bool {
        self.response_body_truncated
    }
}

// Store one bounded, sanitized response header
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionHeader {
    name: String,
    value: String,
}

// Execute exactly one permit-authorized callback-only SSRF probe
#[derive(Debug, Default, Clone)]
pub struct SsrfHttpExecutor;

impl SsrfHttpExecutor {
    // Send one authorized bounded GET and return sanitized transaction evidence
    pub async fn execute(
        &self,
        plan: &SsrfProbePlan,
        permit: ExecutionPermit,
        now: OffsetDateTime,
    ) -> Result<HttpTransactionRecord, ExecutorError> {
        let executable = plan.executable();

        // Revalidate authority before any request is created
        if permit.plan_hash() != plan.plan_hash() || executable.plan_hash() != plan.plan_hash() {
            return Err(ExecutorError::PlanMismatch);
        }
        if now >= permit.authorized_not_after() {
            return Err(ExecutorError::AuthorizationExpired);
        }
        if executable.method() != HttpMethod::Get {
            return Err(ExecutorError::UnsupportedMethod);
        }

        let budget = plan.action_plan().budget();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(budget.max_duration_ms()))
            .no_proxy()
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| ExecutorError::ClientBuild)?;

        let url = executable.mutated_url();
        let started = Instant::now();
        let mut response = match client.get(url).send().await {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.record(
                    plan,
                    started,
                    None,
                    Vec::new(),
                    &[],
                    classify_error(&error),
                ));
            }
        };

        let status = response.status();
        let headers = capture_headers(response.headers());
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut truncated = false;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let len = chunk.len() as u64;
                    if total + len > budget.max_bytes() {
                        truncated = true;
                        break;
                    }
                    total += len;
                    hasher.update(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    return Ok(self.record(
                        plan,
                        started,
                        Some(status.as_u16()),
                        headers,
                        &[],
                        classify_error(&error),
                    ));
                }
            }
        }

        let body_sha256 = hex::encode(hasher.finalize());
        let outcome = if truncated {
            ExecutorOutcome::ResponseTooLarge
        } else if status.as_u16() == 429 {
            ExecutorOutcome::RateLimited
        } else if status.is_server_error() {
            ExecutorOutcome::ServerError
        } else {
            ExecutorOutcome::Completed
        };

        Ok(HttpTransactionRecord {
            plan_hash: plan.plan_hash().to_string(),
            candidate_id: plan.view().candidate_id().to_string(),
            method: HttpMethod::Get,
            target_origin: plan.view().target_origin().to_string(),
            target_path: plan.view().target_path().to_string(),
            input_location: plan.view().input_location().clone(),
            elapsed_ms: elapsed_ms(started),
            status_code: Some(status.as_u16()),
            response_headers: headers,
            response_body_sha256: body_sha256,
            response_body_bytes: total,
            response_body_truncated: truncated,
            outcome,
        })
    }

    // Build a transaction record for a failed or partial send without body content
    fn record(
        &self,
        plan: &SsrfProbePlan,
        started: Instant,
        status_code: Option<u16>,
        headers: Vec<TransactionHeader>,
        body: &[u8],
        outcome: ExecutorOutcome,
    ) -> HttpTransactionRecord {
        HttpTransactionRecord {
            plan_hash: plan.plan_hash().to_string(),
            candidate_id: plan.view().candidate_id().to_string(),
            method: HttpMethod::Get,
            target_origin: plan.view().target_origin().to_string(),
            target_path: plan.view().target_path().to_string(),
            input_location: plan.view().input_location().clone(),
            elapsed_ms: elapsed_ms(started),
            status_code,
            response_headers: headers,
            response_body_sha256: hex::encode(Sha256::digest(body)),
            response_body_bytes: body.len() as u64,
            response_body_truncated: false,
            outcome,
        }
    }
}

// Report deterministic pre-send authority failures that perform zero network I/O
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("permit does not authorize this exact plan")]
    PlanMismatch,
    #[error("authorization window has expired")]
    AuthorizationExpired,
    #[error("only GET probes are executable in this slice")]
    UnsupportedMethod,
    #[error("bounded HTTP client could not be built")]
    ClientBuild,
}

// Compute bounded elapsed milliseconds without exposing wall-clock secrets
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// Capture a bounded set of sanitized response headers
fn capture_headers(headers: &reqwest::header::HeaderMap) -> Vec<TransactionHeader> {
    headers
        .iter()
        .take(MAX_RECORDED_HEADERS)
        .map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            let _ = value;
            TransactionHeader {
                name,
                value: REDACTED_VALUE.to_string(),
            }
        })
        .collect()
}

// Map a transport error to a deterministic stop outcome
fn classify_error(error: &reqwest::Error) -> ExecutorOutcome {
    if error.is_timeout() {
        ExecutorOutcome::Timeout
    } else if is_tls_error(error) {
        ExecutorOutcome::TlsFailed
    } else {
        ExecutorOutcome::ConnectionFailed
    }
}

// Detect a TLS handshake failure by inspecting the error source chain
fn is_tls_error(error: &reqwest::Error) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(current) = source {
        let text = current.to_string().to_ascii_lowercase();
        if text.contains("tls")
            || text.contains("ssl")
            || text.contains("certificate")
            || text.contains("handshake")
        {
            return true;
        }
        source = current.source();
    }
    false
}
