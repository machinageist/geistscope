// Author: Jeff
// Date: 2026-07-31
// Description: Shared in-process SSRF benchmark fixtures
// Notes: Test-only listeners bind ephemeral loopback ports and abort when dropped

// Each test binary consumes a different subset of these shared fixtures
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{OriginalUri, Query, State};
use axum::http::StatusCode;
use axum::routing::{any, get};
use serde::Deserialize;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use url::Url;

const NO_REQUEST_OBSERVATION_MS: u64 = 100;
const REQUEST_WAIT_TIMEOUT_SECS: u64 = 2;

// Count callback-like HTTP requests for target-fixture assertions
pub struct RequestCounter {
    address: SocketAddr,
    state: Arc<RequestCounterState>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct RequestCounterState {
    paths: Mutex<Vec<String>>,
    notify: Notify,
}

impl RequestCounter {
    // Start a request counter on an ephemeral loopback port
    pub async fn start() -> Self {
        let state = Arc::new(RequestCounterState::default());
        let router = Router::new()
            .route("/", any(record_request))
            .route("/*path", any(record_request))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind request counter");
        let address = listener.local_addr().expect("read request counter address");
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve request counter");
        });

        Self {
            address,
            state,
            task,
        }
    }

    // Build one loopback callback URL
    pub fn url(&self, path: &str) -> String {
        format!("http://{}/{path}", self.address)
    }

    // Return the bare loopback origin for campaign callback binding
    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    // Build one loopback URL with a single query parameter
    pub fn url_with_query(&self, path: &str, key: &str, value: &str) -> String {
        let mut url =
            Url::parse(&format!("http://{}/{path}", self.address)).expect("parse counter URL");
        url.query_pairs_mut().append_pair(key, value);
        url.into()
    }

    // Wait until the expected request count arrives or fail the test
    pub async fn wait_for_requests(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(REQUEST_WAIT_TIMEOUT_SECS), async {
            loop {
                if self.state.paths.lock().expect("lock paths").len() >= expected {
                    return;
                }
                self.state.notify.notified().await;
            }
        })
        .await
        .expect("expected callback request did not arrive");
    }

    // Assert that no outbound request arrives during the bounded observation window
    pub async fn assert_no_requests(&self) {
        tokio::time::sleep(Duration::from_millis(NO_REQUEST_OBSERVATION_MS)).await;
        assert!(self.paths().is_empty(), "unexpected callback request");
    }

    // Return captured request paths without exposing headers or bodies
    pub fn paths(&self) -> Vec<String> {
        self.state.paths.lock().expect("lock paths").clone()
    }
}

impl Drop for RequestCounter {
    // Stop the test server when its fixture leaves scope
    fn drop(&mut self) {
        self.task.abort();
    }
}

// Record one bounded callback path
async fn record_request(
    State(state): State<Arc<RequestCounterState>>,
    OriginalUri(uri): OriginalUri,
) -> StatusCode {
    let recorded = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());
    state.paths.lock().expect("lock paths").push(recorded);
    state.notify.notify_waiters();
    StatusCode::NO_CONTENT
}

// Serve vulnerable and secure endpoints with the same input shape
pub struct SsrfBenchmark {
    address: SocketAddr,
    state: Arc<TargetState>,
    task: JoinHandle<()>,
}

struct TargetState {
    client: reqwest::Client,
    vulnerable_requests: AtomicUsize,
    secure_requests: AtomicUsize,
}

#[derive(Deserialize)]
struct FetchQuery {
    url: String,
}

impl SsrfBenchmark {
    // Start the controlled target on an ephemeral loopback port
    pub async fn start() -> Self {
        let state = Arc::new(TargetState {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .expect("build benchmark client"),
            vulnerable_requests: AtomicUsize::new(0),
            secure_requests: AtomicUsize::new(0),
        });
        let router = Router::new()
            .route("/vulnerable", get(vulnerable_fetch))
            .route("/secure", get(secure_fetch))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind SSRF benchmark");
        let address = listener.local_addr().expect("read benchmark address");
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve SSRF benchmark");
        });

        Self {
            address,
            state,
            task,
        }
    }

    // Build the vulnerable endpoint URL with one encoded input
    pub fn vulnerable_url(&self, callback_url: String) -> String {
        self.endpoint_url("vulnerable", callback_url)
    }

    // Build the secure endpoint URL with the same encoded input
    pub fn secure_url(&self, callback_url: String) -> String {
        self.endpoint_url("secure", callback_url)
    }

    // Return vulnerable endpoint invocation count
    pub fn vulnerable_requests(&self) -> usize {
        self.state.vulnerable_requests.load(Ordering::SeqCst)
    }

    // Return secure endpoint invocation count
    pub fn secure_requests(&self) -> usize {
        self.state.secure_requests.load(Ordering::SeqCst)
    }

    // Build one target endpoint URL without manual query encoding
    fn endpoint_url(&self, endpoint: &str, callback_url: String) -> String {
        let mut url = Url::parse(&format!("http://{}/{endpoint}", self.address))
            .expect("parse benchmark URL");
        url.query_pairs_mut().append_pair("url", &callback_url);
        url.into()
    }
}

impl Drop for SsrfBenchmark {
    // Stop the controlled target when its fixture leaves scope
    fn drop(&mut self) {
        self.task.abort();
    }
}

// Perform exactly one outbound GET for the intentionally vulnerable endpoint
async fn vulnerable_fetch(
    State(state): State<Arc<TargetState>>,
    Query(input): Query<FetchQuery>,
) -> StatusCode {
    state.vulnerable_requests.fetch_add(1, Ordering::SeqCst);
    match state.client.get(input.url).send().await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::BAD_GATEWAY,
    }
}

// Accept the same input without performing an outbound request
async fn secure_fetch(
    State(state): State<Arc<TargetState>>,
    Query(_input): Query<FetchQuery>,
) -> StatusCode {
    state.secure_requests.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}
