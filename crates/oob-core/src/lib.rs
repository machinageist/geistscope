/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-07-24
 * Description:     oob-core — deterministic out-of-band callback support
 *                  for the adaptive hunt: mint plan-bound tokens, run a
 *                  loopback listener, correlate inbound hits to a plan.
 * Notes:           Std-only synchronous listener (no tokio/axum). HTTP
 *                  only; a hit is a request whose path carries a minted
 *                  token. Binds 127.0.0.1:0 so tests never leave the host.
 *******************************************************************/

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Length of a minted token in lowercase hex characters
const TOKEN_HEX_LEN: usize = 32;

// How long the accept loop sleeps between non-blocking poll attempts
const POLL_INTERVAL_MS: u64 = 10;

// How long a single callback read is allowed to block before giving up
const READ_TIMEOUT_MS: u64 = 500;

// Minimal 200 response returned to every callback so the caller's fetch completes
const CALLBACK_OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

// The plan/candidate a token is bound to, resolved when a callback lands
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobBinding {
    pub engagement: String,
    pub plan_hash: String,
    pub candidate_id: String,
}

// One correlated inbound callback proving an out-of-band interaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobHit {
    pub token: String,
    pub binding: OobBinding,
    pub method: String,
    pub path: String,
    pub source_ip: String,
    pub received_at: String,
}

// An opaque token embedded in an SSRF payload; the raw value is never model-visible
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OobToken {
    pub value: String,
}

// Mutable listener state shared with the accept worker
struct ListenerInner {
    bindings: HashMap<String, OobBinding>,
    hits: Vec<OobHit>,
}

// Shared handle protecting listener state and signalling new hits
struct ListenerShared {
    inner: Mutex<ListenerInner>,
    signal: Condvar,
}

// A loopback HTTP listener that records callbacks for minted tokens
pub struct OobListener {
    addr: SocketAddr,
    shared: Arc<ListenerShared>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl OobListener {
    // Bind a loopback listener on an ephemeral port and start the accept worker
    pub fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(ListenerShared {
            inner: Mutex::new(ListenerInner {
                bindings: HashMap::new(),
                hits: Vec::new(),
            }),
            signal: Condvar::new(),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = {
            let shared = Arc::clone(&shared);
            let shutdown = Arc::clone(&shutdown);
            thread::spawn(move || serve(listener, &shared, &shutdown))
        };
        Ok(Self {
            addr,
            shared,
            shutdown,
            worker: Some(worker),
        })
    }

    // Return the loopback address callers embed in an OOB URL
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    // Mint an opaque token bound to a specific engagement plan and candidate
    pub fn mint(
        &self,
        engagement: impl Into<String>,
        plan_hash: impl Into<String>,
        candidate_id: impl Into<String>,
    ) -> OobToken {
        let value = random_token();
        let binding = OobBinding {
            engagement: engagement.into(),
            plan_hash: plan_hash.into(),
            candidate_id: candidate_id.into(),
        };
        self.shared
            .inner
            .lock()
            .expect("listener state lock")
            .bindings
            .insert(value.clone(), binding);
        OobToken { value }
    }

    // Build the callback URL to embed in an SSRF payload for a minted token
    pub fn oob_url(&self, token: &OobToken) -> String {
        format!("http://{}/{}", self.addr, token.value)
    }

    // Return a recorded hit for a token without blocking
    pub fn correlate(&self, token: &str) -> Option<OobHit> {
        self.shared
            .inner
            .lock()
            .expect("listener state lock")
            .hits
            .iter()
            .find(|hit| hit.token == token)
            .cloned()
    }

    // Block until a callback for the token lands or the timeout elapses
    pub fn wait_for_hit(&self, token: &OobToken, timeout: Duration) -> Option<OobHit> {
        let deadline = Instant::now() + timeout;
        let mut inner = self.shared.inner.lock().expect("listener state lock");
        loop {
            if let Some(hit) = inner.hits.iter().find(|hit| hit.token == token.value) {
                return Some(hit.clone());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self
                .shared
                .signal
                .wait_timeout(inner, deadline - now)
                .expect("listener signal wait");
            inner = guard;
        }
    }
}

impl Drop for OobListener {
    // Signal the accept worker to stop and join it
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// Accept loop: poll for connections until shutdown, handling each callback
fn serve(listener: TcpListener, shared: &ListenerShared, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => handle_callback(stream, peer, shared),
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
            Err(_) => break,
        }
    }
}

// Read one callback's request line, correlate its token, and answer 200
fn handle_callback(stream: TcpStream, peer: SocketAddr, shared: &ListenerShared) {
    // Accepted sockets can inherit the listener's non-blocking flag, so force blocking reads
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let mut request_line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
    }
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or_default().to_string();
    let raw_path = fields.next().unwrap_or("/").to_string();
    let token = token_from_path(&raw_path);
    {
        let mut inner = shared.inner.lock().expect("listener state lock");
        if let Some(binding) = inner.bindings.get(&token).cloned() {
            inner.hits.push(OobHit {
                token,
                binding,
                method,
                path: raw_path,
                source_ip: peer.ip().to_string(),
                received_at: now_rfc3339(),
            });
            shared.signal.notify_all();
        }
    }
    let mut writer = &stream;
    let _ = writer.write_all(CALLBACK_OK_RESPONSE);
}

// Extract the token segment from a request path, ignoring query and subpaths
fn token_from_path(raw_path: &str) -> String {
    raw_path
        .trim_start_matches('/')
        .split(['/', '?'])
        .next()
        .unwrap_or_default()
        .to_string()
}

// Generate an unpredictable lowercase-hex token
fn random_token() -> String {
    let mut token = String::with_capacity(TOKEN_HEX_LEN);
    for _ in 0..TOKEN_HEX_LEN {
        let nibble = fastrand::u8(0..16);
        token.push(char::from_digit(u32::from(nibble), 16).expect("hex nibble"));
    }
    token
}

// Format the current UTC time as RFC3339 for evidence timestamps
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn correlates_registered_token_callback_to_binding() {
        let listener = OobListener::bind().unwrap();
        let token = listener.mint("acme", "plan-hash-123", "ssrf-record-1");
        send_get(listener.local_addr(), &token.value);

        let hit = listener
            .wait_for_hit(&token, Duration::from_secs(2))
            .expect("callback correlated to a hit");
        assert_eq!(hit.token, token.value);
        assert_eq!(hit.binding.engagement, "acme");
        assert_eq!(hit.binding.plan_hash, "plan-hash-123");
        assert_eq!(hit.binding.candidate_id, "ssrf-record-1");
        assert_eq!(hit.method, "GET");
    }

    #[test]
    fn unknown_token_callback_is_not_a_hit() {
        let listener = OobListener::bind().unwrap();
        let _bound = listener.mint("acme", "plan", "candidate");
        send_get(listener.local_addr(), "deadbeefdeadbeefdeadbeefdeadbeef");

        // Give the worker a moment to process the (unregistered) callback
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            listener
                .correlate("deadbeefdeadbeefdeadbeefdeadbeef")
                .is_none()
        );
    }

    #[test]
    fn minted_token_is_thirty_two_lowercase_hex() {
        let listener = OobListener::bind().unwrap();
        let token = listener.mint("acme", "plan", "candidate");
        assert_eq!(token.value.len(), TOKEN_HEX_LEN);
        assert!(
            token
                .value
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
    }

    #[test]
    fn oob_url_targets_the_loopback_listener() {
        let listener = OobListener::bind().unwrap();
        let token = listener.mint("acme", "plan", "candidate");
        let url = listener.oob_url(&token);
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(url.ends_with(&token.value));
    }

    // Open a loopback GET to the listener, mimicking a server-side SSRF fetch
    fn send_get(addr: SocketAddr, path: &str) {
        let mut stream = TcpStream::connect(addr).unwrap();
        let request = format!("GET /{path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut buffer = Vec::new();
        let _ = stream.read_to_end(&mut buffer);
    }
}
