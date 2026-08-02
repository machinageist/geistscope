# Slice 2 — Bounded HTTP Executor

Status: ready after Slice 1
Depends on: hardened executable plan + `ExecutionPermit`
Parent behavior: `../PLAN.md` Task 4.1

## Goal

Execute exactly one authorized callback-only GET mutation, enforce all plan budgets fail-closed, and return bounded sanitized transaction evidence without exposing response bodies or request secrets.

## Execution authority

The executor API must consume both:

- the engine-only executable SSRF plan; and
- a non-forgeable `ExecutionPermit` whose plan hash matches exactly.

Prefer consuming the permit by value. It should not be `Clone`, so accidental retries require a new policy evaluation and audit event. A hash mismatch must fail before creating/sending a request.

## HTTP client requirements

Use a dedicated client with:

- redirects set to `Policy::none()`;
- TLS verification enabled; never call `danger_accept_invalid_certs`;
- timeout derived from the plan budget, not caller prose;
- no cookie store;
- no proxy inheritance if the library supports explicit disabling for deterministic tests;
- a fixed GeistScope user-agent with no secrets;
- response streaming or bounded chunk reads so the byte budget is enforced before buffering an entire body.

Move `reqwest` from dev-only to a minimal production dependency only when this slice begins. Keep `default-features = false`; enable only required Rustls/stream features.

## Exact request semantics

- Only GET is supported.
- Replace exactly the planned decoded query parameter occurrence with the engine-owned callback URL.
- Preserve target scheme, authority, path, query pair order, duplicate keys, and all unrelated values.
- Send no model-provided headers, cookies, auth, body, or callback destination.
- Send exactly one target request; retries are disabled.
- Redirect responses are recorded but not followed.

## Budget and stop behavior

Enforce:

- `max_requests == 1`;
- `concurrency == 1`;
- elapsed timeout;
- maximum response bytes while streaming;
- no redirects;
- stop classification for 429, 5xx, timeout, connection failure, TLS failure, response-too-large, and policy/plan mismatch.

A 2xx/3xx/4xx response other than explicit stop cases is a completed transaction, not proof of SSRF. A network/timeout/budget failure is an invalid execution, not a negative SSRF result.

Immediately before sending, revalidate permit expiry, authorization expiry, plan/executable-input
hashes, and the trusted target authority. Disable environment/system proxies explicitly; do not
leave this conditional on client defaults. Do not invent response-body WAF or “instability”
heuristics—only structured deterministic signals approved by the plan may stop execution.

The offline benchmark's loopback target and callback are an exact fixture-authority exception. Do
not weaken production destination rules into a general allowance for arbitrary loopback, RFC1918,
link-local, or metadata payloads.

## Sanitized transaction record

Return a serializable `HttpTransactionRecord` (name may vary) containing only:

- plan hash and candidate ID;
- method;
- redacted target origin/path plus query key names/occurrences, not values;
- start/end timestamps or elapsed duration;
- status code if received;
- bounded allowlisted response headers with sensitive values redacted;
- response body SHA-256, observed byte count, and truncation/limit flag;
- executor outcome/stop reason.

Never serialize the callback URL/token, raw query values, request headers containing credentials, or response body.

## Codebase map

Inspect:

- `crates/hunt-engine/src/ssrf.rs`
- `crates/hunt-engine/src/plan.rs`
- Slice 1's policy module and permit type
- `crates/hunt-engine/tests/support/mod.rs`
- `crates/hunt-engine/tests/ssrf_benchmark.rs`
- `crates/hunt-engine/Cargo.toml`

Likely additions:

- `crates/hunt-engine/src/http_executor.rs`
- `crates/hunt-engine/tests/http_executor.rs`

## Behavior-first tests

Use ephemeral loopback Axum fixtures and exact request counters. Prove:

1. Valid permit executes exactly one request and replaces exactly one duplicate query occurrence.
2. Permit/plan mismatch performs zero network I/O.
3. Missing permit has no executable public API path.
4. Redirect response is not followed; second server receives zero requests.
5. Timeout is bounded and classified invalid.
6. Response larger than byte budget is stopped without retaining raw body.
7. 429, 500, connection failure, and TLS failure produce explicit stop outcomes.
8. Response body, callback token, original URL query value, `Set-Cookie`, and authorization-like headers do not appear in serialized transaction records.
9. Secure and vulnerable benchmark endpoints each receive at most one target request.
10. Executor makes no Internet request; tests bind only ephemeral loopback ports.
11. Permit or authorization expiry immediately before send performs zero network I/O.
12. A configured environment proxy receives zero requests.
13. Executable-input hash mismatch performs zero target and callback I/O.

## Non-goals

- No retries, redirects, POST bodies, authenticated replay, cookies, browser execution, DNS callbacks, metadata IPs, or internal-network payloads.
- No finding classification.
- No evidence bundle writing.
- No generic multi-capability worker framework.

## Verification

```bash
cargo test -p hunt-engine --test http_executor
cargo test -p hunt-engine --test ssrf_benchmark
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p hunt-engine -- --check
git diff --check
```

## Done means

A permitted plan can produce one bounded sanitized transaction, while every authority mismatch, retry path, redirect, timeout, or byte-limit case fails deterministically without leaking secrets or producing a finding.
