# SSRF Vertical Slice — Change Specification

Date: 2026-07-31
Status: Accepted working spec; implementation in progress
Product source: `.hermes/plans/2026-07-23_hunting-engine-restructure.md`

## Outcome

Prove the first real end-to-end GeistScope campaign slice with a controlled server-side request forgery target. Starting from an observed in-scope HTTP request containing a plausible server-side URL input, GeistScope must produce a policy-gated test, execute it against a deterministic local benchmark, correlate a unique callback, preserve immutable evidence, classify the result without an AI assertion, and emit a human-verifiable result.

This slice is the benchmark for the new hunting engine. It is not an expansion of the old standalone `mg-ssrf` scanner.

## Successful session

1. The operator creates or loads an engagement with current program rules and explicit scope.
2. A captured or imported request identifies an attacker-controlled URL-like input.
3. Deterministic candidate analysis records an SSRF hypothesis without sending traffic.
4. The engine creates a bounded test plan containing:
   - target scope decision;
   - action risk and required approval state;
   - one unique callback token;
   - the exact request mutation;
   - request, time, byte, and redirect budgets;
   - stop conditions;
   - an evidence contract.
5. Rust-owned policy either blocks the plan or authorizes execution. AI text cannot change the decision.
6. The executor sends the planned request to a controlled local benchmark only.
7. The callback service records the token, source metadata, and timestamps.
8. Deterministic correlation links the callback to the exact immutable test plan.
9. The evidence writer preserves the plan, policy decision, sanitized request/response metadata, callback record, correlation verdict, hashes, and redacted summary.
10. GeistScope emits one of:
    - `verified_finding`: a matching callback proves the controlled target performed the outbound request;
    - `human_verification_candidate`: evidence is suggestive but not sufficient;
    - `negative_test`: no callback arrived within the bounded observation window;
    - `invalid_test`: authorization, scope, execution, callback, or evidence requirements failed.
11. A verification runbook explains how a human can repeat the proof safely.

## Acceptance benchmark

The benchmark contains two endpoints with the same request shape:

- vulnerable: accepts a URL and performs one outbound HTTP request;
- secure: rejects or safely handles the same input without contacting the callback service.

For the vulnerable endpoint, the slice must produce a verified finding only after a matching unique callback is recorded. For the secure endpoint, it must not produce a finding. The same campaign must demonstrate a fail-closed policy case for an out-of-scope or unapproved plan.

The benchmark must be deterministic, local, disposable, and runnable in CI without Internet access.

## Safety invariants

- No cloud metadata, loopback, RFC1918, link-local, file, or alternate-scheme payload is sent in this first slice.
- The only probe destination is the campaign-owned callback service.
- Candidate generation is inert.
- Every active request has a current engagement, current program rules, an in-scope target decision, a risk classification, an audit event, and explicit budget limits.
- Redirects are disabled for the first slice.
- Concurrency is one.
- A callback token is single-plan, high-entropy, expires after the observation window, and is never accepted as proof for another plan.
- A target response alone cannot verify SSRF.
- A callback without a matching plan token cannot verify SSRF.
- Raw secrets are never model-visible.
- All artifact paths remain under the engagement root and evidence bundles are immutable.
- Untrusted target and callback content is bounded and redacted before model-visible serialization.

## AI boundary

AI may rank the candidate, explain why the URL-like input is interesting, and draft prose from structured results.

Deterministic code owns candidate facts, scope and policy checks, token generation, request mutation, execution, callback correlation, evidence hashes, result classification, and whether the evidence contract permits `verified_finding`.

The first benchmark must work with no model configured.

## Reuse classification

Salvage as tested primitives where their interfaces remain suitable:

- `engagement`: scope, program rules, artifact guards, and audit types;
- `action-policy`: fail-closed active-action policy;
- `request-corpus`: inert candidate pattern, but not its authorization-only candidate schema unchanged;
- `replay-engine`: immutable plan hashing pattern, but not its authorization-only plan/verdict schema unchanged;
- `evidence-core`: immutable bundle and redaction behavior;
- `mg-oob`: HTTP-listener behavior as reference code, not as the authoritative callback architecture;
- `mg-webscan/src/ssrf.rs`: URL-input discovery ideas only; do not salvage payload spraying, metadata probes, permissive TLS, response-body heuristics, or direct finding emission.

## Non-goals

- Cloud metadata probing or impact escalation
- Internal network enumeration
- DNS callbacks
- Redirect-chain bypasses
- Alternate URL schemes or parser-confusion payloads
- Header-based SSRF spraying
- Authenticated browser discovery
- Internet-hosted callback infrastructure
- General SSRF payload libraries
- IDOR, injection, or broad scheduler implementation
- Automatic report submission
- Preserving existing crate, CLI, endpoint, or JSON compatibility

## Required design checkpoints

Implementation pauses for Jeff at each checkpoint:

1. Authoritative engine boundary: introduce a new cohesive engine library or evolve the existing `mg-hunt`/candidate/replay crates.
2. Controlled benchmark form: in-process Rust integration fixture or a separately launched containerized lab.
3. Callback ownership: engine-managed callback worker API or adaptation of the existing `mg-oob` process/files.
4. Public local API and persistence boundary after the slice proves domain behavior.
5. First pruning decision: which old SSRF/OOB surfaces become quarantined or deleted after replacement.
