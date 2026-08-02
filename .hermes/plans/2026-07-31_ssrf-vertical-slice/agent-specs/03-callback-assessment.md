# Slice 3 — Callback Observation and Deterministic Assessment

Status: ready after Slice 2
Depends on: callback recorder + bounded transaction record
Parent behavior: `../PLAN.md` Task 4.2

## Goal

Combine the completed target transaction with a finalized callback observation window and produce a deterministic assessment that distinguishes proven callback, clean negative, and invalid/inconclusive execution—without promoting a verified finding yet.

## Classification contract

Introduce a serializable assessment with explicit state and reason codes. Required mapping:

| Execution/correlation state | Assessment |
|---|---|
| successful bounded target transaction + exact live token/plan callback | `callback_proven` |
| successful bounded target transaction + no callback by deadline | `negative` |
| callback plan mismatch, unknown token, expired token, or reused token | `invalid` |
| target timeout, connection/TLS error, byte-budget failure, policy mismatch, audit failure | `invalid` |
| target response contains SSRF-looking text but no callback | still `negative` after successful window |
| callback exists but transaction was never authorized/executed | `invalid` |

`callback_proven` is sufficient evidence input for Slice 4, but this slice must not expose `HuntResultClass::VerifiedFinding`; evidence commit must succeed first.

## Observation window

Add an injected clock/deadline abstraction or an explicit finalized timestamp so tests never sleep for wall-clock seconds. The production orchestration may await a timer later, but the classifier itself must be pure and deterministic.

Required fields:

- plan hash and candidate ID;
- transaction outcome reference/hash;
- callback correlation enum and callback record reference/hash when matched;
- observation start/deadline/finalized timestamps;
- deterministic assessment class and reason code;
- evidence requirements satisfied/missing, without constructing `EvidenceSatisfaction` yet.

Raw token and callback body remain absent.

## Callback worker boundary

The in-process test callback HTTP handler may parse the token path and call `CallbackRecorder::record`, but it must:

- reject malformed/unknown tokens without creating proof;
- bound headers/body before the recorder;
- never echo token/body content into errors;
- bind only an ephemeral loopback port in tests;
- record source metadata as untrusted content subject to existing redaction.
- accept only the exact `/callbacks/{token}` route; prefixes, suffixes, query-carried tokens, and a
  separately supplied known token cannot satisfy the registration;
- cap header count and aggregate header bytes, not only each field;
- stream and hash request bodies under the byte cap rather than first buffering an unbounded body;
- retain bounded peer/source metadata without treating it as trusted proof.

Do not make the HTTP listener itself classify findings.

## Codebase map

Inspect:

- `crates/hunt-engine/src/callback.rs`
- `crates/hunt-engine/src/http_executor.rs` from Slice 2
- `crates/hunt-engine/src/lib.rs`
- `crates/hunt-engine/tests/callback.rs`
- `crates/hunt-engine/tests/support/mod.rs`

Likely additions:

- `crates/hunt-engine/src/assessment.rs`
- `crates/hunt-engine/tests/callback_assessment.rs`

## Behavior-first tests

Prove:

1. Matching token + exact plan hash + successful transaction + live deadline yields `callback_proven`.
2. No callback at the finalized deadline after successful transaction yields `negative`.
3. Before the deadline, no-callback state is `pending`, not negative, if a pending state is exposed.
4. Unknown, malformed, expired, reused, and plan-mismatched callbacks yield `invalid`.
5. A matching callback paired with failed/unauthorized transaction yields `invalid`.
6. Response text/status cannot change negative to proven.
7. Assessment serialization contains no raw token, body, original query value, cookie, or authorization data.
8. Identical structured inputs yield byte-identical canonical assessment JSON or identical hashes.
9. Tests use an injected/fixed clock and contain no long sleeps.
10. A callback received within its lease remains proven when classification occurs after the window closes.
11. Exact-route, header-count, aggregate-header-byte, peer-metadata, and streaming-body limits are enforced.
12. A late callback is invalid rather than negative or proven.
13. Duplicate callback behavior follows the single-use rule and cannot leave valid proof after reuse.

## Non-goals

- Do not write evidence bundles.
- Do not produce a verified `HuntResult`.
- Do not add DNS callbacks or remote callback infrastructure.
- Do not allow response heuristics to substitute for callback proof.

## Verification

```bash
cargo test -p hunt-engine --test callback
cargo test -p hunt-engine --test callback_assessment
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p hunt-engine -- --check
git diff --check
```

## Done means

Given authorized execution output and a finalized callback window, deterministic code emits exactly one pending/proven/negative/invalid assessment with no model judgment and no verified finding promotion.
