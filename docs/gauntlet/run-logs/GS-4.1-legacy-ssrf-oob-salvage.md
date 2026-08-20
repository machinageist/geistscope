# GS-4.1 Legacy SSRF/OOB Salvage Audit

Date: 2026-08-13
Status: inventory complete; dispositions pending Checkpoint 5 and replacement parity
Scope: SSRF/OOB paths only

## Outcome

`hunt-engine` should become the sole SSRF planning, authorization, execution, callback-correlation, assessment, evidence-promotion, and result authority. Existing legacy paths contain useful scenarios and operational mechanics, but none should remain an independent finding authority.

No legacy deletion is authorized by this audit. Deletion requires the parity gates below and explicit Checkpoint 5 approval.

## Retain as authoritative

- Candidate and immutable plan construction: deterministic candidates, exact duplicate-query occurrence selection, original-value hashing, token-bound plan hashes, redacted public views, GET-only planning, fixed budgets, and stop conditions — `crates/hunt-engine/src/ssrf.rs:93-173,235-400,450-590,633-663`.
- Policy gate: plan-bound scope/rules hashes, persisted decision/audit before a non-clonable permit, and authorization expiry — `crates/hunt-engine/src/policy.rs:100-123,125-225,227-294,342-410`.
- Executor: exactly one authorized GET, no redirects/proxies, fixed timeout/byte cap, sanitized headers, hashed body reference, explicit transport outcomes — `crates/hunt-engine/src/http_executor.rs:86-193,224-297`.
- Callback contract: exact route parsing, unknown/expired/reused/plan-mismatch distinctions, token/body hashing, redaction, and bounded metadata — `crates/hunt-engine/src/callback.rs:26-79,102-180,205-332`.
- Assessment: deterministic `Pending`, `CallbackProven`, `Negative`, or `Invalid`, without direct finding promotion — `crates/hunt-engine/src/assessment.rs:63-153,155-239`.

Existing baseline tests to retain:

- `crates/hunt-engine/tests/ssrf_plan.rs:34-137`
- `crates/hunt-engine/tests/ssrf_plan_security.rs:97-490`
- `crates/hunt-engine/tests/policy_gate.rs:127-419`
- `crates/hunt-engine/tests/http_executor.rs:147-534`
- `crates/hunt-engine/tests/callback.rs:32-203`
- `crates/hunt-engine/tests/callback_assessment.rs:109-329`

## Legacy dispositions

### `crates/mg-hunt/src/main.rs` — adapt scenarios; quarantine current SSRF authority; delete only after parity

Preserve as requirements/tests:

- Callback → evidence → finding → resume-ledger E2E: `:1230-1309`.
- Response metadata-marker E2E: `:1321-1404`.
- Header-position SSRF E2E: `:1406-1483`.
- Evidence/finding/resume integration: `:722-750`.
- Header mutation and response-marker coverage: `:754-815`.

Do not retain unchanged:

- One plan/token reused across an unbounded probe set: `:676-697,754-815`.
- Silently skipped send failures: `:688-695,804-807`.
- Direct semantic finding promotion: `:731-743`.
- Self-manufactured approval instead of the policy authority: `:669-674`.

### `crates/mg-webscan/src/ssrf.rs` — quarantine; delete after safe replacement

Adapt only as coverage requirements:

- Crawl/recon ingestion and fallback: `:127-237,366-372`.
- Header-position inventory: `:55-56,200-207`.
- Payload vocabulary as a reviewed/deferred corpus, not executable defaults: `:34-53`.
- Bounded campaign concept: `:393-411`.

Reject unchanged:

- Direct link-local/localhost probing: `:34-42`.
- GET substitution for observed POST semantics: `:186-207,263-270`.
- Incomplete URL encoding: `:244-271,306-316`.
- Disabled TLS verification: `:385-390`.
- Any non-empty HTTP 200 body classified as potential: `:274-285`.
- Substring callback correlation: `:318-344,413-419`.
- Direct finding emission: `:460-480`.

### `crates/oob-core` — merge proven listener behavior, then delete

Preserve:

- Loopback listener lifecycle and blocking wait: `crates/oob-core/src/lib.rs:74-182`.
- Plan/candidate/engagement binding and real HTTP test: `:37-60,114-172,264-315`.

Replace:

- Non-cryptographic token generation: `:242-249`.
- Non-exact route correlation: `:198-239`.
- Unbounded hit storage: `:62-72,215-225`.
- Serializable raw token: `:45-60`.

Keep until an engine-owned production callback-listener adapter exists.

### `crates/mg-oob` — quarantine standalone authority; adapt operations

Adapt:

- Configurable bind/port, known-token provisioning, inactivity/Ctrl-C shutdown: `crates/mg-oob/src/main.rs:44-72,179-251`.
- Method/peer/header/body-preview capture and persistence ergonomics: `:76-107,111-168,257-282`, after bounding/redaction and engine authority are applied.

Reject unchanged:

- Default public bind `0.0.0.0:8765`: `:34-36,57-67`.
- Bare-path token matching without plan registration/expiry: `:121-127`.
- Raw headers/body/token persistence: `:128-155,270-279`.
- Generic high-severity finding emission for any known-token hit: `:291-297`.

### `replay-engine` / `replay-runner` — retain generic replay; remove SSRF authority after migration

Preserve for non-SSRF consumers:

- OOB/response-leak/no-signal distinctions: `crates/replay-engine/src/lib.rs:228-265,572-605`.
- Query/header mutation and secret-header stripping: `:460-559,607-747`.
- Zero traffic for non-executable plans: `crates/replay-runner/src/lib.rs:41-84,159-183`.

Do not use as new SSRF authority:

- Publicly serializable caller-supplied executable plan: `crates/replay-engine/src/lib.rs:71-83`.
- Arbitrary request supplied separately from the plan: `crates/replay-runner/src/lib.rs:41-64`.
- Full response body/header retention: `:65-83`.

## Mandatory parity gates before deletion

1. Full new-path vulnerable E2E through policy, executor, production callback worker, assessment, and atomic evidence; no automatic verified finding.
2. Secure negative E2E: completed request plus no callback at deadline is `Negative`; before deadline is `Pending`.
3. Typed one-header mutation with secret handling, one-request budget, and callback proof.
4. Controlled response-leak slice with bounded/redacted evidence and separate classification from callback proof.
5. Production callback adapter with configurable bind/origin, exact routes, registration/expiry/reuse enforcement, graceful shutdown, and redacted persistence.
6. Crawl/traffic/recon adapter into normalized, deduplicated, scope-backed observations.
7. Atomic evidence, assessment references, tested-plan ledger, and separate result-promotion policy.
8. Zero-I/O failures for stale/mismatched permits, changed candidates, expired leases, unknown/reused tokens, unsafe origins, and stale/out-of-scope policy.
9. Every campaign location/payload becomes a separate immutable one-request plan; no shared token/approval across unbounded loops.

## Checkpoint status

Inventory is complete. Final `adapt`, `merge`, `quarantine`, and `delete-after-replacement` decisions remain blocked on replacement evidence and explicit Checkpoint 5 approval.
