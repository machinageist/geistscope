# GeistScope SSRF Triple-A Review Standard

Date: 2026-08-06
Status: accepted review gate; no current product-level AAA pass
Scope: SSRF/OAST vertical slice and its corrective sub-slices

## Purpose

A slice is not complete merely because focused tests pass. Every implementation slice must survive an independent blind review against demonstrated behavior in established web-security products. Failed findings become new corrective sub-slices and are reviewed again by a fresh blind agent.

“AAA” has three independent axes:

1. **Architecture and authority integrity** — immutable identity, provenance, ownership, correlation, state, and evidence authority.
2. **Adversarial safety** — authorization, scope, bounded execution, secret handling, hostile-input behavior, and fail-closed operation.
3. **Acceptance and product utility** — useful end-to-end detection, operator-visible evidence, exact request review, reproducibility, integration, and recovery.

The final product earns AAA only when every axis earns A, every mandatory item has full evidence, no hard-fail condition remains, and a blind reviewer reproduces the claims from a clean build/configuration.

A narrow corrective sub-slice may earn a scoped AAA pass only for its declared contract. That does not imply the containing slice or product has passed.

## Real-world comparison set

### Burp Suite Professional Scanner and Collaborator

Primary reference for integrated request-to-callback workflow, interaction attribution, operator evidence, private OAST deployment, health checks, and retrieval-secret ownership.

Sources:

- https://portswigger.net/burp/documentation/scanner
- https://portswigger.net/burp/documentation/collaborator
- https://portswigger.net/burp/documentation/desktop/tools/collaborator
- https://portswigger.net/burp/documentation/collaborator/server/private
- https://portswigger.net/burp/documentation/collaborator/server/security

### ProjectDiscovery Nuclei and Interactsh

Primary reference for precise mutation addressability, declarative/repeatable checks, OAST correlation under concurrency, signed/versioned content, explicit fuzzing opt-in, machine-readable operation, and public/self-hosted providers.

Sources:

- https://docs.projectdiscovery.io/opensource/nuclei/overview
- https://docs.projectdiscovery.io/opensource/nuclei/running
- https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview
- https://docs.projectdiscovery.io/templates/reference/oob-testing
- https://docs.projectdiscovery.io/templates/reference/template-signing
- https://docs.projectdiscovery.io/opensource/interactsh/overview
- https://docs.projectdiscovery.io/opensource/interactsh/running

### OWASP ZAP Active Scanner and OAST Support

Secondary reference for explicit active-scan safety warnings, scan policies, provider abstraction, API/script integration, and honest delayed-attribution limitations.

Sources:

- https://www.zaproxy.org/docs/desktop/start/features/ascan/
- https://www.zaproxy.org/docs/desktop/addons/oast-support/
- https://www.zaproxy.org/docs/alerts/40046/

### Caido

Reference for request-centric operator UX, responsiveness, and plugin ergonomics. It is not the primary SSRF/OAST detection baseline unless a specific plugin is selected and version-pinned.

Source: https://docs.caido.io/

## Scoring

Each axis has ten criteria, scored 0–2:

- **0:** absent, misleading, unsafe, or unverified.
- **1:** partially implemented or supported only by happy-path evidence.
- **2:** complete for the declared scope, reproducibly tested, and visible to the operator where applicable.

Axis grade:

- **A:** 16–20
- **B:** 12–15
- **C:** 8–11
- **D/F:** 0–7 or any axis-specific hard failure

AAA requires:

- A on all three axes;
- full credit on every mandatory criterion;
- no hard fail;
- black-box evidence from a clean build/configuration for product-level claims.

## A1 — Architecture and authority integrity

Mandatory:

1. Canonical request identity binds every executable request semantic and byte-sensitive field relevant to the transport.
2. Mutation provenance identifies the exact component and operation.
3. Every dispatched mutation has a unique unguessable callback identity bound to run, request, mutation, payload, and provider.
4. Interleaved, duplicate, reordered, and delayed callbacks cannot cross-associate.

Additional criteria:

5. Pending probes and consumed callbacks have explicit durable/idempotent lifecycle states.
6. OAST providers share one correlation contract across public and private/self-hosted configurations.
7. Registration and polling secrets remain owned by the local provider/run context.
8. Built-in and extension content has visible version/trust identity.
9. Evidence links source request, exact mutation, dispatch, callback, decision, timestamps, and tool/check version.
10. Export/replay reproduces mutation and matcher semantics while regenerating runtime secrets safely.

## A2 — Adversarial safety

Mandatory:

1. Active dispatch requires explicit authorization and selected scope.
2. Scope is rechecked at send time, including target canonicalization and redirect/DNS implications.
3. Default probes are benign callbacks; metadata, private-network, alternate-scheme, or destructive probes require separate explicit authority.
4. Request, concurrency, rate, timeout, retry, redirect, byte, callback-wait, and total-run bounds are enforceable.

Additional criteria:

5. One component is mutated at a time by default.
6. Mutation preserves unrelated request bytes/fields, ordering, authentication, encoding, and framing.
7. Redirect and DNS behavior cannot silently escape egress policy.
8. Secrets are redacted from public/model-visible records, logs, exports, telemetry, and crash output.
9. Callback content is bounded before allocation/storage, redacted, access-controlled, and retention-limited.
10. Pause/stop is prompt and auditable while preserving pending-callback state.

## A3 — Acceptance and product utility

Mandatory:

1. Controlled corpus proves end-to-end blind SSRF detection and distinguishes callback proof from in-band reflection.
2. Findings identify the source request, insertion point, payload class, callback protocol/time/source, proof basis, and safe reproduction.
3. Late and duplicate callbacks enrich the originating run rather than becoming unrelated alerts.
4. Authorized operators can inspect/copy exact original and mutated requests through a privileged local evidence path.

Additional criteria:

5. Operator can select component, replacement mode, one/all behavior, payload family, and preconditions.
6. Manual captured-request testing can become a repeatable automated run and durable finding.
7. Preflight/progress surfaces scope, risk, provider health, budgets, estimates, and run-state counts.
8. Human and machine-readable exports carry stable IDs and redacted evidence.
9. Extensions can add candidate selection, mutation, payload, matchers, and providers through a constrained versioned contract.
10. Provider outages, bad credentials, target failure, restart, duplicate callback, and expiry produce explicit recoverable states.

## Hard-fail conditions

Any one prevents product-level AAA:

1. A callback can be credited to the wrong target request, component, identity, or run.
2. Callback evidence is overstated as internal-resource access or impact it did not prove.
3. Active traffic can leave declared scope without explicit authority.
4. Dangerous internal/metadata/destructive payloads run by default.
5. Polling secrets, target credentials, or sensitive callback content appear in ordinary logs, exports, telemetry, or crash output.
6. Callback identifiers are predictable/reused or interactions can be retrieved by the wrong client.
7. The product reports a successful test without retaining proof of the request actually dispatched.
8. Stop/cancel continues dispatching queued probes without an explicit documented state.
9. Restart loses or reassigns pending callback correlation.
10. Untrusted executable checks silently receive built-in authority.
11. Requests, concurrency, redirects, retries, bytes, or callback retention cannot be bounded.
12. Export/replay changes the mutation target without reporting that change.

## Blind review protocol

For each implementation or corrective sub-slice:

1. Bind the review to a baseline commit and exact diff.
2. Give the reviewer code, tests, public interfaces, controlled fixtures, and external product references—but not the internal plan, implementation rationale, or prior verdicts.
3. Require adversarial reproduction, exact file/line findings, executed commands, and explicit axis grades.
4. Separate pre-existing out-of-scope defects from regressions, but record both in the parent backlog.
5. Treat any material reviewer failure as a new corrective sub-slice.
6. Re-run a fresh blind review after corrections.
7. Commit only after the scoped slice passes its tests, review gate, formatting, and diff hygiene. A known parent-slice quality failure must remain explicit.

## Review history

### 2026-08-06 — initial whole-boundary review

Result: **FAIL AAA**

- Architecture/authority integrity: F
- Adversarial safety: F
- Acceptance/product utility: C

Blocking classes included incomplete executable-request identity, caller-controlled time, repeat permit issuance, callback route/time authority gaps, callback buffering before caps, and secret-bearing path/header serialization.

### 2026-08-06 — corrective sub-slice 0A review

Scope: canonical executable GET identity, exact query mutation, model-safe public path metadata, and private scope target.

Result: **not yet passed**. One reviewer passed the narrow contract; two found blockers:

- empty raw query segments could be counted as real empty-name parameters, mutating the wrong component;
- a public unsalted path digest created a dictionary/equality oracle;
- source-request provenance was absent from public plan/audit evidence;
- public insertion-point names could carry secrets;
- hash schema identity was not versioned.

Corrective sub-slice 0A.1 is in progress. No commit-level completion claim should be made until a fresh blind review passes.
