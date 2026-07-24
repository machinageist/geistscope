# Autonomous Hunting Implementation Plan

## Status (2026-07-23)

Superseded past Phase 7/8.1a by `.hermes/plans/2026-07-23_hunting-engine-restructure.md`. Tasks
through Phase 7 and Task 8.1a (see `AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md`) are real,
committed work and remain an accurate build log — the salvage list in the decision log covers
almost all of it. This plan's phase breakdown after that point (the remainder of Phase 6's
`mg-hunt` loop and anything implied beyond it) predates the priority reset to SSRF / broken
access control / RCE, the bounty-value scheduler, the "expand around success" finding behavior,
and the explicit AI-vs-deterministic boundary. Do not continue task selection from this file's
phase list. Write a new `PLAN.md` against the decision log's open item (choosing and scoping the
first vertical slice) instead.

> For Hermes: implement this plan task-by-task with strict TDD. Write the failing test first, run it, implement only enough production code to pass, then run targeted and full relevant tests.

Goal: Build a program-agnostic autonomous authorization and client-side hunting foundation described in docs/AUTONOMOUS_HUNTING_IMPLEMENTATION.md without letting the model bypass Rust policy, scope, redaction, audit, container isolation, or approval gates. The system must work across HackerOne, Bugcrowd, Intigriti, private programs, and manually-defined engagements rather than assuming Shopify-specific traffic or GraphQL conventions.

Architecture: Start with shared deterministic foundations before active capabilities: scope decisions, program adapter metadata, policy/audit/redaction/storage primitives, lab/session/container models, then proxy/browser capture, corpus candidates, replay plans, semantic diff, client-side analysis, evidence bundles, harness endpoints, TUI surfaces, and finally assisted hunt orchestration. Active traffic and browser automation must always flow through Rust-owned policy decisions, not model intent.

Tech Stack: Rust 2024 workspace under crates/, serde JSON schemas, clap CLIs, tokio/reqwest where networked, browser/container orchestration via Docker/Podman-compatible profiles, local engagement-root artifact storage, existing engagement/session/mg-harness/mg-tui crates where possible.

---

## Phase 0: Scope and policy foundation

### Task 0.1: Add structured scope decisions to engagement

Objective: Make URL and hostname checks produce stable JSON decisions with normalized host/url, matched allow/deny rules, and explicit reason.

Files:
- Modify: crates/engagement/src/scope.rs
- Modify: crates/engagement/src/lib.rs
- Test: crates/engagement/src/scope.rs

TDD:
1. Add tests for these behaviors:
   - any bare host and equivalent URL such as admin.example-program.com and https://admin.example-program.com/ produce the same decision
   - explicit deny beats wildcard allow and reports matched_deny
   - wildcard subdomain matches do not match unrelated domains
   - malformed/empty targets are ambiguous with a reason
2. Run: cargo test -p engagement scope_decision -- --nocapture
   Expected before implementation: FAIL because ScopeDecision/explain are missing.
3. Implement minimal ScopeDecision, ScopeVerdict, ScopeRuleMatch, and Scope::explain.
4. Run targeted test again; then cargo test -p engagement.

### Task 0.2: Add mg-engagement check --json and explain-scope --json

Objective: Expose ScopeDecision through a machine-readable CLI without breaking existing text output.

Files:
- Modify: crates/engagement/src/cli.rs
- Modify: crates/engagement/src/main.rs
- Test: add CLI smoke tests if existing binary test pattern exists; otherwise rely on cargo test plus manual CLI invocation against a temp engagement.

TDD:
1. Add or script a failing check showing mg-engagement check --json emits decision JSON for URL input.
2. Implement --json on Check and ExplainScope command.
3. Verify text behavior remains unchanged.

### Task 0.3: Add shared action policy skeleton

Objective: Introduce the Rust-owned decision object every active tool must call before network traffic.

Files:
- Create: crates/action-policy/Cargo.toml
- Create: crates/action-policy/src/lib.rs
- Modify: crates/Cargo.toml

TDD:
1. Test that high-active actions require approval.
2. Test that out-of-scope or ambiguous scope fails closed.
3. Test that read-only scoped anonymous actions can be allowed when no session is required.

### Task 0.4: Add engagement-root artifact path guard

Objective: Prevent model/user-provided output paths from escaping the engagement root.

Files:
- Create or modify: crates/engagement/src/artifact_store.rs
- Modify: crates/engagement/src/lib.rs

TDD:
1. Test normal relative path resolves under engagement root.
2. Test ../ traversal is rejected.
3. Test symlink escape is rejected.
4. Test atomic JSON write records sha256.

## Phase 1: Program import, authorization snapshot, and audit

Program support requirement: every feature in this phase must be platform-neutral. HackerOne CSV is one adapter, not the core model. The core model must support HackerOne, Bugcrowd, Intigriti, private invite-only programs, and manual JSON/YAML scope definitions with the same internal ProgramAsset and ProgramRule types. Shopify-specific helpers, GraphQL global-ID parsing, shop/tenant naming, or host fixtures must live behind optional analyzers, never in the core policy path.

### Task 1.1: Add program rules snapshot

Objective: Store the authorization artifact required before active traffic.

Files:
- Modify: crates/engagement/src/engagement.rs or new crates/engagement/src/program.rs
- Modify: crates/engagement/src/lib.rs

TDD:
1. Test missing rules snapshot blocks active policy decisions.
2. Test expired snapshot blocks active policy decisions.
3. Test automation_disallowed blocks autonomous hunt.

### Task 1.2: Add platform-neutral program scope import adapters

Objective: Import program scope rows from multiple platforms while preserving asset type, eligibility, max severity, instruction text, and platform-specific rule metadata behind a common ProgramAsset model.

Files:
- Modify: crates/engagement/src/scope.rs
- Modify: crates/engagement/src/cli.rs
- Modify: crates/engagement/src/main.rs

TDD:
1. Test importing minimal HackerOne CSV creates common ProgramAsset rules with eligibility metadata.
2. Test importing Bugcrowd/Intigriti-style JSON or CSV creates the same internal rule shape.
3. Test manual JSON/YAML scope import for private programs without platform assumptions.
4. Test explicit out-of-scope/deny precedence survives every adapter.
5. Test unknown eligibility requires approval in policy.

### Task 1.3: Add typed audit_event helper

Objective: Replace stringly active-event audit calls with structured tool/action/risk/decision/target/evidence records.

Files:
- Modify: crates/engagement/src/engagement.rs or new crates/engagement/src/audit.rs

TDD:
1. Test append-only JSONL audit event format.
2. Test event includes risk, policy decision, scope decision id/hash, and evidence path.
3. Test secret-like values are rejected or redacted.

## Phase 2: Lab model and named session vault

### Task 2.1: Add lab-model crate types

Objective: Model controlled identities, tenants, roles, boundaries, controlled resources, and expected authorization relationships.

Files:
- Create: crates/lab-model/Cargo.toml
- Create: crates/lab-model/src/lib.rs
- Modify: crates/Cargo.toml

TDD:
1. Test identity/tenant/role/resource serialization round trip.
2. Test boundary expected-deny relationship can be queried by subject/session and object/resource.
3. Test invalid cross-engagement IDs are rejected.

### Task 2.2: Add mg-lab CRUD CLI skeleton

Objective: Let the operator create/query lab objects under the engagement root using JSON output.

Files:
- Create: crates/mg-lab/Cargo.toml
- Create: crates/mg-lab/src/main.rs
- Modify: crates/Cargo.toml

TDD:
1. Test identity create --json writes under <engagement>/lab/.
2. Test tenant/role/resource create --json.
3. Test list emits stable JSON.

### Task 2.3: Replace single session config with named session profiles

Objective: Store named session metadata without leaking raw tokens/cookies.

Files:
- Modify: crates/session/src/lib.rs
- Modify: crates/mg-harness/src/lib.rs later for endpoint compatibility

TDD:
1. Test saving SessionProfile creates metadata only and rejects plaintext cookie/header values.
2. Test redacted_summary never contains token-like material.
3. Test expired sessions fail closed.
4. Test named session lookup returns only secret refs, not values.

## Phase 2.5: Containerized account and browser profile testing

### Task 2.5.1: Add browser-container profile model

Objective: Model isolated browser/container profiles for controlled account testing without cross-account cookie, storage, cache, extension, or network contamination.

Files:
- Create: crates/browser-lab/Cargo.toml
- Create: crates/browser-lab/src/lib.rs
- Modify: crates/Cargo.toml

TDD:
1. Test BrowserProfile serialization with engine docker|podman|native, image, proxy settings, session name, identity id, tenant id, role id, and storage volume path.
2. Test two profiles for different identities get distinct cookie/storage/cache volumes.
3. Test profiles cannot mount paths outside the engagement root except explicit read-only browser images.
4. Test profile metadata redacts cookies, localStorage, sessionStorage, and extension secrets.

### Task 2.5.2: Add mg-lab browser profile CLI

Objective: Let the operator create, list, start, stop, and validate isolated account containers for multi-account testing.

Files:
- Modify: crates/mg-lab/src/main.rs

TDD:
1. Test `mg-lab browser create <engagement> --identity alice --tenant tenant-a --role admin --engine podman --json` writes profile metadata under `<engagement>/lab/browser-profiles/`.
2. Test `mg-lab browser start --dry-run --json` emits container run arguments without launching.
3. Test profile start refuses non-loopback proxy exposure unless explicitly approved.
4. Test browser validate confirms profile/session/account labels match expected identity markers.

### Task 2.5.3: Add client-side bug capture model

Objective: Capture DOM, JavaScript console, storage access, postMessage, CSP, mixed content, and sink/source observations as local evidence without leaking browser secrets to the model.

Files:
- Create or extend: crates/browser-lab/src/client_side.rs

TDD:
1. Test DOM observation records URL, frame origin, selector/path, sink type, source type, and redacted snippet.
2. Test console and network errors are bounded and prompt-injection-escaped.
3. Test localStorage/sessionStorage/cookie values are never emitted; only key names and hashes are allowed.
4. Test postMessage observations include origin, target origin, schema shape, and risk class.

### Task 2.5.4: Add safe client-side test planner

Objective: Generate non-destructive browser-side test plans for reflected/stored/DOM XSS, open redirect, postMessage origin flaws, CSP weaknesses, client-side access-control leakage, and cache/storage isolation bugs.

Files:
- Create or extend: crates/browser-lab/src/planner.rs

TDD:
1. Test reflected-input plan uses harmless markers by default, not executable payloads.
2. Test stored-input plan requires controlled sender and controlled viewer profiles.
3. Test executable XSS payloads require explicit approval and controlled victim account only.
4. Test browser automation cannot click billing, staff invite, destructive, integration, webhook, payment, or export actions without approval.
5. Test generated plans include stop conditions, screenshot policy, DOM snapshot policy, and evidence output path.

## Phase 3: Proxy-first traffic capture

### Task 3.1: Add traffic schema v1

Objective: Align TrafficRecord with proxy-first fields: session/identity/role/tenant, scheme/port/query, request/response hashes, operation metadata, risk class, scope decision, and tags.

Files:
- Modify or create shared schema crate from Task 0.3/1 work
- Modify: crates/engagement/src/traffic.rs

TDD:
1. Test schema round trip with all fields.
2. Test redacted headers never include cookie/authorization/set-cookie values.
3. Test raw artifact refs include sha256 and length.

### Task 3.2: Add proxy-core capture library skeleton

Objective: Start with HTTP CONNECT/listen scaffolding, browser-container proxy wiring, and local artifact writer; do not implement broad MITM until CA lifecycle is safe.

Files:
- Create: crates/proxy-core/Cargo.toml
- Create: crates/proxy-core/src/lib.rs
- Modify: crates/Cargo.toml

TDD:
1. Test default listener is loopback only.
2. Test non-loopback listen requires explicit approval flag.
3. Test x-mg-* label headers are stripped before upstream forwarding.
4. Test raw request/response artifacts are written under engagement root.
5. Test container/browser profile metadata is recorded locally but never forwarded upstream.

### Task 3.3: Add mg-proxy CLI skeleton

Objective: Provide start/sessions/tail/export commands with --json/--output/--no-color conventions.

Files:
- Create: crates/mg-proxy/Cargo.toml
- Create: crates/mg-proxy/src/main.rs
- Modify: crates/Cargo.toml

TDD:
1. Test help includes start/sessions/tail/export.
2. Test start --dry-run --json reports listen address and CA path.
3. Test export writes corpus jsonl under engagement root.

## Phase 4: Corpus candidates and replay plans

### Task 4.1: Add request-corpus candidate model

Objective: Cluster traffic/browser observations and propose safe authorization plus client-side candidates without executing requests.

Files:
- Create: crates/request-corpus/Cargo.toml
- Create: crates/request-corpus/src/lib.rs
- Modify: crates/Cargo.toml

TDD:
1. Test comparable A/B GETs become CrossTenantRead candidate.
2. Test POST product creation is classified state-changing and not autonomous.
3. Test GraphQL global IDs are decoded/classified by optional analyzer, not core logic.
4. Test DOM sink/source observations become DOM_XSS_CANDIDATE only when source is attacker-controllable.
5. Test postMessage wildcard origin observations become CLIENT_SIDE_ORIGIN_CANDIDATE.

### Task 4.2: Add mg-corpus CLI

Objective: Import/tag/cluster/pair/query traffic as stable JSON.

Files:
- Create: crates/mg-corpus/Cargo.toml
- Create: crates/mg-corpus/src/main.rs

TDD:
1. Test build --json emits candidate count.
2. Test candidates --risk-class read_only filters correctly.

### Task 4.3: Add replay-engine plan builder

Objective: Convert candidates into immutable ReplayPlan JSON with scope decisions, sessions, substitutions, expected secure result, stop conditions, and evidence output dir.

Files:
- Create: crates/replay-engine/Cargo.toml
- Create: crates/replay-engine/src/lib.rs
- Modify or wrap existing crates/mg-replay later

TDD:
1. Test out-of-scope candidate cannot produce executable plan.
2. Test ambiguous read-only proof requires approval.
3. Test approval grant hash must match plan hash.

## Phase 5: Semantic diff and evidence

### Task 5.1: Add semantic diff verdict engine

Objective: Classify replay outcomes as SecureDenied, InterestingDiff, BoundaryViolationRead, etc., using controlled markers and ownership fields.

Files:
- Create or add to replay-engine: semantic diff module

TDD:
1. Test 401/403/404 becomes SecureDenied.
2. Test target tenant marker in attacker response becomes BoundaryViolationRead.
3. Test expired token shape becomes InvalidTest.
4. Test GraphQL authorization error becomes SecureDenied.

### Task 5.2: Add evidence bundle writer

Objective: Write immutable run bundles containing raw local artifacts, redacted summaries, hashes, plan, approvals, semantic diff, and report skeleton.

Files:
- Create: crates/evidence-core/Cargo.toml or module in replay-engine
- Create: crates/mg-evidence/Cargo.toml

TDD:
1. Test evidence run path includes candidate id and run id.
2. Test existing run cannot be overwritten.
3. Test summary.redacted.md contains no synthetic cookies/tokens/PII.

## Phase 6: Harness, TUI, and assisted hunt loop

### Task 6.1: Add harness endpoint policy metadata

Objective: Extend EndpointSpec with required engagement, scope check, session access, model-visible schema, redaction policy, and confirmation policy.

Files:
- Modify: crates/mg-harness/src/lib.rs

TDD:
1. Test every endpoint has policy metadata.
2. Test prompt injection in target traffic cannot alter endpoint policy.
3. Test invalid model arguments return typed validation errors.

### Task 6.2: Add autonomous endpoint families

Objective: Add program.import_scope, scope.explain, lab.*, session.*, browser_profile.*, proxy.*, traffic.search, corpus.*, replay.*, diff.semantic, client_side.*, evidence.bundle, and hunt.* wrappers.

Files:
- Modify: crates/mg-harness/src/lib.rs

TDD:
1. Test registry includes each endpoint.
2. Test high-risk endpoints block without approval.
3. Test model-visible outputs contain only redacted summaries and evidence refs.

### Task 6.3: Add TUI panes

Objective: Surface proxy feed, session vault, browser/container profiles, lab matrix, corpus candidates, replay/client-side plans, semantic diffs, evidence bundles, and AI next-safe-test.

Files:
- Modify: crates/mg-tui/src/*

TDD:
1. Test tab enum includes required panes.
2. Test active action prompt displays engagement, target, scope decision, session, risk, output path, and approval state.

### Task 6.4: Add mg-hunt assisted loop

Objective: Orchestrate safe next tests with deterministic budgets and resume support.

Files:
- Create: crates/mg-hunt/Cargo.toml
- Create: crates/mg-hunt/src/main.rs
- Modify: crates/Cargo.toml

TDD:
1. Test run --dry-run selects only read-only candidates.
2. Test max-tests/max-duration/max-bytes stop the loop.
3. Test 429/5xx/WAF-like threshold stops execution.
4. Test resume skips already-tested plan hashes.

## First implementation slice

Start with Task 0.1 and part of Task 0.2 because they are small, foundational, and directly address the known class of bugs where a bare hostname and its equivalent URL can diverge. Use example-program.com fixtures in tests, not Shopify-specific assumptions. Do not start proxy/replay/browser automation work before scope decisions are structured and test-backed.


## Implementation phases / issue breakdown

1. Foundation: structured ScopeDecision, check/explain JSON, platform-neutral ProgramAsset, authorization snapshot, action policy, artifact path guard.
2. Program adapters: HackerOne CSV, Bugcrowd/Intigriti/manual imports, deny precedence, eligibility gates, program rules freshness.
3. Lab/session/container model: identities, tenants/workspaces/accounts, roles, boundaries, controlled resources, named sessions, browser-container profiles.
4. Proxy/browser capture: loopback proxy, per-engagement CA lifecycle, browser profile proxy wiring, stripped local labels, raw/redacted traffic and client-side observation capture.
5. Corpus/candidate generation: REST, GraphQL, multi-tenant authz, generic object IDs, optional program-specific analyzers, DOM/postMessage/CSP/storage candidates.
6. Replay/client-side planning: immutable replay plans, read-only proof, controlled browser plans, approval grants bound to plan hashes.
7. Semantic diff/evidence: authz verdicts, client-side verdicts, screenshots/DOM snapshots with redaction, immutable evidence bundles and report skeletons.
8. Harness/TUI/hunt loop: model-visible endpoint wrappers, dense TUI panes, deterministic budgets, resume/dedupe, next-safe-test orchestration.

First implementation issue remains: finish ScopeDecision + mg-engagement JSON CLI. Next issue after that should be ProgramAsset/import adapters, not Shopify-specific logic.
