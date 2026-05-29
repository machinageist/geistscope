# Autonomous Hunting Progress Checklist

Use this as the restart point after clearing context.

Workspace root for Rust commands: `/home/mgeist/geistscope/crates`
Repo root: `/home/mgeist/geistscope`
Primary plan: `/home/mgeist/geistscope/docs/AUTONOMOUS_HUNTING_TDD_PLAN.md`
Original spec: `/home/mgeist/geistscope/docs/AUTONOMOUS_HUNTING_IMPLEMENTATION.md`
Engineering guidelines: `~/.hermes/ai-engineering-best-practices.md`

## Current implementation status

### Phase 0: Scope and policy foundation

- [x] Task 0.1: Add structured scope decisions to engagement
  - Commit: `8ea3d83 feat(engagement): add structured scope decisions`
  - Files:
    - `crates/engagement/src/scope.rs`
    - `crates/engagement/src/lib.rs`
  - Implemented:
    - `ScopeDecision`
    - `ScopeVerdict`
    - `ScopeRuleMatch`
    - `Scope::explain`
    - URL/bare-host normalization
    - deny precedence
    - ambiguous malformed/empty input handling

- [x] Task 0.2: Add `mg-engagement check --json` and `explain-scope --json`
  - Commit: `8ea3d83 feat(engagement): add structured scope decisions`
  - Files:
    - `crates/engagement/src/cli.rs`
    - `crates/engagement/src/main.rs`
  - Implemented:
    - JSON scope decisions for `check`
    - `explain-scope` command
    - backwards-compatible text output

- [x] Task 0.3: Add shared action policy skeleton
  - Commit: `3196c97 feat(policy): add action policy skeleton`
  - Files:
    - `crates/action-policy/Cargo.toml`
    - `crates/action-policy/src/lib.rs`
    - `crates/Cargo.toml`
  - Implemented:
    - `ActionPolicy`
    - `PolicyRequest`
    - `PolicyDecision`
    - `ActionKind`
    - `RiskLevel`
    - `SessionRequirement`
    - `ApprovalState`
  - Safety gates:
    - out-of-scope / ambiguous scope blocks
    - high-active actions require approval
    - read-only scoped actions can be allowed

- [x] Task 0.4: Add engagement-root artifact path guard
  - Commit: `01fae02 feat(engagement): guard artifact output paths`
  - Files:
    - `crates/engagement/src/artifact_store.rs`
    - `crates/engagement/src/lib.rs`
  - Implemented:
    - engagement-root path resolution
    - `..` traversal rejection
    - symlink escape rejection
    - atomic JSON writes
    - SHA-256 write records

### Phase 1: Program import, authorization snapshot, and audit

- [x] Task 1.1: Add program rules snapshot
  - Commit: `92b3ec6 feat(policy): require program rules for active actions`
  - Files:
    - `crates/engagement/src/program.rs`
    - `crates/action-policy/src/lib.rs`
    - `crates/engagement/src/lib.rs`
  - Implemented:
    - `ProgramRulesSnapshot`
    - active policy blocks when snapshot missing
    - active policy blocks when snapshot expired
    - active policy blocks when automation is disallowed

- [x] Task 1.2: Add platform-neutral program scope import adapters
  - Commit: `8359ba1 feat(engagement): import platform program scope`
  - Files:
    - `crates/engagement/src/scope.rs`
    - `crates/engagement/src/cli.rs`
    - `crates/engagement/src/main.rs`
    - `crates/action-policy/src/lib.rs`
  - Implemented:
    - common `ProgramAsset` model
    - HackerOne CSV import
    - Bugcrowd-style JSON import
    - manual JSON import
    - CLI scope import wiring
    - asset metadata in `ScopeDecision`
    - unknown bounty eligibility requires approval
  - Follow-up completed:
    - explicit Intigriti JSON fixture coverage
    - manual YAML scope import support
    - Commit: `0cec901 feat(engagement): add intigriti and yaml scope imports`

- [x] Task 1.3: Add typed audit_event helper
  - Commit: `28993b8 feat(engagement): add typed audit events`
  - Files:
    - `crates/engagement/src/audit.rs`
    - `crates/engagement/src/lib.rs`
  - Implemented:
    - typed JSONL audit events
    - risk / decision / target / reason / evidence fields
    - control-character rejection to prevent audit-line forging

### Phase 2: Lab model and named session vault

- [x] Task 2.1: Add lab-model crate types
  - Commit: `33cf36d feat(lab): add controlled lab model`
  - Files:
    - `crates/lab-model/Cargo.toml`
    - `crates/lab-model/src/lib.rs`
    - `crates/Cargo.toml`
  - Implemented:
    - `Identity`
    - `Tenant`
    - `Role`
    - `Resource`
    - `BoundaryExpectation`
    - `ExpectedDecision`
    - `LabModel`
    - safe ID validation

- [x] Task 2.2: Add `mg-lab` CRUD CLI skeleton
  - Commit: `2929937 feat(lab): add mg-lab CRUD CLI skeleton`
  - Files to create/modify:
    - `crates/mg-lab/Cargo.toml`
    - `crates/mg-lab/src/main.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] `identity create --json` writes under `<engagement>/lab/`
    - [x] tenant/role/resource create emits stable JSON
    - [x] list emits stable JSON
  - Implemented:
    - `mg-lab identity create <engagement> <id> --label <label> --json`
    - `mg-lab tenant create <engagement> <id> --label <label> --json`
    - `mg-lab role create <engagement> <id> --label <label> --json`
    - `mg-lab resource create <engagement> <id> --tenant <tenant-id> --type <resource-type> --json`
    - `mg-lab list <engagement> --json`
  - Why this mattered:
    - makes `lab-model` operator-usable
    - needed before browser profile CLI and account-bound testing

- [x] Task 2.3: Replace single session config with named session profiles
  - Commit: `330c0ca feat(session): add named session profiles`
  - Files:
    - `crates/session/src/lib.rs`
    - `crates/session/Cargo.toml`
  - TDD from plan:
    - [x] metadata only, no plaintext cookies/headers
    - [x] redacted summary contains no token-like material
    - [x] expired sessions fail closed
    - [x] lookup returns secret refs, not values
  - Implemented:
    - `SessionProfile`
    - `SecretRef`
    - `save_session_profile`
    - `load_session_profile`
    - `require_active_session_profile`
    - `session_profile_path`
    - `SessionProfile::redacted_summary`
  - Follow-up completed:
    - named profiles wired into `mg-harness` endpoint compatibility
    - Commit: `7a7edb4 feat(harness): wire named session profiles`

### Phase 2.5: Containerized account and browser profile testing

- [x] Task 2.5.1: Add browser-container profile model
  - Commit: `b080d37 feat(browser): add isolated browser profiles`
  - Files:
    - `crates/browser-lab/Cargo.toml`
    - `crates/browser-lab/src/lib.rs`
    - `crates/Cargo.toml`
  - Implemented:
    - `BrowserProfile`
    - `BrowserEngine`
    - `ProxySettings`
    - `ProfileMount`
    - `MountMode`
    - `RedactedBrowserProfile`
    - storage/cache isolation
    - mount validation
    - redacted model-visible metadata

- [x] Task 2.5.2: Add `mg-lab` browser profile CLI
  - Commit: `12e9fc3 feat(lab): add browser profile CLI`
  - Should follow Task 2.2 after `mg-lab` exists
  - Files:
    - `crates/mg-lab/src/main.rs`
    - `crates/mg-lab/Cargo.toml`
    - `crates/browser-lab/src/lib.rs`
  - TDD from plan:
    - [x] `mg-lab browser create <engagement> --identity alice --tenant tenant-a --role admin --engine podman --json` writes metadata under `<engagement>/lab/browser-profiles/`
    - [x] `mg-lab browser start --dry-run --json` emits container run args without launching
    - [x] profile start refuses non-loopback proxy exposure unless explicitly approved
    - [x] browser validate confirms profile/session/account labels match expected identity markers
  - Implemented:
    - `mg-lab browser create <engagement> <id> --identity <identity-id> --tenant <tenant-id> --role <role-id> --engine <engine> --json`
    - `mg-lab browser list <engagement> --json` with redacted profile metadata
    - `mg-lab browser start <engagement> <id> --dry-run --json`
    - `mg-lab browser validate <engagement> <id> --json`
  - Safety gates:
    - start is dry-run only for now and does not launch containers
    - non-loopback proxy exposure requires explicit approval flag
    - list output uses `RedactedBrowserProfile`, not raw profile internals

- [x] Task 2.5.3: Add client-side bug capture model
  - Commit: `ebafe91 feat(browser): add client-side observation model`
  - Files:
    - `crates/browser-lab/src/client_side.rs`
  - TDD from plan:
    - [x] DOM observation records URL, frame origin, selector/path, sink type, source type, and redacted snippet
    - [x] console and network errors are bounded and prompt-injection-escaped
    - [x] localStorage/sessionStorage/cookie values are never emitted; only key names and hashes
    - [x] postMessage observations include origin, target origin, schema shape, and risk class
  - Implemented:
    - `ClientSideObservation`
    - `DomObservation`
    - `ConsoleObservation`
    - `NetworkObservation`
    - `StorageObservation`
    - `PostMessageObservation`
    - sink/source/storage/risk enums
  - Safety gates:
    - secret-like snippets are redacted before serialization
    - storage values are SHA-256 hashes only
    - console/network text is bounded and prompt-injection escaped

- [x] Task 2.5.4: Add safe client-side test planner
  - Commit: `47db67b feat(browser): add client-side test planner`
  - Files:
    - `crates/browser-lab/src/planner.rs`
    - `crates/browser-lab/src/lib.rs`
  - Implemented:
    - `ClientSidePlanner`
    - `ClientSidePlanRequest`
    - `ClientSideTestPlan`
    - `ClientSideTestKind`
    - `PayloadMode`
    - `BrowserAction`
    - `EvidencePolicy`
  - Safety gates:
    - reflected input uses harmless marker by default
    - stored input requires controlled sender/viewer profiles
    - executable XSS requires approval
    - executable XSS requires controlled victim profile
    - billing/staff/invite/destructive/integration/webhook/payment/export actions require approval
    - evidence path constrained to `evidence/client-side/`
    - generated plans include stop conditions and evidence policy

### Phase 3: Proxy-first traffic capture

- [x] Task 3.1: Add traffic schema v1
  - Commit: `d887369 feat(engagement): add traffic schema v1`
  - Files:
    - `crates/engagement/src/traffic.rs`
    - `crates/engagement/src/lib.rs`
  - TDD from plan:
    - [x] schema round trip with session/identity/role/tenant, scheme/port/query, hashes, operation metadata, risk class, scope decision, tags
    - [x] redacted headers never include cookie/authorization/set-cookie
    - [x] raw artifact refs include SHA-256 and length
  - Implemented:
    - `TrafficRiskClass`
    - session/identity/role/tenant fields
    - scheme/port/query fields
    - operation, scope decision, sorted tags, request/response SHA-256 fields
    - body artifact references with relative path, byte length, SHA-256, truncation flag
  - Safety gates:
    - sensitive request/response headers are omitted from serialized records
    - internal `x-mg-*` label headers are extracted into metadata and not retained as forwarded/visible headers

- [x] Task 3.2: Add proxy-core capture library skeleton
  - Commit: `05748c1 feat(proxy): add proxy-core skeleton`
  - Files:
    - `crates/proxy-core/Cargo.toml`
    - `crates/proxy-core/src/lib.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] default listener is loopback only
    - [x] non-loopback listen requires explicit approval flag
    - [x] `x-mg-*` label headers are stripped before upstream forwarding
    - [x] raw request/response artifacts are written under engagement root
    - [x] browser profile metadata is recorded locally but never forwarded upstream
  - Implemented:
    - `ProxyConfig` listener validation
    - request/header/response/capture skeleton types
    - `PreparedUpstreamRequest` split between upstream request and local metadata
    - engagement-root raw artifact writes with SHA-256 and byte counts
  - Safety gates:
    - default bind is `127.0.0.1:8080`
    - non-loopback bind fails without explicit approval flag
    - internal `x-mg-*` label headers are never placed in the upstream request
    - browser profile metadata remains local-only

- [x] Task 3.3: Add `mg-proxy` CLI skeleton
  - Commit: `13d0273 feat(proxy): add mg-proxy CLI skeleton`
  - Files:
    - `crates/mg-proxy/Cargo.toml`
    - `crates/mg-proxy/src/main.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] help includes start/sessions/tail/export
    - [x] start `--dry-run --json` reports listen address and CA path
    - [x] export writes corpus JSONL under engagement root
  - Implemented:
    - `start`, `sessions`, `tail`, and `export` subcommands
    - `start --dry-run --json` with loopback/non-loopback validation via `proxy-core`
    - export scaffold that creates `traffic/corpus.jsonl` under the engagement root
  - Safety gates:
    - live proxy start is intentionally refused until networking/CA lifecycle is implemented
    - non-loopback listener still requires explicit approval flag through `ProxyConfig`

### Phase 4: Corpus candidates and replay plans

- [x] Task 4.1: Add request-corpus candidate model
  - Commit: `732aed0 feat(corpus): add request candidate model`
  - Files:
    - `crates/request-corpus/Cargo.toml`
    - `crates/request-corpus/src/lib.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] comparable A/B GETs become `CrossTenantRead` candidate
    - [x] POST product creation is classified state-changing and not autonomous
    - [x] GraphQL global IDs are decoded by optional analyzer, not core logic
    - [x] attacker-controllable DOM sink/source observations become `DomXssCandidate`
    - [x] wildcard postMessage origin observations become `ClientSideOriginCandidate`
  - Implemented:
    - `CandidateBuilder`
    - `CorpusCandidate`
    - `CandidateKind`
    - `CandidateSource`
    - `CandidateSafety`
    - `CandidateStateChange`
    - optional `analyzers::graphql::decode_global_id`
  - Safety gates:
    - candidate generation is inert metadata only and does not execute requests
    - read-only cross-tenant candidates are marked autonomous-safe only for proof planning
    - state-changing operations require approval and are not autonomous-safe
    - GraphQL analysis is optional and not enabled in the core grouping path

- [x] Task 4.2: Add `mg-corpus` CLI
  - Commit: `8c9ae2f feat(corpus): add mg-corpus CLI`
  - Files:
    - `crates/mg-corpus/Cargo.toml`
    - `crates/mg-corpus/src/main.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] `build --json` emits candidate count
    - [x] `candidates --risk-class read_only` filters correctly
  - Implemented:
    - `mg-corpus build <engagement> --json`
    - `mg-corpus candidates <engagement> --risk-class read_only --json`
    - stable JSON/JSONL candidate output under `corpus/candidates.jsonl`
  - Safety gates:
    - CLI builds and queries inert candidate metadata only
    - no replay, request execution, proxy start, or browser automation

- [x] Task 4.3: Add replay-engine plan builder
  - Commit: `d755d9b feat(replay): add replay plan builder`
  - Files:
    - `crates/replay-engine/Cargo.toml`
    - `crates/replay-engine/src/lib.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] out-of-scope candidate cannot produce executable plan
    - [x] ambiguous read-only proof requires approval
    - [x] approval grant hash must match plan hash
  - Implemented:
    - `PlanBuilder`
    - `ReplayPlanRequest`
    - `ReplayPlan`
    - `ScopeDecision`
    - `ReplaySubstitution`
    - `ReplayPlanError`
  - Safety gates:
    - replay plans are immutable JSON metadata only
    - out-of-scope candidates fail closed
    - ambiguous or non-autonomous-safe plans require approval
    - approval grants are bound to the derived plan hash
    - evidence output dirs must be safe relative paths

### Phase 5: Semantic diff and evidence

- [x] Task 5.1: Add semantic diff verdict engine
  - Commit: `6169841 feat(replay): add semantic diff verdicts`
  - Files:
    - `crates/replay-engine/src/lib.rs`
  - TDD from plan:
    - [x] 401/403/404 becomes `SecureDenied`
    - [x] target tenant marker in attacker response becomes `BoundaryViolationRead`
    - [x] expired token shape becomes `InvalidTest`
    - [x] GraphQL authorization error becomes `SecureDenied`
  - Implemented:
    - `SemanticDiffEngine`
    - `ReplayOutcome`
    - `SemanticVerdict`
    - `SemanticVerdictClass`
    - `AuthFailureShape`
  - Safety gates:
    - verdict output contains classifications, reasons, and controlled marker names only
    - expired attacker/session token shapes invalidate proofs instead of producing findings
    - GraphQL authorization-denial shapes are treated as secure denial

- [x] Task 5.2: Add evidence bundle writer
  - Commit: `0916e5b feat(evidence): add evidence bundle writer`
  - Files:
    - `crates/evidence-core/Cargo.toml`
    - `crates/evidence-core/src/lib.rs`
    - `crates/mg-evidence/Cargo.toml`
    - `crates/mg-evidence/src/main.rs`
    - `crates/Cargo.toml`
  - TDD from plan:
    - [x] evidence run path includes candidate id and run id
    - [x] existing run cannot be overwritten
    - [x] `summary.redacted.md` contains no synthetic cookies/tokens/PII
  - Implemented:
    - `EvidenceBundleWriter`
    - `EvidenceBundleRequest`
    - `EvidenceBundle`
    - `EvidenceArtifactManifest`
    - `EvidenceBundleError`
    - `mg-evidence write <engagement> --candidate-id ... --run-id ... --json`
  - Safety gates:
    - evidence bundles are immutable and existing runs fail closed
    - bundle paths include candidate id and run id under the engagement root
    - raw artifacts are hashed in the manifest
    - model-visible summaries redact cookie, bearer token, and email-like shapes

### Phase 6: Harness, TUI, and assisted hunt loop

- [x] Task 6.1: Add harness endpoint policy metadata
  - Commit: `daac37f feat(harness): add endpoint policy metadata`
  - Added immutable endpoint policy metadata to every `mg-harness` `EndpointSpec`.
  - Added regression coverage that model-supplied arguments cannot alter endpoint policy metadata.
  - Mapped invalid model/tool arguments to typed `endpoint.invalid_args` results instead of generic endpoint errors.
  - Verified sensitive request headers remain absent from model-visible request output.
- [x] Task 6.2: Add autonomous endpoint families
  - Commit: `3158f3d feat(harness): add autonomous endpoint wrappers`
  - Added registered `hunt.*` assisted-loop endpoint wrappers for next test, status, approve, record, and stop actions.
  - Added registered proxy/session/profile/lab/corpus/replay/diff/evidence endpoint families for the autonomous hunting surface.
  - Safety gates:
    - autonomous wrappers derive risk and policy metadata from Rust-owned static specs, not model arguments
    - high-active autonomous endpoints still require explicit approval
    - model-visible wrapper output is reference-only and redacts model-supplied args
- [x] Task 6.3: Add TUI panes
  - Commit: `540e38c feat(tui): add autonomous hunting panes`
  - Added autonomous hunting tabs for proxy feed, session vault, browser profiles, lab matrix, corpus, replay plans, semantic diffs, evidence bundles, and AI next-safe-test.
  - Added `ActiveActionPrompt` metadata for engagement, target, scope decision, session, risk, output path, and approval state.
  - Safety gates:
    - active-action prompt context keeps policy decisions visible to the operator
    - panes show registered autonomous endpoints without exposing raw secrets
- [x] Task 6.4: Add `mg-hunt` assisted loop
  - Commit: `83e8aab feat(hunt): add assisted loop skeleton`
  - Added `mg-hunt run <engagement>` dry-run planner with deterministic `max-tests`, `max-duration`, and `max-bytes` budgets.
  - Added resume support using local tested plan hashes.
  - Added 429, 5xx, and WAF-like safety stop reasons for execution feedback.
  - Safety gates:
    - dry-run planning selects only autonomous-safe read-only candidates
    - state-changing and browser-only candidates are skipped by policy
    - resume prevents duplicate plan hashes from being selected again

### Phase 7: Hardening and evidence polish

- [x] Task 7.1: Add client-side semantic verdicts
  - Commit: `707c3aa feat(browser): add client-side semantic verdicts`
  - Added deterministic verdict classes for client-side observations.
  - Covered DOM sinks, storage observations, network/console errors, and postMessage origin/schema risk.
  - Safety gates:
    - verdict text stays structured and model-safe
    - secret-like snippets remain redacted before verdict generation

- [x] Task 7.2: Add redacted browser snapshot evidence artifacts
  - Commit: `9aaf9b3 feat(evidence): add redacted browser snapshots`
  - Added redacted DOM snapshot artifacts and hashed screenshot artifacts to evidence bundles.
  - Safety gates:
    - DOM artifacts redact token/email-like material before writing model-visible files
    - screenshot bytes are stored as hashed evidence artifacts without embedding secrets in summaries

- [x] Task 7.3: Wire named session profile compatibility into `mg-harness`
  - Commit: `7a7edb4 feat(harness): wire named session profiles`
  - Added harness support for listing named session profiles and resolving active profile headers.
  - Safety gates:
    - profile listing emits redacted metadata only
    - secret reference names and values are not exposed to model-visible endpoint results

- [x] Task 7.4: Gate assisted `mg-hunt` orchestration
  - Commit: `2f0368f feat(hunt): gate assisted orchestration`
  - Added explicit confirmation gating for non-dry-run orchestration.
  - Added resume-state writes for confirmed plans without sending network traffic.
  - Safety gates:
    - unconfirmed active orchestration fails closed with `approval_required`
    - confirmed runs record deterministic plan hashes for resume/dedupe

- [x] Task 7.5: Add Intigriti and YAML scope import coverage
  - Commit: `0cec901 feat(engagement): add intigriti and yaml scope imports`
  - Added Intigriti JSON fixture coverage using the common `ProgramAsset` model.
  - Added manual YAML scope import support and CLI wiring for `--format yaml|yml`.
  - Safety gates:
    - platform adapters remain behind the platform-neutral scope model
    - deny precedence and asset metadata continue through `ScopeDecision`

## Phase 8 progress

- [x] Task 8.1a: Start real read-only `mg-hunt` execution path
  - Commit: `09fc6b0 feat(hunt): start read-only execution path`
  - `mg-hunt` confirmed orchestration now calls replay/evidence primitives for selected read-only candidates instead of only writing resume hashes.
  - Writes one evidence bundle per executed read-only plan with `plan.json`, `semantic_diff.json`, `approvals.json`, and a redacted summary.
  - Adds deterministic local replay outcome fixture support under `hunt/replay-outcomes/<candidate-id>.json` until live HTTP replay wiring lands.
  - Safety gates:
    - unconfirmed active orchestration still fails closed with `approval_required`
    - state-changing/browser-only candidates are still filtered before execution
    - auth-expired semantic verdicts stop the loop and do not mark the plan hash as tested
    - evidence write failure aborts the run before resume state is advanced

## Latest known commits for this work

```text
0cec901 feat(engagement): add intigriti and yaml scope imports
2f0368f feat(hunt): gate assisted orchestration
7a7edb4 feat(harness): wire named session profiles
9aaf9b3 feat(evidence): add redacted browser snapshots
707c3aa feat(browser): add client-side semantic verdicts
d31d4b3 docs: update autonomous hunting phase 6 progress
83e8aab feat(hunt): add assisted loop skeleton
540e38c feat(tui): add autonomous hunting panes
3158f3d feat(harness): add autonomous endpoint wrappers
daac37f feat(harness): add endpoint policy metadata
0916e5b feat(evidence): add evidence bundle writer
6169841 feat(replay): add semantic diff verdicts
d755d9b feat(replay): add replay plan builder
8c9ae2f feat(corpus): add mg-corpus CLI
732aed0 feat(corpus): add request candidate model
13d0273 feat(proxy): add mg-proxy CLI skeleton
05748c1 feat(proxy): add proxy-core skeleton
d887369 feat(engagement): add traffic schema v1
ebafe91 feat(browser): add client-side observation model
12e9fc3 feat(lab): add browser profile CLI
330c0ca feat(session): add named session profiles
2929937 feat(lab): add mg-lab CRUD CLI skeleton
47db67b feat(browser): add client-side test planner
b080d37 feat(browser): add isolated browser profiles
33cf36d feat(lab): add controlled lab model
8359ba1 feat(engagement): import platform program scope
28993b8 feat(engagement): add typed audit events
92b3ec6 feat(policy): require program rules for active actions
01fae02 feat(engagement): guard artifact output paths
3196c97 feat(policy): add action policy skeleton
8ea3d83 feat(engagement): add structured scope decisions
```

## Latest known verification

Last full targeted verification from the implementation session:

```bash
cd /home/mgeist/geistscope/crates
cargo test -p browser-lab -p evidence-core -p mg-harness -p mg-hunt -p engagement
cargo clippy -p browser-lab -p evidence-core -p mg-harness -p mg-hunt -p engagement -- -D warnings
git diff --check
```

Historical broader verification from earlier implementation sessions:

```bash
cd /home/mgeist/geistscope/crates
cargo test -p mg-lab -p lab-model
cargo clippy -p mg-lab -- -D warnings
cargo test -p session
cargo clippy -p session -- -D warnings
cargo test -p browser-lab
cargo test -p lab-model
cargo test -p action-policy
cargo test -p engagement
cargo clippy -p engagement -- -D warnings
cargo test -p proxy-core
cargo clippy -p proxy-core -- -D warnings
cargo test -p request-corpus
cargo clippy -p request-corpus -- -D warnings
cargo test -p mg-corpus
cargo clippy -p mg-corpus -- -D warnings
cargo test -p replay-engine
cargo clippy -p replay-engine -- -D warnings
cargo test -p evidence-core -p mg-evidence
cargo clippy -p evidence-core -p mg-evidence -- -D warnings
cargo test -p replay-engine -p evidence-core -p mg-evidence
cargo clippy -p replay-engine -p evidence-core -p mg-evidence -- -D warnings
cargo test -p mg-harness -p mg-tui -p mg-hunt -- --nocapture
cargo clippy -p mg-harness -p mg-tui -p mg-hunt -- -D warnings
cargo test -p browser-lab -p engagement -p request-corpus -p mg-corpus -p replay-engine -p evidence-core -p mg-evidence
cargo clippy -p browser-lab -p engagement -p request-corpus -p mg-corpus -p replay-engine -p evidence-core -p mg-evidence -- -D warnings
```

Observed latest targeted results:

- `browser-lab`: 16 tests passed, doctests passed; clippy passed with `-D warnings`
- `engagement`: 48 lib tests passed, 2 `mg-engagement` binary tests passed, doctests passed; clippy passed with `-D warnings`
- `evidence-core`: 4 tests passed, doctests passed; clippy passed with `-D warnings`
- `mg-harness`: 47 tests passed, binary tests passed; clippy passed with `-D warnings`
- `mg-hunt`: 8 tests passed; clippy passed with `-D warnings`
- `git diff --check`: passed

Historical observed results:

- `mg-lab`: 8 tests passed; clippy passed with `-D warnings`
- `lab-model`: 3 tests passed during Task 2.2 verification
- `session`: 8 tests passed; clippy passed with `-D warnings`
- `browser-lab`: 13 tests passed; clippy passed with `-D warnings`
- `lab-model`: 3 tests passed
- `action-policy`: 7 tests passed
- `engagement`: 46 lib tests passed, 2 `mg-engagement` binary tests passed, doctests passed; clippy passed with `-D warnings`
- `proxy-core`: 5 tests passed, doctests passed; clippy passed with `-D warnings`
- `mg-proxy`: 3 tests passed; clippy passed with `-D warnings`
- `request-corpus`: 6 tests passed, doctests passed; clippy passed with `-D warnings`
- `mg-corpus`: 2 tests passed; clippy passed with `-D warnings`
- `replay-engine`: 7 tests passed, doctests passed; clippy passed with `-D warnings`
- `evidence-core`: 3 tests passed, doctests passed; clippy passed with `-D warnings`
- `mg-evidence`: 1 test passed; clippy passed with `-D warnings`
- Phase 5 integration check: `replay-engine` 7 tests passed, `evidence-core` 3 tests passed, `mg-evidence` 1 test passed; clippy passed with `-D warnings`
- `mg-harness`: 45 tests passed; clippy passed with `-D warnings`
- `mg-tui`: 8 tests passed; clippy passed with `-D warnings`
- `mg-hunt`: 6 tests passed; clippy passed with `-D warnings`
- Phase 6 integration check: `mg-harness` 45 tests passed, `mg-tui` 8 tests passed, `mg-hunt` 6 tests passed; clippy passed with `-D warnings`
- Phase 4/5 integration check: `browser-lab` 13 tests passed, `engagement` 46 lib tests + 2 binary tests passed, `request-corpus` 6 tests passed, `mg-corpus` 2 tests passed, `replay-engine` 7 tests passed, `evidence-core` 3 tests passed, `mg-evidence` 1 test passed; clippy passed with `-D warnings`

Latest known git status after Phase 7 documentation update:

```text
clean working tree
```

## Next restart prompt

Paste this into a fresh context:

```text
We are implementing GeistScope autonomous hunting from `/home/mgeist/geistscope/docs/AUTONOMOUS_HUNTING_TDD_PLAN.md`.
Read `/home/mgeist/geistscope/docs/AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md`, `~/.hermes/ai-engineering-best-practices.md`, and load the `geistscope-ai-harness`, `test-driven-development`, and `rust-security-patterns` skills.
Use `/home/mgeist/geistscope/crates` as the Rust workspace root.
Continue after Phase 7. Tasks 7.1-7.5 are complete and committed through `0cec901 feat(engagement): add intigriti and yaml scope imports`; choose the next implementation slice from the Phase 8 roadmap before coding.
Do not start proxy/replay/browser automation until the CLI/lab/session foundations are complete.
Keep active actions gated by Rust policy, fail closed on ambiguous scope, never expose secrets to model-visible output, and commit each verified slice.
```

## Implementation rules to preserve

- Use strict TDD: failing test first, run it, implement minimal code, rerun focused tests, then relevant package tests.
- Commit after each logical slice.
- Keep changes surgical; avoid unrelated formatting or refactors.
- Active network/browser/replay work must call Rust-owned policy gates.
- Never let model intent bypass scope, program rules, approval, redaction, or audit.
- All model/user-directed artifact output paths must stay under the engagement root.
- Browser/account testing must stay isolated by identity/session/profile.
- Model-visible outputs should contain summaries, key names, hashes, and evidence refs, not raw cookies/tokens/storage values.
