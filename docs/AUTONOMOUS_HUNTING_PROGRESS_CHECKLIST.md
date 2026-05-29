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
  - Still possible later:
    - explicit Intigriti fixture coverage if desired
    - YAML manual scope import if desired

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
  - Still possible later:
    - wire named profiles into `mg-harness` endpoint compatibility

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

- [ ] Task 4.2: Add `mg-corpus` CLI
  - Next recommended task
- [ ] Task 4.3: Add replay-engine plan builder

### Phase 5: Semantic diff and evidence

- [ ] Task 5.1: Add semantic diff verdict engine
- [ ] Task 5.2: Add evidence bundle writer

### Phase 6: Harness, TUI, and assisted hunt loop

- [ ] Task 6.1: Add harness endpoint policy metadata
- [ ] Task 6.2: Add autonomous endpoint families
- [ ] Task 6.3: Add TUI panes
- [ ] Task 6.4: Add `mg-hunt` assisted loop

## Latest known commits for this work

```text
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
cargo test -p browser-lab -p engagement -p request-corpus
cargo clippy -p browser-lab -p engagement -p request-corpus -- -D warnings
```

Observed results:

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
- integration check: `browser-lab` 13 tests passed, `engagement` 46 lib tests + 2 binary tests passed, `request-corpus` 6 tests passed; clippy passed with `-D warnings`

Latest known git status before this checklist was created:

```text
clean working tree
```

After this checklist file is created, git status should show:

```text
?? docs/AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md
```

Commit this checklist if you want it versioned:

```bash
cd /home/mgeist/geistscope
git add docs/AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md
git commit -m "docs: add autonomous hunting progress checklist"
```

## Next restart prompt

Paste this into a fresh context:

```text
We are implementing GeistScope autonomous hunting from `/home/mgeist/geistscope/docs/AUTONOMOUS_HUNTING_TDD_PLAN.md`.
Read `/home/mgeist/geistscope/docs/AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md`, `~/.hermes/ai-engineering-best-practices.md`, and load the `geistscope-ai-harness`, `test-driven-development`, and `rust-security-patterns` skills.
Use `/home/mgeist/geistscope/crates` as the Rust workspace root.
Continue with Task 4.2: add `mg-corpus` CLI, using strict TDD and atomic commits.
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
