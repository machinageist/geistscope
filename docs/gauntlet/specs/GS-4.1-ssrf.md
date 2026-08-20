# Spec: GS-4.1 SSRF Vertical Slice Completion

**Feature ID:** GS-4.1-ssrf
**Parent feature:** GS-4
**Spec author agent:** Hermes Agent — GS-4.1 spec author
**Date:** 2026-08-13
**Iteration:** 4

---

## 1. Purpose

### 1.1 One-sentence job

Enable a solo security operator to run one bounded, policy-authorized, callback-only SSRF test against a controlled target and receive a truthful, reproducible result backed by content-addressed, locally reverified evidence.

### 1.2 Why it matters

GS-4.1 is the first completion slice for GeistScope's observe → hypothesize → plan → authorize → execute → assess → preserve → report loop and therefore establishes the contracts later capability packs must reuse (`docs/gauntlet/PLAN.md`, Sections 2, 6, 7, and 12; `docs/gauntlet/feature-tree.md`). The existing engine already proves candidate generation, immutable planning, deterministic policy, one-request execution, and callback assessment in separate components, but it does not yet commit the complete SSRF evidence/result, orchestrate vulnerable/secure/blocked/repeated cases through one production runner, or expose that runner through a thin operator client (`docs/gauntlet/run-logs/GS-4.1-evidence-baseline.md`; `crates/hunt-engine/src/{ssrf.rs,policy.rs,http_executor.rs,assessment.rs,lib.rs}`). Completion closes that gap without reviving the unsafe payload-spraying and heuristic finding behavior in `crates/mg-webscan/src/ssrf.rs`.

### 1.3 Success signal

From one offline command with no model or Internet access, a verifier observes all four campaign cases through the same `hunt-engine` orchestration: vulnerable = exactly one target probe, exactly one matching callback, and exactly one `verified_finding`; secure = exactly one target probe, zero callbacks, one `negative_test`, and zero findings; blocked = zero target requests, zero callbacks, and one blocked/`invalid_test`; repeated = a distinct token, run ID, and content-addressed bundle identity while the writer leaves the prior bundle byte-identical. Fresh replay revalidates descriptor-held bytes against the expected manifest digest before reproducing any authoritative class (`docs/gauntlet/PLAN.md`, Section 12; `.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/05-end-to-end-campaign-benchmark.md`).

---

## 2. User Stories

> As a bug-bounty operator, I want a URL-input observation converted into one safe callback-only SSRF probe, so that I can test a high-value hypothesis without payload spraying.

> As an operator, I want a matching plan-bound callback and committed evidence to be mandatory before a finding is verified, so that a target response or model assertion cannot create a false positive.

> As an operator testing a secure endpoint, I want the completed no-callback result preserved as a negative test rather than discarded or mislabeled secure everywhere, so that campaign coverage remains truthful.

> As a program owner or safety reviewer, I want stale, ambiguous, out-of-scope, automation-disallowed, unauditable, or over-budget plans blocked before active I/O, so that authorization boundaries are deterministic.

> As an operator recovering from a failed write or repeated run, I want previous evidence left untouched and the failed run clearly invalid, so that no partial artifact can retain verified status.

> As a script or external agent author, I want stable versioned JSON containing typed statuses and evidence references but no secrets, so that I can consume the same engine facts without shell access or vendor-specific prose.

> As a keyboard and screen-reader user, I want concise color-independent terminal output, deterministic focus-free command behavior, and machine-readable output, so that the first operator surface is accessible without animation or pointer input.

---

## 3. UX Specification

### 3.1 Screen / view inventory

1. **SSRF campaign command** — reached through the binary/subcommand selected after Design Checkpoint 4; new thin CLI surface. It is a single command-line view, not a full-screen TUI. The exact binary name is deliberately not selected by this spec because the local API/process boundary must be decided from the completed campaign transitions (`.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/06-local-api-and-persistence-discovery.md`).
2. **Human terminal result** — modification/new output mode of the selected CLI. A compact top-to-bottom summary of run state, final class, policy reason, execution/correlation status, and engagement-relative evidence paths.
3. **Stable JSON result** — new non-interactive output mode for automation. It serializes engine-owned schema fields and never human prose as authority.
4. **Progress/error stream** — stderr lines or structured progress events, according to the approved API decision. It must not become a second orchestration state machine.

N/A — this slice introduces no GUI screen, modal, sheet, popover, drawer, or TUI panel. TUI and the cross-campaign learning profile belong to GS-6.3/GS-6.4 (`docs/gauntlet/feature-tree.md`). GS-4.1 still emits and persists a minimum explanatory record over identical engine facts: final class, deterministic reason code, policy decision, executed/callback counts, satisfied and missing evidence requirements, bounded claim, and one closed `next_action_code`. The code is derived deterministically from class/reason/missing requirements, is stored in `semantic-verdict.json` and `runbook.md`, and can be regenerated from committed evidence. It is presentation-only and cannot alter classification. Repeated-run tests prove vulnerable, secure, blocked, invalid, and interrupted facts produce the declared distinct explanation/next-action codes while identical authoritative facts remain byte-stable.

### 3.2 Interaction flows

**Primary flow**

1. Operator supplies an engagement reference, an observed-request reference already imported into the engagement traffic corpus, and a run/campaign identifier accepted by the approved local boundary. GS-4.1 resolves the reference through the production corpus repository, rejects missing/ambiguous/digest-mismatched records, and consumes only normalized method/origin/path/query-name/query-occurrence metadata plus source digest; it never imports cookies, authorization headers, request bodies, or arbitrary replay mutations. Before authorization, the application service returns a typed redacted comparison containing observation digest, method/origin/path, selected query name and zero-based occurrence, candidate kind, planned replacement marker, and unchanged query-name/occurrence list—never original values. The operator can inspect this comparison in human or JSON output and then invoke the same immutable plan; capture and broad cross-request search UI remain parent work. E2E must import and compare through this real seam rather than constructing a candidate directly. The CLI must not accept an arbitrary callback destination, risk downgrade, raw payload, callback token, cookie, or authorization header.
2. CLI submits the typed start request to the same application service used by integration/API tests.
3. Engine validates identifiers, engagement root, source/scope/rules hashes, current authorization, finite budgets, exact campaign callback authority, and audit destination.
4. Engine deterministically generates the inert candidate and immutable plan; this step performs zero I/O (`crates/hunt-engine/src/ssrf.rs`; `crates/hunt-engine/tests/ssrf_candidate.rs`; `crates/hunt-engine/tests/ssrf_plan_security.rs`).
5. Policy outcome branches:
   - `allowed`: audit and policy decision commit before a non-forgeable permit is returned, then execution continues.
   - `requires_approval` or `blocked`: no permit and no network I/O; engine commits safe supporting evidence where possible and returns a blocked/invalid result.
   - policy/audit persistence error: no permit, no network I/O, typed engine failure/invalid result.
6. Allowed execution sends exactly one GET with exactly one planned query occurrence replaced; redirects and retries remain disabled (`crates/hunt-engine/src/http_executor.rs`).
7. Callback window is finalized with an injected/testable clock. Matching live token+plan evidence becomes `callback_proven`; no callback after a successful transaction becomes `negative`; mismatch, expiry, reuse, unauthorized execution, or transport failure becomes `invalid` (`crates/hunt-engine/src/assessment.rs`).
8. Engine serializes a non-authoritative `semantic-verdict.json` containing assessment class/reason, identity bindings, satisfied/missing requirement IDs, bounded explanation, and closed `next_action_code`; none can claim verified status or override classification. It stages every bounded artifact and exclusively publishes one no-overwrite bundle. It computes `manifest_sha256` from committed manifest bytes; that digest—not the pathname—is the authoritative bundle identity. One verified-byte API opens the manifest and required artifacts without following symlinks, reads bounded bytes from held descriptors, verifies manifest/artifact digests and lengths, and passes those exact bytes to `EvidenceContract::validate_local`. Only then may it construct authoritative in-memory `HuntResult` and stable service output. Neither is written back into the bundle.
9. CLI prints either human output or the stable JSON envelope. Human text is presentation-only.
10. Repeating the campaign creates a fresh run ID/token/bundle. Reusing a run ID fails without byte changes to the old run.

**Failure branches**

- Evidence serialization, redaction, path validation, write, fsync, hash validation, manifest construction, or atomic publication failure: no verified result; no final partial bundle; typed `evidence_write_failed`/`invalid_test` response.
- Corrupt or modified committed artifact on revalidation: integrity failure and no promotion/replay claim.
- Operator interruption before Design Checkpoint 4 is fail-closed and non-resumable: cancellation closes target/callback tasks, invalidates the ephemeral token/permit, returns `interrupted_non_resumable`, and requires a fresh run ID plus fresh policy/approval evaluation. A stopped process never resumes an active callback lease or reuses authority. Durable resume semantics may be added only by the accepted Design Checkpoint 4 ADR.

Haptic, sound, and animation cues: N/A — terminal-only surface. No spinner is required; if progress animation is added later it must have a static/reduced-motion mode.

### 3.3 Layout descriptions

**Human terminal result, top to bottom**

1. Stable run/campaign and candidate identifiers.
2. Final result class: `verified_finding`, `negative_test`, `invalid_test`, or the narrowly defined `human_verification_candidate`.
3. Policy verdict and reason code.
4. Execution and callback-correlation status with exact request/callback counts for benchmark mode.
5. Plan hash.
6. Engagement-relative bundle, manifest, semantic-verdict, and runbook paths.
7. Recovery instruction on failure.

States must be labeled with words/symbols, never color alone. Empty state copy is `No SSRF candidate was generated from the selected observation.` A completed secure case says `Completed: no matching callback observed within the bounded window (negative test; not a claim of global security).` A blocked case says `Blocked before execution: <reason>; target requests: 0; callbacks: 0.`

**JSON view**

Data source is the engine result/application-service response, not CLI-owned recomputation. Required top-level fields are specified in Section 4.3. Unknown future fields must be ignorable within the same major schema version; field meaning must not depend on order or terminal formatting.

### 3.4 Input & gestures

- Keyboard/shell arguments and stdin/file references only; no pointer, touch, stylus, game controller, voice, or camera input.
- `--json` (or approved equivalent) selects stable JSON; human output is the default only when appropriate for the chosen CLI conventions.
- Non-interactive execution must never prompt for or echo secrets. Approval references, if supported by the approved boundary, are opaque IDs/handles.
- SIGINT/cancellation must use the approved application-service cancellation semantics and stop listeners/workers; the CLI may not kill arbitrary processes or mutate engine files directly.
- Responsive behavior: lines wrap safely in narrow terminals; JSON remains unchanged. Human output must remain understandable without ANSI color and under `NO_COLOR`/non-TTY execution.
- No feature-specific keyboard shortcuts beyond standard shell editing and Ctrl-C cancellation.

### 3.5 Transitions & animation

- Navigation transitions: N/A — one command invocation.
- State changes may be printed as append-only textual progress (`planned`, `policy_evaluated`, `executed`, `assessed`, `evidence_committed`) or delivered by the approved local API; terminal output must not rewrite prior evidence claims.
- Reduced-motion alternative is static line output with no spinner. JSON mode emits deterministic final JSON to stdout and diagnostics/progress to stderr, never intermixed.

### 3.6 Error states

| Trigger | Presentation | Recovery | Data loss risk |
|---|---|---|---|
| Invalid identifiers/path/source reference | Immediate stderr error + typed JSON error; inline because no campaign began | Correct reference and retry | No |
| Scope/rules stale, ambiguous, out of scope, automation disallowed, approval missing | Final blocked summary with deterministic reason | Refresh rules/scope or obtain valid approval outside this command | No; safe audit/evidence may exist |
| Audit/policy artifact write fails | Final engine failure; explicitly states zero execution | Repair engagement-root permissions/path and retry with a new run | No target impact; no permit |
| Timeout, TLS/connection error, 429, 5xx, response byte cap | `invalid_test`/stop reason, not negative or verified | Resolve target/lab condition; use a new run | Partial safe evidence may be committed, never verified |
| Callback unknown/mismatched/expired/reused | `invalid_test` with correlation reason | Start a new run/token; do not import legacy callback files as proof | No |
| Evidence redaction/path/hash/write/publication failure | `evidence_write_failed`; no verified result and no claimed bundle | Repair storage; remove/quarantine incomplete staging only via engine recovery; rerun with new ID | Partial staging may be quarantined; no final evidence loss |
| Existing run ID/final path | `run_already_exists`; existing hash shown if safely available | Choose new run ID | No; existing bytes unchanged |
| CLI/API unavailable or interrupted | Actionable transport/cancellation error | Restart approved local process or rerun; resume only per accepted checkpoint design | Depends on checkpoint design; must never duplicate active execution |
| No candidate | Completed non-executing result/error code, not finding | Choose another observation | No |

Banners, toasts, and modals are N/A because no graphical surface exists.

### 3.7 Accessibility

- Every status includes a textual label and deterministic reason code; ANSI color is optional decoration only.
- Output order follows campaign chronology, then final references. No cursor-position dependence.
- JSON supplies an equivalent machine-readable representation for assistive tooling.
- Human output honors terminal width, avoids unbroken raw URLs/tokens, and provides a no-color/static mode.
- Text scaling is controlled by the terminal; output must not use fixed pixel layout.
- Screen-reader labels/hints/traits and custom accessibility actions are N/A for a CLI. The equivalent requirement is explicit option help, meaningful exit codes, stdout/stderr separation, and keyboard-complete operation.
- Focus order is N/A because the command has no interactive controls.

---

## 4. Implementation Specification

### 4.1 Architecture placement

**Authoritative ownership**

- `crates/hunt-engine` remains the business-logic owner. Add a small SSRF campaign/application service (likely `src/campaign.rs`) that sequences normalized observation → candidate → plan → policy → execution → callback finalization → assessment → evidence commit → result. Tests must drive production orchestration, not duplicate it (`.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/05-end-to-end-campaign-benchmark.md`).
- `crates/action-policy` remains the sole deterministic action-policy authority; `crates/hunt-engine/src/policy.rs` stays a narrow adapter.
- `crates/evidence-core` owns generic atomic bundle mechanics. The proven legacy writer and current in-progress generic API are baseline/salvage inputs, not evidence that Task 4.3 is complete (`docs/gauntlet/run-logs/GS-4.1-evidence-baseline.md`; current worktree `crates/evidence-core/src/lib.rs`).
- `crates/engagement` remains the trusted artifact-root, typed scope/rules, and audit boundary consumed by policy.
- The callback recorder remains engine-owned (`crates/hunt-engine/src/callback.rs`). `mg-oob` cannot be an evidence/finding authority.
- One CLI crate/binary is selected only after the local API/persistence decision. Its code is a thin client of the same application service and contains no target HTTP, policy, callback correlation, evidence validation, or result-promotion logic.

**Required completion sequence**

1. Finish Task 4.3 immutable evidence and deterministic result promotion.
2. Add the production campaign runner and offline E2E campaign.
3. Execute the local API/SQLite discovery checkpoint and produce an ADR + atomic plan; do **not** implement API/SQLite until Jeff accepts an option.
4. Implement the smallest accepted local boundary and one thin CLI only to the extent needed for GS-4.1.
5. Produce a legacy SSRF/OOB salvage/disposition record; change/delete old surfaces only after explicit Checkpoint 5 approval and replacement proof.

### 4.2 Data model

Names may vary to match repository conventions, but semantics and authority must not.

```rust
/// Stable schema envelope returned by the application service and thin clients.
#[derive(Serialize)]
pub struct SsrfCampaignOutputV1 {
    pub schema_version: String,              // exactly "gs.ssrf.campaign-result.v1"
    pub campaign_id: String,
    pub run_id: String,
    pub candidate_id: Option<String>,
    pub plan_sha256: Option<String>,
    pub state: SsrfCampaignState,
    pub result_class: Option<HuntResultClass>,
    pub policy: PolicySummary,
    pub execution: ExecutionSummary,
    pub correlation: CorrelationSummary,
    pub evidence: Option<CommittedBundleIdentity>,
    pub error: Option<CampaignError>,
}

/// Engine-owned lifecycle; clients observe but cannot force transitions.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SsrfCampaignState {
    Observed,
    CandidateGenerated,
    Planned,
    PolicyEvaluated,
    Blocked,
    Executed,
    CallbackWindowFinalized,
    Assessed,
    EvidenceCommitted,
    ResultEmitted,
    Failed,
}

/// Content identity plus non-authoritative locators for one published bundle.
#[derive(Serialize)]
pub struct CommittedBundleIdentity {
    pub bundle_path: String,                 // engagement-relative locator; not integrity identity
    pub manifest_path: String,               // engagement-relative locator; not integrity identity
    pub manifest_sha256: String,             // authoritative bundle content identity
    pub semantic_verdict_path: String,       // locator; non-authoritative assessment record
    pub runbook_path: String,                // locator
}

/// Stable script-consumable failure without target-controlled prose.
#[derive(Serialize)]
pub struct CampaignError {
    pub code: CampaignErrorCode,
    pub message: String,                     // bounded, redacted
    pub retryable: bool,
}

#[derive(Serialize)]
pub struct PolicySummary {
    pub verdict: PolicyVerdict,              // allowed | requires_approval | blocked
    pub reason_code: PolicyReasonCode,       // closed checked-in enum
    pub decision_sha256: Option<String>,     // null only when policy could not persist a decision
}

#[derive(Serialize)]
pub struct ExecutionSummary {
    pub status: ExecutionStatus,             // not_executed | completed | stopped | failed
    pub request_count: u8,                   // exactly 0 or 1
    pub response_status: Option<u16>,        // null when no HTTP response completed
    pub response_bytes: u32,
    pub stop_reason: Option<ExecutionStopReason>,
}

#[derive(Serialize)]
pub struct CorrelationSummary {
    pub status: CorrelationStatus,            // not_started | no_match | matched | invalid
    pub callback_count: u8,                   // exactly 0 or 1 for GS-4.1
    pub reason_code: CorrelationReasonCode,
    pub satisfied_requirements: Vec<String>, // canonical requirement-ID order
    pub missing_requirements: Vec<String>,   // canonical requirement-ID order
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignErrorCode {
    InvalidInput,
    InvalidReference,
    NoCandidate,
    PolicyBlocked,
    ApprovalRequired,
    PolicyAuditFailed,
    ExecutionStopped,
    ExecutionFailed,
    CallbackInvalid,
    EvidenceWriteFailed,
    EvidenceIntegrityFailed,
    RunAlreadyExists,
    InterruptedNonResumable,
    InvariantViolation,
}
```

All fields shown above are required in V1. `Option` serializes as JSON `null`, never omission. Summary and reason enums are closed snake-case enums in the checked-in schema. IDs/hashes are lowercase validated strings; count and byte fields are nonnegative bounded integers. `error` is non-null only for `Failed`/blocked infrastructure outcomes and must be null for completed verified/negative results. `evidence` is non-null only after successful publication and revalidation.

Legal state invariants are checked by constructors and schema tests: `Observed` through `Assessed` have `evidence=null` and `result_class=null`; `EvidenceCommitted` requires non-null evidence but still has `result_class=null`; `ResultEmitted` requires non-null evidence, non-null result class, and `error=null`; `Blocked`/`Failed` require non-null error and cannot carry `verified_finding`; `Blocked` requires request/callback counts of zero; completed `negative_test` uses `ResultEmitted`, not `Failed`. Illegal combinations cannot be publicly constructed or deserialized as validated output.

`HuntResult` must be extended so every class binds candidate ID, run ID, plan hash when a plan exists, authoritative manifest digest, locator metadata, classification, and committed evidence references. External/deserialized data must not construct a validated aggregate or `verified_finding`; `EvidenceSatisfaction` remains engine-created only from descriptor-held bytes whose manifest/artifact digests and lengths have just been verified (`crates/hunt-engine/src/lib.rs`). `HuntResult` and `SsrfCampaignOutputV1` are authoritative derived outputs, not bundle members. They may be regenerated only from the verified-byte API; no cached/deserialized `verified_finding` survives failed revalidation. Locator existence or prior pathname identity checks are never proof.

Task 4.3 bundle layout, under `ENGAGEMENT_ROOT/evidence/<candidate_id>/<run_id>/`:

```text
observation.json
candidate.json
plan.redacted.json
policy-decision.json
transaction.redacted.json
callback-correlation.redacted.json
callback-assessment.json
semantic-verdict.json
runbook.md
summary.redacted.md
manifest.json
```

Every non-manifest artifact is listed with engagement-relative locator, SHA-256, byte length, content type, and visibility. The manifest cannot hash itself; `CommittedBundleIdentity.manifest_sha256` binds its exact committed bytes and transitively identifies the listed artifact byte set. Paths locate candidate bytes but never establish integrity. `semantic-verdict.json` is explicitly non-authoritative: before publication it records assessment class/reason, identity bindings, satisfied/missing requirement IDs, bounded explanation, and closed `next_action_code`; none can itself claim verified status or override verified-byte validation. Raw callback tokens and raw request/response bodies are not persisted in this slice. If any private artifact is demonstrably required, it lives under `raw/`, is bounded and marked `private_local`, and is absent from model-visible summaries.

Database migrations: **N/A for the pre-checkpoint completion work.** Slice 6 is explicitly documentation/discovery only; any SQLite schema and migration must follow an approved ADR and map every table/field to observed E2E transitions (`.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/06-local-api-and-persistence-discovery.md`).

### 4.3 API contracts

#### Domain/application service (required before the checkpoint)

```rust
/// Runs one complete bounded SSRF campaign through engine-owned transitions.
pub async fn run_ssrf_campaign(
    &self,
    input: SsrfCampaignInput,
) -> Result<SsrfCampaignOutputV1, SsrfCampaignError>;
```

The `Result` boundary has one unambiguous rule: all expected domain outcomes—including invalid input/reference, no candidate, blocked/approval-required, policy/audit failure, execution stop/failure, callback invalidity, evidence failure, duplicate run, and interruption—return `Ok(SsrfCampaignOutputV1)` with `state`/`error` populated according to the V1 schema. `Err(SsrfCampaignError)` is reserved for an internal invariant or serialization failure that prevents constructing any trustworthy V1 envelope; the CLI converts it to a fixed process-level `internal_envelope_failure` diagnostic and never fabricates campaign JSON. Golden fixtures cover every `CampaignErrorCode` and the process-level failure.

`SsrfCampaignInput` accepts engagement/source/scope/rules references, controlled callback worker authority, approval handle/state, campaign/run IDs, and injected time for tests. The callback worker is inert until the runner has a current allowed policy decision and exact-plan `ExecutionPermit`; registration and listener startup occur only after those checks and the listener accepts only the runner-generated plan-bound token. It does not accept raw callback tokens, arbitrary payload URLs, risk overrides, unbounded budgets, model prose, cookies, or authorization headers. Production creates the token and fixed safe budgets.

`SsrfObservationComparisonV1` is the pre-execution manual-inspection contract. It contains only the source digest and normalized redacted fields listed in Section 3.2, plus the candidate/plan hash once generated. Exact-reference lookup, digest verification, comparison rendering, and later offline replay all use the same production corpus/evidence adapters. Tests cover exact lookup, missing and ambiguous references, query-name/occurrence disambiguation, redaction, byte-stable JSON, and refusal to execute a plan whose comparison/source digest changed.

Required errors include invalid input/reference, no candidate, blocked/requires approval, policy/audit failure, execution stop/failure, callback invalidity, evidence redaction/path/write/hash/publication failure, existing run, cancellation, and invariant violation. Errors are typed and bounded; target-controlled content cannot become an error code.

#### Stable JSON (required)

- `schema_version`: exactly `gs.ssrf.campaign-result.v1` for this contract.
- Required fields: campaign/run/candidate IDs, state, result class, plan hash, policy verdict/reason code, bounded execution/correlation status, engagement-relative evidence paths, and typed error.
- Serialization is deterministic for identical structured/fixed-time inputs. Map/object ordering is canonicalized wherever output bytes are hashed or fixture-compared.
- `verified_finding` requires a published and revalidated bundle. `negative_test` is a successful completed hunt with no finding. Blocked/invalid/engine failures produce non-zero CLI exit; stable error codes distinguish them.
- Auth/permissions: local engagement permissions and opaque approval/vault handles only. No raw secrets in JSON.
- Identity V1: anonymous target probing only. GS-4.1 never imports a browser/account session, cookie, authorization header, client certificate, or user credential. Reauthentication is therefore N/A for target identity; approval expiry or process interruption requires a fresh opaque approval evaluation and new run. Authenticated/multi-account testing belongs to a separately approved capability contract.
- Pagination: N/A — one campaign result.
- Rate limiting: N/A at the API transport layer for one local command; engine request/time/byte/concurrency/callback budgets are mandatory.

#### Versioned local transport/API (decision checkpoint, not silently specified)

After the E2E campaign passes, inspect real state transitions and compare embedded library + SQLite, local service over Unix socket/HTTP, and supervised stdio JSON-RPC/line protocol. Produce an ADR and implementation plan covering single writer, restart, cancellation/progress, API versioning, filesystem/SQLite boundary, migrations, callback lease handling, duplicate/idempotent commands, and concurrent-execution prevention. No Axum route, daemon, SQLite dependency, or migration may be added before Jeff accepts that checkpoint (`.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/06-local-api-and-persistence-discovery.md`).

#### Thin CLI (after accepted checkpoint)

The exact command name is intentionally TBD. It invokes the approved application-service boundary and may only parse input, display progress, serialize `SsrfCampaignOutputV1`, and map typed outcomes to exit codes. It must never call the target directly, read legacy OOB callback files as proof, or synthesize success from missing fixture/API data (`.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/07-thin-cli-and-pruning.md`).

### 4.4 State management

- `SsrfCampaignRunner`/application service owns in-process state transitions and all authority-bearing objects. CLI/tests observe them; they do not mutate them. The runner stops before another request on any policy revocation, cancellation, callback-worker failure, target 429/5xx, transport instability, byte/time breach, or audit/evidence persistence failure; GS-4.1 has no retry path and records the deterministic stop reason.
- `CallbackRecorder` owns ephemeral plan-bound registrations/records for the active run (`crates/hunt-engine/src/callback.rs`).
- `action-policy` owns the allow/block/approval verdict; `ExecutionPermit` is exact-plan, non-cloneable, non-deserializable authority (`crates/hunt-engine/src/policy.rs`).
- `evidence-core` owns staged same-filesystem publication, no writer-mediated overwrite, manifest construction, and bounded content verification; `hunt-engine` owns which descriptor-verified typed artifacts satisfy the SSRF contract and result mapping. The manifest digest identifies the minimum durable coverage/negative-knowledge ledger for GS-4.1. GS-3.6 may later index locators/digests but must not replace or reinterpret verified bytes.
- Content-addressed filesystem evidence is the source of evidence bytes. Paths are locators, arbitrary same-user mutation is detected at consumption rather than claimed impossible, and evidence must not be duplicated into SQLite blobs.
- Durable operational state, single-writer ownership, restart transitions, and callback lease persistence are **TBD by Design Checkpoint 4**. Plaintext callback tokens may not silently enter SQLite. Until accepted, the E2E runner is one-process/offline, admits only one active run per process, and interruption is explicitly non-resumable: all workers close, ephemeral authority is discarded, no result is emitted, and retry requires a new run ID plus fresh policy/approval evaluation. This pre-checkpoint behavior is complete and testable; the checkpoint may add crash-safe persistence without weakening it.
- Draft persistence: N/A — no user-authored draft exists.

### 4.5 Dependencies

- Reuse existing workspace crates: `hunt-engine`, `action-policy`, `engagement`, `evidence-core`, Axum/Reqwest test/runtime components already used by the slice, Serde, SHA-256, time, and tempfile test support.
- The current uncommitted generic evidence work uses target-gated system bindings for exclusive rename on macOS/Linux (`crates/evidence-core/src/lib.rs`) without adding a dependency. Before acceptance, review the FFI constants/signatures, run configured audit gates, and provide a safe behavior or explicit unsupported-platform failure for other platforms; a plain racy fallback must not claim exclusive no-overwrite guarantees.
- No AI/model SDK, cloud callback, DNS, browser, database, daemon, or new remote service dependency is required before the checkpoint.
- SQLite/API dependencies are forbidden until the ADR is accepted.
- New assets/resources: only deterministic loopback fixtures and JSON golden fixtures; no third-party payload corpus.
- Infrastructure: ephemeral loopback listeners only. No Internet, public target, cloud metadata service, or uncontrolled callback.

### 4.6 Platform-specific considerations

- Linux-first release behavior is required; macOS remains a supported development/test path. Atomic no-replace publication must be proven on each supported platform. Unsupported platforms fail clearly rather than degrade to overwrite-prone behavior.
- Filesystem publication requires staging and final directories on the same filesystem, create-new writes, symlink-safe root traversal, bounded artifacts, fsync/error propagation, and exclusive final publish.
- Loopback fixtures use ephemeral ports and `127.0.0.1`; no shared fixed port or DNS.
- Reqwest redirects, retries, cookie store, proxy inheritance, and permissive TLS stay disabled as already established in `crates/hunt-engine/src/http_executor.rs` and `crates/hunt-engine/tests/http_executor.rs`.
- Feature flags/gradual rollout: the CLI command remains experimental/non-default until E2E, checkpoint, and blind implementation review pass. Legacy commands are not deleted or promoted based on this spec alone.
- Renderer/framework migration: N/A — no GUI renderer.

### 4.7 Performance budget

These are acceptance ceilings, not optimization targets:

- Target requests: exactly 1 allowed probe per run; 0 when blocked.
- Concurrency: 1.
- Redirects/retries: 0.
- Plan maximum: 10,000 ms and 262,144 response bytes; the current builder is stricter at 2,000 ms and 131,072 bytes and may remain so (`crates/hunt-engine/src/ssrf.rs`). Callback window is finite and plan-bound.
- Callback capture: exactly one accepted callback request per run; additional requests are rejected and recorded as invalid/reuse without increasing authoritative evidence. The worker enforces at read time—not after buffering—a 2,048-byte body ceiling, 32-header ceiling, 8,192 aggregate header-byte ceiling, bounded request-line/peer metadata, and the plan's finite callback deadline (`crates/hunt-engine/src/callback.rs`). It reads no chunk after a ceiling is reached, closes the connection/listener, and never allocates from an untrusted declared length.
- Cancellation: SIGINT/test cancellation closes the target future and callback listener within 1,000 ms, accepts zero further callbacks, invalidates the permit/token, and returns `interrupted_non_resumable`. Failure to close within the deadline is `invariant_violation`; it cannot emit a result or retain verified state.
- Generic evidence artifact: at most 16 MiB per artifact and 32 MiB per generic bundle under the current writer. The fixed SSRF structured assembler has a binding 4 MiB aggregate ceiling and should normally remain below 1 MiB. Exceeding 4 MiB fails before publication with no result.
- Memory: bounded response/callback streaming and staged artifact buffers; no unbounded target body/header retention. Peak target-body memory must not exceed the configured response cap plus ordinary transport overhead.
- CPU: hashing/serialization linear in bounded artifact bytes; no payload loops.
- Network payload: one mutated GET, no request body, fixed user agent, no imported cookies/auth headers.
- Storage: one exclusively published, content-addressed bundle identity per run; repeat runs never overwrite through the writer. Staging is removed or explicitly quarantined after failure. Arbitrary same-user mutation is outside pathname-immutability claims and must be detected by every authority-bearing consumer.
- Startup: no model initialization and no Internet discovery; benchmark should start within normal Rust test timing. Exact release startup SLO is N/A until the local-process architecture is chosen.

---

## 5. Test Specification

### 5.1 Unit tests

All tests use synthetic values and local temporary roots.

| Test name / location | Setup | Assertion / edge covered |
|---|---|---|
| `complete_proven_bundle_promotes_once` — `crates/hunt-engine/tests/evidence_result.rs` | Fixed observation/candidate/plan/policy/transaction/matched callback/assessment | Atomic commit precedes exactly one `verified_finding`; result binds run, candidate, plan, bundle, manifest |
| `missing_required_artifact_never_verifies` | Omit each of policy, transaction, callback, assessment, manifest requirement in turn | Typed failure/invalid; no verified result |
| `negative_and_invalid_commit_truthful_classes` | Negative and invalid assessments | `negative_test` and `invalid_test`; never finding; safe evidence retained |
| `write_failure_prevents_promotion` | Inject failure at every write/manifest/publish boundary | No final bundle, no verified result, staging removed/quarantined |
| `existing_run_is_byte_immutable` | Commit run, snapshot hashes, rerun same ID | `RunAlreadyExists`; all prior bytes unchanged |
| `unsafe_paths_and_symlinks_fail_closed` | traversal, absolute path, symlinked evidence/candidate/run/intermediate path | no escape/write/promotion |
| `manifest_covers_every_fixed_artifact` | Complete bundle | every artifact except manifest has relative path, hash, length, type, visibility; committed bytes match |
| `tamper_revalidation_demotes_or_fails` | Modify/delete each required committed artifact | revalidation fails; no promotion/replay verification |
| `locator_is_never_integrity_identity` | Rename/replace bundle, manifest, nested directory, and artifact after publication | stale locator/cached result cannot verify; only matching manifest/artifact digests can reconstruct authority |
| `verified_bytes_are_consumed_without_reopen_gap` | Mutate a pathname after descriptor verification while the consumer derives result | result derives only from bytes already read and verified from held descriptors; no unchecked reopen |
| `manifest_digest_is_bundle_identity` | Copy exact bundle bytes to another safe locator and separately alter one byte | exact copy verifies to the same identity; altered copy fails regardless of path |
| `model_visible_artifacts_have_no_secrets` | Synthetic callback token, original URL, cookie, auth header, bodies in source inputs | whole-bundle scan finds none in JSON/Markdown/model-visible files |
| `stable_result_json_is_canonical` | Fixed IDs/time/input twice | byte-identical JSON and exact `gs.ssrf.campaign-result.v1`; no target prose controls codes |
| `all_result_classes_validate_ids` | unsafe/empty candidate/run IDs | every constructor rejects, not only verified path |
| `bundle_total_size_is_bounded` | Many individually legal artifacts over total limit | rejected before final publish |
| `exclusive_publish_is_race_safe` | concurrent same-ID publishers | one succeeds, one `RunAlreadyExists`, no merged/overwritten bytes |
| `callback_limits_are_enforced_while_streaming` | oversized/chunked body, excess headers, second callback, slow sender | bounded allocation/read, listener closes, invalid/reuse reason, never verified from excess data |
| `cancellation_closes_authority_within_deadline` | cancel during target and callback waits using injected clock | tasks close within 1,000 ms, zero later callbacks, token/permit unusable, no result |
| `output_state_invariants_reject_illegal_combinations` | every state with null/non-null result/evidence/error permutations | only declared V1 combinations construct/validate; blocked counts remain zero |

Retain and rerun existing focused tests in `crates/hunt-engine/tests/{result_contract,ssrf_candidate,ssrf_plan,ssrf_plan_security,policy_gate,http_executor,callback,callback_assessment}.rs` and `crates/evidence-core/src/lib.rs`.

`runbook.md` has a fixed heading/field order: schema version; campaign/run/candidate IDs; observation source digest; plan hash; policy verdict/reason/decision digest; exact mutation position without original value; request and callback counts; bounded timing/byte ceilings; assessment class/reason; satisfied/missing requirement IDs; deterministic explanation and `next_action_code`; evidence locators/digests; bounded impact statement; cleanup status; and replay procedure. It does not contain the enclosing manifest digest because the manifest hashes `runbook.md`; `CommittedBundleIdentity.manifest_sha256` is derived only after publication and appears in authoritative service output, not backfilled into any bundle artifact.

The replay procedure is offline validation, not active retesting. Implement `offline_replay_from_environment` in `crates/hunt-engine/tests/evidence_result.rs`; it requires `GS_REPLAY_ENGAGEMENT_ROOT`, `GS_REPLAY_CANDIDATE_ID`, `GS_REPLAY_RUN_ID`, and expected `GS_REPLAY_MANIFEST_SHA256`. It opens without following symlinks, reads bounded descriptor-held bytes, verifies the manifest identity and every referenced artifact, invokes `EvidenceContract::validate_local` on those exact bytes, regenerates class/explanation/next-action, prints one secret-free canonical JSON document, and performs zero network I/O. The exact runbook command is:

```bash
cd crates
GS_REPLAY_ENGAGEMENT_ROOT='<engagement-root>' \
GS_REPLAY_CANDIDATE_ID='<candidate-id>' \
GS_REPLAY_RUN_ID='<run-id>' \
GS_REPLAY_MANIFEST_SHA256='<manifest-sha256>' \
cargo test -p hunt-engine --test evidence_result --locked offline_replay_from_environment -- --exact --nocapture
```

Missing/unsafe environment values fail before filesystem access; tampered bytes fail before printing a class. A checked-in temporary-root fixture test invokes the same function without shell placeholders.

### 5.2 Integration tests

Create `crates/hunt-engine/tests/ssrf_campaign_e2e.rs`, driven through production `SsrfCampaignRunner`/application service rather than test-owned sequencing.

1. **Blocked first:** out-of-scope, stale-rules, automation-disallowed, and audit-write-failure variants. Assert no permit, zero target requests, zero callbacks, audited block when storage permits, no verified result, and stable blocked/invalid JSON.
2. **Vulnerable:** exactly one candidate, allowed policy/audit, exactly one target request, exactly one matching callback, one final content-addressed bundle identity, one `verified_finding`, identical plan hash across policy/permit/transaction/assessment/manifest references/result.
3. **Secure:** same shape and policy path, exactly one target request, zero callbacks, finalized window, committed negative bundle, `negative_test`, zero findings. Response keywords cannot promote it.
4. **Repeated:** second run has distinct token, plan hash where token-bound semantics require it, run ID, and bundle; old token cannot satisfy it; old bytes remain unchanged; duplicate ID fails.
5. **Evidence failures:** injected serialization, redaction, artifact write, manifest write, hash mismatch, fsync/publication, and persistence-boundary failures all prevent promotion.
6. **Offline/no-model:** clear model/provider credential variables, use only ephemeral `127.0.0.1`, disable environment proxies, and assert no DNS/Internet listener receives traffic.
7. **Lifecycle cleanup:** target and callback tasks terminate on every success/failure/cancellation path.
8. **Result JSON:** output from all cases validates against `docs/gauntlet/schemas/gs.ssrf.campaign-result.v1.schema.json` and checked-in golden fixtures under `crates/hunt-engine/tests/fixtures/ssrf-output-v1/`; canonicalization and secret scans cover every class.
9. **Interruption matrix:** cancel during policy-to-permit handoff, target wait, callback wait, evidence staging, and committed-byte revalidation. Every case closes workers within 1,000 ms, invalidates permit/token, accepts zero later callbacks, emits no result, and requires a new run ID plus fresh policy/approval evaluation.
10. **Pre-checkpoint diagnostics:** an application-service diagnostic verifies engagement-root readability, corpus-reference resolution, evidence-root create/sync/quarantine capability, loopback bind capability, and schema version without target I/O. Each check has a stable code and remediation; Linux and macOS fixture tests cover success and fail-closed permissions/path cases.

Exact focused command:

```bash
cd crates
cargo test -p hunt-engine --test ssrf_campaign_e2e -- --nocapture
```

After the E2E passes, the Design Checkpoint 4 ADR test plan must additionally cover load-time hash revalidation, illegal transitions, duplicate/idempotent commands, restart during an active callback lease, atomic operational-state/evidence promotion, and prevention of two concurrent executions of one authorized plan. Those persistence/API tests are not implemented until the architecture is accepted.

### 5.3 UI / E2E tests

After the thin CLI exists, create package-scoped CLI tests using a fake and the real local application boundary:

1. CLI delegates to the application service and performs no direct target HTTP.
2. Vulnerable command emits V1 JSON pointing to committed verified evidence.
3. Secure command exits success as a completed negative test with no finding.
4. Blocked/invalid/infrastructure outcomes exit non-zero and report zero execution where applicable.
5. stdout contains only final JSON in JSON mode; diagnostics/progress go to stderr.
6. Human output remains understandable with ANSI disabled and in a narrow terminal.
7. Ctrl-C/cancellation follows approved engine semantics and does not leave duplicate execution or verified partial evidence.
8. Missing fixture/API data cannot synthesize HTTP success or a completed hunt.
9. Legacy OOB files cannot be imported as authoritative proof.
10. Default help/docs expose only the approved command state and clearly label deferred/quarantined behavior.

Exact package name/command is recorded in the accepted checkpoint ADR and implementation brief; placeholder commands must not be claimed passing.

### 5.4 Visual / manual verification

- Light/dark terminal themes: textual states remain readable; color is non-authoritative.
- No-color and non-TTY output.
- Narrow (approximately 40-column) and wide terminal widths; long hashes/paths wrap without hiding labels.
- Empty/no-candidate, vulnerable, secure, blocked, invalid, evidence failure, and repeated-run states.
- JSON piped through a parser; stdout has one valid result document.
- Screen-reader pass over `--help` and representative human output.
- Text-size extremes are controlled by the terminal; verify no cursor-position layout breaks.
- GUI screen-size, touch, and visual-regression snapshots: N/A — no graphical UI.

Required implementation verification tiers:

**Phase A — Task 4.3 and campaign runner, executable before Design Checkpoint 4:**

```bash
cd crates
cargo fmt -p evidence-core -p hunt-engine -- --check
cargo test -p evidence-core --locked
cargo test -p action-policy -p engagement --locked
cargo test -p hunt-engine --test evidence_result --locked
cargo test -p hunt-engine --test ssrf_campaign_e2e --locked -- --nocapture
cargo test -p hunt-engine --test ssrf_campaign_e2e interruption_ --locked -- --nocapture
cargo test -p hunt-engine --locked
cargo clippy -p evidence-core -p hunt-engine --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --tests --locked -- -D warnings
cd ..
git diff --check
```

**Phase B — accepted boundary and CLI:** the Design Checkpoint 4 ADR must amend this spec with the selected package/binary, exact start command, health/readiness diagnostic, CLI invocation, package-scoped test, and strict Clippy command before any CLI implementation begins. No placeholder command is a passing gate. Phase B must test interruption, stale approval, duplicate command, concurrent execution refusal, schema output, stdout/stderr separation, and Linux startup prerequisites.

At the product/release boundary also run `cargo build --workspace --locked`, `cargo audit --deny warnings`, the configured Docker smoke test, and image build from `docs/gauntlet/PLAN.md`, Section 11.

---

## 6. Compliance & Safety Gate

### 6.1 Sensitive data classification

- [ ] No sensitive data involvement
- [x] Handles sensitive data — protection measures below
- [x] Uses synthetic/test data only until compliance gate clears

Potentially sensitive input includes original observed query values, cookies/auth headers in source traffic, callback tokens, target/callback bodies, peer metadata, approval/vault references, and engagement paths. Controls:

- executable raw state remains crate-private and non-serializable (`crates/hunt-engine/src/ssrf.rs`);
- public plan/transaction/assessment/result contain hashes, names/occurrences, bounded status, and references only;
- token is generated engine-side, single-plan, expiring, and never persisted raw in this slice;
- no imported cookies/auth headers or request body are sent;
- response/callback bodies are streamed/bounded and represented by hashes, not raw bytes;
- model-visible artifacts undergo structured redaction and whole-bundle secret tests;
- opaque credential/approval handles only; no raw vault values in API/SQLite/CLI;
- all acceptance data is synthetic and all active I/O is controlled loopback.

### 6.2 Asset provenance

- [x] No third-party assets
- [ ] Uses third-party assets — list each with source, license, and rights status

No model, payload corpus, image, font, external data, or public target is used. Rust dependencies are software supply-chain items rather than content assets and remain subject to licensing/provenance/audit checks under Lens 2F and auto-fail 12.

### 6.3 Language / claims audit

- [ ] Make claims not supported by evidence? (MUST NOT unless flagged)
- [ ] Promise capabilities not yet built? (MUST NOT)
- [ ] Use language restricted by domain regulations? (MUST NOT)

Required terminology:

- `verified_finding` means only deterministic matching callback proof plus descriptor-held evidence bytes verified against the authoritative manifest digest and contract.
- `negative_test` means this bounded test observed no callback; it does not mean the endpoint/application is globally secure.
- `invalid_test` means no security conclusion.
- `human_verification_candidate` is only for a specifically modeled inconclusive state, never generic storage/transport errors.
- Report impact is limited to the controlled outbound callback behavior observed. No cloud metadata access, internal reachability, credential theft, or severity claim is inferred.
- Planned API/SQLite/CLI/legacy disposition is labeled pending until implemented and independently verified.

### 6.4 Regulatory alignment

This feature is a security-testing capability and must meet `docs/gauntlet/criteria.md` Lens 3 in full:

- **3A deterministic evidence:** only Rust-owned contract validation can construct evidence satisfaction/verified result; response keywords, target prose, and model confidence are non-authoritative (`crates/hunt-engine/src/lib.rs`, `crates/hunt-engine/src/assessment.rs`).
- **3B immutable contained artifacts:** same-filesystem staged publication, exclusive no-writer-overwrite rename, authoritative manifest content digest, complete artifact hash/length/type/visibility entries, symlink/traversal rejection, bounded/redacted files under the engagement root, and consumer-time verified-byte enforcement. Arbitrary same-user pathname mutation is detected, not claimed impossible.
- **3C reproducibility:** deterministic `runbook.md`, plan hash, structured references, exact evidence hashes, and offline replay instructions without raw secrets.
- **3D truthful classification:** verified, candidate, negative, invalid, blocked, pending, and infrastructure failure stay distinct through engine JSON, accepted local boundary, CLI, eventual persistence, and reports.
- **3E report quality:** result/runbook states prerequisites, exact callback-only behavior, bounded impact, false-positive checks, evidence, cleanup, and repeat steps without unsupported severity.
- **3F failure behavior:** mismatch, expiry/reuse, partial write, hash/redaction/persistence/publication failure blocks promotion and produces typed invalid/inconclusive/error state.

### Safety auto-fail application

Every rule in `docs/gauntlet/criteria.md` applies. GS-4.1 automatically fails if any of the following occurs:

1. Any target/callback I/O precedes current scope/rules, policy, approval, audit, and finite-budget checks.
2. Scope defaults allow, deny precedence is bypassable, or stale/ambiguous authorization executes.
3. Model/client/deserialized JSON controls scope, risk, approval, secrets, evidence satisfaction, or verification.
4. Raw secret/private data enters model-visible output, logs, reports, fixtures, committed artifacts, or ordinary persistence.
5. A verified finding exists without exact capability-specific evidence satisfaction.
6. A plan is unbounded or omits required stops/cleanup.
7. Evidence escapes root, follows a symlink, is overwritten through the writer, omits hashes, treats a locator as proof, consumes unchecked reopened bytes, or remains verified after integrity/write/revalidation failure.
8. Tests require public targets, cloud metadata, Internet, or uncontrolled callbacks.
9. The slice adds destructive/evasive/persistence/credential-harvesting/DoS/post-exploitation behavior.
10. Output fabricates/overstates impact or hides negative/inconclusive outcomes.
11. CLI duplicates/bypasses engine authority or grants arbitrary shell access.
12. A dependency is unjustified, incompatible, unlicensed, or fails configured vulnerability audit.
13. Tests are flaky, Internet-dependent, share nondeterministic ports/state, or cannot distinguish vulnerable/secure/blocked.
14. Existing safety invariants are weakened without approved migration and replacement tests.
15. Docs claim pending/prototype/quarantined behavior is shipped or leave state ambiguous.
16. Legacy behavior is deleted without inventory, salvage analysis, explicit disposition, and replacement/parity evidence.

---

## 7. Gap Analysis vs. Current State

### 7.1 What exists today

**Implemented and tested at the current engine baseline**

- Capability-neutral evidence requirements/references and distinct result classes; verified construction is crate-private, but result identity is still incomplete and validation is not wired to committed SSRF evidence (`crates/hunt-engine/src/lib.rs`; `crates/hunt-engine/tests/result_contract.rs`; `docs/gauntlet/run-logs/GS-4.1-evidence-baseline.md`).
- Normalized HTTP observation, inert absolute HTTP(S) query candidate generation, redacted immutable SSRF plan view, crate-private executable state, exact query occurrence mutation, token-bound plan hash, fixed budgets/stops (`crates/hunt-engine/src/ssrf.rs`; `crates/hunt-engine/tests/{ssrf_candidate,ssrf_plan,ssrf_plan_security}.rs`).
- In-process vulnerable/secure loopback target fixtures (`crates/hunt-engine/tests/support/mod.rs`; `crates/hunt-engine/tests/ssrf_benchmark.rs`).
- Plan-bound callback token/registration/record/correlation and bounded redacted callback metadata (`crates/hunt-engine/src/callback.rs`; `crates/hunt-engine/tests/callback.rs`).
- `action-policy` adapter, audited exact-plan permit, and blocked cases before I/O (`crates/hunt-engine/src/policy.rs`; `crates/hunt-engine/tests/policy_gate.rs`).
- One-request, no-redirect, no-proxy, bounded executor with sanitized transaction record and exact network-count tests (`crates/hunt-engine/src/http_executor.rs`; `crates/hunt-engine/tests/http_executor.rs`).
- Pure pending/proven/negative/invalid callback assessment that does not promote a finding (`crates/hunt-engine/src/assessment.rs`; `crates/hunt-engine/tests/callback_assessment.rs`).
- Legacy `evidence-core::EvidenceBundleWriter` no-overwrite/redaction/hash helpers, but the verified baseline shows direct writes to final paths and an incomplete manifest (`crates/evidence-core/src/lib.rs`; `docs/gauntlet/run-logs/GS-4.1-evidence-baseline.md`).

**Rejected/superseded implementation work**

- The current worktree contains an uncommitted generic staged evidence API and tests in `crates/evidence-core/src/lib.rs`. Final fingerprint `bf384dcf6998ec9f3a5a716a531d7cca8ac2e85b2005aefd89395b35cfa5bea5` passed 27 native/Linux tests and strict gates but failed independent review because repeated pathname verification cannot close the same-user post-verification mutation window. It is preserved as rejected experimental work and must not be committed or patched as remediation 4. `docs/gauntlet/implementation-briefs/GS-4.1-content-addressed-evidence-identity.md` defines the replacement architecture pending this iteration-4 spec review.

**Planned/absent**

- Task 4.3 complete SSRF bundle and promotion path: absent.
- Production `SsrfCampaignRunner` plus vulnerable/secure/blocked/repeated E2E: absent.
- Evidence failure injection through campaign promotion: absent.
- Stable result V1 bound to run/plan/bundle/manifest: absent.
- Local API/SQLite ADR and accepted architecture: pending discovery checkpoint; production implementation intentionally absent.
- Thin CLI using the accepted boundary: absent.
- Formal legacy salvage inventory: complete in `docs/gauntlet/run-logs/GS-4.1-legacy-ssrf-oob-salvage.md`; replacement parity, final Checkpoint 5 dispositions, and README alignment remain pending.

**Legacy/quarantined candidates**

- `crates/mg-webscan/src/ssrf.rs` contains useful URL-input discovery ideas but also cloud metadata payloads, response keyword heuristics, permissive TLS, callback-file scanning, and direct finding emission; these must not become the new authority.
- `crates/mg-oob/src/main.rs` and `crates/oob-core/src/lib.rs` provide listener/process ideas but are not plan-bound result authorities.
- `crates/mg-hunt/src/main.rs` contains fixture/evidence flow worth inventorying but uses the older orchestration/finding path.

The manifest records GS-4.1 as implementation-blocked pending a fresh exact-SHA review of this content-addressed iteration-4 contract (`docs/gauntlet/manifest.md`).

### 7.2 Delta to spec

**New files/modules expected**

- `crates/hunt-engine/src/evidence.rs` — SSRF artifact assembly, committed-reference validation, promotion mapping.
- `crates/hunt-engine/src/campaign.rs` — production state sequencing/application service.
- `crates/hunt-engine/tests/evidence_result.rs`.
- `crates/hunt-engine/tests/ssrf_campaign_e2e.rs`.
- Checked-in V1 JSON schema/golden fixtures in the repository's approved test/schema location.
- Design Checkpoint 4 ADR and implementation plan after E2E success.
- One CLI module/tests after architecture approval.
- Legacy SSRF/OOB salvage inventory exists; replacement evidence and final Checkpoint 5 disposition are required before any deletion.

**Modified files expected**

- `crates/hunt-engine/src/lib.rs` — exports and complete stable result identity; remove dead-code allowances by wiring validation/promotion.
- `crates/hunt-engine/Cargo.toml` as minimally required for `evidence-core` integration.
- `crates/evidence-core/src/lib.rs` and possibly Cargo metadata — complete/review generic atomic API while preserving or deliberately migrating legacy callers.
- Approved CLI crate Cargo/source files after checkpoint.
- README/progress docs only after tests prove shipped behavior.

**Migrations/schema**

- No database migration before checkpoint. After acceptance, add only the SQLite/API schema justified by real campaign transitions, with migration/rollback/crash tests.

**Dependencies**

- No new network/model/database dependency before checkpoint. Review the target-gated exclusive-publication bindings and their unsupported-platform behavior.

**Required design/review artifacts**

- Blind spec scorecard before implementation.
- Implementation brief with exact RED/GREEN commands.
- Checkpoint 4 ADR/options and explicit Jeff decision.
- Checkpoint 5 legacy inventory with demonstrated behavior, tests/fixtures, salvageable algorithms/data, safety defects, duplicate owners, missing contracts, disposition (`adapt`, `merge`, `quarantine`, or `delete after replacement`), and parity/intentional-improvement test.

### 7.3 Estimated scope

**L (large).** The remaining domain work is bounded to one capability and much of the safe execution baseline exists, but completion crosses atomic filesystem publication, deterministic promotion, production orchestration, adversarial offline integration, stable schemas, an architecture decision, one client, and legacy disposition. API/SQLite implementation can make the slice XL if the checkpoint chooses a long-lived service; therefore the checkpoint must select the smallest boundary justified by observed needs and may split GS-1.5/GS-6.1 implementation while keeping GS-4.1's stable application-service/CLI acceptance intact.

### 7.4 Blocking dependencies

1. Independent review of the staged `evidence-core` generic writer; do not assume it is accepted until the exact-snapshot verdict passes.
2. Task 4.3 evidence commit/promotion must pass before campaign E2E.
3. Campaign E2E must pass before Design Checkpoint 4 discovery.
4. Jeff's explicit local API/persistence decision blocks production API/SQLite and the thin CLI transport choice.
5. The completed salvage inventory, a passing replacement benchmark, and explicit Checkpoint 5 decisions block deletion/quarantine changes to old SSRF/OOB surfaces.
6. Blind spec approval blocks implementation under the completion-gauntlet protocol (`docs/gauntlet/PLAN.md`, Sections 9–10).

---

## 8. Open Questions

- **Q1:** Which Design Checkpoint 4 option is accepted after E2E evidence: embedded single-process library + SQLite, local service over Unix socket/HTTP, or supervised stdio protocol? — blocks: production local transport, persistence, CLI package/command, restart semantics.
- **Q2:** Which operational transitions must persist, and are active callback leases deliberately non-resumable or protected through a dedicated secret mechanism? Plaintext tokens may not enter ordinary SQLite/API rows. — blocks: persistence schema and crash recovery.
- **Resolved for iteration 2:** V1 schema lives at `docs/gauntlet/schemas/gs.ssrf.campaign-result.v1.schema.json`; golden fixtures live under `crates/hunt-engine/tests/fixtures/ssrf-output-v1/`; object fields follow the declared schema order for golden bytes, arrays use canonical semantic order, and maps are forbidden in hashed/golden V1 output.
- **Resolved for iteration 2:** the reviewed generic writer's target-gated descriptor-relative no-replace bindings are the candidate implementation; exact-snapshot blind PASS and Linux CI proof remain acceptance gates, while unsupported platforms fail closed.
- **Resolved for iteration 2:** the generic ceiling remains 32 MiB and the structured SSRF assembler has a binding 4 MiB aggregate ceiling with no raw bodies.
- **Q6:** After replacement proof, should `mg-oob` become a thin callback worker, should useful listener primitives merge into engine-owned worker code, or should it be quarantined? — blocks: Checkpoint 5 disposition only.
- **Q7:** After inventory/parity review, should `mg-webscan ssrf` be quarantined or deleted? Its metadata probes, payload spraying, permissive TLS, keyword heuristics, and direct finding emission are explicitly not salvageable; URL-input discovery ideas may be adapted. — blocks: Checkpoint 5 disposition and docs.
- **Q8:** Which existing CLI binary should host the thin command after the boundary is accepted, or should a minimal new client be created? — blocks: Section 3 command name and CLI test package.

---

## Blind-review scoring obligations

This section does not replace the template sections above; it makes the approved weighting and slice evidence explicit for reviewers.

| Lens | Weight | GS-4.1 completion obligation |
|---|---:|---|
| Adaptive Hunt Completion and Competitive Depth | 35% | One production runner completes the closed loop; callback-only automation is bounded and explainable; vulnerable/secure/blocked/repeated offline cases are distinguishable; negative knowledge is preserved; the same campaign state/result feeds evidence and the client rather than disconnected demos. Traffic-centric proxy depth, broader families, scheduler expansion, and learning UI are parent/sibling work, but GS-4.1 must not contradict or falsely claim them. |
| Authorization, Safety, and Deterministic Control | 30% | Default-deny fresh scope/rules, sole `action-policy` authority, exact-plan non-forgeable permit, finite request/time/byte/concurrency/redirect/callback budgets, audit-before-I/O, engine-only secrets, controlled loopback fixtures, clean dependency/license/audit evidence, and zero I/O for blocked/failure preconditions. |
| Evidence, Finding, and Report Integrity | 20% | Rust-only promotion, complete immutable contained hashed bundle, stable identity/revalidation, reproducible redacted runbook, distinct result classes, bounded impact language, and fail-closed behavior for correlation, redaction, persistence, write, publish, and integrity failures. |
| Operator and Agent API Usability | 15% | One engine with stable V1 typed output, evidence-based local API/persistence checkpoint, one thin CLI, keyboard/no-color/narrow-terminal behavior, actionable typed errors, and accepted cancellation/resume semantics without duplicated authority. |

A passing blind review requires no auto-fail, no criterion scored 0, every lens average at least 2.0, weighted composite at least 2.25, no lens with more than two scores of 1, feasibility not `infeasible`, and verifier-executed evidence for every passing command (`docs/gauntlet/criteria.md`).
