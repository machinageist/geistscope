# GeistScope Completion Gauntlet Plan

> **Execution note:** Follow this plan task-by-task using isolated author, implementer, and blind-review contexts. Tooling may vary by agent; the file contracts and verification commands are authoritative.

**Goal:** Finish GeistScope as a demonstrably working, safe, local-first bug-hunting and pentest suite for the full recon → model → hypothesize → test/exploit → verify → evidence → report pipeline by advancing verified vertical slices through a model-agnostic spec → implementation → blind verification → remediation loop.

**Architecture:** Retain the universal gauntlet’s criteria, feature-tree, blind-review, and three-remediation structure, but extend it beyond spec quality into executable completion gates. Every agent works from versioned files, writes declared artifacts, runs exact commands, and leaves a restartable checkpoint; no step depends on a vendor-specific slash command, private chain of thought, or chat history.

**Tech Stack:** Rust 2024 workspace, `hunt-engine`, `action-policy`, `evidence-core`, local versioned API, SQLite operational state, immutable evidence files, CLI/TUI clients, in-process and Docker-backed local benchmarks, GitHub Actions.

---

## 1. Why this is a completion gauntlet, not only a spec gauntlet

The vendored universal protocol in `docs/gauntlet/templates/UNIVERSAL-GAUNTLET.md` ends after generating and grading product specs. GeistScope needs a second, executable half:

1. Criteria and feature tree are confirmed.
2. A feature spec is generated and blind-reviewed.
3. The approved spec is implemented with behavior-first tests.
4. A fresh verifier reviews the implementation against the same criteria and the approved spec.
5. Failed gates loop through focused remediation at most three times.
6. A slice becomes complete only after local acceptance evidence and repository-wide quality gates pass.
7. The manifest and handoff are updated so any agent can resume from files alone.

This extension preserves the universal protocol rather than replacing it.

## 2. Ground truth discovered on 2026-08-13

- Repository: the Git root containing `docs/gauntlet/` (commands are repository-relative)
- Branch at discovery: `main`, 23 commits ahead of `origin/main`, clean worktree.
- Stack: Rust workspace with 83 package manifests and 84 listed workspace members.
- Current product direction: one adaptive closed loop—observe → remember → hypothesize → plan → authorize → execute → interpret → preserve evidence → continue → verify → report.
- Primary v1 user: a technically capable solo bug-bounty hunter; learning support is progressive disclosure over the same engine and evidence standard.
- First-release spine: web applications, HTTP/GraphQL APIs, authenticated/multi-account workflows, browser/client behavior, request capture/mutation/replay, evidence, and reporting.
- Ultimate product scope: a coherent bug-hunting and pentest suite spanning program intake, passive and active recon, traffic/corpus construction, adaptive prioritization, vulnerability testing, controlled exploitation, verification, evidence, reporting, cleanup, and regression. Network, cloud/container, mobile/binary, and post-exploitation capabilities enter as later typed capability packs after the core contract is proven.
- Permanent non-goals unless Jeff explicitly changes them: uncontrolled destructive/evasive/persistence behavior, hosted-service lock-in, automatic bounty submission without review, arbitrary agent shell execution, and scanner-count marketing unsupported by integrated evidence.
- Current authoritative engine: `crates/hunt-engine`, with `crates/action-policy` as the sole deterministic policy authority.
- Current implementation frontier: `.hermes/plans/2026-07-31_ssrf-vertical-slice/PLAN.md` reports Tasks 1.1 through 4.2 complete. Tasks 4.3, 5.1, 6.1, local API/persistence, and pruning remain.
- Existing CI runs locked workspace build/tests/clippy plus a Docker-backed pipeline smoke test. Weekly dependency audit runs `cargo audit --deny warnings`.
- Documentation drift exists: top-level README still presents a large 69-tool/90+-endpoint suite as the product while the accepted product decision log says shallow scanners should be quarantined or deleted unless they contribute to the closed loop.

## 3. Authoritative input order

Every agent MUST read these files in order before acting:

1. This plan.
2. `docs/gauntlet/HANDOFF.md` once created.
3. `docs/gauntlet/manifest.md` once created.
4. `docs/gauntlet/criteria.md` once confirmed.
5. `docs/gauntlet/feature-tree.md` once confirmed.
6. `.hermes/plans/2026-07-23_hunting-engine-restructure.md`.
7. The active slice’s approved spec and scorecard.
8. The active slice’s relevant source and test files.
9. `README.md`, `crates/README.md`, `crates/Cargo.toml`, and `.github/workflows/ci.yml` only as current-state evidence; decision records and tested source override stale claims.

Conflict rule: confirmed criteria → accepted product decision log → approved slice spec → tested source → README prose. Record unresolved conflicts in `docs/gauntlet/decisions-needed.md`; do not silently choose.

## 4. Proposed completion criteria (requires user sign-off)

### Scoring

Each criterion is scored 0–3:

- 0: missing, contradicted, fabricated, or not executable.
- 1: superficial or materially incomplete.
- 2: correct, usable, tested, and acceptable for v1.
- 3: best-in-class, polished, and supported by strong acceptance evidence.

Pass conditions:

- No auto-fail is triggered.
- No criterion is 0.
- Every lens average is at least 2.0.
- Composite weighted score is at least 2.25.
- No more than two criteria score 1 in any lens.
- Feasibility verdict is not `infeasible`.
- All commands claimed as passing were run by the current implementation verifier, with output summarized in the scorecard.

### Lens 1 — Adaptive Hunt Completion and Competitive Depth (35%)

The benchmark inventory includes Burp Suite and Caido.[1][2]

It also includes Nuclei and ProjectDiscovery.[3][4]

ZAP, mitmproxy, and OWASP WSTG complete the initial set.[5][6][7]

Their role here is not feature-copying; each supplies a capability floor while GeistScope differentiates through a persistent, evidence-backed adaptive loop.

1A. **Closed-loop continuity** — Observations create structured hypotheses; authorized plans execute; results update state; new evidence changes the next action; confirmed findings generate neighboring hypotheses rather than ending the campaign.

1B. **Traffic-centric manual depth** — Capture/import, inspect, search, mutate, replay, compare, and preserve HTTP/browser traffic must be coherent enough to replace routine proxy/repeater workflows for supported slices.

1C. **Automation depth without spray** — Deterministic templates/checks, resumable campaigns, budgets, and explainable scheduling must achieve broad low-cost coverage while reserving depth for high-value hypotheses.

1D. **Priority vulnerability proof** — SSRF, broken access control/IDOR, and one critical server-side injection family each have an offline vulnerable/secure/blocked benchmark through the same engine contract.

1E. **Coverage and negative knowledge** — Hunt state records tested, vulnerable, secure, blocked, inconclusive, and untested cells across object/action/identity/tenant/interface dimensions; it never equates “no finding” with “secure everywhere.”

1F. **Differentiation** — Persistent local engagement memory, explainable budget reallocation, deterministic verification, finding-adjacent expansion, and inspectable coverage work together in one real campaign rather than existing as disconnected demos.

### Lens 2 — Authorization, Safety, and Deterministic Control (30%)

2A. **Effective scope and rule freshness** — Default-deny scope, deny precedence, current program-rule snapshots, authorization expiry, and ambiguity handling are enforced before active I/O.

2B. **AI/control-plane boundary** — AI can propose and explain but cannot expand scope, lower risk, bypass approval, access raw secrets, fabricate evidence, or promote verification.

2C. **Budgets and stop conditions** — Every active plan binds request, time, byte, concurrency, redirect, callback, and operator-interruption budgets plus hard stops for rate limits, WAF distress, instability, credential failure, and unintended impact.

2D. **Identity and secret isolation** — Credentials remain in a local vault or environment-backed reference; model-visible state exposes labels/capabilities only; identities are isolated by account/role/tenant/browser session.

2E. **Safe execution and fixtures** — Acceptance tests use loopback fixtures or explicitly controlled lab containers; active tests are bounded, deterministic, cleanup-aware, and never require public third-party targets.

2F. **Auditability and supply chain** — Allow/block/error/approval decisions, provider disclosures, dependency provenance, license state, and security audit results are inspectable; repository dependencies pass the configured audit gate.

### Lens 3 — Evidence, Finding, and Report Integrity (20%)

3A. **Deterministic evidence contracts** — Only Rust-owned evidence predicates can create `verified_finding`; target prose, model confidence, or response keywords alone cannot.

3B. **Immutable, contained artifacts** — Evidence is append-only or content-addressed, hash-manifested, symlink/path-traversal safe, bounded, redacted, and rooted under the engagement directory.

3C. **Reproducibility** — A fresh verifier can replay the minimized proof from structured plan/evidence references without raw secrets in the report.

3D. **Truthful classification** — Verified findings, human-verification candidates, negative tests, invalid tests, and inconclusive outcomes remain distinct through API, CLI/TUI, persistence, and reporting.

3E. **Impact and report quality** — Reports state prerequisites, exact behavior, bounded impact, confidence, evidence, false-positive checks, cleanup, and reproducible steps without unsupported severity or exploit claims.

3F. **Evidence failure behavior** — Correlation mismatch, expiry, partial writes, hash mismatch, redaction failure, or persistence failure prevents promotion and yields a clear invalid/inconclusive state.

### Lens 4 — Operator and Agent API Usability (15%)

4A. **One engine, multiple thin clients** — CLI, TUI, built-in AI, and external agents use one versioned local API and do not duplicate orchestration or policy logic.

4B. **Agent-agnostic typed contracts** — Inputs/outputs are schema-versioned, bounded, documented, machine-readable, and usable without shell access or a specific model vendor.

4C. **Expert workflow efficiency** — Keyboard-first navigation, searchable traffic and hunt state, fast request editing/replay, semantic comparison, plan inspection, and explicit approvals minimize context switching.

4D. **Learning profile** — The same facts and safety gates can explain hypothesis rationale, expected secure/vulnerable behavior, false-positive diagnostics, evidence needs, and stopping points without hiding expert controls.

4E. **Recovery and resumability** — Interrupted campaigns restart without token reuse, evidence overwrite, duplicate active execution, or loss of audit/coverage state; stale sessions request reauthentication.

4F. **Install, diagnostics, and accessibility** — Linux-first install is documented and reproducible; startup validates dependencies/config; errors identify recovery actions; TUI output is keyboard-complete, color-independent, terminal-size aware, and usable with reduced animation.

## 5. Proposed auto-fail rules

Any one of these fails the slice regardless of numerical score:

1. Active network I/O occurs before deterministic scope, rule-freshness, policy, approval, and budget checks.
2. Scope is default-allow, deny precedence can be bypassed, or ambiguous/stale authorization proceeds.
3. AI/model output can change effective scope, risk class, approval state, executable secret material, evidence satisfaction, or finding verification.
4. Raw credentials, cookies, tokens, sensitive bodies, callback tokens, or unredacted private data enter model-visible state, logs, reports, fixtures, or committed artifacts.
5. A verified finding can exist without its capability-specific deterministic evidence contract being satisfied.
6. An active plan lacks finite request/time/byte/concurrency/output limits, required stop conditions, or cleanup/rollback handling where state can change.
7. Evidence can escape the engagement root, follow a symlink outside it, overwrite an existing bundle, omit required hashes, or remain “verified” after an artifact write/integrity failure.
8. Acceptance or CI requires scanning/testing a live third-party target, public bounty program, cloud metadata service, or uncontrolled callback endpoint.
9. A slice introduces destructive, persistence, evasion, credential-harvesting, denial-of-service, or post-exploitation behavior into v1 without an explicit newly approved product decision.
10. Claims overstate observed impact, mark heuristic output verified, fabricate requests/responses/callbacks, or conceal inconclusive/negative outcomes.
11. An operator surface bypasses the versioned engine API by duplicating policy/orchestration or exposing arbitrary shell execution to an agent/model.
12. A new dependency has unknown/incompatible licensing, unresolved known-vulnerability audit failure, or is added without a justified need and version compatibility check.
13. Required tests are flaky, depend on Internet access, use nondeterministic shared ports/state, or cannot distinguish vulnerable, secure, and blocked cases.
14. The implementation deletes or weakens a previously tested safety invariant without an explicit approved migration and replacement test.
15. Documentation represents planned/prototyped/quarantined behavior as shipped or leaves the resuming agent unable to identify the authoritative current state.
16. A legacy tool is deleted merely because it is outside the first release, without first inventorying its tested behavior, algorithms, fixtures, interoperability value, and migration target.

## 6. Proposed feature tree (requires user sign-off)

```text
GS-0 Product contract and release boundary
├── GS-0.1 Criteria, feature tree, manifest, handoff protocol
├── GS-0.2 Shipped/prototype/quarantined/deferred inventory
└── GS-0.3 Linux-first install, diagnostics, and release gates

GS-1 Engagement foundation
├── GS-1.1 Program import and normalized scope/rules
├── GS-1.2 Automation policy, approvals, budgets, stops
├── GS-1.3 Identity/session/vault references
├── GS-1.4 Audit ledger and provider disclosure
└── GS-1.5 SQLite operational state + immutable artifact boundary

GS-2 Traffic and attack-surface foundation
├── GS-2.1 Proxy/browser/import capture
├── GS-2.2 Normalized request corpus and semantic search
├── GS-2.3 Asset/endpoint/security graph
├── GS-2.4 Mutation/replay/semantic comparison
└── GS-2.5 Continuous discovery and change detection

GS-3 Adaptive hunt engine
├── GS-3.1 Observation and hypothesis contracts
├── GS-3.2 Immutable plans and evidence contracts
├── GS-3.3 Policy-gated bounded execution
├── GS-3.4 Result interpretation and state update
├── GS-3.5 Explainable dual-queue scheduler
├── GS-3.6 Coverage matrix and negative knowledge
├── GS-3.7 Finding-adjacent expansion and chain search
└── GS-3.8 Pause/resume/diminishing-return stops

GS-4 Capability slices
├── GS-4.1 SSRF vertical slice (finish first)
├── GS-4.2 Broken access control / IDOR vertical slice
├── GS-4.3 Critical server-side injection vertical slice
├── GS-4.4 Browser/client-side capability pack
└── GS-4.5 GraphQL/API capability pack

GS-5 Evidence and reporting
├── GS-5.1 Immutable bundle writer and manifest
├── GS-5.2 Deterministic result promotion
├── GS-5.3 Human verification runbooks
├── GS-5.4 Root-cause grouping and per-asset evidence
├── GS-5.5 Bounty-ready report drafts
└── GS-5.6 Replay and regression verification

GS-6 Operator and agent surfaces
├── GS-6.1 Versioned local API
├── GS-6.2 Thin CLI
├── GS-6.3 Expert TUI
├── GS-6.4 Learning presentation profile
├── GS-6.5 Built-in AI client
└── GS-6.6 External-agent typed client contract

GS-7 Consolidation and release
├── GS-7.1 Classify every legacy crate: retain/adapt/quarantine/delete
├── GS-7.2 Remove duplicate policy, HTTP, finding, and orchestration paths
├── GS-7.3 Align README/docs with tested reality
├── GS-7.4 Offline end-to-end campaign gauntlet
├── GS-7.5 Performance/reliability/security audits
└── GS-7.6 Reproducible package/container/release artifacts

GS-8 Full recon-to-exploit capability packs
├── GS-8.1 Passive recon and OSINT (DNS, CT, archives, code/search sources)
├── GS-8.2 Active service discovery and fingerprinting
├── GS-8.3 Web/API/browser vulnerability families
├── GS-8.4 Authentication, authorization, and business-logic testing
├── GS-8.5 Infrastructure and native-protocol auditing
├── GS-8.6 Cloud, container, and orchestration security
├── GS-8.7 Mobile, artifact, binary, and client analysis
├── GS-8.8 Controlled exploitation and impact confirmation
├── GS-8.9 Post-exploitation enumeration and cleanup (explicit pentest policy only)
└── GS-8.10 External-tool interoperability (for example Nuclei and mature ecosystem workers)
```

GS-8 is not permission to bolt the old binaries back onto the product unchanged. Each pack must implement the common capability contract: observations consumed/produced, hypotheses generated, executable actions, risk and authorization metadata, budgets/stops, identity/secret needs, evidence contract, verification, cleanup, result mapping, and operator/API exposure.

## 7. Execution order

Do not fan out across the entire tree. Advance one executable spine:

1. **GS-4.1 SSRF completion:** immutable evidence/result → vulnerable/secure/blocked/repeat E2E → local API/persistence checkpoint → thin CLI → old SSRF/OOB classification.
2. **GS-1.5 + GS-6.1:** stabilize SQLite/artifact and versioned local API boundaries from real SSRF transitions.
3. **GS-4.2 IDOR:** prove multi-identity/tenant corpus, replay, comparison, evidence, runbook, and report through the same engine.
4. **GS-4.3 critical injection:** prove the third capability family without weakening policy/evidence contracts.
5. **GS-3 adaptive loop:** scheduler, coverage, finding-adjacent expansion, and resume over the three proven capabilities.
6. **GS-2 + GS-6 browser/operator path:** capture/import, traffic exploration, manual replay, expert TUI, and learning profile.
7. **GS-5 reporting:** root-cause grouping, minimized proofs, report drafts, replay/regression.
8. **GS-7 consolidation:** merge old and new work behind the common engine contract, quarantine only what cannot yet meet it, remove proven duplicates, align docs, and run the first-release offline campaign and release gates.
9. **GS-8 capability expansion:** migrate the best legacy recon/testing/exploitation behavior pack-by-pack, then add missing pentest depth through the same contracts. A pack advances only when it composes with campaign state, policy, evidence, reporting, and cleanup; a standalone binary demo is not completion.

A parent passes only when its required children pass and a parent-level integration verifier confirms their composition.

## 8. Model-agnostic artifact layout

Create after criteria/tree sign-off:

```text
docs/gauntlet/
├── README.md
├── criteria.md
├── feature-tree.md
├── manifest.md
├── HANDOFF.md
├── decisions-needed.md
├── summary.md
├── specs/
├── spec-scorecards/
├── implementation-briefs/
├── implementation-scorecards/
├── run-logs/
├── gap-reports/
└── schemas/
    ├── manifest.schema.json
    └── scorecard.schema.json
```

`README.md` explains the protocol without naming a model vendor. `HANDOFF.md` is the only restart entry point and must stay short enough to read first.

## 9. Manifest state machine

Each feature row contains:

```text
feature_id | parent | owner | state | spec_iteration | implementation_iteration |
spec_path | spec_scorecard | implementation_brief | implementation_scorecard |
last_verified_commit | last_commands | blocker | next_action | updated_at
```

Allowed states:

```text
pending
→ spec-in-progress
→ spec-review
→ spec-remediation-1|2|3
→ spec-pass|escalated
→ implementation-in-progress
→ implementation-review
→ implementation-remediation-1|2|3
→ slice-pass|escalated
→ integration-review
→ complete
```

Only a verifier may write a `*-pass` state. The implementation agent may never grade its own work. `complete` requires a parent/integration review when the feature has siblings or callers.

## 10. Per-slice loop

### Phase A — Baseline

1. Read the authoritative inputs and active handoff.
2. Confirm clean/known git state with `git status --short --branch`.
3. Run the smallest existing tests that exercise the slice.
4. Record current behavior, failing gaps, relevant files, and exact baseline commands in `run-logs/{feature-id}-baseline.md`.
5. Never “fix while discovering.” Baseline first.

For any feature with a legacy implementation, the baseline must also produce a salvage record:

```text
legacy paths | demonstrated behavior | tests/fixtures | algorithms/data worth keeping |
safety defects | duplicate owners | missing engine contracts | proposed disposition |
retain unchanged (rare) | adapt | merge | quarantine | delete after replacement
```

No rewrite starts until this record identifies what old work should be carried forward and what acceptance test will prove parity or intentional improvement.

### Phase B — Spec generation

1. A spec agent copies the universal spec template.
2. It states target behavior first, then current gap, exact architecture placement, contracts, failure states, performance budgets, tests, safety alignment, and open decisions.
3. It distinguishes implemented/prototyped/planned/quarantined/absent.
4. It cites actual source paths and tests.
5. It writes only `specs/{feature-id}.md` and updates its manifest fields.

### Phase C — Blind spec review

1. A fresh agent reads criteria, feature tree, spec, and actual referenced source.
2. It grades every criterion, applies auto-fails, checks feasibility, and writes `spec-scorecards/{feature-id}.md`.
3. On fail, another fresh remediation agent changes only the spec according to Priority 1 findings.
4. Repeat blind review, maximum three remediations; then write `gap-reports/{feature-id}-spec-escalation.md` and stop that branch.

### Phase D — Implementation brief

After spec pass, an owner writes `implementation-briefs/{feature-id}.md` with:

- approved spec and scorecard hashes;
- exact files expected to change;
- one behavior-first test at a time;
- RED command and expected failure;
- minimal GREEN change;
- focused and affected-package commands;
- repository-wide gate required at the slice boundary;
- migration/rollback and cleanup rules;
- explicit non-goals;
- artifact/output paths;
- restart checkpoint after every task.

No agent implements from an unapproved spec.

### Phase E — Behavior-first implementation

For each atomic task:

1. Add one failing behavior test.
2. Run it and save the observed failure summary.
3. Implement the minimum behavior.
4. Run the focused test.
5. Run affected-package tests and clippy.
6. Inspect `git diff --check` and changed-file scope.
7. Update the implementation brief checkbox and `HANDOFF.md` immediately.
8. Do not commit unless Jeff explicitly requests commits.

### Phase F — Blind implementation review

A fresh verifier must:

1. Read approved spec, criteria, implementation brief, source diff, and tests.
2. Re-run focused acceptance tests itself.
3. Attempt at least one adversarial case for each relevant auto-fail boundary.
4. Check sibling call paths for the same flaw.
5. Confirm docs describe tested state honestly.
6. Write `implementation-scorecards/{feature-id}.md` with command/output summaries and exact remediation.

A source review without execution cannot pass a slice.

### Phase G — Remediation

1. Fresh remediation agent receives only the approved spec, failing scorecard, current diff, and relevant source/tests.
2. It fixes Priority 1 items only, unless a Priority 2 item is inseparable.
3. Fresh verifier reruns the entire implementation review.
4. Maximum three loops; then escalate with unresolved criteria, evidence, attempted fixes, and decision options.

### Phase H — Integration and closure

1. Run the parent integration test or campaign benchmark.
2. Run repository gates.
3. Verify manifest/handoff/docs against source.
4. Classify replaced legacy paths.
5. Mark slice pass; mark parent complete only after composition review.
6. Generate the next slice’s baseline task—never leave `next_action` blank.

Legacy disposition rules:

- **Retain:** already satisfies the common contracts and quality gates.
- **Adapt:** useful implementation becomes a worker/client behind engine-owned policy, state, and evidence.
- **Merge:** overlapping tools contribute tested primitives into one capability pack; duplicate public paths are deprecated.
- **Quarantine:** useful but unsafe, shallow, unintegrated, or outside the current release; keep source/history discoverable with an explicit migration issue.
- **Delete:** only after replacement parity is demonstrated or the inventory proves no unique behavior remains. Record the replacement test and decision.

## 11. Required command tiers

Commands run from the repository's `crates/` directory unless noted.

### Atomic task

```bash
cargo fmt -p <affected-package> -- --check
cargo test -p <affected-package> <focused-test-filter>
cargo clippy -p <affected-package> --all-targets -- -D warnings
cd .. && git diff --check
```

### Slice boundary

```bash
cd crates
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --tests --locked -- -D warnings
cd ..
git diff --check
```

### Product/release boundary

```bash
cd crates
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --tests --locked -- -D warnings
cargo audit --deny warnings
cd ..
docker compose -f tests/target/docker-compose.yml up -d --wait
bash tests/integration/pipeline-smoke.sh
docker compose -f tests/target/docker-compose.yml down -v
docker build -t geistscope:gauntlet .
git diff --check
```

A future final campaign command should replace the generic smoke test as soon as GS-4.1 exposes the real engine through a thin client. Until implemented, the expected command belongs in the SSRF spec and cannot be claimed as passing.

## 12. SSRF first-run brief

Resume at `.hermes/plans/2026-07-31_ssrf-vertical-slice/PLAN.md:244`.

1. Implement Task 4.3: immutable evidence bundle and result promotion failure behavior.
2. Implement Task 5.1: vulnerable, secure, blocked, and repeat-run integration benchmark.
3. Run Design Checkpoint 4 using observed campaign state transitions to choose local API and SQLite boundaries.
4. Implement one thin CLI client with stable versioned JSON.
5. Run Design Checkpoint 5 and classify `mg-webscan ssrf` plus `mg-oob` as adapter/quarantine/delete.
6. Update README claims only after the new path passes.

SSRF acceptance requires:

- vulnerable: exactly one probe, one matching callback, one verified finding;
- secure: exactly one probe, no callback, negative test, no finding;
- blocked: zero target requests, zero callbacks, blocked/invalid result;
- repeat: new token and new immutable bundle, no overwrite;
- all outputs under engagement root;
- evidence write failure prevents verification;
- no model configured;
- no Internet access.

## 13. HANDOFF.md contract

Every agent must update `docs/gauntlet/HANDOFF.md` before stopping, even after failure. It contains exactly:

```markdown
# GeistScope Gauntlet Handoff

Current feature:
Current state:
Current owner role:
Last completed action:
Last verified commit/worktree state:
Commands run and outcomes:
Files changed:
Artifacts produced:
Known failures/blockers:
Decision required (or none):
Exact next action:
Exact next command:
Do not redo:
```

Rules:

- Describe observed facts, not hidden reasoning.
- Include paths and command outcomes, not “tests pass.”
- If a command was not run, say `NOT RUN`.
- If the worktree is dirty, list intentional files and pre-existing files separately.
- Never include secrets or raw target data.
- `Exact next action` must be executable by a context-free agent.
- On restart, trust neither the handoff nor manifest blindly: re-run git status and the last focused verification command.

## 14. Role prompts

### Orchestrator

```text
Read this plan, HANDOFF.md, manifest.md, criteria.md, and feature-tree.md. Select only the next unblocked feature. Dispatch one role at a time. Never let an author verify its own artifact. Advance manifest state only from files and executed gates. Stop for criteria/tree sign-off or after a third remediation failure. Before stopping, ensure HANDOFF.md has an exact next action and command.
```

### Spec agent

```text
Write one complete target-state spec from the approved criteria and actual source. Use the universal SPEC-TEMPLATE. Distinguish implemented, prototyped, planned, quarantined, and absent. Cite paths. Do not implement. Do not grade your own spec. Update the manifest and handoff.
```

### Implementation agent

```text
Implement only the approved spec and implementation brief. Work behavior-first: observe RED, implement minimal GREEN, run focused and affected-package gates, then update the checkpoint. Do not broaden scope, change criteria, self-approve, commit, or claim commands you did not run.
```

### Verification agent

```text
Blind-review the artifact against every criterion and auto-fail. Read actual source and tests. For implementation review, execute the focused acceptance commands and adversarial safety checks yourself. Cite file paths and command outcomes. Write actionable Priority 1 remediation. You may not edit the artifact under review.
```

### Remediation agent

```text
Read the approved spec, failing scorecard, current artifact/diff, and relevant source. Fix Priority 1 failures without unrelated refactors. Re-run focused gates. Do not self-approve. Update handoff with exact outcomes and next verification command.
```

## 15. Initial setup tasks after sign-off

### Task 1: Materialize the confirmed protocol

**Objective:** Create project-local gauntlet artifacts from this approved plan.

**Files:**
- Create: `docs/gauntlet/README.md`
- Create: `docs/gauntlet/criteria.md`
- Create: `docs/gauntlet/feature-tree.md`
- Create: `docs/gauntlet/manifest.md`
- Create: `docs/gauntlet/HANDOFF.md`
- Create: `docs/gauntlet/decisions-needed.md`
- Create directories listed in Section 8

**Verification:** A context-free agent can identify current feature, state, next action, next command, and grading contract by reading only `docs/gauntlet/README.md` then `HANDOFF.md`.

### Task 2: Seed the manifest from current reality

**Objective:** Mark GS-4.1 as implementation-in-progress and all unproven branches pending.

**Files:**
- Modify: `docs/gauntlet/manifest.md`
- Modify: `docs/gauntlet/HANDOFF.md`

**Verification:** No feature is marked passed solely from README claims; completed SSRF subtasks link to actual tests/source and remaining tasks link to the 2026-07-31 plan.

### Task 3: Generate and blind-review the final SSRF completion spec

**Objective:** Convert the accepted SSRF change spec plus current implementation state into the gauntlet template and grade it before further code changes.

**Files:**
- Create: `docs/gauntlet/specs/GS-4.1-ssrf.md`
- Create: `docs/gauntlet/spec-scorecards/GS-4.1-ssrf.md`

**Verification:** Spec passes all four lenses and explicitly covers Task 4.3, Task 5.1, local API/persistence, thin CLI, and pruning.

### Task 4: Resume SSRF with immutable evidence

**Objective:** Implement the first failing acceptance behavior from Task 4.3 under the approved spec.

**Files:** Determine exact paths by tracing `hunt-engine` evidence/result symbols and `evidence-core` usages before editing.

**Verification:** Follow the focused TDD commands specified by the implementation brief, then the slice commands in Section 11.

## 16. Risks and controls

- **Risk: 83-crate breadth consumes the project.** Control: first inventory all legacy value, then migrate in release-ordered capability packs. A crate need not ship in the first release to survive, but it must have a clear disposition and eventual common-contract path.
- **Risk: rewrite discards useful old work.** Control: mandatory salvage records, parity fixtures, algorithm/test extraction, and deletion only after verified replacement.
- **Risk: universal spec scores become paperwork.** Control: implementation pass requires executed local acceptance evidence and adversarial checks.
- **Risk: agents overwrite each other.** Control: one active implementation owner per feature, manifest owner field, serialized integration, and fresh read of git status.
- **Risk: stale docs become false authority.** Control: explicit authority order and shipped/prototype/quarantine/deferred inventory.
- **Risk: model-specific orchestration.** Control: all state, prompts, commands, schemas, and outputs live in Markdown/JSON files; any tool-capable model can assume a role.
- **Risk: self-review bias.** Control: separate author/verifier roles and fresh review context.
- **Risk: endless remediation.** Control: three attempts, then evidence-rich escalation.
- **Risk: broad benchmark imitation.** Control: benchmark capability floors, not UI cloning; differentiation remains the adaptive evidence loop.

## 17. User checkpoints

The loop pauses for Jeff only at:

1. Approval or edits to Sections 4–6 (criteria, auto-fails, feature tree).
2. Product/architecture decisions explicitly listed in `decisions-needed.md`, beginning with SSRF local API/persistence.
3. Any feature that fails three spec or implementation remediation loops.
4. Any proposal to expand v1 into destructive, evasive, persistence, post-exploitation, live-target, or hosted-service behavior.

Everything else is autonomous and restartable from files.

## 18. Completion definition

GeistScope’s first releasable adaptive-hunting spine is finished only when:

- SSRF, IDOR, and critical injection each pass vulnerable/secure/blocked offline benchmarks through the same engine.
- A campaign imports/collects traffic, creates hypotheses, schedules bounded tests, updates persistent hunt state, expands around a finding, records coverage/negative knowledge, and resumes safely.
- Deterministic evidence contracts produce reproducible findings/runbooks/reports without a model.
- CLI/TUI/external agent paths are thin clients of one versioned local API.
- Routine supported traffic inspection/mutation/replay can be completed without Burp.
- Legacy breadth is classified as retain/adapt/merge/quarantine/delete, useful old behavior has explicit migration targets, and misleading shipped-state claims are removed.
- Workspace fmt/build/test/clippy/audit, Docker smoke/final campaign, and image build pass.
- A fresh agent follows `docs/gauntlet/README.md` + `HANDOFF.md`, reruns verification, and reaches the same state without this conversation.

The full GeistScope suite is finished only when, in addition:

- Recon results flow into the same persistent asset/request/security model rather than ending as disconnected scanner output.
- Supported web, API, authz, infrastructure, cloud/container, artifact/mobile, and controlled exploitation packs satisfy the common capability contract and have vulnerable/secure/blocked local benchmarks appropriate to their risk.
- Pentest-only impact confirmation and post-exploitation steps require explicit engagement permission, least-impact proofs, cleanup/rollback, immutable evidence, and separate release/policy gates.
- An end-to-end local lab campaign proves program/scope intake → recon → surface model → hypothesis selection → safe exploitation → deterministic verification → evidence/report → cleanup/resume across multiple capability packs.
- Old and new implementations have converged on one engine, policy authority, evidence model, persistence boundary, and versioned API; compatibility adapters are bounded and documented rather than permanent parallel architectures.

## Sources

[1] https://portswigger.net/burp/documentation/desktop — Burp Suite documentation: desktop editions - PortSwigger
[2] https://docs.caido.io — Caido Documentation
[3] https://docs.projectdiscovery.io/tools/nuclei/overview — Nuclei Overview - ProjectDiscovery Documentation
[4] https://docs.projectdiscovery.io/cloud/introduction — Introducing ProjectDiscovery - ProjectDiscovery Documentation
[5] https://www.zaproxy.org/docs/desktop — ZAP Desktop User Guide
[6] https://docs.mitmproxy.org/stable/overview/features — mitmproxy Features
[7] https://owasp.org/www-project-web-security-testing-guide/stable — OWASP Web Security Testing Guide stable
