# GeistScope Git-Native Archive and Active-Branch Reduction Plan

Status: proposed; non-mutating plan only
Date: September 22, 2026
Decision authority: `docs/PRODUCT_RECOVERY_DECISIONS.md`

## Purpose

Preserve the broad GeistScope workspace as an immutable, browsable Git-native legacy snapshot, including the pre-interview uncommitted prototypes and plans except for the two Gauntlet paths explicitly excluded by the user decision recorded in Section A. Then reduce active `main` to the approved manual-first web/API authorization learning repository.

This plan does not authorize any Git state change by itself. It is the review artifact required before creating branches, commits, tags, removals, or remote updates.

## Accepted direction

The active product during the 12-week learning phase is not an operator-ready security platform.

Active `main` must contain only:

- public technical documentation;
- the web/API authorization learning curriculum;
- decision records;
- synthetic fixtures; and
- future tiny exercises that pass the approved three-case admission gate.

The broad Rust workspace, scanner inventory, harness, TUI, active-testing code, CI/product scaffolding, legacy plans, and tool claims move out of active `main` and remain available only through the legacy snapshot.

## Baseline observed on September 22, 2026

- `main` and `origin/main` both point to `7de5cfa` (`documentation update`, August 20, 2026).
- The worktree contains tracked modifications, a tracked deletion, untracked Rust prototypes, legacy plans/evaluations, and the newly created recovery/learning documentation.
- The current workspace does not have a passing frozen build gate. The active reduction must not describe the old workspace as working or supported.

The worktree recorded on September 22, 2026 had three logical groups:

1. Legacy workspace and pre-interview prototypes
   - tracked modifications under `crates/`;
   - untracked `crates/campaign-core/`, `crates/mg-engine/`, and `crates/mg-observe/`;
     `crates/gauntlet-output/` was also present at the September 22 baseline but
     is excluded from the future snapshot by the later user decision in Section A;
   - legacy `.hermes` plans and `docs` evaluations/MVP material;
   - legacy source, tests, CI, Docker, and repository tooling.

2. Active learning/recovery documentation
   - `docs/PRODUCT_RECOVERY_DECISIONS.md`;
   - `docs/WEB_API_AUTHORIZATION_LEARNING_TRACK.md`;
   - `docs/learning/web-api-authorization/`;
   - this archive/reduction plan.

3. Unclassified local session data
   - `.sessions`.

## Non-negotiable safety rules

- Do not use `git reset --hard`, `git clean`, force-push, history rewriting, or a broad deletion before a named snapshot branch and tag exist locally.
- Do not push any branch, tag, or commit without a separate explicit approval.
- Do not stage `.sessions` into the public repository. Its contents and publication suitability are unclassified. Preserve it separately in a user-controlled private local backup before any worktree cleanup or branch switch that could threaten it.
- Do not try to repair, format, regenerate, or otherwise improve legacy code during the archive operation. The archive preserves evidence; it is not a cleanup pass.
- Do not add new product code, test fixtures derived from real activity, or tool capabilities during this operation.

## Target Git references

The implementation should create these local references only after approval:

```text
recovery/staging-2026-09-22
archive/geistscope-pre-reduction-2026-09-22
geistscope-pre-reduction-2026-09-22
recovery/reduced-main-2026-09-22
```

Reference roles:

- `recovery/staging-2026-09-22`
  - reconciled in-scope pre-reduction staging commit, excluding `.sessions` and the two Section A paths;
  - temporary safety reference retained until the user explicitly decides otherwise.

- `archive/geistscope-pre-reduction-2026-09-22`
  - permanent browsable legacy branch pointing to the staging snapshot;
  - no further feature work or maintenance.

- `geistscope-pre-reduction-2026-09-22`
  - annotated local tag pointing to the exact same snapshot commit;
  - human-readable immutable recovery marker.

- `recovery/reduced-main-2026-09-22`
  - proposed narrow active tree for review;
  - `main` remains unchanged until the user reviews this branch and explicitly authorizes a fast-forward merge.

## Exact path classification

### A. Preserve in the legacy snapshot

The snapshot must preserve the exact current state of all remaining legacy repository material, including modifications and untracked prototypes existing before the recovery interview, subject to the explicit exclusions below.

Tracked legacy material:

```text
.dockerignore
.github/
.hermes/
.pre-commit-config.yaml
Dockerfile
crates/
docs/AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md
tests/
resume-commands (preserve its current deleted state in the snapshot commit)
```

All additional tracked root material not explicitly retained below is legacy material and remains in the snapshot, subject to the exclusions below.

Pre-interview untracked legacy material:

```text
.hermes/plans/2026-09-02_adaptive-hunt-engine-bootstrap/
crates/campaign-core/
crates/mg-engine/
crates/mg-observe/
docs/ADAPTIVE_HUNT_ENGINE_EVALUATION.md
docs/GEISTSCOPE_SUITE_INTEGRATION_EVALUATION.md
docs/MVP.md
```

**Explicit user decision (October 11, 2026):** `docs/gauntlet/` and
`crates/gauntlet-output/` are intentionally discarded by this narrow cleanup
and must not be restored to or promised in the future legacy snapshot. The
generated `crates/gauntlet-output/` directory was verified to contain only 13
regular Markdown experiment artifacts before deletion. Their absence is
intentional, not an incomplete preservation pass.

The snapshot may also contain copies of the recovery documentation because it is an exact pre-reduction commit. Those copies do not alter the active-branch authority described below.

### B. Keep on the proposed reduced active branch

```text
LICENSE
.gitignore (rewritten for a documentation/fixture repository)
README.md (rewritten to describe the learning repository accurately)
docs/ARCHIVE_REDUCTION_PLAN.md
docs/PRODUCT_RECOVERY_DECISIONS.md
docs/WEB_API_AUTHORIZATION_LEARNING_TRACK.md
docs/learning/web-api-authorization/
fixtures/README.md (new synthetic-fixture policy and placeholder)
```

### C. Explicitly exclude from public Git history during this operation

```text
.sessions
```

Before execution, copy `.sessions` to a user-controlled private location and verify the copy. Do not inspect or publish its contents as part of the archive operation. Its absence from the snapshot is a deliberate data-safety exception, not data loss.

### D. Remove from the proposed reduced active branch after snapshot creation

```text
.dockerignore
.github/
.hermes/
.pre-commit-config.yaml
Dockerfile
crates/
tests/
docs/AUTONOMOUS_HUNTING_PROGRESS_CHECKLIST.md
docs/ADAPTIVE_HUNT_ENGINE_EVALUATION.md
docs/GEISTSCOPE_SUITE_INTEGRATION_EVALUATION.md
docs/MVP.md
resume-commands
```

The final reduction pass must use a generated allowlist based on section B rather than relying on this abbreviated removal list. The allowlist prevents an old tool claim, Cargo manifest, CI workflow, or legacy plan from being left active by mistake.

## Commit boundaries

### Commit 1: reconciled pre-reduction staging snapshot

Branch: `recovery/staging-2026-09-22`

Intent:

- capture all in-scope tracked legacy changes and pre-interview untracked prototypes/plans, subject to the explicit exclusions in Section A;
- capture the recovery/learning docs already written in this interview;
- preserve the current deleted state of `resume-commands`;
- exclude `.sessions` from Git.

Suggested message:

```text
recovery: preserve reconciled pre-reduction workspace snapshot
```

Before committing, the operator must inspect the staged path list and confirm that `.sessions` and both Section A exclusions are absent and every remaining in-scope legacy prototype is present.

### Commit 2: proposed active-branch reduction

Branch: `recovery/reduced-main-2026-09-22`, created from Commit 1.

Intent:

- remove the broad workspace and product scaffolding from the active branch;
- retain only the approved documentation and synthetic-fixture paths;
- rewrite root repository positioning;
- add `fixtures/README.md`;
- update `.gitignore` to reject accidental private workspace/notebook material;
- remove legacy tool and product readiness claims instead of soft-deprecating them.

Suggested message:

```text
recovery: narrow active branch to authorization learning curriculum
```

`main` is not updated during this step.

### Promotion to `main`

Only after user review of the proposed reduced branch and successful verification:

```text
main --fast-forward--> recovery/reduced-main-2026-09-22
```

This fast-forward is a separate explicit approval. No force update and no remote push are part of this plan.

## Proposed execution sequence after approval

### Phase 0: preflight and private-data protection

1. Re-read current `git status --short --branch` and compare it to this plan.
2. Confirm `.sessions` is still the only unclassified local session path.
3. Copy `.sessions` to a user-controlled private backup location outside the repository.
4. Verify the backup by comparing file counts and checksums without revealing contents.
5. Record the backup destination only in private session context, never in public repository documentation.
6. Abort if new unclassified target data, credentials, or local artifacts appear.

### Phase 1: create the staging snapshot

1. Create `recovery/staging-2026-09-22` from the current worktree.
2. Stage all intended tracked and untracked repository paths except `.sessions` and the explicit Section A exclusions.
3. Inspect the full staged name list, diff statistics, and whitespace check.
4. Confirm the three remaining untracked Rust prototypes (`campaign-core`, `mg-engine`, and `mg-observe`) and all listed legacy plans/evaluations are staged; confirm both Section A exclusions are absent.
5. Commit the snapshot.
6. Create `archive/geistscope-pre-reduction-2026-09-22` and annotated tag `geistscope-pre-reduction-2026-09-22` at that exact commit.
7. Verify branch/tag SHA equality and verify that the snapshot contains the Cargo workspace and legacy plans.

### Phase 2: build the proposed reduced branch

1. Create `recovery/reduced-main-2026-09-22` from the staging snapshot.
2. Generate a tracked-path allowlist from section B.
3. Remove every tracked path outside the allowlist, excluding Git metadata and the unclassified `.sessions` directory.
4. Create `fixtures/README.md` that permits only synthetic, secret-free, non-target fixture material.
5. Replace root `README.md` with a concise statement of:
   - manual-first web/API authorization learning focus;
   - controlled labs/CTF only during the current phase;
   - documentation/fixtures-only active branch;
   - legacy code available through the named archive reference;
   - no operator-ready product claim.
6. Replace `.gitignore` with a minimal active-branch policy that guards against accidental notebook, engagement, session, credential, raw-evidence, and local-build artifacts. It must not silently ignore synthetic fixtures intended for version control.
7. Remove all Rust Cargo manifests, CI workflows, Docker files, scanner/harness/TUI source, old gauntlet material, and legacy product claims from active `main` candidate.
8. Do not add a replacement CI pipeline until code exists. Documentation link validation is the only active verification need initially.

### Phase 3: verify the reduced branch

Run all checks on `recovery/reduced-main-2026-09-22`:

```bash
# Git identity and archive integrity
git rev-parse recovery/staging-2026-09-22
git rev-parse archive/geistscope-pre-reduction-2026-09-22
git rev-parse geistscope-pre-reduction-2026-09-22
git diff --exit-code recovery/staging-2026-09-22 archive/geistscope-pre-reduction-2026-09-22

# Active tree is genuinely narrow
git ls-files | sort
! git ls-files | grep -E '^(crates/|tests/|\.github/|\.hermes/|Dockerfile$|\.dockerignore$|\.pre-commit-config\.yaml$)'
! git ls-files | grep -E '(mg-hunt|mg-harness|mg-tui|mg-proxy|Cargo\.toml|Cargo\.lock)'

# Required active documentation exists
test -f README.md
test -f LICENSE
test -f fixtures/README.md
test -f docs/ARCHIVE_REDUCTION_PLAN.md
test -f docs/PRODUCT_RECOVERY_DECISIONS.md
test -f docs/WEB_API_AUTHORIZATION_LEARNING_TRACK.md
test -f docs/learning/web-api-authorization/README.md

# Public docs have no broken local Markdown links
python3 - <<'PY'
from pathlib import Path
import re

root = Path('.').resolve()
for source in root.rglob('*.md'):
    for target in re.findall(r'\]\(([^)#]+\.md(?:#[^)]+)?)\)', source.read_text()):
        relative = target.split('#', 1)[0]
        resolved = (source.parent / relative).resolve()
        if root not in resolved.parents and resolved != root:
            raise SystemExit(f'{source}: link escapes active repository: {target}')
        if not resolved.exists():
            raise SystemExit(f'{source}: missing Markdown target: {target}')
print('all active relative Markdown links resolve')
PY

# Git hygiene
git diff --check recovery/staging-2026-09-22..HEAD
git status --short
git fsck --full
```

The link-validation command is intentionally local-only and verifies every relative Markdown link among active documentation without network access.

### Phase 4: human review and promotion decision

Present to Jeff:

1. archive branch/tag names and exact SHA;
2. full reduced-branch `git diff --stat` and changed path list;
3. final root README;
4. active tracked-file list;
5. verification output;
6. the private `.sessions` backup verification result without disclosing its content.

Do not update `main`, push, or delete any local reference until Jeff explicitly approves the promotion.

## Rollback plan

Before promotion:

- `main` remains untouched at its original commit.
- The staging branch and archive branch/tag retain the same reconciled in-scope snapshot, with both Section A exclusions absent.
- Delete only the proposed reduced branch if the review rejects it; do not delete the snapshot references.

After a local fast-forward promotion to `main`:

- restore the prior state by switching to the staging or archive snapshot and creating a new corrective branch;
- prefer a new revert/recovery commit over history rewriting;
- never force-push or delete the archive branch/tag as part of rollback.

## Acceptance criteria for implementation approval

The archive/reduction operation is ready to execute only when all are true:

- [ ] `.sessions` has a verified private backup and is absent from Git staging.
- [ ] The staging snapshot contains every listed in-scope legacy path and pre-interview prototype/plan; both Section A exclusions remain absent by decision.
- [ ] Archive branch and annotated tag resolve to the exact staging snapshot SHA.
- [ ] The reduced branch contains only the section-B allowlist plus intentionally added synthetic-fixture documentation.
- [ ] No `Cargo.toml`, `Cargo.lock`, `crates/`, `tests/`, `.github/`, Docker, harness, TUI, scanner, proxy, or legacy gauntlet path remains active.
- [ ] Root README makes no release, operational, autonomous, or tool-support claim.
- [ ] All active relative Markdown links resolve locally.
- [ ] `git diff --check` and `git fsck --full` pass.
- [ ] `main` and all remotes remain unchanged pending a separate explicit promotion approval.

## Deferred work after reduction

Do not attach any of this to the archive operation:

- building a Rust replacement workspace;
- creating a SQLite database, TUI, proxy, AI harness, or automation;
- importing private notebook cases into the repository;
- publishing an `mg-server` retrospective;
- restoring any legacy tool;
- creating a public real-target workflow.

The only next active work is the approved 12-week manual authorization curriculum. Any later code must satisfy the documented three-case, one-page user-approved admission gate.
