# Decisions Needed

An explicit architecture/review-series decision blocks the active slice.

## Recorded decision: descriptor-chain authority successor series

Date: 2026-08-20

Root-locator iteration 3/3 was rejected at committed snapshot `cd4e708f1c20e5bcb275eaaf6d1f575f724c9c4d` and scoped fingerprint `8dc08ba5a3f1e2515175a347f4658e8315b02eb88d21418de12cb2ec34ede618`. The final blind verdict contained zero Critical and two Important findings: the public legacy writer still follows a symlinked authority root through pathname publication, and `ArtifactStore::atomic_bytes_write` can continue through an already-open intermediate directory after it is moved outside the retained engagement root.

The user explicitly authorized a separately named strict-TDD descriptor-chain authority series and requested atomic deployable commits. This successor must begin with public RED regressions for both findings, route or harden the legacy writer without weakening compatibility, retain and revalidate every authority-bearing ancestor descriptor through publication, add no dependency/lockfile drift, and restart blind review at iteration 1.

This is not root-locator remediation 4. Each independently deployable RED/GREEN slice must pass its focused and affected-crate gates before an atomic commit.

## Recorded decision: successor to exhausted nonblocking-reader series

Date: 2026-08-13

The nonblocking-reader successor series exhausted remediation 3/3. Final exact fingerprint `47a4db57bb965c14e73f8c3c1c29e15b1e432c97a32a7cc34fce2dd78405ee0c` was rejected with no Critical and one Important finding: `EvidenceBundleWriter` and `engagement::ArtifactStore` canonicalize the caller-supplied engagement root before no-follow opening, so a terminal root symlink is followed. The FIFO production and bounded-harness work passed review.

The user explicitly authorized a new strict-TDD series preserving the approved architecture. It begins with public regressions requiring `EvidenceBundleWriter`, `EvidenceBundleReader`, and `engagement::ArtifactStore` to reject the original caller-supplied root locator when it is a symlink, before canonicalization or descriptor opening. Existing FIFO production and bounded-harness work remains cumulative rejected implementation to be reviewed afresh.

This is a separately authorized series beginning at iteration 1, not successor remediation 4.

## Recorded decision: successor to exhausted content-addressed implementation series

Date: 2026-08-13

The content-addressed implementation series exhausted remediation 3/3. Final exact fingerprint `992e70cc1aa3de163a048b3e765e074c883e77e088deb0e91d324dd306a69fd1` was rejected because authority-bearing manifest and artifact opens can block indefinitely on FIFO locators before regular-file validation. No Critical findings remained, but the Important availability/safety defect prevents downstream promotion.

The decision prompt timed out with authorization to use best judgment. The integration owner selected the lowest-churn safe option: authorize a new strict-TDD implementation series preserving the approved content-addressed architecture. The successor series begins with target-correct nonblocking opens and bounded manifest/artifact FIFO regressions on macOS and Linux, then restarts exact-fingerprint blind review at iteration 1.

This preserves public contracts and avoids dependency/lockfile churn. Replacing the syscall layer remains the escalation path if the new series exposes a broader abstraction defect. Deferral remains available if the successor series fails.

No content-addressed remediation 4 is permitted under the exhausted series; all successor edits and reviews belong to a separately authorized series.

## Recorded decision: content-addressed evidence identity

Date: 2026-08-13

The dependency-free writer reset series exhausted remediation 3/3. Final exact fingerprint `bf384dcf6998ec9f3a5a716a531d7cca8ac2e85b2005aefd89395b35cfa5bea5` was rejected because same-user mutation or rename remains possible after final verification and before return. The decision prompt timed out, so the integration owner selected the conservative local-first default: authoritative identity is the manifest digest, paths are locators, and every authority-bearing consumer must derive results from bounded descriptor-held bytes verified against manifest/artifact digests and lengths.

The accepted architecture is recorded in `docs/gauntlet/implementation-briefs/GS-4.1-content-addressed-evidence-identity.md`. GS-4.1 spec iteration 4 incorporates it and requires a fresh exact-SHA PASS before a new implementation series begins. This is not reset remediation 4.

## Recorded decision: evidence-writer review-series reset

Date: 2026-08-13

The pre-reset remediation-3 snapshot was rejected after three Important defects were confirmed. The integration owner selected the lowest-churn safe default: a new strict-TDD series using dependency-free target-specific FFI. That reset decision is historical and is now superseded by the reset-series exhaustion above.

## Upcoming checkpoint: SSRF local API and persistence

Trigger: after the immutable evidence writer and vulnerable/secure/blocked/repeat benchmark pass.

Decision inputs must be observed campaign state transitions, not speculative endpoint design. Compare at least:

- in-process engine API plus SQLite repository;
- local HTTP/Unix-socket service owning state and workers;
- versioning, crash recovery, concurrent-client semantics, migration strategy, and Linux-first packaging.

The implementation owner may recommend a default. Record the selected boundary here before implementing GS-1.5/GS-6.1.

## Upcoming checkpoint: legacy SSRF/OOB disposition

Trigger: after the thin engine client passes.

Inventory is complete in `docs/gauntlet/run-logs/GS-4.1-legacy-ssrf-oob-salvage.md`. After replacement parity, choose final retain, adapt, merge, quarantine, or delete-after-replacement dispositions for `mg-hunt` SSRF, `mg-webscan` SSRF, `oob-core`, `mg-oob`, and SSRF authority in replay-engine/replay-runner. Deletion is forbidden without demonstrated replacement parity or proof that no unique behavior remains.
