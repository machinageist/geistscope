# GS-4.1 Generic Evidence Writer — Remediation-Limit Escalations

Date: 2026-08-13
State: BLOCKED after remediation cycle 3/3
Rejected exact staged fingerprint: `5e6061dcc7b263c2bd1908b5ca65ad4c9ee19e5d8efcab6c2385f1c31068c4c8`
Staged scope:

- `crates/evidence-core/src/lib.rs`
- `docs/gauntlet/run-logs/GS-4.1-generic-evidence-writer.md`

Do not commit this fingerprint. The findings below remain live in the exact staged source. The completion protocol forbids a fourth blind-remediation cycle without escalation and an explicit architecture/reset decision.

## Important findings

### 1. Linux `openat` creation flags are Darwin constants

Current source uses `O_CREAT = 0x0200` and `O_EXCL = 0x0800` in the shared macOS/Linux `write_relative_create_new` branch. Those are Darwin values. Linux requires `O_CREAT = 0x40` and `O_EXCL = 0x80`.

Impact:

- On Linux, a new artifact file is opened without Linux `O_CREAT`.
- Generic evidence publication can fail with `ENOENT` before writing the first file.
- macOS-only tests cannot prove the supported Linux path.

Required reset work:

1. Use target-specific constants or a reviewed platform abstraction.
2. Add Linux CI/runtime coverage that creates and publishes a nested generic bundle.
3. Re-run ABI/constants review for every target-specific syscall flag.

### 2. Identity-check failures bypass staging quarantine

After staging exists, both descriptor/path identity checks can return `UnsafePath` directly rather than routing through `quarantine_staging`:

- immediately after the test/swap hook;
- immediately before exclusive promotion.

Impact:

- A concurrent same-user rename/symlink swap can leave a `.staging-*` directory outside the pathname currently visible to the process.
- The contract requires no `.staging-*` residue: failed staging must be removed or explicitly quarantined with cleanup failure observable.
- The current swap regression proves no escaped final publication but does not prove cleanup/quarantine of the displaced staging directory.

Required reset work:

1. Route every post-staging failure through descriptor-relative quarantine.
2. Add a regression that inventories the original and displaced parent trees and proves zero `.staging-*` names remain.
3. Surface quarantine rename or parent-sync failure without claiming cleanup.

### 3. The 32 MiB bundle ceiling excludes `manifest.json`

Pre-write validation sums only caller-supplied artifact bytes. The writer serializes and writes `manifest.json` afterward without adding its byte length to the complete-bundle total.

Impact:

- A request at the advertised 32 MiB artifact limit publishes a bundle larger than 32 MiB.
- The run log and public constant describe a complete-bundle limit that implementation does not enforce.

Required reset work:

1. Define whether the ceiling covers all published regular-file bytes or only supplied artifacts. The current gauntlet contract requires all published bytes.
2. Serialize the prospective manifest during validation or perform checked total accounting before filesystem creation.
3. Add exact-boundary tests for artifact bytes plus manifest bytes: one byte at/under succeeds; one byte over fails before creating `evidence/`.

## Verified unaffected behavior

The active macOS gates remain green:

- `cargo test -p evidence-core --locked` — 20 passed.
- `cargo check -p evidence-core --all-targets --locked` — passed.
- `cargo clippy -p evidence-core --all-targets --locked -- -D warnings` — passed.
- `cargo fmt -p evidence-core -- --check` — passed.
- `cargo test -p mg-hunt --locked` — 16 passed.
- `cargo test -p mg-evidence --locked` — 1 passed.

These green checks do not override the cross-platform, cleanup, or accounting defects.

## Decision required

Choose one before further production edits:

1. **Reset implementation review with an approved fourth remediation cycle.** Keep the dependency-free FFI design, add target-specific flags, descriptor-relative cleanup coverage, and complete-byte accounting; then restart blind review at iteration 1 of a new explicitly authorized review series.
2. **Replace the syscall layer with a reviewed capability/filesystem abstraction.** Approve dependency and lockfile changes first, preserve the public writer API, and restart TDD/review as a new implementation approach.
3. **Defer Linux support.** This is incompatible with the current Linux-first release requirement unless the specification and release criteria are explicitly changed and approved.

Until a decision is recorded, Task 4.3 implementation remains blocked and the staged writer snapshot must not be committed.

## Content-addressed-series exhaustion

Date: 2026-08-13
State: BLOCKED after content-addressed-series remediation 3/3
Rejected exact fingerprint: `992e70cc1aa3de163a048b3e765e074c883e77e088deb0e91d324dd306a69fd1`
Rejected scope:

- `crates/evidence-core/src/lib.rs`
- `crates/engagement/src/artifact_store.rs`
- `docs/gauntlet/run-logs/GS-4.1-generic-evidence-writer.md`

The content-addressed architecture correctly demoted paths to locators and made the externally supplied manifest digest authoritative. Iterations 1 and 2 remediated root-symlink following, noncanonical manifest paths, reader metadata semantics, writer/reader content-type mismatch, and macOS `ArtifactStore` FIFO blocking. Final iteration 3 passed the recorded macOS and Linux aarch64 test/check/strict-Clippy/format gates but received `REQUEST_CHANGES` with one Important finding and no Critical findings.

### Residual blocking special-file open

`EvidenceBundleReader::read_relative_bounded` opens `manifest.json` and artifact members with blocking `O_RDONLY | O_NOFOLLOW` and checks `metadata().is_file()` only after `openat` returns. A FIFO substituted at either the manifest or artifact locator can therefore block indefinitely before verification can reject it. The separate macOS `engagement::ArtifactStore` path already demonstrates the required ordering by applying `O_NONBLOCK` before its regular-file check; the content-addressed reader does not.

Impact:

- authority-bearing bundle verification can hang indefinitely on both macOS and Linux;
- the 16 MiB/32 MiB byte bounds do not help because execution blocks before bounded reading begins;
- policy, promotion, replay, API, or report consumers cannot safely depend on this reader.

Required work for any explicitly authorized successor series:

1. apply target-correct nonblocking semantics before regular-file validation for manifest and artifact opens;
2. add bounded regressions for FIFO substitution at both `manifest.json` and nested artifact locators on macOS and Linux;
3. re-audit sockets, devices, and other special files before read allocation;
4. rerun the full exact-fingerprint blind review from iteration 1 of a newly authorized series.

The rejected fingerprint is unstaged and uncommitted. A blocked reviewer attempt that performed no inspection did not consume an iteration; the subsequent completed review did. No content-addressed remediation 4 is authorized.

## Nonblocking-reader successor-series exhaustion

Date: 2026-08-13
State: BLOCKED after successor remediation 3/3
Rejected exact fingerprint: `47a4db57bb965c14e73f8c3c1c29e15b1e432c97a32a7cc34fce2dd78405ee0c`

The separately authorized successor series fixed and independently validated nonblocking manifest/artifact opens and fully deadline-bounded FIFO regressions. Its final blind review nevertheless found one remaining Important cumulative defect: `EvidenceBundleWriter` and `engagement::ArtifactStore` canonicalize the caller-supplied engagement root before applying no-follow descriptor opens. A terminal root symlink is therefore followed. `EvidenceBundleReader` already rejects the original root locator before opening it, demonstrating the required fail-closed ordering.

Impact:

- writer publication and policy-facing `ArtifactStore` reads can be redirected through a caller-supplied symlinked engagement root;
- later `O_NOFOLLOW` checks protect the resolved target, not the supplied locator;
- trustworthy evidence publication, policy use, and typed result promotion remain blocked.

The final fingerprint is unstaged and uncommitted. No successor remediation 4 is authorized.

## Reset-series exhaustion

Date: 2026-08-13
State: BLOCKED after reset-series remediation 3/3
Rejected exact fingerprint: `bf384dcf6998ec9f3a5a716a531d7cca8ac2e85b2005aefd89395b35cfa5bea5`

The explicitly authorized reset series also exhausted its three-remediation limit. Its final independent review confirmed the exact two-file scope and unchanged fingerprint, reran all native gates successfully, and returned `REQUEST_CHANGES` with one Important finding.

### Residual check-to-return mutation window

The final snapshot retains every nested-directory and artifact/manifest descriptor and revalidates path identity, file length, and descriptor-read SHA-256 before and after exclusive promotion. However, files remain owner-writable and descriptor-opened read/write. After final verification finishes, the writer synchronizes the candidate directory and returns. A same-user process can still rename/replace the published directory or modify an artifact, including `manifest.json`, between final verification and return. Parent `sync_all` provides durability but does not revalidate identity or contents.

Impact:

- Success does not guarantee that returned paths still identify the verified bundle at the instant of return.
- Repeating path verification cannot eliminate the final check-to-use window; it only moves it.
- This is the same integrity class as the reset iteration-2 nested-directory replacement defect.

Verified unaffected behavior for the rejected fingerprint:

- `evidence-core` — 27 passed.
- all-target check — passed.
- strict Clippy — passed.
- formatting — passed.
- `mg-hunt` — 16 passed.
- `mg-evidence` — 1 passed.
- Linux aarch64 author gates — 27 tests/check/strict Clippy/formatting passed.

Do not commit this fingerprint. No reset remediation 4 is authorized. Choose and record a new architecture before production edits resume.

## Current decision required

1. **Change the trust/immutability contract.** Define atomic publication as immutable against writer-mediated overwrite and path races, but explicitly exclude arbitrary same-user post-publication mutation. Update the approved spec and acceptance criteria, then begin a new review series.
2. **Move evidence ownership across an OS-enforced trust boundary.** Use a dedicated service/account, privileged helper, sandbox, read-only filesystem snapshot, or equivalent mechanism so the calling same-user process cannot mutate published evidence. This changes packaging and operations and requires a new architecture/spec review.
3. **Use a content-addressed object store plus signed/verified bundle identity.** Return immutable content identities rather than promising pathname stability; consumers must reopen and verify by digest. This changes the public contract and typed-promotion design and requires a new spec/review series.
4. **Defer production evidence publication.** Keep the current implementation as rejected experimental work, block typed result promotion, and proceed only with independent work that does not depend on trustworthy evidence publication.
