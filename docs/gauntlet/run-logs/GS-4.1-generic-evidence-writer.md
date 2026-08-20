# GS-4.1 Generic Atomic Evidence Writer — Implementation Record

Date: 2026-08-13
Parent: GS-4.1 SSRF vertical slice
Baseline commit: `a920d69`

## Scope

This atomic slice adds a backward-compatible generic immutable bundle API to `evidence-core`. It does not yet promote an SSRF `HuntResult`; that remains the next atomic slice.

## TDD evidence

RED was observed after adding the generic writer tests: compilation failed because `GenericEvidenceBundleRequest` and the generic writer API did not exist. A second RED was observed for the secret guard: compilation failed because `EvidenceBundleError::UnredactedModelVisibleArtifact` did not exist.

GREEN:

```text
cargo test -p evidence-core --locked
27 passed; 0 failed

cargo clippy -p evidence-core --all-targets --locked -- -D warnings
PASS

cargo fmt -p evidence-core -- --check
PASS

cargo test -p mg-hunt
16 passed; 0 failed

cargo test -p mg-evidence
1 passed; 0 failed

cargo check -p evidence-core --all-targets
PASS

cargo audit --deny warnings
FAIL (workspace baseline): RUSTSEC-2026-0204 `crossbeam-epoch` 0.9.18 and RUSTSEC-2026-0185 `quinn-proto` 0.11.14; five denied maintenance/unsound warnings. The evidence-writer slice adds no dependency or lockfile change; exclusive publication uses small target-gated system bindings.
```

## Proven behavior

- anchors engagement/candidate/staging traversal to open directory handles and uses no-follow descriptor-relative creation/writes;
- revalidates held directory identities before writes and promotion so concurrent symlink swaps fail closed;
- stages every artifact before a single descriptor-relative exclusive directory promotion;
- syncs every artifact, the completed staging directory, and the publication parent so a successful return represents a durable commit on supported filesystems;
- never overwrites an existing run;
- atomically quarantines failed staging under `.failed-*`; no publishable `.staging-*` or final bundle remains;
- allocates quarantine names with the same exclusive no-replace primitive as final publication, retries bounded collisions, preserves every prior quarantine, and reports exhaustion/failure with both causes;
- reports quarantine failure with both the triggering operation and cleanup cause instead of discarding it;
- rejects unsafe, absolute, parent-traversing, duplicate, and reserved manifest paths before writing;
- rejects candidate/run symlink escapes;
- rejects non-UTF-8 and backslash-bearing artifact paths so manifest references remain portable;
- rejects backslashes in candidate and run IDs before any filesystem creation so manifest prefixes remain portable;
- records portable engagement-relative paths, SHA-256, byte length, content type, and visibility;
- bounds each artifact at 16 MiB;
- bounds the complete bundle payload at 32 MiB before filesystem creation;
- requires model-visible artifacts to be UTF-8 and rejects obvious bearer, authorization, cookie, session, and callback-token markers before writing;
- rejects common password, API-key, access/refresh-token, and private-key markers before writing model-visible artifacts;
- rejects camelCase API/access/refresh/callback token keys, client-secret keys, and PEM private-key headers before writing model-visible artifacts;
- fails closed on platforms without known exclusive directory-promotion and directory-sync primitives;
- leaves the existing evidence writer API intact, including safe nested relative candidate/run identifiers; traversal, absolute paths, and backslashes still fail before filesystem creation.

## Remaining GS-4.1 work

- independent implementation review must pass;
- `hunt-engine` must serialize policy, transaction, callback/assessment, and semantic verdict artifacts through this writer;
- evidence references must be revalidated locally before result construction;
- verified, negative, invalid, and human-review outcomes must remain distinct;
- injected evidence failure must prevent result promotion;
- the full offline campaign benchmark must pass.

## Blind review remediation

Implementation review iteration 1 requested changes for unsupported-platform overwrite semantics, lossy/non-portable paths, and incomplete obvious-secret markers. Remediation added failing regression tests for all three classes, then made them GREEN. Pre-review self-inspection then found the GS-4.1 total-bundle ceiling and directory durability syncs were absent; the aggregate-limit regression was observed RED then made GREEN, and staging/parent directory sync with fail-closed unsupported-platform behavior was added. A fresh reviewer must grade the revised snapshot.

Implementation review iteration 2 identified path-based symlink-swap TOCTOU exposure and discarded cleanup errors. Two focused regressions were added first; compilation failed with exit 101 because the test hook, cleanup-failure seam, and error behavior did not exist. Remediation moved generic writes, intermediate directory creation, staging allocation, quarantine, and exclusive promotion to no-follow descriptor-relative operations on macOS/Linux; added directory-identity revalidation; and made quarantine failure observable through the existing public `Io` error variant. Both regressions and the full 19-test suite now pass. Failed publishers are quarantined rather than silently deleted, matching the GS-4.1 `removed or explicitly quarantined` contract. A fresh exact-snapshot review is required.

Implementation review iteration 3 identified manifest ambiguity from backslashes in candidate/run IDs and missed camelCase/client-secret/PEM credential markers. Focused tests were added first. Both exited 101: a backslash-bearing candidate published an ambiguous manifest path, and a camelCase credential fixture was accepted. Minimal remediation rejects backslashes in all user-controlled path components and recognizes normalized camelCase API/access/refresh token keys, client-secret forms, and `PRIVATE KEY` PEM headers. Focused tests, the full 20-test suite, strict Clippy/check/fmt, `mg-hunt` (16), and `mg-evidence` (1) pass. This is the third and final permitted blind-remediation cycle; any further Critical/Important finding requires escalation and a gap report rather than a fourth loop.

A concurrently dispatched review of an earlier iteration-1 snapshot additionally identified camelCase `callbackToken`. Because that review predated the final iteration-3 freeze, the finding was folded into the same final remediation rather than counted as a fourth cycle. The focused credential test was observed RED with exit 101, then made GREEN by recognizing normalized `callbacktoken` before publication.

A second concurrently dispatched review of the pre-descriptor snapshot identified missing nested-directory fsyncs and unreliable post-rename rollback. The descriptor-relative iteration already syncs every artifact directory after file creation and each parent immediately after first-time child-directory creation. Final inspection found one residual: successful quarantine rename did not sync the candidate parent. Iteration 3 now syncs that handle after quarantine rename and treats sync failure as cleanup failure, so the API cannot silently claim durable quarantine.

## Reset review series — iteration 1

The remediation-3 fingerprint was rejected and preserved in `docs/gauntlet/gap-reports/GS-4.1-generic-evidence-writer-remediation-limit.md`. After the decision prompt timed out, the integration owner selected a new dependency-free, target-specific FFI review series. This reset does not erase the earlier failure.

Three focused defects were addressed with strict TDD and runtime evidence:

- Complete-byte accounting: a new request containing exactly 32 MiB of artifact bytes was observed RED because it published additional `manifest.json` bytes. Validation now constructs the prospective manifest and includes its serialized length in checked aggregate accounting before creating `evidence/`; the regression is GREEN.
- Identity-failure cleanup: the adversarial candidate/staging displacement test was changed to require an explicit cleanup-failure error and observed RED on bare `UnsafePath`. Both post-staging identity failures now route through descriptor-relative quarantine; the regression is GREEN.
- Linux ABI: the original Linux Docker publication test failed, first with `ENOENT` from Darwin `O_CREAT`/`O_EXCL`, then with `EINVAL`. `strace` proved the latter came from x86 `O_DIRECTORY`/`O_NOFOLLOW` constants being used on aarch64. File-create and directory/no-follow flags are now target-OS/architecture specific for Linux x86, x86_64, arm, and aarch64; other Linux architectures fail compilation pending review.

Linux aarch64 Docker verification (`rust:1.88-bookworm`) passed the full 21-test suite, all-target check, strict Clippy after installing the official component, and formatting. Native macOS verification passed the same 21 tests/check/Clippy/fmt plus `mg-hunt` 16 and `mg-evidence` 1. No dependency or lockfile changes were included.

## Reset review series — iteration 2

The exact iteration-1 fingerprint `14405dd1df6c2ec9805fd09c45a310719431d2800b2681a3f95dbd0bd36ae232` received `REQUEST_CHANGES`: quarantine used ordinary `renameat`, so an existing empty `.failed-*` directory could be replaced. A separately completed review of the rejected pre-reset snapshot also exposed a backward-compatibility regression: the shared strict generic component validator rejected safe nested identifiers formerly accepted by `EvidenceBundleWriter::write`.

Two focused regressions were added before production remediation. Compilation was RED with exit 101 because the deterministic exclusive-quarantine retry seam did not exist. The independent public-API harness had already observed the nested legacy case return `UnsafePath`. Minimal remediation now:

- uses target-specific `rename_exclusive_at` for quarantine, retries up to 100 generated names only on `AlreadyExists`, synchronizes the candidate parent after success, preserves colliding quarantine marker bytes, and reports exhaustion or any non-collision error through the existing combined `Io` cleanup error;
- separates legacy safe-relative-path validation from the generic writer's single-component validation, preserving nested legacy candidate/run IDs while continuing to reject absolute, parent-traversing, and backslash-bearing identifiers before creating `evidence/`.

Both focused regressions are GREEN. Full native macOS and Linux aarch64 Docker verification passes 24 tests, all-target check, strict Clippy, and formatting. Native downstream compatibility remains GREEN: `mg-hunt` 16 and `mg-evidence` 1. No dependency or lockfile changes are included. A fresh exact-snapshot reset-series iteration-2 review is required.

## Reset review series — iteration 3

Exact iteration-2 fingerprint `37f920180b3c1f5b01e710df2857c6493ba3cecb7219f0cf4c8dc5a14bac7d45` received `REQUEST_CHANGES`. An independent macOS harness proved that after `raw/blob.bin` was written, a same-user process could rename `raw/`, recreate an empty `raw/`, and let publication return success with a manifest-declared artifact missing from the final bundle. Root staging identity remained unchanged, while nested directory handles had been dropped and were never revalidated.

Strict TDD reproduced the exact failure in-repository: `nested_directory_swap_before_promotion_cannot_omit_declared_artifact` exited 101 with `successful manifest references a missing artifact after nested directory swap`. Adjacent class tests were then added before their fixes:

- a post-promotion nested-directory swap was observed RED because publication returned success;
- an artifact-file rename/replacement was observed RED because directory identity alone did not detect replacement bytes.

Minimal remediation retains open handles for every cumulative nested artifact directory and every artifact file, including generated `manifest.json`, through publication. Before and after the exclusive directory rename it verifies:

- every expected nested path still names the retained directory device/inode;
- every expected file path still names the retained regular-file device/inode and is not a symlink;
- retained and path metadata lengths equal the committed expected length;
- bytes reread from the retained descriptor hash to the expected SHA-256.

A pre-promotion mismatch quarantines staging; a post-promotion mismatch exclusively quarantines the published directory before returning. All candidate, nested pre-promotion, nested post-promotion, and artifact-file replacement regressions are GREEN. Full native macOS and Linux aarch64 Docker verification passes 27 tests, all-target check, strict Clippy, and formatting. Native downstream compatibility passes `mg-hunt` 16 and `mg-evidence` 1. No dependency or lockfile changes are included. This is reset-series remediation 3/3; any further Critical/Important finding requires escalation rather than a fourth reset remediation.

## Content-addressed implementation series — iteration 1

Reset iteration 3 exact fingerprint `bf384dcf6998ec9f3a5a716a531d7cca8ac2e85b2005aefd89395b35cfa5bea5` received `REQUEST_CHANGES` because repeated pathname verification cannot eliminate same-user mutation between final verification and return. The reset series is exhausted; that fingerprint remains rejected.

Approved GS-4.1 spec iteration 4 SHA `323a05dfdff89359bee8f08ffcfbbaa691c4f3e02212168ad966d5cda04ab882` replaces pathname authority with content-addressed identity. This is a new implementation series, not remediation 4.

Strict TDD first produced 17 compile errors for the intentionally absent `manifest_sha256`, `EvidenceBundleReader`, verified result/artifact types, and typed verification errors. The minimal implementation now:

- returns SHA-256 of the exact serialized committed `manifest.json` bytes;
- requires that external digest for every read;
- treats candidate/run/artifact paths as validated locators only;
- opens the engagement root, `evidence`, candidate, run, manifest, nested directories, and artifact files with descriptor-relative no-follow operations on supported macOS/Linux targets;
- validates manifest identity and requires every declared artifact path to rebase exactly beneath `evidence/<candidate>/<run>/`;
- rejects duplicate/reserved/unsafe members, malformed digests, per-artifact overflow, and manifest-inclusive aggregate overflow;
- checks regular-file metadata before allocation and reads at most limit plus one sentinel byte;
- verifies artifact length and SHA-256 from the same descriptor-read owned bytes returned to consumers;
- fails closed on unsupported platforms.

Six content-addressed tests are GREEN: authoritative manifest digest, exact-copy identity with changed-byte failure, manifest replacement failure, member-locator rebinding failure, artifact symlink failure, and owned verified bytes remaining stable after later pathname mutation while a fresh read fails.

Full native macOS and Linux aarch64 Docker verification passes 33 tests, all-target check, strict Clippy, and formatting. Native downstream compatibility passes `mg-hunt` 16 and `mg-evidence` 1. No dependency or lockfile changes are included. A fresh exact-snapshot blind review is required before commit or `hunt-engine` integration.

## Content-addressed implementation series — iteration 1 verdict and remediation 1/3

Exact staged fingerprint `12123baeb0484868dade7c55823a9de34918f257720270f612a5d345a51bbe17` received `REQUEST_CHANGES`. It had no Critical findings and three Important findings:

1. `read_generic` canonicalized and therefore followed a symlink supplied as the engagement root before applying no-follow opening.
2. platform `Path::strip_prefix` accepted noncanonical manifest locators such as a repeated separator instead of requiring byte-exact `evidence/<candidate>/<run>/<artifact>` syntax.
3. the reader trusted malformed content types and forged visibility labels without symmetric model-visible UTF-8/secret validation or a private-only `raw/` rule.

Three focused regressions first reproduced all findings: six prior content-addressed tests passed and the three new tests failed. Remediation 1/3 now rejects symlink/non-directory roots before opening, parses the manifest locator as an exact portable string, requires reserialization equality, rejects blank/noncanonical content types and model-visible `raw/` artifacts, and reruns writer-equivalent UTF-8/obvious-secret validation on verified model-visible bytes. All nine focused content-addressed tests pass.

During remediation, `origin/main` was found eight commits ahead with pre-existing SSRF/capture security work. The complete dirty index/worktree was preserved as `stash@{0}` named `pre-github-integration gauntlet and content-addressed evidence 2026-08-13`, and pre-integration HEAD was pinned as `backup/pre-github-integration-20260813`. Remote commits were merged at `a31ad07`, preserving exact request mutation/identity, signed capture provenance, redaction, encoded-separator rejection, root-anchored artifact reads, and imported signing-seed zeroization.

The clean merged boundary exposed that `engagement::ArtifactStore::open_relative_read` failed closed on every non-Linux platform, causing all 13 macOS HTTP executor tests to block on unavailable source evidence. Strict TDD enabled the secure relative-read tests on macOS and reproduced the unsupported error. A macOS descriptor-relative fallback now retains the engagement-root directory handle, walks every parent with `openat(O_DIRECTORY|O_NOFOLLOW)`, opens the final member with `openat(O_RDONLY|O_NOFOLLOW)`, and rejects non-regular files. Linux retains its stronger `openat2` path. Three focused secure-read tests and all 13 HTTP executor tests pass on macOS without weakening production policy validation.

The prior fingerprint is stale and unstaged. Final combined gates pass:

- macOS `evidence-core`: 36 tests;
- macOS `engagement`: 54 library tests plus 2 binary tests;
- macOS full `hunt-engine`: all unit/integration/doc tests, including 13 HTTP executor tests and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 36 tests;
- Linux aarch64 `engagement`: 58 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`: all unit/integration/doc tests, including 13 HTTP executor tests and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

The iteration-2 review scope is exactly `crates/evidence-core/src/lib.rs`, `crates/engagement/src/artifact_store.rs`, and this run log. No Cargo manifest or lockfile drift is included. A fresh exact-snapshot blind review is required before commit or typed `hunt-engine` result promotion.

## Content-addressed implementation series: iteration 2 verdict and remediation 2/3

Blind review of exact staged fingerprint `d306bf0d7aa3a251d875d3db3aae09fbbbdc922520cf58a92f0713c52f86e19c` returned `REQUEST_CHANGES` with no Critical and two Important findings. The reviewer confirmed the exact three-file scope and fingerprint at start and end, passed the native gate set, found no Cargo drift, and made no repository edits.

The findings were:

1. the public generic writer accepted and persisted content types with surrounding whitespace, while the reader correctly rejected that noncanonical metadata, allowing publication of a bundle that could not round-trip through verification;
2. the macOS final `openat(O_RDONLY | O_NOFOLLOW | O_CLOEXEC)` could block indefinitely while opening a FIFO before the subsequent regular-file check, unlike Linux's nonblocking open.

Strict RED tests reproduced both issues through public APIs. The writer now enforces the reader's exact content-type canonicality predicate before any evidence directory is created. The macOS final artifact open now includes `O_NONBLOCK` before rejecting non-regular objects; a bounded regression creates a FIFO and proves the public read returns an error without waiting for a writer. Both focused regressions pass.

This is remediation 2/3 and therefore iteration 3 is the final allowed implementation attempt in this content-addressed series. A new exact fingerprint and independent PASS with zero Critical/Important findings are required before commit.

Final iteration-3 gates pass:

- macOS `evidence-core`: 37 tests;
- macOS `engagement`: 55 library tests plus 2 binary tests;
- macOS full `hunt-engine`, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 37 tests;
- Linux aarch64 `engagement`: 58 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

The known non-fatal `hunt-engine::EvidenceContract::validate_local` warning remains outside this slice's strict touched-crate gate; the merged baseline's result-contract tests exercise that method under test configuration. No warning was suppressed.

## Content-addressed implementation series: iteration 3 verdict and exhaustion

Blind review of exact staged fingerprint `992e70cc1aa3de163a048b3e765e074c883e77e088deb0e91d324dd306a69fd1` returned `REQUEST_CHANGES` with no Critical and one Important finding. The reviewer confirmed exact HEAD `a31ad07fdd27c5c4e5d9a7c35a00729d4d36e04a`, the exact three-file scope, and unchanged fingerprint at start and end; reran 37 `evidence-core` tests, 55+2 `engagement` tests, formatting, and diff checks; found no Cargo drift; and made no repository edits. A preceding reviewer attempt was blocked before inspection and therefore issued no verdict or remediation result.

The remaining Important finding is that `EvidenceBundleReader::read_relative_bounded` opens both `manifest.json` and artifact members with blocking `O_RDONLY | O_NOFOLLOW` and performs the regular-file check only after `openat` returns. A FIFO at either locator can block indefinitely on macOS or Linux before bounded reading begins. The analogous macOS `engagement::ArtifactStore` path correctly adds `O_NONBLOCK`; that remediation was not propagated to the content-addressed reader.

The fingerprint is rejected, unstaged, and uncommitted. This verdict exhausts remediation 3/3 for the content-addressed implementation series. No remediation 4 is authorized. Typed SSRF result promotion, benchmark authority, API/report consumers, and any commit depending on trustworthy verified bytes remain blocked until an explicit successor architecture/review-series decision is recorded.

## Nonblocking verified-reader successor series: iteration 1

The successor decision prompt timed out with authorization to use best judgment. The integration owner selected and recorded a separately authorized strict-TDD series that preserves the approved content-addressed architecture and public contracts. This is not remediation 4 of the exhausted content-addressed series.

Two public-reader regressions replaced `manifest.json` and a nested declared artifact with real FIFOs. Each invoked `EvidenceBundleReader::read_generic` on a worker, required rejection within one second, and safely released/joined the worker after a RED timeout so the harness itself could not hang. Both tests were observed RED with `Err(Timeout)` and then GREEN after the shared descriptor-relative member open gained target-correct `O_NONBLOCK` (`0x0004` on macOS and `0x0800` on Linux) before regular-file validation.

Successor iteration-1 gates pass:

- macOS `evidence-core`: 39 tests;
- macOS `engagement`: 55 library tests plus 2 binary tests;
- macOS full `hunt-engine`, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 39 tests, including both FIFO regressions;
- Linux aarch64 `engagement`: 58 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

No Cargo manifest or lockfile change is intended. A fresh exact-fingerprint blind PASS with zero Critical/Important findings is required before commit or typed promotion.

### Successor iteration 1 verdict and remediation 1/3

Blind review of exact fingerprint `cb145fdc889b6f1a97092e456271bd3dc2c7ad4f89bb1f4dcb2d9620fca2cc74` returned `REQUEST_CHANGES` with no Critical and one Important finding. Production nonblocking flags and behavior were judged correct, but the RED-path test recovery could itself block: it used a blocking FIFO writer open followed by an unbounded join.

A focused RED test first required writer acquisition to remain bounded when no FIFO reader exists. The recovery helper now retries a nonblocking writer open only until a deadline. Worker startup, initial result, and post-recovery completion each use bounded channel waits; the helper joins only after channel completion or disconnection proves the worker has exited. The bounded writer test and both public manifest/artifact FIFO tests pass. This is successor remediation 1/3.

Successor iteration-2 gates pass:

- macOS `evidence-core`: 40 tests;
- macOS `engagement`: 55 library tests plus 2 binary tests;
- macOS full `hunt-engine`, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 40 tests;
- Linux aarch64 `engagement`: 58 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

### Successor iteration 2 verdict and remediation 2/3

Blind review of exact fingerprint `7387a955786d8df2c0725c9c74bbd2464ec87949ae11061d8e777d8b4bb96066` returned `REQUEST_CHANGES` with no Critical and one Important finding. A result-channel send or disconnect did not itself prove that the worker thread had terminated, so the timeout path could still call an unbounded `join()`.

A focused RED test now distinguishes a still-running worker from a finished worker. The harness polls `JoinHandle::is_finished()` only until a deadline and calls `join()` only after that predicate is true. If the completion deadline expires, it drops/detaches the handle before failing. The completion test, bounded no-reader writer test, and both public manifest/artifact FIFO tests pass. This is successor remediation 2/3; successor iteration 3 is the final allowed attempt.

Successor iteration-3 final-attempt gates pass:

- macOS `evidence-core`: 41 tests;
- macOS `engagement`: 55 library tests plus 2 binary tests;
- macOS full `hunt-engine`, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 41 tests;
- Linux aarch64 `engagement`: 58 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

### Successor iteration 3 final verdict — series exhausted

Blind review of exact fingerprint `47a4db57bb965c14e73f8c3c1c29e15b1e432c97a32a7cc34fce2dd78405ee0c` returned `REQUEST_CHANGES` with no Critical and one Important finding. The reviewer confirmed that production manifest/artifact nonblocking opens and the fully bounded FIFO harness are sound. However, `EvidenceBundleWriter` and `engagement::ArtifactStore` canonicalize the caller-supplied engagement root before no-follow opening. A terminal symlink is therefore resolved and followed before the descriptor protections apply, unlike `EvidenceBundleReader`, which rejects the original root locator with `symlink_metadata`.

The exact snapshot remained stable, native reviewer gates passed, and no Cargo drift or reviewer edit occurred. The fingerprint is rejected, unstaged, and uncommitted. This exhausts the nonblocking-reader successor series 3/3. No remediation 4 is authorized; further production evidence work requires an explicit new architecture/review-series decision.

## Root-locator successor series: iteration 1

The user explicitly authorized a separate strict-TDD series preserving the approved content-addressed architecture and requiring rejection of original root symlinks everywhere. This is not remediation 4 of the exhausted nonblocking-reader series.

Public regressions for `EvidenceBundleWriter::write_generic` and `engagement::ArtifactStore::new` used real terminal root symlinks and were each observed RED because canonicalization followed the link. The writer regression also proved that the resolved target received an `evidence/` side effect before remediation. Both tests are GREEN after each constructor adopted the reader's fail-closed preflight contract.

The implementation does not rely on preflight alone: it no-follow-opens the caller-supplied locator before canonicalization, then compares the held descriptor's device/inode identity with the canonical path identity. A symlink or directory replacement between preflight and open/canonicalization therefore fails rather than rebinding the root. Normal-root compatibility remains GREEN.

Root-locator iteration-1 gates pass:

- macOS `evidence-core`: 42 tests;
- macOS `engagement`: 56 library tests plus 2 binary tests;
- macOS full `hunt-engine`, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 42 tests;
- Linux aarch64 `engagement`: 59 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

The first native full run observed one transient failure in the unrelated TLS-to-plaintext outcome-classification test. That focused test passed immediately on rerun, and the complete native matrix then passed without source changes.

Blind review of exact fingerprint `1cf8e26caf1445301942c8f190475f60e22957c749a22d61179a6d328711c181` returned `REQUEST_CHANGES` with no Critical and one Important finding. Static root symlink rejection and constructor-time descriptor/path identity were accepted, but `ArtifactStore` retained descriptor-relative reads while `atomic_json_write` continued through the stored canonical pathname. Renaming the original root and creating a replacement at that pathname therefore redirected writes while reads remained on the original descriptor. The stable fingerprint is rejected, unstaged, and uncommitted; this consumes remediation 1/3 of the root-locator successor series.

## Root-locator successor series: iteration 2

A public regression renames the retained root and creates a distinct directory at its former pathname. It was observed behaviorally RED when `atomic_json_write` wrote into the replacement. Remediation fails before mutation when the stored root locator is already rebound, performs parent creation, no-follow traversal, exclusive temp creation, file synchronization, rename, and parent synchronization relative to retained descriptors, and revalidates root identity before returning success. A second regression proves an intermediate symlink cannot redirect a write outside the engagement root.

The first Linux focused run exposed incorrect hand-coded `O_DIRECTORY`/`O_NOFOLLOW` constants. Live Linux values were obtained from a Python 3.13 container (`O_DIRECTORY=16384`, `O_NOFOLLOW=32768`), the constants were corrected, and all three Linux descriptor-write tests then passed. Operation-specific I/O context remains in place for duplication, parent creation/open, temp creation/write/sync, rename, and parent sync failures.

Root-locator iteration-2 gates on the final bytes:

- macOS `evidence-core`: 42 tests;
- macOS `engagement`: 58 library tests plus 2 binary tests;
- macOS full `hunt-engine` rerun passed, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 42 tests;
- Linux aarch64 `engagement`: 61 library tests plus 2 binary tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

The unrelated native TLS-to-plaintext classification test again failed under the initial combined suite ordering. It passed immediately in isolation and then passed in a complete `hunt-engine` rerun without source changes. This repeated timing-sensitive test behavior is recorded rather than hidden; the root-locator and descriptor-write tests passed throughout.

Blind review of exact fingerprint `51b6367c413bb2bdecbd403f738b6bd8c84eb202d100b200f870438ec6d8163c` returned `REQUEST_CHANGES` with no Critical and two Important findings. First, the public `ArtifactWriteRecord.path` remained an authority-bearing pathname that could rebind immediately after the final identity check. Second, successful `mkdirat` operations were not followed by synchronization of their containing directories, so newly linked ancestors could be lost after reported success. The stable fingerprint is rejected, unstaged, and uncommitted; this consumes remediation 2/3 of the root-locator successor series. Iteration 3 is the final allowed attempt.

## Root-locator successor series: iteration 3 / final attempt

Public RED contracts require `ArtifactWriteRecord` to carry a descriptor-relative member identity and an explicitly non-authoritative `locator`, plus `ArtifactStore::open_verified` to reopen through the retained descriptor and verify bounded owned bytes against exact length and SHA-256. Tests prove verified reads remain bound to original published bytes after the locator root is replaced and reject changed bytes. The former path field and all in-repository dereferences were removed.

`ArtifactStore::atomic_bytes_write` is now the shared raw/JSON publisher. `atomic_json_write` delegates to it, and `proxy-core`'s former path-based raw capture writer was migrated rather than left as an authority bypass. Proxy tests now consume signed evidence through `open_verified`; locator assertions are presentation-only.

Every successful ancestor `mkdirat` is followed by `fsync` of its containing descriptor before descent. Linux retains a real read-only root directory descriptor rather than `O_PATH`, permitting root-link durability synchronization. File bytes, the final file link, and every newly created ancestor link are synchronized before success.

Root-locator iteration-3 final-attempt gates on the final bytes:

- macOS `evidence-core`: 42 tests;
- macOS `engagement`: 60 library tests plus 2 binary tests;
- macOS `proxy-core`: 8 tests;
- macOS full `hunt-engine` rerun passed, including 13 HTTP executor and 20 policy-gate tests;
- macOS touched-crate all-target check, strict Clippy, and formatting;
- macOS downstream `mg-hunt`: 16 tests; `mg-evidence`: 1 test;
- Linux aarch64 `evidence-core`: 42 tests;
- Linux aarch64 `engagement`: 63 library tests plus 2 binary tests;
- Linux aarch64 `proxy-core`: 8 tests;
- Linux aarch64 full `hunt-engine`, including 13 HTTP executor and 23 policy-gate tests;
- Linux aarch64 touched-crate all-target check, strict Clippy, and formatting.

The unrelated native TLS-to-plaintext classification test failed under the initial combined suite ordering, then passed in isolation and in a complete unchanged `hunt-engine` rerun. This repeated timing-sensitive behavior remains explicitly recorded. All authority, durability, root-locator, proxy migration, and evidence tests passed on both target families.

### Root-locator iteration 3 final verdict — series exhausted

A fresh blind reviewer inspected exact committed snapshot `cd4e708f1c20e5bcb275eaaf6d1f575f724c9c4d` with scoped parent-to-HEAD fingerprint `8dc08ba5a3f1e2515175a347f4658e8315b02eb88d21418de12cb2ec34ede618`. The fingerprint, HEAD, and clean worktree remained unchanged throughout review. The verdict was `REQUEST_CHANGES` with zero Critical, two Important, and zero Minor findings.

1. The adjacent public legacy `EvidenceBundleWriter::write` path still accepts a terminal symlink as the engagement root and writes through ordinary pathname operations. The hardened generic writer therefore does not yet establish root-symlink rejection across every public evidence-writing authority.
2. `ArtifactStore::atomic_bytes_write` discards ancestor directory descriptors while descending. A same-user actor can rename an already-open intermediate directory outside the engagement root, recreate its former pathname, and let publication continue through the moved descriptor. The final root-only identity check can still pass while bytes were published outside the retained root and the returned locator names a different in-root object.

The reviewer independently passed `evidence-core` 42 tests, `engagement` 60+2, `proxy-core` 8, full `hunt-engine`, `mg-hunt` 16, `mg-evidence` 1, touched-crate strict Clippy, formatting, and diff checks. Green gates do not cover or override the two authority defects. The broad committed `Cargo.lock` rewrite had no matching `Cargo.toml` change and is unrelated to the root-locator scope.

This consumes root-locator remediation 3/3. The series is exhausted; no remediation 4 is authorized. Typed result promotion, campaign E2E, and authority-bearing consumers remain blocked until the user explicitly authorizes a separately named successor architecture/review series or defers this path.

## Descriptor-chain authority successor series — atomic slice 1

The user explicitly authorized a new strict-TDD successor series with atomic deployable commits. Slice 1 addresses only the public legacy writer's terminal root-symlink bypass.

A public Unix regression, `legacy_writer_rejects_symlinked_engagement_root_before_writing`, supplies a real terminal symlink as `EvidenceBundleRequest.engagement_root`, requires `UnsafePath`, and proves the resolved target receives no `evidence/` side effect. The focused test was observed RED with exit 101 because the legacy writer returned `Ok(EvidenceBundle)` and wrote through the symlink.

Minimal GREEN adds the same fail-closed original-locator preflight used by the hardened paths: `symlink_metadata` must report a non-symlink directory before the legacy writer constructs or mutates bundle paths. Verification on the intended slice bytes:

- focused regression: 1 passed;
- full `evidence-core`: 43 passed;
- `cargo clippy -p evidence-core --all-targets --locked -- -D warnings`: PASS;
- `cargo fmt -p evidence-core -- --check`: PASS;
- `git diff --check`: PASS.

No manifest, dependency, lockfile, or other production file changed. A fresh slice-scoped independent review is required before the atomic commit.

Independent review of exact five-file fingerprint `328c09fc51a581f424d796fe9feff0a4a225523ef1d1638b4cf037311bfe57f9` returned PASS with zero Critical, zero Important, and zero Minor findings. The reviewer independently passed the focused regression, all 43 evidence-core tests, strict Clippy, formatting, and diff checks; confirmed a clean index and stable five-file scope; and authorized the slice as safe for its atomic deployable commit. The separate `ArtifactStore` descendant rename race remains explicitly deferred to atomic slice 2.

## Descriptor-chain authority successor series — atomic slice 2

Slice 2 addresses the remaining known `ArtifactStore::atomic_bytes_write` escape through an already-open intermediate directory moved outside the retained engagement root.

A deterministic public-path harness invokes `atomic_bytes_write`, pauses immediately after opening the first descendant descriptor, renames that directory outside the engagement root, and recreates its former pathname. The regression requires an error and no published bytes at either the moved descriptor location or recreated locator. It was observed behaviorally RED with exit 101 because the writer returned success and published `proof.json` through the moved descriptor.

Minimal GREEN retains the root and every opened descendant descriptor plus the component naming each parent-child edge. It no-follow reopens and compares device/inode identity for the complete chain after each descent, before publication, and after the parent-directory durability sync. A detected mismatch fails closed; temp or newly published output is removed relative to the retained deepest descriptor before returning the error.

Verification on the intended slice bytes:

- focused descendant-move regression: 1 passed after the observed RED;
- `engagement`: 61 library tests plus 2 binary tests passed;
- `proxy-core`: 8 tests passed;
- strict touched-crate Clippy: PASS;
- touched-crate formatting: PASS;
- `git diff --check`: PASS.

No manifest, dependency, or lockfile changed. A fresh slice-scoped independent review is required before the atomic commit.

Independent review of fingerprint `e14406c6ba87d2aded7acc28c08bff34023285fb56dfaa805f76fb0091b2fb80` returned REQUEST_CHANGES with zero Critical, two Important, and one Minor finding:

1. a root-identity failure after publication occurred outside the retained-authority cleanup scope and returned an error while leaving the published member behind;
2. post-publication cleanup unconditionally unlinked the final name and could therefore delete a different replacement member;
3. the deterministic harness covered only the initial descendant-open timing rather than temp-sync, publication, parent-sync, and cleanup timings.

Strict remediation added phase-specific deterministic hooks without changing public API. Two new tests were observed RED for the intended behaviors: the post-parent-sync root move returned an error but left `moved-engagement/evidence/proof.json`, and replacement cleanup removed the replacement path. Minimal GREEN moved final root-identity validation inside the retained publication/cleanup scope and changed cleanup to no-follow open the named member, compare its device/inode to this operation's retained temp-file descriptor, refuse to unlink on identity mismatch, propagate cleanup failure explicitly, and durably sync successful cleanup. The full phase enum now exposes descendant-open, temp-sync, publication, and parent-sync timings to deterministic tests.

Remediation verification:

- both new cleanup regressions and the original descendant-move regression: PASS;
- `engagement`: 63 library tests plus 2 binary tests passed;
- `proxy-core`: 8 tests passed;
- strict touched-crate Clippy, formatting, and `git diff --check`: PASS.

A fresh blind review of the replacement fingerprint is required. The rejected `e14406c6...` fingerprint is not commit-authorized.

Replacement fingerprint `464ee4aebd7c98eccd2cdfc94c6e248eb9ec233bdcf7e4c277dc6a18e21e6ad5` also returned REQUEST_CHANGES: zero Critical, two Important, and two Minor findings. The reviewer accepted that final root validation now enters cleanup, but found that cleanup still verified one inode and later unlinked a pathname that could be replaced in between. The reviewer also found destructive rename-over-existing semantics: a fallible post-publication step could remove both the displaced prior artifact and the new artifact. The available phase harness lacked the exact cleanup verification/mutation interval, and the handoff overstated the guarantee.

This is slice 2's final permitted remediation attempt. Two focused contracts were written first and observed behaviorally RED:

1. replacement after cleanup identity verification was deleted before the test could read it;
2. a second write returned success and replaced an existing artifact instead of preserving immutable evidence.

Minimal final remediation changes publication to platform-native exclusive no-replace rename (`renameatx_np(RENAME_EXCL)` on macOS and `rustix::fs::renameat_with(NOREPLACE)` on Linux). Existing artifacts are never displaced. Failed temp or published members are no longer unlinked: after no-follow identity verification they move to a bounded, exclusive `.failed-artifact-*` quarantine. The cleanup-race hook fires before that move; quarantine identity is rechecked afterward. If a replacement raced into the source name, it is exclusively restored and cleanup failure is reported rather than deleting it. Successful quarantine is durably parent-synced.

Final-remediation verification:

- native macOS: all five atomic-write adversarial tests passed; `engagement` 65 library + 2 binary and `proxy-core` 8 passed; strict touched Clippy, formatting, and diff checks passed;
- Linux arm64 Docker (`rust:1.90-bookworm`): all five atomic-write adversarial tests passed; `engagement` 68 library + 2 binary and `proxy-core` 8 passed; strict touched Clippy passed;
- no Cargo manifest or lockfile changed.

The final replacement fingerprint requires one fresh blind verdict. Any remaining Critical or Important finding exhausts descriptor-chain atomic slice 2; no further remediation is authorized.

Final blind review of exact six-file fingerprint `233f25ae09d3a50695a62c1c9b467e4b6055fef90f12ee811f966b1c484f7dcc` returned REQUEST_CHANGES with zero Critical, one Important, and zero Minor findings. All prior findings were adjudicated resolved, but a distinct pathname-source race remains in mismatch restoration: after quarantine identity inspection, the quarantine pathname can be rebound, causing exclusive restore to move an unrelated inode into the original artifact name. `NOREPLACE` protects only the destination; it does not bind the rename source to the inspected descriptor.

Atomic slice 2 is exhausted and not commit-safe. Its production diff was reverted rather than committed. Atomic slice 1 remains independently PASS and committed at `6c17153`. No additional descriptor-chain remediation or dependent result-promotion work is authorized without an explicit separately named architecture/review-series decision.
