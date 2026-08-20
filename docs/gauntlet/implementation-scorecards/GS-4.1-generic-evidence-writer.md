# GS-4.1 Generic Atomic Evidence Writer — Implementation Scorecard

Date: 2026-08-13
Review state: REQUEST_CHANGES; root-locator successor series exhausted 3/3
Latest rejected exact commit: `cd4e708f1c20e5bcb275eaaf6d1f575f724c9c4d`
Latest rejected scoped fingerprint: `8dc08ba5a3f1e2515175a347f4658e8315b02eb88d21418de12cb2ec34ede618`

## Scope

- `crates/evidence-core/src/lib.rs`
- `crates/engagement/src/artifact_store.rs`
- `crates/proxy-core/src/lib.rs`
- `docs/gauntlet/run-logs/GS-4.1-generic-evidence-writer.md`

## Verified commands

```text
cargo test -p evidence-core --locked
27 passed; 0 failed

cargo clippy -p evidence-core --all-targets --locked -- -D warnings
PASS

cargo fmt -p evidence-core -- --check
PASS

git diff --cached --check
PASS
```

Linux aarch64 was executed in `rust:1.88-bookworm`: 27 tests, all-target check, strict Clippy, and formatting passed. Native macOS passed the same gates plus `mg-hunt` 16 and `mg-evidence` 1. Windows remains a CI verification obligation; unsupported publication targets fail closed.

## TDD/remediation evidence

- Model-visible secret rejection was observed RED before implementation.
- Aggregate bundle bound was observed RED before the checked 32 MiB limit.
- Concurrent same-run publication passes with exactly one successful publisher, one `RunAlreadyExists`, no mixed bytes, one explicit failed quarantine, and no `.staging-*` residue.
- Successful publication syncs files, the staging directory, and the publication parent; unsupported directory-durability platforms fail closed.
- Blind remediation iteration 1 addressed unsupported-platform publication, portable path encoding, and incomplete secret markers.
- Blind remediation iteration 2 addressed same-user symlink-swap TOCTOU using no-follow descriptor-relative operations and made quarantine failures observable without expanding the public error enum.
- Blind remediation iteration 3 rejects backslashes in candidate/run IDs and recognizes camelCase API/access/refresh-token keys, client-secret forms, and PEM private-key headers. This is the final permitted loop.
- A concurrently dispatched pre-freeze review added camelCase `callbackToken`; its focused RED/GREEN fix was folded into iteration 3 before the final snapshot.
- A pre-descriptor durability review prompted verification of nested/first-time directory syncs and a final fix to sync the candidate parent after quarantine rename.

## Blind verdict

RESET ITERATION 1: REQUEST_CHANGES for non-exclusive quarantine naming against exact fingerprint `14405dd1df6c2ec9805fd09c45a310719431d2800b2681a3f95dbd0bd36ae232`.

RESET ITERATION 2 remediation added bounded exclusive no-replace quarantine retries and restored safe nested legacy identifiers while retaining strict generic identifiers.

RESET ITERATION 2 VERDICT: REQUEST_CHANGES for a reproducible nested artifact-directory swap that allowed success with a manifest-declared artifact missing from the published bundle.

RESET ITERATION 3 VERDICT: REQUEST_CHANGES. Every nested directory and artifact/manifest file remains descriptor-held through publication and is revalidated by path identity plus expected file length/hash both before and after promotion, and the adversarial regressions are GREEN. However, a same-user process can still mutate or rename the published bundle after final verification and before return. Parent synchronization does not close that window. The reset series is exhausted; do not commit this fingerprint or perform remediation 4 without an explicit new architecture/review-series decision.

CONTENT-ADDRESSED ITERATION 1 VERDICT: REQUEST_CHANGES for engagement-root symlink following, normalized acceptance of noncanonical repeated separators, and incomplete reader-side metadata validation.

CONTENT-ADDRESSED ITERATION 2 VERDICT: REQUEST_CHANGES for writer/reader content-type contract mismatch and a blocking macOS FIFO open in `engagement::ArtifactStore`.

CONTENT-ADDRESSED ITERATION 3 VERDICT: REQUEST_CHANGES against exact fingerprint `992e70cc1aa3de163a048b3e765e074c883e77e088deb0e91d324dd306a69fd1`. Prior findings were remediated and native/Linux gates passed, but `EvidenceBundleReader::read_relative_bounded` opens manifest and artifact members with blocking `O_RDONLY | O_NOFOLLOW` before checking regular-file type. A FIFO at either locator can block an authority-bearing verification indefinitely on macOS and Linux. No Critical findings were reported; this remaining Important finding exhausts the content-addressed series. Do not commit the rejected fingerprint or perform remediation 4 without an explicit architecture/new-series decision.

NONBLOCKING-READER SUCCESSOR ITERATION 1 VERDICT: REQUEST_CHANGES against `cb145fdc889b6f1a97092e456271bd3dc2c7ad4f89bb1f4dcb2d9620fca2cc74`; production FIFO handling was correct, but regression recovery used a blocking writer open and unbounded join.

NONBLOCKING-READER SUCCESSOR ITERATION 2 VERDICT: REQUEST_CHANGES against `7387a955786d8df2c0725c9c74bbd2464ec87949ae11061d8e777d8b4bb96066`; writer acquisition was bounded, but channel completion did not prove thread termination before an unbounded join.

NONBLOCKING-READER SUCCESSOR ITERATION 3 VERDICT: REQUEST_CHANGES against `47a4db57bb965c14e73f8c3c1c29e15b1e432c97a32a7cc34fce2dd78405ee0c`. FIFO production and harness remediations passed review, but `EvidenceBundleWriter` and `engagement::ArtifactStore` canonicalize the caller-supplied engagement root before no-follow opening, so a terminal root symlink is followed. No Critical findings remained. This exhausts the successor series; no remediation 4 or dependent commit is authorized.

ROOT-LOCATOR SUCCESSOR ITERATION 1 VERDICT: REQUEST_CHANGES. Static original-root symlink rejection and constructor descriptor/path identity were accepted, but `ArtifactStore::atomic_json_write` still followed the stored canonical pathname after root replacement.

ROOT-LOCATOR SUCCESSOR ITERATION 2 VERDICT: REQUEST_CHANGES. Descriptor-relative publication and static intermediate-symlink rejection passed, but the public write record still exposed an authority-bearing pathname and newly created ancestor links were not durably synchronized.

ROOT-LOCATOR SUCCESSOR ITERATION 3 VERDICT: REQUEST_CHANGES against committed snapshot `cd4e708f1c20e5bcb275eaaf6d1f575f724c9c4d` and scoped fingerprint `8dc08ba5a3f1e2515175a347f4658e8315b02eb88d21418de12cb2ec34ede618`. The reviewer found zero Critical and two Important defects: the public legacy writer still follows a symlinked engagement root through pathname-based publication, and `ArtifactStore::atomic_bytes_write` can continue through an intermediate directory descriptor after that directory is moved outside the retained root. This exhausts root-locator remediation 3/3. No remediation 4 or dependent result-promotion work is authorized without an explicit new-series decision.
