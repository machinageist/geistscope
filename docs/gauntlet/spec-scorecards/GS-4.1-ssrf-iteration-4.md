# GS-4.1 SSRF Specification — Iteration 4 Scorecard

Date: 2026-08-13
Reviewed SHA-256: `323a05dfdff89359bee8f08ffcfbbaa691c4f3e02212168ad966d5cda04ab882`
Verdict: PASS
Auto-fail: none
Critical/Important defects: none
Feasibility: feasible with caveats
Composite: 2.300/3

## Binding lens results

- Adaptive Hunt Completion: 2.000 — pass.
- Authorization and Safety: 2.667 — pass.
- Evidence and Reporting: 2.500 — pass.
- Operator/API Usability: 2.000 — pass.

No criterion scored 0. Scores of 1 per lens were 1, 0, 0, and 1. The reviewer applied the binding 2.25/3 threshold.

## Criterion scores

- 1A 2; 1B 2; 1C 3; 1D 1; 1E 2; 1F 2.
- 2A 3; 2B 3; 2C 3; 2D 2; 2E 3; 2F 2.
- 3A 3; 3B 3; 3C 2; 3D 2; 3E 2; 3F 3.
- 4A 2; 4B 3; 4C 2; 4D 2; 4E 1; 4F 2.

## Approved content-addressed contract

- `manifest_sha256` is the authoritative bundle identity; paths are locators only.
- The external manifest digest avoids self-hashing and digest substitution.
- The manifest transitively binds every required artifact by digest and length.
- One verified-byte API must open without following symlinks, read bounded bytes from held descriptors, and pass those exact bytes to contract/result derivation without unchecked reopen.
- Cached/deserialized verified status cannot survive failed consumer-time revalidation.
- Identical bytes at another validated locator retain identity; any changed byte fails.
- SQLite may index locators and digests but cannot replace evidence bytes or treat a path as proof.
- Same-run no-overwrite publication, staging, containment, durability, callback, budget, authorization, and secret requirements remain.

## Reviewer execution notes

The reviewer confirmed stable initial/final SHA and ran 38 focused baseline tests: result contract 3, SSRF candidate 4, policy gate 10, HTTP executor 12, and callback assessment 9. `git diff --check` passed. The expected `EvidenceContract::validate_local` dead-code warning confirms production promotion remains absent rather than falsely complete.

Implementation-time caveats remain: exact-copy member resolution/rebasing must be explicit; Linux/macOS no-replace bindings and unsupported-platform failure require proof; Phase A/E2E/schema/strict-Clippy gates are not yet passing because the replacement implementation is absent.
