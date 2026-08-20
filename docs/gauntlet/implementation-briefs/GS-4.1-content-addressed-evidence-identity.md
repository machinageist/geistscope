# GS-4.1 Content-Addressed Evidence Identity

Date: 2026-08-13
Status: accepted architecture default; spec review required before implementation
Decision owner: integration owner after decision prompt timeout
Supersedes: dependency-free pathname-immutability writer approach

## Decision

Authoritative evidence identity is content-addressed. `manifest_sha256` identifies the exact manifest bytes, and the manifest transitively binds every artifact by engagement-relative locator, SHA-256, byte length, content type, and visibility.

A filesystem path is a non-authoritative locator only. Publication still uses bounded staging, exclusive no-overwrite rename, traversal/symlink defenses, durability synchronization, and quarantine on detected failure, but the product does not claim that a pathname is immutable against another process with the same OS authority.

Every authority-bearing consumer must:

1. open the expected manifest without following symlinks;
2. read bounded bytes from the opened descriptor;
3. verify those exact bytes against `manifest_sha256`;
4. parse and validate the manifest;
5. open each required artifact without following symlinks;
6. verify length and SHA-256 from the opened descriptor;
7. derive `EvidenceSatisfaction`, `HuntResult`, replay output, API output, persistence projections, and reports only from that verified byte set.

A path change, missing file, byte change, digest mismatch, manifest mismatch, or reopen failure invalidates the evidence for that read. Cached/deserialized verified status never survives failed revalidation.

## Rationale

Two strict three-remediation review series showed that repeated pathname identity checks cannot eliminate a final check-to-use window when publisher and attacker share the same filesystem authority. Content identity gives local-first consumers a verifiable integrity contract without requiring a privileged daemon or dedicated OS account.

## Consequences

- `CommittedBundleIdentity.bundle_path` and artifact paths are locators, not integrity identities.
- `manifest_sha256` is the authoritative bundle identity.
- The manifest cannot hash itself; its digest is computed from committed bytes and returned outside the bundle.
- Result promotion and offline replay must consume descriptor-verified bytes, not perform a check and then reopen unchecked paths.
- SQLite may index locators and digests but must not replace evidence bytes or treat a locator as proof.
- Same-run exclusive publication and no writer-mediated overwrite remain required.
- Arbitrary same-user post-publication mutation is detected on consumption; it is not claimed impossible.
- The rejected fingerprint `bf384dcf6998ec9f3a5a716a531d7cca8ac2e85b2005aefd89395b35cfa5bea5` remains uncommitted evidence of the superseded approach.

## Required gates before implementation

1. Amend GS-4.1 spec and schemas to distinguish identity from locator.
2. Obtain fresh exact-SHA blind spec PASS.
3. Create a new strict-TDD implementation series; do not call it reset remediation 4.
4. Include adversarial tests for manifest/artifact rename, replacement, in-place mutation, symlink substitution, stale cached result, and mutation between verification and later consumption.
5. Require every authority-bearing consumer to use one verified-byte API.
