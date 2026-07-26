# PLAN — Input pipeline slice (target → hunt without hand-authored files)

Dated: 2026-07-26. Slice 3 of the post-SSRF roadmap. Removes the requirement that the corpus be fed
only by hand-exported, hand-labeled proxy files. Living PLAN.

## Why

Today the hunt loop only runs on imported HAR/Burp/Caido files whose identity/tenant labels the
operator set by hand (via `x-mg-*` capture headers). Real captures lack those labels (so no IDOR
candidates), and there is no way to seed the corpus from recon/crawl. This slice adds identity
inference on import and a crawl→traffic bridge. MITM live capture stays deferred.

## Tasks (TDD; commit each)

- [~] **0. Scaffold** — this PLAN.md + METHODOLOGY.md.
- [x] **1. Identity inference on import** (`engagement`) — when `identity_id` is absent, derive a
  stable fingerprint from the request's auth material (sha256 of Authorization/Cookie) *before*
  redaction; also seed `tenant_id` from it when absent. Distinct credentials → distinct identities →
  IDOR candidates from real captures; the secret is never stored. Gate: `cargo test -p engagement` +
  clippy.
- [ ] **2. Crawl → TrafficRecord bridge** (`engagement` + `mg-corpus`) — `import_crawl_endpoints`
  reads `crawl/<host>/endpoints.json`, builds unauthenticated GET records (reusing
  `build_pending_record`), appends to the corpus. Expose via a `mg-corpus from-crawl` subcommand.
  Gate: `cargo test` + clippy.
- [ ] **3. E2E + status** — `init → crawl fixture → import_crawl_endpoints → corpus build` yields an
  SSRF candidate from recon; a synthetic multi-identity import yields a `CrossTenantRead` candidate
  via inferred identities. Update checklist. Gate: E2E passes; full `cargo test`; `git diff --check`.

## Reuse

`engagement::traffic::build_pending_record` (private record builder), `TrafficStore::import_pending`
(dedup append), `sha256_hex`, `header_value`. Candidate detectors in `request-corpus` unchanged.

## Safety

The identity fingerprint is a hash of the credential, never the credential itself — no secret is
stored or made model-visible. Crawl records are unauthenticated GET surface only. Jeff's conventions.
