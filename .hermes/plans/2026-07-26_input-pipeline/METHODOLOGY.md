# METHODOLOGY — Input pipeline slice (living dev-log)

Per task: RED → what failed → GREEN → what the test revealed → adjustment.

## Why this slice, this way

Slices 1–2 gave the engine two vuln classes, but it can only run on a proxy export the operator
captured and *labeled* by hand — so in practice a human still does the tedious part. This slice
attacks that: infer identity labels from the auth material already in a capture (so IDOR candidates
arise without hand-labeling), and seed the corpus straight from crawl output (so SSRF/surface
candidates arise without any proxy export). Both are detection/labeling improvements; execution
credentials for a live IDOR test still legitimately come from the operator's controlled sessions.
The safety line to hold: infer identity from a *hash* of the credential, never the credential.

## Task 0 — Scaffold

Wrote this dev-log and the slice PLAN. Confirmed `build_pending_record` is reusable for crawl
endpoints and the identity extraction point sees auth headers before redaction.

## Task 1 — Identity inference on import

**Goal.** Make distinct credentials in a capture become distinct identities, so IDOR candidates form
without hand-labeling — without ever storing the credential.

**Design.** `infer_identity_fingerprint(headers)` hashes the request's `Authorization` (or `Cookie`)
value with sha256 and returns `id-<12 hex>`. In `build_pending_record`, `identity_id` falls back to
this fingerprint when `x-mg-identity-id` is absent, and `tenant_id` falls back to the identity — so
two requests to the same endpoint under different credentials get distinct tenant labels and the
existing `CrossTenantRead` grouping fires.

**RED → GREEN.** One test: same credential → same label; different credentials → different labels;
label starts with `id-`; the secret never appears in the label; no auth → no fingerprint. engagement
51/51 (existing import tests unaffected — they carry no auth headers). Clippy clean.

**What it revealed.** The fingerprint is a one-way function of the credential, so the identity label
is safe to store and show while the credential is still stripped by `sanitize_headers`. Detection is
now possible from a raw capture; execution still needs the operator's controlled sessions (correct —
you can't replay as an identity you don't hold).

**Adjustment.** None.
