# METHODOLOGY — IDOR slice (living dev-log)

Running record of *how* this slice is built, to teach. Per task: **RED** → **what failed** →
**GREEN** → **what the test revealed** → **adjustment**. Companion to the SSRF slice's
methodology; distillable into a public writeup later.

## Why this slice, this way

The SSRF slice proved the adaptive loop but left the runner GET-only and auth-blind, and the
authorization/IDOR path running on fixtures. IDOR is the highest capability-per-line next move: it
reuses the candidate, the verdict, the runner, and the evidence writer that already exist, and needs
no out-of-band machinery — it's a direct-response class. The one real body of work is making the
engine *authenticated*: materialize a named identity's credentials into headers, send a captured
request as a *different* identity (the session swap), and let the existing semantic verdict decide
whether the attacker reached the victim's data. That "auth-aware runner" is also exactly what SSRF
needs to reach authenticated sinks, so it pays for two classes at once.

The discipline is the same: each capability starts as a failing test that pins the behavior —
including the safety refusals (never materialize a plaintext secret; never send a non-executable
plan) — then the minimum code to make it pass.

## Task 0 — Scaffold

Wrote this dev-log and the slice PLAN.md. No code; the gate is that the docs exist. Design intent
recorded so the first RED test (Task 1) fails for the right reason.

## Task 1 — Session header resolver

**Goal.** Turn a named identity's stored credential *references* into real request headers, so the
runner can send a request "as Alice" vs "as Bob" — the primitive a session swap needs.

**Design.** `SessionProfile` stored `auth_refs: Vec<SecretRef{kind, env_var}>` but nothing turned a
*profile* into headers (only a private `SessionConfig` path existed). Added
`SessionProfile::resolve_headers(env_lookup)` with an injectable lookup for testability, plus an
`auth_headers()` convenience over the real environment. Header mapping keys off `SecretRef.kind`:
`token`/`bearer` → `Authorization: Bearer …`, `authorization` → raw `Authorization`, `cookie` →
`Cookie`, anything else → a literal header name (covers `X-Api-Key`, `X-Tenant`, …).

**RED → GREEN.** Three tests: env refs resolve to the right headers; a missing env var fails
(`MissingEnv`); and — the safety property — a plaintext `SecretRef` is **never** materialized into a
header (`PlaintextSecretRejected`). `cargo test -p session` first failed to compile
(`no method resolve_headers`), then passed 11/11; clippy clean.

**What it revealed.** Enforcing the no-plaintext invariant *at resolution* (not just at save) means a
credential can only ever reach the wire through an env reference — the resolver structurally cannot
leak a stored plaintext value, mirroring the same defense the SSRF slice put in `build_injected_request`.

**Adjustment.** None. Task 2's runner will call `resolve_headers` for the attacker identity.
