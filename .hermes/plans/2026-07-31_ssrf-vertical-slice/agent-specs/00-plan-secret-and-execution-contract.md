# Slice 0 — Harden Plan Secrets and the Execution Contract

Status: ready
Priority: mandatory before policy or networking
Parent behavior: `../SPEC.md` safety invariants and `../PLAN.md` Task 3.2

## Goal

Make the current SSRF probe plan safe to authorize and execute: the immutable hash must bind exact executable semantics, while public/model-visible serialization must not reveal callback tokens or raw observed query values.

## Why this slice exists

The current Task 3.2 tests prove plan hashing and callback-origin constraints, but the production shape is not yet a safe worker boundary:

- `SsrfProbePlan` derives `Serialize` while carrying `callback_url`, which contains the raw callback token.
- `ActionDescriptor.target` receives the full observed URL, including original query values.
- executable semantics are hashed from an ad-hoc newline-delimited string rather than a named canonical structure.
- the builder consumes `CallbackToken` but does not expose a safe engine-only registration/execution path for the same token.
- later agents need a precise mutation contract; they must not reparse public prose or reconstruct behavior from hashes.

## Required outcome

Create two deliberately different views:

1. Engine-only executable plan state containing the validated target request template, exact query occurrence, callback token/URL, and policy references.
2. Public/redacted plan metadata containing hashes, candidate/observation IDs, target origin/path, query parameter name/occurrence, budgets, scope/risk, and evidence requirements—but no raw token or query value.

The immutable plan hash must be computed from a named `Serialize` hash-material structure. It must bind:

- observation source artifact hash;
- candidate ID and original-value hash;
- method;
- target scheme/host/effective port/path;
- exact query parameter name and occurrence;
- callback origin and token hash or exact engine-only callback URL;
- scope and rules artifact hashes;
- callback observation-window duration and lease expiry semantics;
- risk, scope disposition, budgets, redirect policy, stop conditions, and evidence contract.

Presentation rationale and redacted display labels remain outside hash material.

## Compile-time authority boundary

- Public callers may inspect `SsrfProbePlanView` (name may vary) and the immutable plan hash.
- Raw token access and executable request mutation data must remain crate-private or available only through a crate-private executor interface.
- Provide a crate-internal method that creates `CallbackRegistration` using the same token and final plan hash. Do not require reparsing a serialized callback URL.
- Bind callback authority through an engine-created runtime lease/registration object, not merely a
  public constructor accepting an arbitrary syntactically valid origin. Reject URL userinfo and
  require the origin to match the active callback worker authority.
- Do not derive `Deserialize` for executable/validated plan aggregates.
- If `ActionPlan` needs new getters, expose immutable policy-safe values only; do not expose arbitrary mutation setters.

## Exact mutation behavior

For duplicate query keys, occurrence is zero-based among values with the same decoded parameter name. Mutation replaces exactly that occurrence and preserves all other query pairs in order. It must not:

- append a second attacker-controlled parameter;
- replace every parameter with the same name;
- alter the method, path, unrelated query values, headers, or body;
- follow or pre-resolve redirects;
- perform I/O during plan construction.

## Codebase map

Inspect before editing:

- `crates/hunt-engine/src/ssrf.rs`
- `crates/hunt-engine/src/plan.rs`
- `crates/hunt-engine/src/callback.rs`
- `crates/hunt-engine/src/lib.rs`
- `crates/hunt-engine/tests/ssrf_plan.rs`
- `crates/hunt-engine/tests/ssrf_candidate.rs`

Likely new focused test: `crates/hunt-engine/tests/ssrf_plan_security.rs`.

## Behavior-first tests

Add tests proving:

1. Serializing the public plan view contains neither the raw callback token nor the original suspected URL/query value.
2. Serializing `SsrfProbePlan` directly is impossible by API design, or a custom serializer emits only the redacted view.
3. Changing token, target path, query occurrence, source artifact hash, scope hash, rules hash, or budget changes the plan hash.
4. Changing rationale does not change the plan hash.
5. Duplicate query keys mutate only the selected occurrence in the engine-only executable request.
6. A candidate from another observation cannot build a plan.
7. GET is permitted for this autonomous slice; POST/PUT/PATCH/DELETE are rejected before permit creation.
8. Callback registration produced from the plan uses its exact plan hash and expires at the supplied deadline.
9. Plan construction causes zero target and callback network attempts.
10. Callback origins with userinfo, query, fragment, non-root paths, or authority differing from
    the active worker are rejected.
11. Observation-window/lease duration changes the plan hash, and registration expiry cannot diverge
    from the plan-bound window.
12. A source artifact/value hash that no longer matches the executable observation is rejected before
    policy evaluation.
13. SSRF plans always include `AuthorizationExpired`; missing it is rejected.
14. Stop conditions reject duplicates or canonicalize ordering so semantically identical sets hash identically.
15. Generic budgets above explicit engine safety ceilings cannot reach an execution adapter.

## Non-goals

- Do not call `action-policy`.
- Do not send HTTP requests.
- Do not write evidence files.
- Do not add browser/body/header SSRF candidates.
- Do not expose a general plugin ABI.

## Verification

```bash
cargo test -p hunt-engine --test ssrf_plan
cargo test -p hunt-engine --test ssrf_plan_security
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p hunt-engine -- --check
git diff --check
```

## Done means

A subsequent policy agent can inspect a redacted immutable plan, bind a permit to its hash, and hand the engine-only request to an executor without ever putting token/query secrets in public JSON.
