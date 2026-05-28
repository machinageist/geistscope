# GeistScope Autonomous Hunting Implementation Instructions

## Objective

Eliminate Burp from the normal GeistScope hunting workflow.
Implement a local-first proxy, session vault, traffic corpus, safe replay, semantic diff, and evidence pipeline that lets an AI agent autonomously perform scoped, low-risk, read-only authorization hunting against user-provided bug bounty programs and controlled accounts.

## Non-negotiable constraints

- Rust validates every model-requested action before dispatch.
- The model never receives raw cookies, bearer tokens, CSRF tokens, passwords, private keys, or third-party PII.
- Active network traffic requires an engagement, a scoped target, a named session or explicit anonymous state, an audit event, and a risk decision.
- State-changing, destructive, volumetric, brute-force, OOB/internal-network, ambiguous-scope, and real-data-touching actions require explicit human approval.
- Raw evidence remains local; model-visible artifacts are redacted summaries plus stable evidence paths and hashes.
- All CLIs support `--json`, `--output <path>`, `--no-color`, deterministic exit codes, and machine-parseable errors.
- All new commands read/write under the engagement root.

## New crates / binaries

Add these workspace members under `crates/`:

- `proxy-core`: HTTP(S) intercepting proxy library, certificate handling, request/response recording, WebSocket pass-through metadata.
- `mg-proxy`: CLI wrapper for `proxy-core`; starts local proxy, installs/prints CA instructions, records traffic to the engagement.
- `lab-model`: controlled account/store/tenant/role/boundary model.
- `mg-lab`: CLI for identities, sessions, tenants, roles, boundaries, and controlled-resource labels.
- `request-corpus`: normalized traffic corpus builder and candidate generator.
- `mg-corpus`: CLI for importing, tagging, clustering, pairing, and querying traffic.
- `replay-engine`: scoped replay library with session injection, token refresh hooks, substitution plans, semantic diffing, and evidence writing.
- `mg-hunt`: orchestrated autonomous/assisted hunt loop over `lab-model`, `request-corpus`, and `replay-engine`.

Prefer library crates for reusable logic and thin CLIs for operators and harness endpoints.

## Extend existing crates

### `engagement`

Add:

- Robust scope normalization for URL, hostname, wildcard, path, port, scheme, and explicit deny precedence.
- `ScopeDecision`:
  - `input: String`
  - `normalized_host: Option<String>`
  - `normalized_url: Option<String>`
  - `decision: InScope | OutOfScope | Ambiguous`
  - `matched_allow: Vec<ScopeRule>`
  - `matched_deny: Vec<ScopeRule>`
  - `reason: String`
  - `asset_type: Option<String>`
  - `bounty_eligible: Option<bool>`
  - `submission_eligible: Option<bool>`
  - `notes: Vec<String>`
- `mg-engagement check --json` and `mg-engagement explain-scope --json`.
- Program scope import:
  - `mg-engagement scope-import --format hackerone-csv <file>`
  - Preserve `eligible_for_bounty`, `eligible_for_submission`, max severity, asset type, instruction text.
- Audit helpers:
  - `audit_event(tool, action, risk, decision, target, evidence_path)`.

Acceptance:

- `admin.shopify.com` and `https://admin.shopify.com/` resolve to the same decision.
- Explicit deny beats wildcard allow.
- `*.example.com` matches subdomains but not unrelated domains.
- Scope decisions are stable JSON.

### `session`

Replace environment-header-only behavior with a local named session vault.

Add:

- `SessionProfile`:
  - `name`
  - `engagement`
  - `identity_id`
  - `role_id`
  - `tenant_id`
  - `auth_state: Anonymous | Authenticated | Expired | Unknown`
  - `cookie_jar_path`
  - `header_secret_refs`
  - `csrf_strategy`
  - `last_validated_at`
  - `redacted_summary`
- Encrypted or file-permission-hardened local storage for cookies/headers.
- Redacted display by default.
- `mg-lab session import-from-proxy <session-name> --selector <container/profile/tag>`.
- `mg-lab session validate <session-name> --url <scoped-url>`.
- Header/cookie injection API for `replay-engine`.

Acceptance:

- Raw session material is never emitted in JSON or logs.
- Named sessions can replay captured requests without env vars.
- Expired sessions fail closed.

### `mg-harness`

Expose typed endpoints only; do not expose raw shell.

Add endpoint families:

- `program.import_scope`
- `scope.explain`
- `lab.identity_create`
- `lab.tenant_create`
- `lab.role_create`
- `lab.boundary_create`
- `session.list`
- `session.validate`
- `proxy.start`
- `proxy.stop`
- `traffic.search`
- `corpus.build`
- `corpus.candidates`
- `replay.plan`
- `replay.execute_readonly`
- `diff.semantic`
- `evidence.bundle`
- `hunt.next_safe_test`
- `hunt.run_assisted`

Each endpoint declares:

- risk class
- required engagement
- required scope check
- required session access
- model-visible output schema
- redaction policy
- confirmation policy

Acceptance:

- Prompt-injection fixtures in target traffic cannot alter endpoint policy.
- Invalid model arguments return typed validation errors.
- High-risk endpoints block without explicit approval.

### `mg-tui`

Add views:

- Proxy traffic feed.
- Session vault status.
- Lab model matrix.
- Corpus candidate table.
- A/B pair inspector.
- Replay plan viewer.
- Semantic diff viewer.
- Evidence bundle drawer.
- AI next-safe-test panel.

Every active action shows engagement, target, scope decision, session, risk class, output path, and approval state.

## Proxy implementation

Implement `proxy-core` as a local HTTP(S) intercepting proxy.

Required behavior:

- Listen on configurable address, default `127.0.0.1:8088`.
- Generate or load a local CA under engagement-global config.
- MITM HTTPS for user-installed CA contexts.
- Preserve raw request bytes, raw response bytes, timing, TLS SNI, remote address, and proxy connection metadata.
- Decode HTTP/1.1 and HTTP/2 where practical; store lossless raw artifacts plus parsed summaries.
- Never modify requests unless a replay plan explicitly does so.
- Support capture labels from headers or UI controls:
  - `x-mg-session: store_a_owner`
  - `x-mg-role: owner`
  - `x-mg-tenant: attacker_shop`
- Provide browser setup output:
  - proxy host/port
  - CA cert path
  - per-container/profile naming instructions.

CLI:

```bash
mg-proxy start <engagement> --listen 127.0.0.1:8088 --session store_a_owner --json
mg-proxy sessions <engagement> --json
mg-proxy tail <engagement> --filter host=admin.shopify.com --json
mg-proxy export <engagement> --format corpus --output requests/corpus/raw.jsonl
```

Storage:

```text
<engagement>/traffic/raw/<timestamp>-<id>.request
<engagement>/traffic/raw/<timestamp>-<id>.response
<engagement>/traffic/index.jsonl
<engagement>/traffic/bodies/<sha256>
```

`TrafficRecord` minimum fields:

- `id`
- `timestamp`
- `session_name`
- `identity_id`
- `role_id`
- `tenant_id`
- `auth_state`
- `method`
- `scheme`
- `host`
- `port`
- `path`
- `query`
- `url_normalized`
- `status`
- `request_headers_redacted`
- `response_headers_redacted`
- `request_body_ref`
- `response_body_ref`
- `request_hash`
- `response_hash`
- `content_type`
- `operation_name`
- `graphql_kind`
- `risk_class`
- `scope_decision`
- `tags`

## Lab model

Implement controlled test state as data, not markdown.

Types:

- `Identity`: controlled account or actor.
- `Tenant`: shop/org/workspace/store/account boundary.
- `Role`: owner/admin/staff/customer/anonymous/custom.
- `SessionProfile`: named authenticated or anonymous browser/proxy session.
- `Boundary`: relationship that should or should not permit access.
- `ControlledResource`: product/customer/order/file/webhook/export/etc. created for testing.

CLI:

```bash
mg-lab identity add <engagement> store_a_owner --email machinageist@wearehackerone.com --controlled true
mg-lab tenant add <engagement> attacker_shop --host cc882q-40.myshopify.com --kind shop --controlled true
mg-lab role add <engagement> owner --privilege owner
mg-lab session add <engagement> store_a_owner --identity store_a_owner --tenant attacker_shop --role owner
mg-lab boundary add <engagement> cross_store --from attacker_shop --to target_shop --expected deny
mg-lab resource add <engagement> attacker_product --tenant attacker_shop --kind product --id 'gid://shopify/Product/...'
mg-lab matrix <engagement> --json
```

Acceptance:

- The hunt loop can decide whether a replay crosses a legitimate boundary.
- Reports can state why both sides are controlled and why access should be denied.

## Corpus builder

Implement `request-corpus` over traffic records.

Required analyzers:

- REST path/object-ID extractor.
- Query parameter extractor.
- JSON body extractor.
- Form body extractor.
- GraphQL operation/variables extractor.
- Shopify-style operation URL extractor:
  - `/api/operations/<hash>/<operation>/shopify/<shop>`
  - `operationName`
  - `variables`
  - `gid://shopify/<Type>/<id>`
- Object reference extractor:
  - numeric IDs
  - UUIDs
  - slugs
  - GIDs
  - tenant/shop/org IDs
- Risk classifier:
  - `Passive`
  - `ReadOnlyAuthenticated`
  - `LowRiskStateChangingControlledData`
  - `HighRiskStateChanging`
  - `Destructive`
  - `Volumetric`
  - `CredentialSensitive`
  - `OobInternalSensitive`
  - `Ambiguous`

Candidate types:

- `CrossTenantRead`
- `CrossTenantWrite`
- `VerticalPrivilegeRead`
- `VerticalPrivilegeWrite`
- `UnauthenticatedAccess`
- `ExportJobConfusion`
- `DownloadTokenConfusion`
- `GraphqlBola`
- `GraphqlBfla`
- `MassAssignment`
- `OAuthShopSwap`
- `WebhookLifecycle`

Pairing algorithm:

- Group by normalized host, operation name, method, route template, body shape, GraphQL operation, and risk class.
- Pair records across sessions/tenants when operation and shape match.
- Identify substitution points: shop handle in path, object ID/GID in variables/body/query, tenant ID, job ID, download token.
- Produce `ReplayPlan` only when scope decision is in-scope and risk is allowed.

CLI:

```bash
mg-corpus build <engagement> --from traffic --json --output requests/corpus/current.json
mg-corpus candidates <engagement> --boundary cross_store --risk read-only --json
mg-corpus show <engagement> <candidate-id> --json
```

Acceptance:

- Shopify `AdminProductDetails` attacker/target requests pair automatically.
- `ProductCreateSet` is classified as state-changing and not run autonomously.
- Read-only product detail/index/export status candidates are produced first.

## Replay engine

Implement replay as plans, not ad hoc requests.

`ReplayPlan` fields:

- `id`
- `engagement`
- `candidate_id`
- `hypothesis`
- `risk_class`
- `requires_approval`
- `scope_decisions`
- `sessions`
- `control_requests`
- `test_requests`
- `substitutions`
- `expected_secure_result`
- `stop_conditions`
- `evidence_output_dir`

Replay matrix for authorization:

- A session + A resource = baseline control.
- B session + B resource = baseline control.
- A session + B resource = exploit candidate.
- Anonymous + B resource = unauth candidate when safe.

Rules:

- Default autonomous mode allows only read-only requests.
- Concurrency defaults to 1 for authenticated replay.
- Request bodies are immutable unless a substitution plan explicitly names the field.
- CSRF/token refresh is strategy-based and session-local.
- Redirect following is disabled by default or recorded explicitly.
- Any 5xx spike, rate-limit response, WAF block, or unexpected state-changing response stops the plan.

CLI:

```bash
mg-replay plan <engagement> --candidate <id> --json --output replay/plans/<id>.json
mg-replay execute <engagement> --plan replay/plans/<id>.json --mode read-only --json
mg-replay diff <engagement> --run <run-id> --semantic --json
```

Acceptance:

- A read-only cross-store product detail test can run without Burp.
- A write/mutation plan is generated but blocked pending approval.
- Evidence contains raw requests/responses plus redacted summaries.

## Semantic diff

Implement semantic diff beyond status/body hash.

Diff dimensions:

- HTTP status class and exact code.
- Redirect target.
- Content type.
- Response size and structural hash.
- JSON keys added/removed.
- GraphQL `data` versus `errors`.
- Object identity fields.
- Tenant/shop ownership fields.
- Sensitive field presence.
- Test marker presence.
- Expected controlled resource title/value.
- Error text class, not full untrusted text.

Verdicts:

- `SecureDenied`: expected 401/403/404 or GraphQL authorization error.
- `NoIssueSameTenantOnly`: response only contains caller-owned resource.
- `InterestingDiff`: manual review needed.
- `BoundaryViolationRead`: attacker read target-controlled resource.
- `BoundaryViolationWrite`: attacker modified target-controlled resource.
- `UnauthenticatedExposure`: anonymous access to controlled private resource.
- `InvalidTest`: token expired, stale request, ambiguous scope, unsafe side effect.

Acceptance:

- 200 is not enough for a finding.
- A finding requires target object identity or target marker in attacker-session response.
- Expected Shopify errors are suppressed as secure denials.

## Evidence pipeline

Implement evidence bundles.

Directory:

```text
<engagement>/evidence/<candidate-id>/
  scope.json
  lab.json
  replay_plan.json
  control_a.request
  control_a.response
  control_b.request
  control_b.response
  test_ab.request
  test_ab.response
  diff.json
  summary.redacted.md
  hashes.json
```

CLI:

```bash
mg-evidence bundle <engagement> --run <run-id> --json
mg-report draft <engagement> --evidence <candidate-id> --template authz --json
```

Report skeleton must include:

- Affected endpoint.
- Scope proof.
- Controlled-account proof.
- Boundary expectation.
- Control request/response paths.
- Exploit request/response paths.
- Minimal reproduction steps.
- Impact statement.
- Safety statement: no real merchant/customer data, no enumeration.

## Autonomous hunt loop

Implement `mg-hunt` as a policy-bound orchestrator.

Command:

```bash
mg-hunt run <engagement> \
  --mode assisted \
  --boundary cross_store \
  --risk read-only \
  --max-tests 20 \
  --concurrency 1 \
  --require-approval state-changing \
  --json
```

Loop:

1. Load engagement, scope, lab, sessions, traffic.
2. Validate named sessions.
3. Build/update corpus.
4. Generate candidates.
5. Rank candidates by bug-class value and safety.
6. Generate replay plan for top candidate.
7. Execute only if risk policy allows.
8. Semantic diff responses.
9. Write evidence bundle.
10. Create finding draft only for boundary violation verdicts.
11. Stop on finding, unsafe condition, expired session, ambiguous scope, or approval need.
12. Emit next safe action.

Default ranking:

1. Cross-tenant/store read of controlled object.
2. Low-priv staff read of owner-only controlled object.
3. Export/job status/download token confusion.
4. GraphQL resolver BOLA/BFLA.
5. Webhook read/update lifecycle.
6. OAuth/app install shop swap.
7. Settings/billing/staff permission boundary.
8. Controlled write proof requiring approval.

## Proxy-first replacement for Burp workflow

Target operator flow:

```bash
mg-engagement init shopify-h1 --target shopify.com --platform hackerone --url https://hackerone.com/shopify
mg-engagement scope-import shopify-h1 --format hackerone-csv scopes.csv
mg-lab identity add shopify-h1 attacker_owner --email machinageist@wearehackerone.com --controlled true
mg-lab identity add shopify-h1 target_owner --email mgeist-target@wearehackerone.com --controlled true
mg-lab tenant add shopify-h1 attacker_shop --host cc882q-40.myshopify.com --controlled true
mg-lab tenant add shopify-h1 target_shop --host ix1psu-hv.myshopify.com --controlled true
mg-lab boundary add shopify-h1 cross_store --from attacker_shop --to target_shop --expected deny
mg-proxy start shopify-h1 --listen 127.0.0.1:8088
# user/browser logs in through mg-proxy once per named session
mg-lab session validate shopify-h1 store_a_owner
mg-lab session validate shopify-h1 store_b_owner
mg-corpus build shopify-h1 --from traffic --json
mg-hunt run shopify-h1 --mode assisted --boundary cross_store --risk read-only --max-tests 20 --json
```

No Burp export exists in the happy path.

## TUI requirements

`mg-tui` must provide keyboard-first equivalents for all core loop states:

- `P`: proxy feed.
- `L`: lab matrix.
- `S`: session vault.
- `C`: corpus candidates.
- `R`: replay plan.
- `D`: semantic diff.
- `E`: evidence bundle.
- `A`: AI next-safe-test.

Each row must expose stable IDs that can be passed to CLI commands.

## Tests

Add local integration target with two tenants and three roles:

- tenant A owner.
- tenant B owner.
- tenant A low-priv staff.
- endpoints with intentional secure behavior.
- endpoints with one intentional read BOLA.
- endpoints with one intentional vertical BFLA.
- GraphQL endpoint with one secure resolver and one vulnerable resolver.
- export job endpoint with secure and vulnerable variants.

Test cases:

- Scope normalization.
- Explicit deny precedence.
- Proxy capture and redaction.
- Session import without raw secret output.
- Corpus extraction of REST IDs and GraphQL GIDs.
- A/B request pairing.
- Read-only replay matrix.
- State-changing replay blocked without approval.
- Semantic diff promotes only true boundary violations.
- Evidence bundle contains raw local artifacts and redacted model summary.
- Harness endpoint refuses prompt-injection content in target responses.

Commands required before merge:

```bash
cd /home/mgeist/geistscope/crates
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Migration strategy

Phase 1:

- Scope normalization and JSON outputs.
- Lab model CLI.
- Session vault skeleton.
- Traffic schema.

Phase 2:

- `mg-proxy` capture.
- Corpus builder over proxy traffic.
- Shopify operation/GID analyzers.

Phase 3:

- Replay plans.
- Read-only differential replay.
- Semantic diff.
- Evidence bundles.

Phase 4:

- Harness endpoints.
- TUI panes.
- `mg-hunt run` assisted loop.

Phase 5:

- Limited browser automation for controlled test-data setup.
- Additional bug-class-specific candidate generators.

## Definition of done

A coding agent is finished when this command sequence works without Burp:

```bash
mg-proxy start shopify-h1 --listen 127.0.0.1:8088
# Operator logs both controlled Shopify accounts through proxy and creates one product in each shop.
mg-corpus build shopify-h1 --from traffic --json
mg-hunt run shopify-h1 --mode assisted --boundary cross_store --risk read-only --max-tests 5 --json
```

Expected outcome:

- GeistScope discovers equivalent product detail requests.
- GeistScope generates a read-only cross-store replay plan.
- GeistScope runs only scoped read-only requests.
- GeistScope decides secure denial, interesting diff, or boundary violation.
- GeistScope writes a complete local evidence bundle.
- GeistScope emits a redacted finding draft only if attacker-session response contains target-controlled object identity or marker.
