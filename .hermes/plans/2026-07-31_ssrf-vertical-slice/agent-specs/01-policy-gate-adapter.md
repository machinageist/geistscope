# Slice 1 — Deterministic Policy Gate Adapter

Status: blocked only on Jeff's policy-reuse checkpoint
Recommended decision: reuse `action-policy` as the sole action policy authority
Depends on: Slice 0
Parent behavior: `../PLAN.md` Task 3.3

## Goal

Require every SSRF probe to pass the existing Rust `action-policy` rules and a successful audit write before code can obtain the non-forgeable execution permit consumed by the HTTP executor.

## Product behavior

For the callback-only GET probe:

- action maps to `ActionKind::HttpRequest`;
- engine `HuntRisk::LowActive` maps to `RiskLevel::LowActive` and cannot be lowered by arguments;
- no session is required for the local benchmark;
- only an in-scope, bounty-eligible target with a current automation-allowed rules snapshot may execute without approval;
- ambiguous/out-of-scope, missing/expired rules, automation disallowed, and bounty-ineligible decisions block;
- unknown bounty eligibility returns `RequiresApproval` unless a valid approval is supplied;
- audit failure blocks even when policy would otherwise allow.

## Authority design

Add a narrow adapter in `hunt-engine`; do not copy policy rules into a second evaluator.

Recommended types:

- `SsrfPolicyContext`: actual `engagement::ScopeDecision`, `ProgramRulesSnapshot`, `ApprovalState`, evaluation timestamp, engagement root, and the plan-bound scope/rules references.
- `SsrfPolicyGate`: converts engine plan facts to `action_policy::PolicyRequest`.
- `PolicyGateOutcome`: `Allowed(ExecutionPermit)`, `Blocked(PolicyDecisionRecord)`, or `RequiresApproval(PolicyDecisionRecord)`.
- `ExecutionPermit`: crate-owned, non-`Clone`, non-`Deserialize`, private fields, bound to the exact plan hash and policy-decision hash. It is the only input that Slice 2 may consume for network execution.

Names may change, but the authority relationship may not.

## Trusted policy context

The adapter must not trust a caller-supplied `ScopeDisposition` alone. Before evaluation it must:

1. Verify scope/rules artifact paths and hashes under the canonical engagement root.
2. Parse or obtain the typed engagement values from the trusted engagement boundary.
3. Confirm the scope decision target matches the plan's normalized scheme/host/effective port/path.
4. Confirm the artifact hashes equal the references bound into the plan hash.
5. Reject any mismatch as blocked/invalid before `ActionPolicy::evaluate`.
6. Reject rules captured in the future as well as rules that are missing or expired.

Do not treat a public JSON `in_scope` string as authorization.

## Audit contract

Every evaluation outcome writes one typed audit event. The structured audit data must include or reference:

- plan hash;
- action `ssrf.callback_probe`;
- risk;
- allowed/blocked/requires-approval verdict;
- normalized redacted target;
- deterministic reason;
- scope/rules evidence paths;
- approval ID when applicable, but no credentials or tokens.

`engagement::AuditEvent` currently lacks a plan-hash field. The agent may add a backward-compatible optional field with `#[serde(default)]`, or write a separate immutable policy-decision artifact and reference it from the audit event. Do not put the plan hash into free-form reason text as the only binding.

Audit append and policy-decision artifact creation occur before returning `ExecutionPermit`. Any write error returns a blocked/invalid outcome and no permit.
Audit persistence must use the engagement root's symlink-aware artifact boundary or equivalent
canonical-ancestor checks; direct `root.join("audit")` trust is insufficient for an authorization
grant.

## Codebase map

Inspect:

- `crates/action-policy/src/lib.rs`
- `crates/engagement/src/scope.rs`
- `crates/engagement/src/audit.rs`
- `crates/hunt-engine/src/plan.rs`
- `crates/hunt-engine/src/ssrf.rs`
- `crates/hunt-engine/Cargo.toml`

Likely additions:

- `crates/hunt-engine/src/policy.rs`
- `crates/hunt-engine/tests/policy_gate.rs`

Expected dependency additions: path dependencies on `action-policy` and `engagement`, plus `time`. Use existing workspace-compatible versions and minimal features.

## Behavior-first tests

Prove:

1. Valid in-scope/current/automation-allowed/bounty-eligible policy yields one permit bound to the exact plan hash.
2. Ambiguous and out-of-scope decisions yield no permit.
3. Missing and expired rules yield no permit.
4. `automation_allowed = false` yields no permit.
5. `bounty_eligible = false` blocks; `None` requires approval.
6. A granted approval permits unknown eligibility and the decision records the approval ID.
7. A mismatched target, scope artifact hash, rules artifact hash, or plan hash yields no permit.
8. Model/caller arguments cannot substitute `ReadOnly` risk for the plan's `LowActive` risk.
9. Audit write failure yields no permit.
10. Every outcome writes exactly one audit event and zero network requests.
11. `ExecutionPermit` cannot be constructed or deserialized by an external integration test.
12. Future-captured rules block, even if their expiration is in the future.
13. `HuntRisk::Observe` has an explicit tested mapping or is rejected; it is never silently coerced.
14. An audit-directory symlink escape or other hardened-root failure yields no permit.

Use a loopback request counter as a zero-network sentinel where useful.

## Non-goals

- Do not execute HTTP.
- Do not redesign all `action-policy` action kinds.
- Do not introduce a second policy rule table in `hunt-engine`.
- Do not persist campaign state in SQLite.
- Do not accept model confidence or prose as policy input.

## Verification

```bash
cargo test -p action-policy
cargo clippy -p action-policy --all-targets -- -D warnings
cargo test -p engagement
cargo test -p hunt-engine --test policy_gate
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p action-policy -p engagement -p hunt-engine -- --check
git diff --check
```

## Done means

There is no public Rust path from an `SsrfProbePlan` to network execution without an exact-plan permit produced by current scope/rules policy and a successful audit write.
