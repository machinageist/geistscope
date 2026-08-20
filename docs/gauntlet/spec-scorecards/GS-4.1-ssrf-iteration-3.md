# GS-4.1 SSRF Specification — Iteration 3 Scorecard

Date: 2026-08-13
Reviewed SHA-256: `7f02f632fc3c09f073e5ce1470d196e5841ec2b0a2462b9868d0e4d2df7e295c`
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

No criterion scored 0. Each lens had at most one score of 1. The reviewer applied the repository's binding 2.25/3 rule rather than the obsolete 85% rule.

## Criterion scores

- 1A 2; 1B 2; 1C 3; 1D 1; 1E 2; 1F 2.
- 2A 3; 2B 3; 2C 3; 2D 2; 2E 3; 2F 2.
- 3A 3; 3B 3; 3C 2; 3D 2; 3E 2; 3F 3.
- 4A 2; 4B 3; 4C 2; 4D 2; 4E 1; 4F 2.

## Approved contract

- Production corpus lookup and typed redacted observation/plan comparison provide minimum slice-level manual depth.
- Deterministic explanation and closed `next_action_code` provide persistent slice-level differentiation without claiming completion of the cross-campaign learning UI.
- The authoritative result remains outside the bundle and is constructed only after exclusive publication and committed-byte revalidation.
- The manifest hashes `runbook.md`; the runbook excludes the enclosing manifest digest. `CommittedBundleIdentity.manifest_sha256` is derived after publication and is never backfilled into a bundle artifact.
- Exact offline replay, interruption, diagnostics, callback, budget, stable-envelope, secret, and legacy-disposition contracts are executable acceptance requirements.

## Exact-snapshot clarification

The approved SHA includes the final consistency clarification: the primary flow lists the same non-authoritative `semantic-verdict.json` fields required by the evidence section—class/reason, identity bindings, satisfied/missing requirement IDs, bounded explanation, and `next_action_code`. The reviewer confirmed the hash was identical at the start and end of review.

## Reviewer execution notes

The reviewer passed 24 `evidence-core` tests, current `action-policy`/`engagement` tests, 75 `hunt-engine` tests, focused formatting, and `git diff --check`. Strict `hunt-engine` Clippy still fails because production promotion has not yet wired `EvidenceContract::validate_local`; the spec identifies that implementation gap and does not claim the gate currently passes.
