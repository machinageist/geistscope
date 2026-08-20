# GS-4.1 SSRF Specification — Blind Review Iteration 1

Date: 2026-08-13
Spec SHA-256 reviewed: `727264e3f394a5ede6e2ba76882f5a23461e98c4c481e2dfa9d2a02ef35cb8ed`
Verdict: FAIL
Auto-fail: none
Reviewer composite: 2.008/3 (66.94%)
Binding threshold: 2.25/3 (75%) per `docs/gauntlet/criteria.md`

The review prompt incorrectly mentioned an 85% threshold, but that did not affect the verdict: the measured composite was also below the binding 75% threshold, Lens 1 and Lens 4 averages were below 2.0, and several criteria scored 1.

## Blocking findings

1. Evidence/result publication was circular because the spec placed authoritative `result.json` inside the bundle while requiring publication and revalidation before verified result construction.
2. Minimum traffic-corpus integration and durable negative-knowledge handoff were underspecified.
3. Pre-checkpoint interruption, restart, concurrency, and reauthorization behavior was ambiguous.
4. Stable summary/error types, nullability, schema/golden location, and canonicalization were incomplete.
5. CLI placeholder commands were mixed into implementation gates before the required architecture decision.
6. Runbook/replay details, callback startup authority, anonymous/authenticated identity scope, distress stops, and the SSRF-specific aggregate ceiling needed binding contracts.

## Iteration 2 remediation

- Replaced bundle `result.json` with non-authoritative `semantic-verdict.json`.
- Defined publish → committed-reference construction → final-file validation → authoritative `HuntResult`/service output as an acyclic sequence; derived outputs are not bundle members.
- Added the real traffic-corpus import seam and made the immutable bundle the minimum durable coverage/negative-knowledge ledger.
- Added a minimum explanatory output contract without claiming the deferred learning profile.
- Bound pre-checkpoint execution to one process/one active run, fail-closed non-resumable interruption, fresh run/policy/approval on retry, and inert callback authority until permit issuance.
- Defined V1 summary/error structures, nullability, closed enum behavior, anonymous-only target identity, schema/golden paths, and canonical ordering.
- Bound a 4 MiB SSRF aggregate ceiling, stop conditions, fixed runbook schema, and offline replay validation.
- Split executable Phase A gates from mandatory post-decision Phase B command amendments; removed fake package placeholders.
- Preserved Design Checkpoint 4 for Jeff's transport/persistence/CLI decision rather than inventing it.

A fresh SHA-bound blind review is required. This scorecard does not approve iteration 2.
