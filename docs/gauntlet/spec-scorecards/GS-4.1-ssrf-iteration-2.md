# GS-4.1 SSRF Specification — Iteration 2 Scorecard

Date: 2026-08-13
Reviewed SHA-256: `9cff07c2fbad1b5454b76ddef31c450fe434440ad2d75821c76363f39035c007`
Verdict: FAIL
Auto-fail: none
Feasibility: feasible with caveats
Composite: 2.100/3

## Lens results

- Adaptive Hunt Completion: 1.667 — below 2.0; three criteria scored 1.
- Authorization and Safety: 2.667 — pass.
- Evidence and Reporting: 2.333 — pass.
- Operator/API Usability: 1.667 — below 2.0.

## Binding failures

- Composite below 2.25.
- Lens 1 and Lens 4 below 2.0.
- Lens 1 had more than two scores of 1.

## Important findings

1. Traffic/manual workflow remained import-only; capture/search/comparison and adaptive follow-up were too heavily deferred.
2. Replay named an undefined package helper rather than an exact executable interface.
3. Pre-checkpoint interruption acceptance was not directly present in the Phase-A E2E matrix.
4. Startup/readiness diagnostics remained entirely deferred.

## Iteration-3 remediation

The live successor is SHA `2da8091ee127bde2d1c6041fc800b4249fffbc4eeb01c174b0653a8a06ad772f`. It adds a production corpus lookup and typed redacted observation/plan comparison; persistent deterministic explanation and closed next-action codes; an exact environment-driven offline replay test command; a Phase-A interruption matrix; and pre-checkpoint application-service diagnostics. IDOR/injection and broad cross-request traffic UI remain honest sibling/parent deferrals.
