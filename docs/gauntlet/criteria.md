# GeistScope Completion Criteria

Approved from the 2026-08-13 gauntlet interview and execution direction. Full rationale is in `PLAN.md` Sections 4–5.

## Scoring

Each criterion receives 0–3:

- 0: missing, contradicted, fabricated, or not executable
- 1: superficial or materially incomplete
- 2: correct, usable, tested, and acceptable
- 3: best-in-class and backed by strong acceptance evidence

A feature passes only if no auto-fail triggers, no criterion is 0, every lens average is at least 2.0, the weighted composite is at least 2.25, no lens has more than two scores of 1, feasibility is not `infeasible`, and the verifier personally ran every claimed passing command.

## Lens 1 — Adaptive Hunt Completion and Competitive Depth (35%)

- 1A Closed-loop continuity
- 1B Traffic-centric manual depth
- 1C Automation depth without payload spray
- 1D Offline proof for priority vulnerability families
- 1E Coverage and negative knowledge
- 1F Persistent, explainable adaptive-loop differentiation

Benchmarks: Burp Suite, Caido, Nuclei/ProjectDiscovery, ZAP, mitmproxy, and OWASP WSTG. Match capability floors; do not clone interfaces.

## Lens 2 — Authorization, Safety, and Deterministic Control (30%)

- 2A Effective default-deny scope and current rules
- 2B AI/control-plane separation
- 2C Finite budgets and hard stop conditions
- 2D Identity and secret isolation
- 2E Controlled offline execution fixtures
- 2F Auditability, provenance, licensing, and dependency safety

## Lens 3 — Evidence, Finding, and Report Integrity (20%)

- 3A Deterministic evidence contracts
- 3B Immutable, contained, hashed artifacts
- 3C Reproducible minimized proof
- 3D Truthful result classes
- 3E Bounded impact and report claims
- 3F Fail-closed evidence/persistence behavior

## Lens 4 — Operator and Agent API Usability (15%)

- 4A One engine with thin clients
- 4B Versioned model-agnostic typed contracts
- 4C Efficient expert workflow
- 4D Learning profile over identical facts/gates
- 4E Crash-safe resumability and reauthentication
- 4F Install diagnostics and accessible terminal operation

## Auto-fail rules

1. Active I/O before deterministic scope, freshness, policy, approval, and budget checks.
2. Default-allow scope, bypassable deny precedence, or execution under ambiguous/stale authorization.
3. Model control over scope, risk, approval, executable secrets, evidence satisfaction, or verification.
4. Raw secrets or unredacted sensitive data in model-visible state, logs, reports, fixtures, or committed artifacts.
5. Verified findings without capability-specific deterministic evidence satisfaction.
6. Unbounded active plans or missing cleanup for state-changing behavior.
7. Artifact escape, symlink escape, overwrite, missing hashes, or retained verification after write/integrity failure.
8. Acceptance requiring live third-party targets or uncontrolled callbacks.
9. Unapproved destructive, persistence, evasion, credential-harvesting, denial-of-service, or post-exploitation behavior.
10. Fabricated/overstated impact or concealed negative/inconclusive outcomes.
11. Client-side duplication/bypass of engine policy/orchestration or arbitrary agent shell access.
12. Unjustified, incompatible, unlicensed, or known-vulnerable dependency additions.
13. Flaky/Internet-dependent tests or tests unable to distinguish vulnerable, secure, and blocked behavior.
14. Weakening tested safety invariants without approved migration and replacement tests.
15. Documentation claiming planned/prototype/quarantined behavior is shipped or leaving restart state ambiguous.
16. Deleting legacy behavior without inventory, salvage analysis, and a verified replacement/disposition.
