# Week 11 — Real-program readiness rehearsal without a real target

Status: active learning unit

## Weekly goal

Practice the restraint, scope reading, and evidence standards required before any public-program exploration.

## Expected private artifact

A synthetic policy preflight, one constrained lab case, and a self-audit.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Read a synthetic policy checklist

Use a synthetic program-policy scenario: in-scope assets, prohibited actions, authentication rules, rate limits, and disclosure expectations. Identify unknowns that require stopping.

### 30–60 min — Map policy to action

For each possible manual action, label it as allowed, prohibited, unclear, or unnecessary. Explain why unclear means stop rather than “probably okay.”

### 60–90 min — Source case-study slot

If eligible, perform `code-study-005` on a frozen scope/policy validation path. Focus on fail-closed behavior: what happens when the system lacks a clear allow decision?

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Run a policy preflight

Before opening a lab exercise, fill out the same preflight fields you would use later: authorization basis, target, allowed actions, prohibited actions, session identities, data sensitivity, and stop conditions.

### 30–60 min — Perform one low-noise manual exercise

Use a PortSwigger lab or other controlled environment. Keep the interaction narrowly aligned with the preflight rather than following every potential lead.

### 60–90 min — Audit your own compliance

Compare what you did against the preflight. Record any drift, assumption, or unplanned step. This is practice for discipline, not a compliance claim.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 010

Add the preflight and self-audit to the private case file.

### 30–60 min — Perform readiness self-review

Review secret handling, scope reasoning, classification discipline, runbook quality, and evidence limits across your cases.

### 60–90 min — Identify remaining gaps

List concrete gaps still preventing public-program practice. A gap list is success if it is honest and actionable.

## End-of-week check

Run the five mandatory weekly retention questions in [the quiz protocol](QUIZ_PROTOCOL.md) before starting the next week. The questions below are supplemental retrospective prompts.

Before starting the next unit, answer:

1. What did I observe directly?
2. What did I infer, and what evidence limits that inference?
3. What remains unknown?
4. Did any manual friction recur in at least three documented cases?
5. Did I stay inside the learning-phase automation and data boundaries?

If an answer is unclear, record it as a gap. Do not solve it by expanding scope or building a tool.

## References

- [Learning track and resources](../../WEB_API_AUTHORIZATION_LEARNING_TRACK.md)
- [Decision record](../../PRODUCT_RECOVERY_DECISIONS.md)
- [Unit index](README.md)
