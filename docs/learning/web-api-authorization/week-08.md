# Week 08 — Redacted evidence and human verification runbooks

Status: active learning unit

## Weekly goal

Turn an observation into a safe, reproducible explanation without leaking secrets or teaching unsafe behavior.

## Expected private artifact

One redacted human-verification runbook tied to a controlled lab case.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Study evidence versus narrative

Review the learning-track runbook requirements. Separate observed facts from interpretation and from the next verification step.

### 30–60 min — Practice redaction

On a synthetic request/response, identify what must not be copied: cookies, bearer tokens, passwords, recovery material, personal data, and unnecessary payload detail.

### 60–90 min — Write runbook skeleton

Create a blank runbook skeleton with preconditions, controlled identities, minimal action, secure versus vulnerable outcomes, false-positive checks, evidence, cleanup, and stop condition.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Revisit best candidate-quality case

Choose your clearest prior candidate-quality lab case. Do not change the target; use the record to reconstruct the exact safe reasoning path.

### 30–60 min — Write a human runbook

Write the steps so another careful learner could understand the boundary without receiving credentials or a destructive action recipe.

### 60–90 min — Perform a self-reproduction check

Follow your own runbook against the controlled lab only. Record where it is unclear, overbroad, or dependent on hidden knowledge.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Improve the case file

Update the selected private case file with the runbook reference and any corrections from the self-reproduction check.

### 30–60 min — Add evidence-quality notes to index

Record which evidence facts made the runbook reproducible and which details were intentionally excluded.

### 60–90 min — Decide whether friction repeated

Assess whether evidence organization or redaction has occurred as a real friction at least three times. Only documented repetition can justify a future inert helper proposal.

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
