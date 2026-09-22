# Week 12 — Capstone review, evidence synthesis, and next-slice decision

Status: active learning unit

## Weekly goal

Determine whether you met the learning gate and whether any future GeistScope helper has earned a narrowly approved specification.

## Expected private artifact

A capstone private case, a completed learning-gate review, and either one justified future-helper proposal or an explicit no-helper decision.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Audit the evidence set

Review all private case files and INDEX.md. Confirm that candidate, negative, and invalid classifications each have honest support, or record which one remains missing.

### 30–60 min — Review the decision record

Read `../../PRODUCT_RECOVERY_DECISIONS.md`. Identify any decision that was tested by actual practice and any assumption that remains untested.

### 60–90 min — Build the capstone checklist

Prepare a checklist for the final controlled exercise: scope/preflight, identities, ownership, expected rule, manual test, classification, redacted evidence, runbook, cleanup, and retrospective.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Choose one capstone exercise

Select a fresh controlled authorization/API exercise matching the established vertical. Do not select a new vulnerability family because it seems more exciting.

### 30–60 min — Execute manually

Perform the full manual workflow. Use no target-facing automation. Stop if you cannot establish the required identity, ownership, or authorization facts.

### 60–90 min — Produce complete controlled artifact

Write the classification, evidence references, limitations, and human verification runbook. Preserve the fact that it is a learning artifact, not a verified real-world finding.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Complete capstone case and index

Create the final private case and update index coverage, time, repeated friction, and transfer notes.

### 30–60 min — Decide whether any helper earned a proposal

For each proposed helper, require three observed instances, the smallest local-only behavior, what it must not automate, a controlled acceptance test, and explicit user approval. “None” is a valid result.

### 60–90 min — Prepare publication candidate

If a concept milestone is genuinely complete, outline a synthetic, self-contained `mg-server` retrospective. Do not publish from private notes directly and do not claim product readiness.

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
