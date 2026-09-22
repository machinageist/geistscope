# Week 09 — Authorization review from first principles

Status: active learning unit

## Weekly goal

Solve a fresh authorization exercise by deriving the model before touching the request.

## Expected private artifact

A fresh no-hints authorization case solved from a written first-principles checklist.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Build a first-principles checklist

Write the investigation order: scope/lab authorization, identity, object ownership, action, expected rule, normal behavior, smallest comparison, classification, evidence, stop condition.

### 30–60 min — Review common mistaken shortcuts

List why these shortcuts fail: guessing IDs, treating 200 as success proof, assuming a token proves authorization, or using a changed response as a finding.

### 60–90 min — Frozen-code case-study slot

If eligible after two more artifacts, do `code-study-004` on a small frozen scope or input-validation path. Otherwise refine your checklist.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Select a fresh PortSwigger target

Choose an uncompleted authorization/API exercise. Do not read solution material. Write the checklist before navigation.

### 30–60 min — Execute the manual workflow

Use only normal interaction, careful request inspection, and a minimal manual comparison. Respect every stop condition.

### 60–90 min — Explain outcome aloud and in notes

Before writing the case file, verbally explain why the result is candidate, negative, or invalid. If you cannot explain it, classify it invalid and note the missing fact.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 008

Use the full template and include the first-principles checklist outcome.

### 30–60 min — Compare to week 1

Compare this case with the week-1 diagnostic. Identify concrete improvements in request reading, identity handling, and evidence—not feelings of confidence.

### 60–90 min — Review code eligibility

If you believe a helper is needed, test the proposal against the three-instance rule. Otherwise write “no helper justified” and move on.

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
