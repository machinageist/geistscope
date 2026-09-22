# Week 03 — Scope and identity validation as a code case study

Status: active learning unit

## Weekly goal

Connect manually learned boundaries to one small frozen legacy code path without reviving the old product.

## Expected private artifact

One frozen-code teaching note and a third private authorization case.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Read the legacy scope path

Open the frozen legacy `engagement` scope implementation only after reviewing your first two case files. Identify inputs, normalization, allow rules, deny rules, and result categories.

### 30–60 min — Translate code to the manual model

For each major function you read, write the manual equivalent: what fact is it trying to establish, what ambiguous input does it reject, and what could go wrong if it guessed?

### 60–90 min — Write a teaching note

Create a private short note called `code-study-001`: one invariant the code expresses well, one question you cannot answer yet, and one reason the source is not a substitute for a lab.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Choose a fresh authorization scenario

Select a PortSwigger exercise that differs from the first two cases. State the expected identity/object/action boundary before interacting with the challenge.

### 30–60 min — Inspect normal flow

Use ordinary navigation to find the relevant request. Identify whether the object reference is in a path, query, form body, JSON body, or application state.

### 60–90 min — Make one controlled observation

Perform one minimal manual comparison and classify it. If the result is ambiguous, preserve that ambiguity as `invalid` rather than guessing.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 003

Write the third case file with a precise expected rule and an explicit statement of what the evidence does not prove.

### 30–60 min — Compare all three cases

In the index, compare where object identity appeared, how identity was established, and which evidence was most useful. Note only observed repeated friction.

### 60–90 min — Review boundaries

Check that no notebook entry contains credentials, session tokens, raw target details, or copied private artifacts. Correct the notes manually if needed.

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
