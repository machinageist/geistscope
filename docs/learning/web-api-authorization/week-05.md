# Week 05 — Vertical and context-dependent authorization

Status: active learning unit

## Weekly goal

Learn that authorization is not only object IDs: roles and workflow state matter too.

## Expected private artifact

A role- or workflow-oriented access-control case and, if eligible, a second frozen-code teaching note.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Study vertical access control

Review role-based and function-level access-control concepts. In plain language, distinguish “may user A read object B?” from “may ordinary user A invoke administrator function X?”

### 30–60 min — Study context-dependent rules

Write a synthetic workflow rule such as “a user may edit a draft they own but may not alter an approved record.” Identify identity, object, action, and state.

### 60–90 min — Read code after behavior

If you have completed four private cases, use this slot for `code-study-002`: inspect one small frozen validation or policy path and map it to identity, action, and decision. Otherwise continue concept review.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Select a role or workflow lab

Choose a PortSwigger access-control exercise that emphasizes a role or context boundary. State the rule before testing.

### 30–60 min — Observe normal and denied behavior

Navigate through normal behavior first. Identify what is role-controlled or workflow-controlled before changing an input.

### 60–90 min — Perform one minimal comparison

Test the smallest relevant difference manually. Record whether a response demonstrates a candidate, a secure negative, or insufficient context.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 005

Write the case with a clear distinction between object-level and function/context-level authorization.

### 30–60 min — Update index patterns

Add a pattern note: did the relevant decision depend on object ownership, role, state, or several facts together?

### 60–90 min — Review teaching friction

Ask whether any manual friction has occurred in at least three documented cases. If not, no GeistScope helper is eligible.

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
