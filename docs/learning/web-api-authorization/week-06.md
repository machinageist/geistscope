# Week 06 — API object references and request locations

Status: active learning unit

## Weekly goal

Find authorization-relevant references in paths, query parameters, and request bodies without treating every identifier as vulnerable.

## Expected private artifact

An API-focused authorization case with explicit request-location and state-risk reasoning.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Map request locations

Review API-testing material. Make a synthetic table for object references in URL paths, query parameters, form fields, JSON bodies, and headers.

### 30–60 min — Learn method and state semantics

For each relevant method, mark whether it is normally read-oriented or may change state. Explain why changing state increases the need for caution.

### 60–90 min — Design a manual comparison

Choose one synthetic API request and describe the single field you would inspect, the ownership fact you need, and the secure expected outcome.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Discover from normal behavior

Use a PortSwigger API-oriented lab and normal application behavior to identify a candidate endpoint. Do not enumerate broadly or automate discovery.

### 30–60 min — Trace object reference

Identify where the object reference travels in the request. Confirm whether it is client-controlled and whether another server-side ownership check should exist.

### 60–90 min — Make a bounded observation

Carry out one manual, permitted comparison. Prefer read-only paths. If a request might change data, stop and write the safety concern instead.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 006

Record the request location, method, expected rule, and why the operation was read-only or why you stopped.

### 30–60 min — Update index and coverage

Update the index with object-reference location and state-changing risk. Review whether you have enough quality examples of candidate, negative, and invalid.

### 60–90 min — Plan transfer relevance

Write one sentence describing which learned authorization idea could later transfer to HTB without turning the active product into a general CTF tool.

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
