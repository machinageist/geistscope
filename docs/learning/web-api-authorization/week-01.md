# Week 01 — Revalidate HTTP and one known IDOR/BOLA lab

Status: active learning unit

## Weekly goal

Turn prior exposure into a current, no-hints baseline. Produce the first complete secret-free case file.

## Expected private artifact

One full private case file for a no-hints IDOR/BOLA revalidation.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Reconstruct HTTP messages

Read the HTTP overview and messages sections in `../../WEB_API_AUTHORIZATION_LEARNING_TRACK.md`. In your own words, label method, host, path, headers, cookie/session state, body, status, and response body on one synthetic example.

### 30–60 min — Separate authentication from authorization

Write two definitions without consulting a source: authentication answers who the caller is; authorization answers whether that caller may perform this action on this object. Then correct the definitions against the learning-track references.

### 60–90 min — State the expected boundary

Choose one previously solved PortSwigger authorization lab. Before opening hints or solution material, write the expected rule in one sentence: identity, object, action, and expected allow/deny result.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Establish controlled context

Open the chosen PortSwigger lab. Identify the relevant identity/role context and object reference location. Do not use hints. Record only aliases and redacted request facts.

### 30–60 min — Perform one minimal manual comparison

Navigate normally, inspect the relevant request, and make only the smallest manual change necessary to test the written authorization rule. Do not automate, crawl, replay by script, or broaden the target.

### 60–90 min — Stop and classify

Record what happened. Use `candidate` only when the observation supports a boundary-violation signal; use `negative` when the boundary held for the tested path; use `invalid` when ownership, identity, or meaning is unclear.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 001

Create the first private Markdown case file from the template. Include expected rule, identities as aliases, object ownership, minimal change, observed response, classification, limitations, and next safe step.

### 30–60 min — Update INDEX.md

Add the case to the private index: concept, lab, classification, time spent, confusion points, and any manual friction. Do not record credentials, tokens, or raw request bodies.

### 60–90 min — Diagnose retained skill

Answer: What did I remember independently? What required rediscovery? What would have made me misclassify the result? Do not propose GeistScope code from one case.

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
