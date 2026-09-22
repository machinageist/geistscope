# Week 10 — HTB transfer test under a narrow contract

Status: active learning unit

## Weekly goal

Test whether the authorization reasoning transfers to a less guided environment without broadening GeistScope requirements.

## Expected private artifact

One constrained HTB transfer case tied to a specific completed PortSwigger concept.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Select transfer criteria

Choose an HTB exercise only if it has a clear web/API authorization-relevant component. State which PortSwigger concept it will test. If it does not fit, remain in PortSwigger.

### 30–60 min — Define exclusions

Write what will not become product scope from this exercise: host exploitation, privilege escalation, broad recon tooling, packet analysis, or unrelated CTF mechanics.

### 60–90 min — Build a transfer hypothesis

State the identity/object/action boundary you expect to encounter and how you will classify an ambiguous outcome.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Orient manually

Use the HTB environment only as permitted by its rules. Look for the chosen web/API concept; do not run generalized tooling because the box exists.

### 30–60 min — Apply the learned method

Follow the same manual order: establish identity, ownership, expected rule, normal flow, minimal comparison, classification.

### 60–90 min — Stop at the concept boundary

Record transfer success or failure. If the route becomes a different vulnerability family, note it and stop rather than expanding the current vertical.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 009

Write a transfer-case file. Name the PortSwigger concept being tested and the facts that did or did not transfer.

### 30–60 min — Update index

Mark the environment as HTB transfer, not a new product requirement. Add any repeated friction only if it matches prior manual work.

### 60–90 min — Compare constraints

Write one paragraph: what did PortSwigger make clear that HTB obscured, and what did HTB reveal about your understanding?

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
