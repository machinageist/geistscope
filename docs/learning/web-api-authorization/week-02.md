# Week 02 — Sessions, cookies, and identity separation

Status: active learning unit

## Weekly goal

Understand how two controlled browser identities remain distinct and why session material is secret material.

## Expected private artifact

Second private case file plus an explicit two-identity/session map.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Read cookie/session foundations

Read the cookie and controlled-identity sections of `../../WEB_API_AUTHORIZATION_LEARNING_TRACK.md`. Explain why a session cookie can act like a temporary password.

### 30–60 min — Draw two identity states

Draw a synthetic `lab-a` / `lab-b` diagram: browser profile, account alias, tenant/role label, owned object, and expiry/relogin point. Do not write any actual login value.

### 60–90 min — Define session mistakes

List three mistakes that would invalidate an authorization test: using the wrong account, accidentally sharing a browser session, or failing to establish who owns the object.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Set up separate sessions

Use distinct controlled sessions or the PortSwigger-provided identities. Confirm which identity is active before each action. Record labels only.

### 30–60 min — Inspect authorization-relevant state

Find where the application references a user, role, resource, or session-dependent action. Observe normal behavior first; do not force a request change immediately.

### 60–90 min — Compare safely

Perform a minimal manual authorization comparison. Prefer a read-only path. Stop if you cannot establish identity or ownership from the lab context.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 002

Write a second private case file. Emphasize the identity/session model and exactly how you prevented cross-session confusion.

### 30–60 min — Update the index and friction log

Update `INDEX.md`. Note repeated friction only if it actually occurred in both cases; do not generalize from theory.

### 60–90 min — Prepare for code case study

Write three manual invariants you now understand: separate identities, known object ownership, and a stated expected boundary. These become the basis for the next source walkthrough.

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
