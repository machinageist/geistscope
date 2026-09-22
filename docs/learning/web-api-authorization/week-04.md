# Week 04 — Horizontal access control: user A versus user B

Status: active learning unit

## Weekly goal

Practice the core BOLA/IDOR pattern with an ownership matrix and one deliberate negative or invalid observation.

## Expected private artifact

A controlled ownership matrix and a deliberately honest candidate, negative, or invalid result.

## Before you start

- Use only the authorized training environment selected for this unit.
- Keep credentials and session material out of the notebook.
- Use the [private case-file template](CASE_FILE.template.md) and update private `INDEX.md`.
- Do not add or revive GeistScope product features while completing this unit.

## Session 1 — Protocol/study (90 minutes)

### 0–30 min — Study horizontal access control

Review the Access control and OWASP BOLA material linked from the learning track. Define horizontal access control using a two-user, two-object example.

### 30–60 min — Build the ownership matrix

Before the lab, write the four-cell matrix: A→A allowed, A→B denied, B→A denied, B→B allowed. Identify which cell the exercise will test.

### 60–90 min — Predict secure and insecure evidence

Describe what you expect a secure response to look like and what evidence would support a candidate. Include the possibility that a changed response is still insufficient evidence.

## Session 2 — Controlled lab (90 minutes)

### 0–30 min — Establish ownership facts

In a controlled authorization lab, identify the two identities and separately owned records. Do not assume sequential numeric IDs prove ownership.

### 30–60 min — Test one boundary manually

Perform one carefully scoped A→B or B→A comparison. Preserve the smallest redacted fact needed to explain the result.

### 60–90 min — Seek a non-candidate outcome

If the tested boundary holds, record a `negative`. If the lab gives no meaningful secure comparison, state why the observation is `invalid`. Do not force every exercise to become a candidate.

## Session 3 — Private notebook and retrospective (90 minutes)

### 0–30 min — Create case file 004

Write the ownership matrix into the case file, then record the exact boundary tested and classification.

### 30–60 min — Update classification coverage

Update INDEX.md so you can see whether you now have candidate, negative, and invalid observations. Missing classes are a learning gap, not a reason to manufacture evidence.

### 60–90 min — Identify one question

Write one unanswered question about authorization behavior that you can pursue in a later lab. Do not answer it with automation or a new tool.

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
