# Web/API Authorization Learning Units

Status: active learning curriculum
Date: September 22, 2026

This directory converts the 12-week manual-first authorization learning vertical into twelve weekly documents. Each weekly document contains three 90-minute sessions:

1. protocol/study;
2. controlled hands-on lab; and
3. private notebook/retrospective.

Every 90-minute session is divided into three explicit 30-minute chunks. Do not merge or skip the final retrospective chunk to make room for extra lab work.

## Non-negotiable boundaries

- Use only controlled labs and permitted CTF environments during this curriculum.
- Keep actual passwords, cookies, bearer tokens, recovery material, target details, and raw evidence out of the public repository and private Markdown notebook.
- Use two controlled identities when an exercise requires authorization comparison.
- All target-facing navigation, account switching, request comparison, and testing decisions remain manual.
- Existing GeistScope code is frozen teaching material. After every two completed private controlled-lab artifacts, one study session may become a frozen-code walkthrough tied to a concept already practiced manually.
- The public GeistScope repository remains code and technical documentation. `mg-server` is the publication surface for completed, sanitized concept milestones.

## Documents

- [Week 01 — Revalidate HTTP and one known IDOR/BOLA lab](week-01.md)
- [Week 02 — Sessions, cookies, and identity separation](week-02.md)
- [Week 03 — Scope and identity validation as a code case study](week-03.md)
- [Week 04 — Horizontal access control: user A versus user B](week-04.md)
- [Week 05 — Vertical and context-dependent authorization](week-05.md)
- [Week 06 — API object references and request locations](week-06.md)
- [Week 07 — Evidence quality: candidate, negative, and invalid](week-07.md)
- [Week 08 — Redacted evidence and human verification runbooks](week-08.md)
- [Week 09 — Authorization review from first principles](week-09.md)
- [Week 10 — HTB transfer test under a narrow contract](week-10.md)
- [Week 11 — Real-program readiness rehearsal without a real target](week-11.md)
- [Week 12 — Capstone review, evidence synthesis, and next-slice decision](week-12.md)

## Supporting documents

- [Learning track and web resources](../../WEB_API_AUTHORIZATION_LEARNING_TRACK.md)
- [Product-recovery decision record](../../PRODUCT_RECOVERY_DECISIONS.md)

## AI-session workflow

Start every AI-assisted learning session with the repository-level
[`AGENTS.md`](../../../AGENTS.md), then follow:

1. [AI learning-session protocol](AI_SESSION_PROTOCOL.md) — resume and advancement rules;
2. [Retention quiz protocol](QUIZ_PROTOCOL.md) — periodic recall and remediation rules;
3. [Private learning-state template](PRIVATE_STATE.template.md) — public template for the private progress file; and
4. [Private case-file template](CASE_FILE.template.md) — secret-free evidence and retrospective format.

The initialized private state is outside Git at
`~/.local/share/geistscope-learning/LEARNING_STATE.md`. It begins at Week 01,
Session 1, chunk 0–30. Ask an AI to read `AGENTS.md` and that exact private
state file, then resume the indicated chunk. Do not ask it to search the
private notebook.

## Private notebook reminder

The public repository does not hold the real case files. Keep one secret-free Markdown case file per session in the private notebook and maintain its `INDEX.md`. The notebook supplies the evidence for any future code proposal.
