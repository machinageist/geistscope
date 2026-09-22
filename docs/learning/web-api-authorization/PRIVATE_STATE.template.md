# Private Learning State Template

Copy this file to the private notebook as:

```text
~/.local/share/geistscope-learning/LEARNING_STATE.md
```

Do not commit the completed file. It is a secret-free progress handoff, not an evidence store. Keep detailed case files under the private notebook’s `cases/` directory and maintain `INDEX.md` manually.

Never record passwords, cookies, bearer tokens, recovery material, target hostnames, raw request/response bodies, screenshots containing sensitive material, or unredacted lab evidence.

```markdown
# GeistScope Private Learning State

Status: not started | active | paused | complete

## Current position

- Week: 01
- Session: 1 — protocol/study
- Chunk: 0-30
- Block status: not started
- Next safe action: Start Week 01, Session 1, chunk 0-30.

## Active remediation override

- Remediation status: none | required | in progress | passed
- Blocked curriculum position: —
- Prerequisite gap: —
- Next remediation action: —
- Fresh recheck result: —

When remediation status is `required` or `in progress`, it overrides the curriculum position above. A fresh AI session resumes the remediation interlude, not the blocked lab or retrospective block. After a `retained` recheck, manually set the remediation status to `passed` and set the blocked block to `not started` or `in progress` before resuming it.

## Completion ledger

| Position | User-confirmed status | Private artifact alias | Notes safe to share with an AI |
|---|---|---|---|
| Week 01 / Session 1 / 0-30 | not started | — | — |

## Quiz ledger

| Quiz scope | Result: retained/developing/gap | Main concept(s) | Remediation or next retrieval prompt |
|---|---|---|---|
| — | — | — | — |

## Retained concepts

- None recorded yet.

## Developing concepts or gaps

- None recorded yet.

## Private artifact index summary

- Case files completed: 0
- Controlled-lab artifacts completed: 0
- Classification coverage: candidate: 0; negative: 0; invalid: 0
- Repeated manual friction observed in three or more cases: none recorded

## Safety self-check

- Two controlled identities used when the exercise required comparison: not applicable yet
- Credentials/session values/raw traffic kept out of notes and chat: yes
- All target-facing activity remained manual and inside the permitted lab: not started

## Next-session prompt context

State only the minimum context needed for a coach to resume. Use aliases, not targets or secrets.

- Current question or confusion:
- What I can explain without notes:
- What I need to revisit:
- Constraints for the next session:
```
