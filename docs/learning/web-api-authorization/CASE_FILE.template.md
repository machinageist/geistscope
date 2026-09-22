# Private Case-File Template

Copy this template into the private notebook’s `cases/` directory. Do not commit completed case files to GeistScope or paste sensitive content into an AI session.

A case file records what you understood and observed in a controlled lab. It is not a report of a verified vulnerability.

```markdown
# Case [local alias]

## Learning context

- Curriculum position: Week NN / Session N / chunk NN-NN
- Authorized environment label: [generic local label only]
- Date: [local date]
- Concept: [for example, horizontal authorization]
- Time spent: [minutes]

## Expected authorization rule

In one sentence, name the identity, object, action, and expected allow/deny boundary.

## Controlled context

- Identity aliases: lab-a / lab-b / role alias as applicable
- Object ownership or role facts: [redacted summary]
- Preconditions I confirmed manually: [redacted summary]
- Scope boundary: controlled lab or permitted CTF only

## Minimal manual comparison

- Normal action or request location: [redacted semantic description]
- Smallest manual change: [redacted semantic description]
- Why this change tests the expected rule: [your reasoning]
- Automation used: none

## Observation

- Observable result: [redacted semantic result]
- What I observed directly:
- What I inferred:
- What remains unknown:

## Learning-phase classification

Choose one only:

- `candidate`: a boundary-violation signal was observed, but this is not `verified`;
- `negative`: the tested boundary held for this path;
- `invalid`: identity, ownership, scope, request meaning, or observation quality was insufficient.

Classification: [candidate | negative | invalid]
Reasoning and limits:

## Evidence hygiene

- No passwords, cookies, bearer tokens, recovery material, hostnames, raw request/response bodies, or sensitive screenshots recorded: yes/no
- Redaction limits or missing evidence:
- What another learner could reproduce safely in a comparable controlled lab:

## Retrospective

- What I remembered independently:
- What required rediscovery:
- What could have caused a misclassification:
- Manual friction observed:
- Is this friction repeated across three documented cases? [no / yes, aliases only]
- Next safe learning action:
```
