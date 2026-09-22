# Retention Quiz Protocol

Status: active learning workflow

## Purpose

Quizzes measure whether a concept is available from memory and can be applied to a small synthetic scenario. They are not scores for security ability, finding verdicts, or permission to test a live target.

The AI asks first and explains second. The user may use a gap as evidence to revisit material; a gap is not failure.

## Cadence

| Trigger | Quiz format | Time budget |
|---|---|---|
| Week 1, Session 1 | No opening quiz; establish a baseline during normal teaching. | 0 minutes |
| Start of every later 90-minute session | Three short retrieval questions from the prior relevant material. | 5-10 minutes |
| End of each week | Five questions: recall, distinction, synthetic transfer, evidence limit, and safety boundary. | 10-15 minutes |
| Before a frozen-code walkthrough after two private lab artifacts | One concept-to-code readiness question. | 2-5 minutes |
| User says `quiz me` | Three to five questions; do not move curriculum position. | user-selected |

## Question design

For each quiz, use the active unit and the immediately relevant earlier units. Prefer these categories:

1. Recall: define a concept in the user’s own words.
2. Distinction: contrast two easy-to-confuse concepts, such as authentication versus authorization.
3. Synthetic transfer: reason about a fictional `lab-a`, `lab-b`, and separately owned object without using real target data.
4. Evidence boundary: distinguish observation, inference, and unknowns.
5. Safety boundary: identify what must remain manual or private.

Ask one question at a time. Do not reveal answers, provide multiple-choice cues, or turn a question into a lecture before the user answers. Follow an incomplete answer with one neutral prompt before explaining.

Use synthetic examples only. Never ask the user to reveal a credential, cookie, bearer token, hostname, raw request, raw response, or private case-file contents.

## Grading

Use only these learning labels:

- `retained`: accurate explanation or application, including an appropriate limit where relevant.
- `developing`: partly correct but missing a key distinction, assumption, or boundary.
- `gap`: materially incorrect, unsupported, or unable to answer after a neutral prompt.

These labels are unrelated to the curriculum’s observation classifications:

- `candidate`
- `negative`
- `invalid`

During this learning phase, `verified` remains unavailable.

## Remediation and advancement

- Zero or one `developing` result, with no `gap`: continue the planned block and record the weak point for later retrieval.
- One `gap` or two or more `developing` results on a prerequisite concept before a study block: reserve the first 15 minutes of that study block for explanation and re-retrieval before new dependent material.
- The same result before a controlled-lab or notebook/retrospective block: mark that block `blocked`, run a separate 15–30 minute retrieval-remediation interlude, then ask two fresh recall/transfer questions. Do not use lab or retrospective time for unplanned teaching or testing.
- A repeated `gap` after remediation: record it in the private state, do not erase completed work, and do not advance into a dependent controlled-lab concept until the user can explain the boundary in a fresh synthetic scenario.
- A quiz never creates a product requirement, implementation task, or need for automation.

## Required weekly retention check

Before a new week begins, ask all five:

1. What did you observe directly in the last relevant lab or study exercise?
2. What did you infer, and what evidence limits that inference?
3. What is the difference between authentication and authorization in this week’s context?
4. In a synthetic two-identity example, what rule would you test manually and why?
5. Which data, actions, and claims remain outside the learning-phase boundary?

Adapt terminology to the week, but preserve the distinction between direct observation, inference, and unknowns.

## Private-state record

After a quiz, propose a concise ledger row for `LEARNING_STATE.md`:

```text
| Week NN / Session N opening | retained | authorization versus authentication; direct observation versus inference | retrieve object-ownership assumptions before next lab |
```

The user manually decides whether to copy it into private state.

If a prerequisite gap blocks a lab or retrospective block, also propose this private-state override:

```text
- Block status: blocked
- Remediation status: required
- Blocked curriculum position: Week NN / Session N / chunk NN-NN
- Prerequisite gap: [concept only]
- Next remediation action: 15–30 minute retrieval review and two-question recheck
- Fresh recheck result: pending
```

Until the user records remediation as `passed` and resets the blocked curriculum block to `not started` or `in progress`, a fresh AI session must resume remediation rather than the blocked block.
