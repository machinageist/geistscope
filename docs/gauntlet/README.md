# GeistScope Gauntlet

This directory is the durable, model-agnostic control plane for finishing GeistScope.

Start every resumed run in this order:

1. `HANDOFF.md`
2. `manifest.md`
3. `criteria.md`
4. `feature-tree.md`
5. `PLAN.md`
6. The active feature's spec, scorecard, implementation brief, and source/tests

Reusable universal templates are vendored under `templates/`; the loop does not depend on files in a particular user's home directory.

Rules:

- Files and executed command output are authoritative; chat history and hidden reasoning are not.
- One implementation owner works on one active slice at a time.
- Artifact authors never approve their own work.
- A fresh verifier must execute acceptance tests before setting a pass state.
- Failures receive at most three focused remediation loops before escalation.
- Production behavior is developed test-first: observe RED, implement minimal GREEN, rerun focused and affected gates.
- Commit only independently reviewed, deployable atomic slices.
- Before stopping for any reason, update `HANDOFF.md` with an exact next action and command.
- Never place secrets, live target data, raw credentials, cookies, callback tokens, or sensitive response bodies here.

State machine and full operating protocol are defined in `PLAN.md`.
