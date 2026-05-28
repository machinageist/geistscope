---
name: geistscope-ai-harness
description: "Use when build or review GeistScope's AI harness: typed tool endpoints, local dispatch, model-provider adapters, strict schemas, scoped active testing, redaction, audit logs, prompt-injection defenses, allowed-tool narrowing, and safe integration with the Rust engine. Use when adding mg-harness, AI tool calling, endpoint schemas, or model-assisted actions in the TUI."
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [geistscope, ai-harness, rust, tool-calling, security]
    related_skills: [rust-security-patterns, requesting-code-review]
    source: /home/mgeist/.claude/geistscope-skills/geistscope-ai-harness/SKILL.md
    migrated_from: claude-memory
---

# GeistScope AI Harness Skill

## Overview

This skill was migrated from Jeff's pre-existing Claude memory skill library into Hermes' curated `SKILL.md` format. It preserves the original working playbook while adding standard frontmatter, trigger guidance, safety notes, pitfalls, and a verification checklist so Hermes can load it predictably in future sessions.

Source file: `/home/mgeist/.claude/geistscope-skills/geistscope-ai-harness/SKILL.md`

## When to Use

- Use when build or review GeistScope's AI harness: typed tool endpoints, local dispatch, model-provider adapters, strict schemas, scoped active testing, redaction, audit logs, prompt-injection defenses, allowed-tool narrowing, and safe integration with the Rust engine. Use when adding mg-harness, AI tool calling, endpoint schemas, or model-assisted actions in the TUI.
- Use when the user's current task matches the original trigger language preserved below.
- Combine with related skills when the task spans project work, implementation, review, reporting, or infrastructure.

## Operating Principles

- Treat this as a reusable playbook, not a transcript or task log.
- Prefer small, verified actions over broad speculative changes.
- Preserve Jeff's preference for first-principles explanations and CLI-native workflows.
- For security testing: stay inside authorized scope, minimize impact, use harmless proofs, and preserve clean evidence.

## Original Playbook

# GeistScope AI Harness Skill

## Workflow

1. Read `docs/PRODUCT_DOCTRINE.md` and `docs/AI_TOOL_ENDPOINTS.md`.
2. Identify whether the change is endpoint schema, dispatcher, provider adapter,
   prompt template, TUI action, or existing tool integration.
3. Keep the model boundary strict: the model requests endpoints; Rust validates
   and dispatches endpoints.
4. Add or update audit events for every dispatch, block, and confirmation.
5. Add prompt-injection and malformed-argument tests for any model-visible path.

## Endpoint Rules

- Endpoint names are stable: `domain.action`.
- Inputs and outputs are typed Rust structs.
- Model request, validated request, and persisted audit record are separate.
- Active endpoints require engagement and target.
- Scope check happens before network traffic.
- High-active and state-changing endpoints require user confirmation.
- Raw shell command construction from model-provided text is not allowed.

## Redaction Rules

- Do not send cookies, bearer tokens, API keys, private keys, or third-party PII
  to the model by default.
- Store full evidence locally and send model-visible summaries plus hashes.
- Cap response bodies before model ingestion.
- Preserve enough evidence references for replay and reporting.

## Rust Conventions

- Preserve the required file header comment.
- Add `// Verb + noun` comments above functions and major blocks.
- Keep library logic reusable and binaries thin.
- Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

## Autonomous Bug-Hunting Capability Gaps

For detailed implementation notes from the scope/policy foundation slice, see `references/autonomous-hunting-foundation.md`.

For the TDD-and-commit workflow that worked while implementing the first autonomous hunting slices, see `references/autonomous-hunting-slice-workflow.md`.

For the lab/account model, isolated browser profile, and safe client-side planner foundation patterns, see `references/autonomous-hunting-lab-browser-foundation.md`.

For the `mg-lab` CRUD CLI and named session profile foundation pattern, see `references/autonomous-hunting-cli-session-foundation.md`.

For GeistScope implementation sessions, also consult Jeff's engineering guideline file at `~/.hermes/ai-engineering-best-practices.md` for spec-first work, small chunks, atomic commits, and automated safety nets.

For low-input autonomous hunting, the AI harness needs deterministic local capabilities around the model, not just more prompting:

- Program intake: parse HackerOne/Bugcrowd scope exports, normalize asset types, model in-scope/out-of-scope precedence, and run reliable bare-host/full-URL scope checks.
- Account lab state: typed records for controlled identities, stores/tenants/orgs, roles, permissions, browser profiles, and which boundaries are legitimate versus testable.
- Proxy/browser integration: ingest live Burp/mitmproxy traffic without manual export, preserve request/response pairs, and tag each request by session, role, store, auth state, host, operation, and IDs.
- Secret/session vault: store cookies/tokens locally, expose only redacted summaries to the model, and allow replay using named sessions without leaking credentials.
- Corpus builder: cluster captured traffic into safe candidates by endpoint, method, object IDs, GraphQL operation, shop/tenant context, side-effect risk, and comparable A/B requests.
- Differential replay: safely replay captured requests across controlled session pairs with low concurrency, automatic variable substitution, CSRF token refresh handling, and strong scope/risk gates.
- Response diff/triage: compare status, semantic data ownership, sensitive fields, object identity, and error shapes; suppress expected 401/403/noise; promote only meaningful boundary violations.
- GraphQL mapper: decode operation hashes, variables, global IDs, shop context, query/mutation risk, and resolver-level object references.
- Evidence/report pipeline: save raw evidence locally, generate redacted model summaries, create control/exploit pairs, verify replayability, and emit report skeletons with exact evidence paths.
- Human approval gates: require explicit confirmation for high-risk tools, state-changing requests, large exports, OOB/internal URL tests, brute force, DoS-like tests, or ambiguous scope.

## Review Checklist

```text
[ ] Endpoint has risk class and schema.
[ ] Scope gate covers active calls.
[ ] Redaction happens before model-visible output.
[ ] Audit log records dispatch or block.
[ ] Prompt-injection fixture covers untrusted web/log content.
[ ] Tests cover invalid model arguments.
[ ] No raw shell access is exposed to the model.
```

## Common Pitfalls

1. **Using the playbook outside scope.** Confirm the engagement, project, or system is authorized before running active tests or making changes.
2. **Treating old context as current truth.** If project stack or business direction may have changed, check the current repo docs before relying on historical notes.
3. **Over-collecting noisy context.** Load only the relevant skill(s), then gather current files, requests, logs, or docs needed for the task.
4. **Skipping verification.** Every exploit proof, code change, or infrastructure operation needs a concrete verification step.
5. **Starting with proxy/replay/model automation before structured policy.** For autonomous hunting, first create stable Rust-owned decision objects for scope, risk, session, approval, and redaction. Boolean helpers and model prompts must delegate to those objects, not reimplement policy.
6. **Making a single bounty program the architecture.** Keep program/platform quirks in adapters or analyzers. Core scope, corpus, replay, lab, and evidence code should work for HackerOne, Bugcrowd, Intigriti, private programs, and manual engagements.
8. **Skipping discrete commits during multi-slice implementation.** For autonomous hunting foundations, finish one Rust-owned gate at a time, run focused and package tests, then commit before starting the next slice. This keeps security-sensitive policy changes reviewable and prevents proxy/replay/browser work from blending with foundational gates.
9. **Relying on lexical path checks for artifacts.** Model/user-directed evidence paths need an engagement-root artifact guard that rejects absolute paths and `..`, canonicalizes the deepest existing ancestor to catch symlink escapes, writes atomically, and records a digest.
10. **Letting operator-friendly CLIs bypass library-owned validation.** For autonomous hunting foundations, CLIs such as `mg-lab` should call model constructors and persistence helpers that enforce safe IDs, engagement-root paths, redaction, expiry, and secret-reference rules. Do not duplicate weaker path or secret checks in the CLI layer.
11. **Committing progress docs before verified code state is known.** Update restart/progress checklists after the code slice is tested and committed so the checklist records real commit hashes and next-step state. Prefer a separate docs commit after the implementation commit for clean rollback/review.

## Verification Checklist

- [ ] The task matches this skill's trigger conditions.
- [ ] Current project/program/scope information has been checked when relevant.
- [ ] Actions are authorized, minimal, and reversible where possible.
- [ ] Evidence, commands, outputs, or changed files have been verified.
- [ ] Any newly discovered stable workflow improvement is folded back into a skill.
