---
name: geistscope-tui-browser
description: "Use when build or review GeistScope's Ratatui bug-hunting browser: request corpus, response inspector, host/path/parameter views, replay and fuzz actions, OOB callback feed, finding drawer, AI next-test panel, keyboard-first workflows, stable terminal layouts, and dense professional security tooling UX. Use when editing mg-tui or designing terminal UI behavior."
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [geistscope, ratatui, tui, bug-bounty, rust]
    related_skills: [rust-security-patterns]
    source: /home/mgeist/.claude/geistscope-skills/geistscope-tui-browser/SKILL.md
    migrated_from: claude-memory
---

# GeistScope TUI Browser Skill

## Overview

This skill was migrated from Jeff's pre-existing Claude memory skill library into Hermes' curated `SKILL.md` format. It preserves the original working playbook while adding standard frontmatter, trigger guidance, safety notes, pitfalls, and a verification checklist so Hermes can load it predictably in future sessions.

Source file: `/home/mgeist/.claude/geistscope-skills/geistscope-tui-browser/SKILL.md`

## When to Use

- Use when build or review GeistScope's Ratatui bug-hunting browser: request corpus, response inspector, host/path/parameter views, replay and fuzz actions, OOB callback feed, finding drawer, AI next-test panel, keyboard-first workflows, stable terminal layouts, and dense professional security tooling UX. Use when editing mg-tui or designing terminal UI behavior.
- Use when the user's current task matches the original trigger language preserved below.
- Combine with related skills when the task spans project work, implementation, review, reporting, or infrastructure.

## Operating Principles

- Treat this as a reusable playbook, not a transcript or task log.
- Prefer small, verified actions over broad speculative changes.
- Preserve Jeff's preference for first-principles explanations and CLI-native workflows.
- For security testing: stay inside authorized scope, minimize impact, use harmless proofs, and preserve clean evidence.

## Original Playbook

# GeistScope TUI Browser Skill

## Workflow

1. Read `docs/PRODUCT_DOCTRINE.md`, `docs/BUG_HUNTING_METHODOLOGY.md`, and
   `docs/FEATURE_ROADMAP.md`.
2. Identify the operator workflow: inspect, replay, fuzz, OOB, report, or ask AI.
3. Keep panes stable. Dynamic content must not resize the layout unexpectedly.
4. Prefer dense tables, split panes, filters, and keyboard actions over cards or
   explanatory text.
5. Every active action should show engagement, target, scope/risk status, and
   output path.

## Required Views

- Engagements.
- Hosts and services.
- Request corpus.
- Request/response inspector.
- Replay editor.
- Fuzz marker/payload view.
- OOB event feed.
- Findings and evidence drawer.
- Audit log.
- AI next safe test panel.

## UX Rules

- Optimize for repeated professional use over onboarding copy.
- Use predictable shortcuts and status bars.
- Do not hide scope or risk mode.
- Make redactions visible without exposing secrets.
- Link every finding back to raw evidence and replay status.
- Avoid decorative layouts; terminal space is for work.

## Ratatui Engineering Notes

- Keep data loading separate from rendering.
- Avoid blocking network or filesystem work in the render path.
- Use stable row keys and selected indices.
- Keep text within pane bounds.
- Add tests for parsers/loaders where possible.

## Review Checklist

```text
[ ] View supports keyboard-only operation.
[ ] Layout remains stable with long hostnames, URLs, and headers.
[ ] Active actions are routed through scope/risk policy.
[ ] Evidence paths are visible.
[ ] Secrets are redacted in panes.
[ ] Empty/error states are useful and terse.
```

## Common Pitfalls

1. **Using the playbook outside scope.** Confirm the engagement, project, or system is authorized before running active tests or making changes.
2. **Treating old context as current truth.** If project stack or business direction may have changed, check the current repo docs before relying on historical notes.
3. **Over-collecting noisy context.** Load only the relevant skill(s), then gather current files, requests, logs, or docs needed for the task.
4. **Skipping verification.** Every exploit proof, code change, or infrastructure operation needs a concrete verification step.

## Verification Checklist

- [ ] The task matches this skill's trigger conditions.
- [ ] Current project/program/scope information has been checked when relevant.
- [ ] Actions are authorized, minimal, and reversible where possible.
- [ ] Evidence, commands, outputs, or changed files have been verified.
- [ ] Any newly discovered stable workflow improvement is folded back into a skill.
