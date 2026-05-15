---
name: geistscope-tui-browser
description: >
  Build or review GeistScope's Ratatui bug-hunting browser: request corpus,
  response inspector, host/path/parameter views, replay and fuzz actions, OOB
  callback feed, finding drawer, AI next-test panel, keyboard-first workflows,
  stable terminal layouts, and dense professional security tooling UX. Use when
  editing mg-tui or designing terminal UI behavior.
---

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
