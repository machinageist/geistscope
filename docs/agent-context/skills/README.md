# GeistScope Skill Sets

Last updated: 2026-05-15

This repo now carries two generated skill sets.

## Bug Hunting Skills

Path: `docs/skills/bug-hunting/`

These are vulnerability-class skills that can be copied into
`~/.claude/bug-hunting-skills/` or another `MG_SKILLS_DIR` for `ai-prioritize`.

- `api-schema-bola`: OpenAPI/Swagger/Postman/REST schema hunting for BOLA, BFLA,
  object-property authorization, and mass assignment.
- `oob-blind-callbacks`: OOB-first hunting for blind SSRF, XXE, SSTI, command
  injection, webhook, parser, and import/fetch bugs.
- `web-cache-and-edge-flaws`: CDN/cache deception, cache poisoning, unkeyed
  input, host/header confusion, and edge authorization mistakes.

## GeistScope Builder And Field Workflow Skills

Path: `docs/skills/geistscope-builder/`

These are for agents building the program and for live consulting workflow. Keep
them outside `MG_SKILLS_DIR` unless the prioritizer is updated to distinguish
bug-class skills from builder/meta skills.

- `geistscope-ai-harness`: Build the AI endpoint harness safely.
- `geistscope-tui-browser`: Build the TUI browser workflow around request,
  response, replay, fuzz, OOB, findings, and AI suggestions.
- `attack-surface-recon-workflow`: Run structured recon and turn surface signals
  into first safe tests.
- `consulting-evidence-ops`: Manage evidence, redaction, replay, reports, and
  consulting deliverables.

## Install Guidance

Recommended layout:

```bash
# Vulnerability-class skills used by ai-prioritize:
cp -R docs/skills/bug-hunting/* ~/.claude/bug-hunting-skills/

# Builder/workflow skills kept separate from ai-prioritize:
mkdir -p ~/.claude/geistscope-skills
cp -R docs/skills/geistscope-builder/* ~/.claude/geistscope-skills/
```

The skills are plain folders with required `SKILL.md` files. They intentionally
avoid extra files inside each skill directory.
