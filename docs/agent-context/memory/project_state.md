---
name: GeistScope project state
description: Pipeline build status, crate inventory, and next steps for the GeistScope bug bounty tooling
type: project
---

Repo renamed from `~/redbrowser` to `~/geistscope` on 2026-05-08.

## What's built (as of 2026-05-08)

All crates compile, all tests pass, clippy clean under `-D warnings`.

| Crate | Status |
|-------|--------|
| `http-client` | complete |
| `llm-client` | complete |
| `fingerprint` lib + `mg-fingerprint` bin | complete — bin added 2026-05-08 |
| `corpus-builder` | complete |
| `subdomain-enum` | complete — `--engagement` wiring added 2026-05-08 |
| `mg-scan` | complete — `--engagement` wiring added 2026-05-08 |
| `engagement` | complete |
| `mg-recon` | complete — new crate added 2026-05-08 |

## Workflow as of this build

```bash
mg-engagement init <name> --target <domain> [--platform hackerone]
mg-recon <name>                      # runs all 4 stages, writes recon/summary.json
# or individual tools:
subdomain-enum <domain> --engagement <name>
mg-scan <host> --engagement <name>
mg-fingerprint https://<host> --engagement <name>
```

**Why:** The primary goal is for Claude to read `recon/summary.json` and help Jeff
prioritize targets for medium-high impact bug bounty findings.

## Next steps (from ULTRAPLAN.md)

- Step 3: `ai-prioritize` crate — reads recon files, outputs `priorities.json` + `priorities.md`
- Step 4: `mg-crawl` — BFS crawler with JS secret extraction
- Step 5: `mg-replay` — re-execute curl commands from finding markdown to confirm/deny fix
- Polish deferred: Output<T> envelope, JSONL audit, atomic writes, Session helper
