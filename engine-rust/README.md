# RedBrowser engine — Rust workspace

Recon and offensive-security tooling that powers the RedBrowser project.
The Rust workspace is one process group; a Go orchestrator (planned) will
fan-out to individual binaries and consume their JSON output.

## Crates

| Crate            | Type     | Purpose                                                       |
| ---------------- | -------- | ------------------------------------------------------------- |
| `http-client`    | lib      | Shared reqwest wrapper: UA rotation, rate limit, jittered retry |
| `llm-client`     | lib      | Unified Ollama (local) + Anthropic LLM interface              |
| `fingerprint`    | lib      | HTTP response → tech stack + tech-specific wordlist hints     |
| `corpus-builder` | lib+bin  | Mine crt.sh + Wayback into a SQLite subdomain/path corpus     |
| `subdomain-enum` | lib+bin  | Passive (CT logs) + active (DNS brute force) subdomain enum   |
| `mg-scan`        | lib+bin  | Async TCP port scanner with banner grab + stealth controls    |
| `engagement`     | lib+bin  | Bug bounty engagement workspace: scope, audit, findings        |

## Dependency graph

```
http-client ◄─── fingerprint
            ◄─── corpus-builder
            ◄─── subdomain-enum (planned migration)

llm-client            (standalone)
engagement            (standalone)
mg-scan               (standalone)
```

## Bug bounty workflow

The `engagement` crate defines the unit of work. Every other tool reads
and writes to a standard layout so the operator and an LLM assistant can
both reason about state from files alone.

```
engagements/<name>/
├── engagement.json   # name, target, platform, url, created_at, tags
├── scope.json        # in_scope / out_of_scope patterns (default-deny)
├── notes.md          # human-editable running notes
├── audit.log         # append-only log of every active probe
├── recon/            # subdomain-enum.json, ports.json, fingerprint.json
├── crawl/            # (future) HTML/JS dumps
└── findings/         # one markdown file per finding
```

### Typical flow

```bash
# 1. Initialize
mg-engagement init acme-bounty --target acme.example.com --platform hackerone

# 2. Refine scope (default is target + *.target)
mg-engagement scope-deny acme-bounty '*.dev.acme.example.com'

# 3. Recon (planned: tools accept --engagement <name> and write to recon/)
subdomain-enum acme.example.com --format json > engagements/acme-bounty/recon/subdomains.json
mg-scan api.acme.example.com -p 1-10000 --format json > engagements/acme-bounty/recon/ports.json

# 4. Capture observations
mg-engagement note acme-bounty "auth subdomain returns 401 with verbose error"

# 5. Draft a finding
mg-engagement finding acme-bounty "IDOR on /api/orders" \
    --target api.acme.example.com --severity high
# → opens findings/2026-05-02-001-idor-on-api-orders.md

# 6. Verify scope before any active probe
mg-engagement check acme-bounty api.acme.example.com   # exit 0 = in scope, 2 = out
```

## Build / test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Conventions

- 4-space indentation
- `// Verb + noun` comment above each function
- Header block: `// Author: Jeff` / `// Date: YYYY-MM-DD` / `// Description: …`
- Constants in `ALL_CAPS_SNAKE_CASE`; declare-and-initialize together
- Section dividers above the block they describe, never trailing
