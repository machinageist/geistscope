# GeistScope engine — Rust workspace

Recon and offensive-security tooling that powers the GeistScope project.
The Rust workspace is one process group; a Go orchestrator (planned) will
fan-out to individual binaries and consume their JSON output.

## Crates

| Crate            | Type     | Purpose                                                              |
| ---------------- | -------- | -------------------------------------------------------------------- |
| `http-client`    | lib      | Shared reqwest wrapper: UA rotation, rate limit, jittered retry      |
| `llm-client`     | lib      | Unified Ollama (local) + Anthropic LLM interface                     |
| `fingerprint`    | lib+bin  | HTTP response → tech stack; `mg-fingerprint` binary for standalone use |
| `corpus-builder` | lib+bin  | Mine crt.sh + Wayback into a SQLite subdomain/path corpus            |
| `subdomain-enum` | lib+bin  | Passive (CT logs) + active (DNS brute force) subdomain enum          |
| `mg-scan`        | lib+bin  | Async TCP port scanner with banner grab + stealth controls           |
| `engagement`     | lib+bin  | Bug bounty engagement workspace: scope, audit, findings              |
| `mg-recon`       | bin      | Full recon pipeline: subdomain enum → fingerprint → port scan → summary |

## Dependency graph

```
http-client ◄─── fingerprint
            ◄─── corpus-builder
            ◄─── subdomain-enum (planned migration)

engagement ◄─── subdomain-enum
           ◄─── mg-scan
           ◄─── fingerprint
           ◄─── mg-recon

llm-client            (standalone)
```

## Bug bounty workflow

The `engagement` crate defines the unit of work. Every other tool reads
and writes to a standard layout so the operator and an LLM assistant can
both reason about state from files alone.

```
engagements/<name>/
├── engagement.json        # name, target, platform, url, created_at, tags
├── scope.json             # in_scope / out_of_scope patterns (default-deny)
├── notes.md               # human-editable running notes
├── audit.log              # append-only log of every active probe
├── recon/
│   ├── subdomain-enum.json  # discovered subdomains + IPs
│   ├── fingerprint.json     # hostname → tech stack map
│   ├── mg-scan.json         # per-host open ports
│   └── summary.json         # merged per-host record (primary AI input)
├── crawl/                 # (future) HTML/JS dumps
└── findings/              # one markdown file per finding
```

### Typical flow

```bash
# 1. Initialize
mg-engagement init acme-bounty --target acme.example.com --platform hackerone

# 2. Refine scope (default is target + *.target)
mg-engagement scope-deny acme-bounty '*.dev.acme.example.com'

# 3. Full automated recon (writes all recon/ files)
mg-recon acme-bounty

# 3b. Individual tools with engagement wiring
subdomain-enum acme.example.com --engagement acme-bounty
mg-scan api.acme.example.com --engagement acme-bounty
mg-fingerprint https://api.acme.example.com --engagement acme-bounty

# 4. Capture observations
mg-engagement note acme-bounty "auth subdomain returns 401 with verbose error"

# 5. Draft a finding
mg-engagement finding acme-bounty "IDOR on /api/orders" \
    --target api.acme.example.com --severity high

# 6. Verify scope before any active probe
mg-engagement check acme-bounty api.acme.example.com   # exit 0 = in scope, 2 = out
```

### Resumable recon

`mg-recon` checks for existing output files before running each stage. Re-run
safely at any time; only missing stages execute. Use `--force` to re-run all.

```bash
mg-recon acme-bounty --force          # re-run everything
mg-recon acme-bounty --ports 1-10000  # custom port range
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
- One-line pseudocode comment above every logical block explaining the why
