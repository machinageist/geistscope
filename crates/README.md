# GeistScope engine — Rust workspace

Experimental Rust libraries and CLIs for local, owned, or explicitly authorized
security-testing research. The workspace includes engagement scope, request
corpus, replay/proxy, evidence, TUI, and typed harness surfaces alongside a much
broader scanner inventory.

Workspace membership, compilation, or harness registration is not proof that a
crate is safe, complete, publication-ready, or validated on a real engagement.
The reviewed project state lives in `../docs/gauntlet/manifest.md` and
`../docs/gauntlet/summary.md`.

## Crates

| Crate            | Type     | Binary           | Purpose                                                              |
| ---------------- | -------- | ---------------- | -------------------------------------------------------------------- |
| `engagement`     | lib+bin  | `mg-engagement`  | Bug bounty engagement workspace: scope, audit, findings              |
| `session`        | lib      | —                | Engagement session config and auth header resolution for tools       |
| `payload-engine` | lib      | —                | Stack-aware payload selection for fuzzing and harness planning       |
| `security-graph` | lib      | —                | Local-first operational intelligence graph and JSONL store           |
| `http-client`    | lib      | —                | Shared reqwest wrapper: UA rotation, rate limit, jittered retry      |
| `llm-client`     | lib      | —                | Unified Ollama (local) + Anthropic LLM interface                     |
| `fingerprint`    | lib+bin  | `mg-fingerprint` | HTTP response → tech stack detection                                 |
| `corpus-builder` | lib+bin  | `corpus-builder` | Mine crt.sh + Wayback into a SQLite subdomain/path corpus            |
| `subdomain-enum` | lib+bin  | `subdomain-enum` | Passive (CT logs) + active (DNS brute force) subdomain enum          |
| `mg-scan`        | lib+bin  | `mg-scan`        | Async TCP port scanner with banner grab + stealth controls           |
| `mg-recon`       | bin      | `mg-recon`       | Full recon pipeline: subdomain enum → fingerprint → port scan → summary |
| `ai-prioritize`  | bin      | `ai-prioritize`  | Rank attack surface and write exploit-chain analysis with LLM        |
| `mg-crawl`       | bin      | `mg-crawl`       | BFS crawler: HTML, JS secrets, endpoints, internal refs, GraphQL and library signals |
| `mg-probe`       | bin      | `mg-probe`       | Passive posture plus optional `--active` marker/SQL/open-redirect probes |
| `mg-fuzz`        | bin      | `mg-fuzz`        | Burp Intruder-style payload fuzzer: sniper / battering-ram / pitchfork / cluster-bomb |
| `mg-replay`      | bin      | `mg-replay`      | Replay curl evidence from findings; verdict: still_vulnerable / appears_fixed |
| `mg-report`      | lib+bin  | `mg-report`      | Generate bounty-ready reports from findings with local CVSS 3.1 scoring |
| `mg-tui`         | bin      | `mg-tui`         | Ratatui dashboard/browser with host pivoting, harness status, inspector, search, and session headers |
| `mg-harness`     | lib+bin  | `mg-harness`     | JSON endpoint dispatcher + chat REPL with 119 registered endpoints across gated profiles |
| `mg-recopilot`   | bin      | `mg-recopilot`   | Decompiled-pseudocode analysis: reads RE output, writes structured findings   |
| `mg-aifuzz`      | bin      | `mg-aifuzz`      | Adversarial LLM-endpoint fuzzer; requires operator consent before sending     |
| `mg-exploitgen`  | bin      | `mg-exploitgen`  | CVE-driven exploit scaffolding from CVE description + target-env JSON         |

### Broader workspace inventory

The Cargo workspace currently contains 83 packages. The broad active-testing,
auth/session, OSINT, protocol, infrastructure, cloud, post-access, mobile, and
workflow surface remains experimental. Some endpoints are hidden from the
default profile, lab-only, service-internal, retired pending repackaging, or
unimplemented. Do not infer automatic finding flow or validation from a crate's
presence. See the top-level [README](../README.md) for the inventory and current
safety boundary.

`mg-engagement credentials-set` writes `session.json` using env-var references
only. `mg-harness session.get_headers` resolves headers for tools but returns
redacted metadata to model-visible callers. `mg-crawl`, `mg-probe`, `mg-fuzz`,
and `mg-tui` apply configured session headers through their HTTP clients.

## Dependency graph

```
http-client ◄─── fingerprint ◄─── mg-recon ◄─── ai-prioritize
            ◄─── corpus-builder           ◄─── mg-probe (reqwest direct)
            ◄─── mg-crawl (reqwest direct)

engagement ◄─── subdomain-enum
           ◄─── session
           ◄─── mg-scan
           ◄─── fingerprint
           ◄─── mg-recon
           ◄─── ai-prioritize
           ◄─── mg-crawl
           ◄─── mg-probe
           ◄─── mg-fuzz
           ◄─── mg-replay
           ◄─── mg-report
           ◄─── security-graph

llm-client ◄─── ai-prioritize
           ◄─── mg-report

mg-recon ◄─── mg-harness
engagement ◄─── mg-harness
mg-report ◄─── mg-harness
security-graph ◄─── mg-harness
```

Harness relationship map (non-exhaustive):

```text
mg-harness -> engagement/http-client/llm-client/current tool libraries
mg-tui     -> mg-harness endpoints for replay, fuzz, OOB, reporting, ranking
```

The live registry currently reports 119 endpoints: 111 marked implemented and
8 marked unimplemented. These are registry states, not publication verdicts.
The core control surface lives in `mg-harness/src/lib.rs::registry()`;
subprocess-dispatched entries derive from `SUBPROCESS_TOOLS` with binary, risk,
exposure, and description metadata. Invoke `endpoint.registry` to enumerate the
runtime list:

```bash
echo '{"endpoint":"endpoint.registry","engagement":"any"}' | mg-harness dispatch --pretty
```

## Engagement directory layout

```
engagements/<name>/
├── engagement.json        # name, target, platform, url, created_at, tags
├── scope.json             # in_scope / out_of_scope patterns (default-deny)
├── notes.md               # human-editable running notes
├── audit.log              # append-only log of every tool invocation
├── recon/
│   ├── subdomain-enum.json  # discovered subdomains + IPs
│   ├── fingerprint.json     # hostname → tech stack map
│   ├── mg-scan.json         # per-host open ports
│   ├── summary.json         # merged per-host record (primary AI input)
│   ├── probe-report.json    # security header / CORS / cookie check results
│   └── fuzz-<ts>.json       # payload fuzzer results per run
├── crawl/
│   └── <host>/
│       ├── pages/<sha256>.html
│       ├── js/<sha256>.js
│       ├── index.json         # URL → sha256 map
│       ├── endpoints.json     # enriched JS/form API paths
│       ├── secrets.json       # regex-matched secret candidates
│       ├── internal-refs.json # internal hostnames/RFC1918 refs from JS
│       ├── vulnerable-libraries.json # embedded vulnerable JS library hints
│       └── graphql-candidates.json # GraphQL signals, plus graphql-schema.json if introspection succeeds
├── findings/
│   ├── <id>-<slug>.md         # one markdown file per finding
│   ├── <id>-<slug>-report.md  # bounty-ready report generated by mg-report
│   └── <id>-<slug>-replay-<date>.json  # replay verdict
└── graph/
    ├── nodes.jsonl            # local security-graph nodes
    └── edges.jsonl            # local security-graph edges
```

## Safe local starting workflow

```bash
# From crates/
cargo run -p engagement --bin mg-engagement -- \
  init local-lab --target lab.example.test --platform local

cargo run -p engagement --bin mg-engagement -- \
  explain-scope local-lab https://lab.example.test/

printf '%s\n' '{"endpoint":"endpoint.registry","engagement":"local-lab"}' | \
  cargo run -p mg-harness -- dispatch --pretty
```

Start with scope explanation and registry inspection. Use active tools only
against a local intentionally vulnerable target and only after checking the
endpoint risk, exposure, confirmation, and current gauntlet state.

## Fuzz template format

Templates are raw HTTP requests with `§marker§` position markers:

```
GET /api/v1/users/§id§ HTTP/1.1
Host: api.acme.example.com
Authorization: Bearer VALID_TOKEN
```

Built-in payload sets: `sqli`, `xss`, `ssti`, `traversal`, `ssrf`,
`common-passwords`, `http-methods`, `usernames`, `numbers:N-M`.

Attack modes mirror Burp Intruder: `sniper`, `battering-ram`, `pitchfork`, `cluster-bomb`.

## Build / test / install

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --tests --locked -- -D warnings
```

The repository does not currently claim a supported install-everything path.
Install or run only the specific package needed for a reviewed local workflow.
The focused accepted-snapshot gates are authoritative for the current GS-4.1
state; workspace-wide lint may still expose unrelated pre-existing warnings and
must not be described as green without a fresh successful run.

## AI harness rules

The harness is what enables an AI agent (or the chat REPL) to drive this
toolchain without shell access. Rules in force:

- Every endpoint is dispatched through a typed JSON `Invocation` and returns a
  bounded `EndpointResult` — no arbitrary command execution.
- Model-provided args are validated before dispatch.
- Active endpoints check engagement scope before touching any target.
- Subprocess tool calls run with a 5-minute wall-clock cap and 64 KiB stdout/
  stderr cap each — runaway tools cannot starve the harness.
- High-active and state-change endpoints require `confirmed: true` in the JSON
  path; the chat REPL prompts the operator with the proposed args and sets it
  after approval. Destructive endpoints are hidden from the chat catalog
  unless `--unsafe-mode` is set.
- Tokens, cookies, and sensitive response bodies are redacted before model
  ingestion.
- Every dispatch — allow, block, error — appends to `audit.log`.

These are intended harness contracts, not a substitute for per-endpoint review.
GS-4.1 result promotion remains blocked after the descriptor-chain slice-2
series exhausted independent review; rejected production code was reverted.

Provider-specific LLM clients live behind the `chat::ChatBackend` trait in
`mg-harness/src/chat/` (Anthropic, OpenAI-compatible, Ollama). Tool policy
lives in the harness itself.

## Code conventions

- Block comment header at top of every file (Filename / Author / Date / Description / Notes)
- `// Verb + noun` above every function and major code block
- Constants in `ALL_CAPS_SNAKE_CASE`; declare-and-initialize together
- 4-space indentation; section dividers sit above the block they describe
- `-D warnings` passes on every crate before commit
