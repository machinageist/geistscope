# GeistScope

GeistScope is an experimental, local-first Rust workspace for learning about
authorized security testing, evidence handling, request replay, and scoped
human/AI tool orchestration. It is not a finished product or a claim that every
workspace crate is safe, complete, or independently validated.

Use it only on systems you own or have explicit permission to test.

## Learning-session entry point

The current learning authority is the [product-recovery decision record](docs/PRODUCT_RECOVERY_DECISIONS.md)
and [AI learning-session protocol](docs/learning/web-api-authorization/AI_SESSION_PROTOCOL.md).
The broad Rust workspace and tool inventory below are retained legacy material,
not the active learning workflow.

For an AI-assisted learning session, begin with [`AGENTS.md`](AGENTS.md), then
follow the decision record and protocol alongside the
[web/API authorization curriculum](docs/learning/web-api-authorization/README.md).
The private, secret-free resume state is deliberately outside this repository
at `~/.local/share/geistscope-learning/LEARNING_STATE.md`.

## Legacy prototype inventory — not active learning instructions

Everything below this heading describes the broad legacy prototype inventory.
It does not define the active learning workflow or current project authority.
Do not run its build, Docker, chat, credential, scanner, crawler, replay,
fuzzing, or target-facing commands as part of the current learning curriculum.
The active entry point is the learning-session section above.

## Architecture

```text
crates/               Legacy Rust workspace: CLIs, libraries, TUI
tests/                Legacy integration smoke tests
docs/                 Recovery decisions, learning curriculum, and legacy notes
```

## Intended pipeline map

This diagram is a historical orientation map for the legacy prototype, not a
statement of readiness or the current learning workflow. Current learning
authority is in the [product-recovery decision record](docs/PRODUCT_RECOVERY_DECISIONS.md)
and [AI learning-session protocol](docs/learning/web-api-authorization/AI_SESSION_PROTOCOL.md).

```
[Target domain]
      │
      ▼
mg-recon              ← subdomain enum + fingerprint + port scan → summary.json
      │
      ├── ai-prioritize   ← LLM ranks attack surface using skill files
      │
      ├── mg-crawl        ← BFS crawler; extracts JS secrets, endpoints, GraphQL/library signals
      │
      ├── mg-probe        ← Passive security posture: headers, CORS, cookies, debug paths
      │
      ├── mg-fuzz         ← Payload fuzzer (Burp Intruder equivalent)
      ├── mg-replay       ← Finding verification (Burp Repeater equivalent)
      │
      ├── mg-report       ← HackerOne-ready report generation with local CVSS scoring
      │
      └── mg-tui          ← Terminal dashboard / TUI browser foundation

mg-harness            ← Scoped AI tool endpoint dispatcher
```

## Quick start

```bash
# Build and test the workspace
cd crates
cargo build --workspace --locked
cargo test --workspace --locked

# Initialize a local engagement for an owned/authorized target
cargo run -p engagement --bin mg-engagement -- \
  init local-lab --target lab.example.test --platform local

# Inspect the live endpoint registry without executing a testing tool
printf '%s\n' '{"endpoint":"endpoint.registry","engagement":"local-lab"}' | \
  cargo run -p mg-harness -- dispatch --pretty
```

Do not begin with the broad scanner inventory. Start with engagement scope,
read-only registry inspection, focused tests, and a local intentionally
vulnerable target. Active endpoints retain normal scope and confirmation policy.

### Docker

A multi-stage `Dockerfile` builds the workspace binaries into one image. The
image is a development artifact, not evidence that every included binary is
release-ready. Mount a host directory at `/workspace/engagements` to persist
local engagement data.

```bash
# Pull the latest image
docker pull ghcr.io/machinageist/geistscope:latest

# Single-shot endpoint dispatch — same as the CLI
echo '{"endpoint":"endpoint.registry","engagement":"foo"}' | \
  docker run --rm -i -v "$PWD/engagements:/workspace/engagements" \
    ghcr.io/machinageist/geistscope:latest dispatch

# Chat REPL backed by a local Ollama on the host
docker run --rm -it --network host \
  -v "$PWD/engagements:/workspace/engagements" \
  ghcr.io/machinageist/geistscope:latest chat my-engagement \
  --backend ollama --base-url http://localhost:11434 --model qwen2.5-coder

# Build locally
docker build -t geistscope .
```

## Selected operator surfaces

The table below highlights navigation points, not a release manifest. Confirm
current behavior in source, tests, and `endpoint.registry` before relying on it.

| Binary           | What it does                                        |
|------------------|-----------------------------------------------------|
| `mg-engagement`  | Init workspaces, manage scope, add notes, findings  |
| `subdomain-enum` | Passive CT log + active DNS brute force enum        |
| `mg-scan`        | Async TCP port scanner                              |
| `mg-fingerprint` | HTTP tech stack detection                           |
| `mg-recon`       | Orchestrates the full 4-stage recon pipeline        |
| `ai-prioritize`  | LLM-ranked attack surface and exploit-chain analysis |
| `mg-crawl`       | BFS crawler with JS secrets, endpoints, internal refs, GraphQL and library signals |
| `mg-probe`       | Passive posture checker with optional low-volume active endpoint probes |
| `mg-fuzz`        | Burp Intruder-style HTTP fuzzer                     |
| `mg-replay`      | Burp Repeater-style finding verification            |
| `mg-report`      | HackerOne-ready report drafts with local CVSS 3.1 scoring |
| `mg-tui`         | Ratatui dashboard/browser: engagements, hosts, findings, fuzz, logs, harness status, host pivoting, page rendering, inspector, search, and session headers |
| `mg-harness`     | Scoped JSON endpoint dispatcher + chat REPL (Ollama / OpenAI-compatible / Anthropic) |

### Chat REPL

`mg-harness chat <engagement>` opens an interactive coding-agent loop pinned to
one engagement. The model gets tool-use access to a profile-filtered harness
catalog — default, advanced, or lab — so common recon, request-corpus, graph,
and reporting work stays prominent while noisy or hazardous standalone tools
are hidden until the operator asks for them. Findings emitted by tools land in
the engagement workspace automatically.

```bash
# Default profile: common engagement, request corpus, graph, recon, report, and safe audit helpers
mg-harness chat my-engagement --backend ollama --model qwen2.5-coder

# Advanced profile: adds OOB/aifuzz/high-active helpers; still hides retired/lab-only tools
mg-harness chat my-engagement --backend ollama --model qwen2.5-coder --tool-profile advanced

# Lab profile: exposes lab-only scaffolding; destructive tools still need --unsafe-mode
mg-harness chat my-engagement --backend ollama --model qwen2.5-coder --tool-profile lab

# OpenAI-compatible server (LM Studio, vLLM, OpenRouter, etc.)
mg-harness chat my-engagement --backend openai --base-url http://localhost:1234/v1 \
                                                --model llama-3-70b-instruct

# Anthropic (reads ANTHROPIC_API_KEY)
mg-harness chat my-engagement --backend anthropic --model claude-opus-4-7
```

Active-class endpoints prompt before running. The default tool profile hides
retired, lab-only, service-internal, and destructive affordances. Use
`--tool-profile advanced` for explicit high-active/OOB work, use
`--tool-profile lab` for lab-only scaffolding, and combine lab with
`--unsafe-mode` only when destructive endpoints are intentionally needed.
Slash commands: `/help`, `/tools`, `/reset`, `/quit`.

Credential profiles are stored as environment-variable references, not raw
secrets:

```bash
mg-engagement credentials-set acme-bounty --token-env MG_TOKEN
mg-engagement credentials-test acme-bounty --url https://api.example.com/me
```

`mg-crawl`, `mg-probe`, `mg-fuzz`, and the TUI browser apply those headers when
an engagement has a configured session profile.

## Core Libraries

| Library | What it does |
|---------|--------------|
| `session` | Engagement auth/session config and header resolution for tools without plaintext token storage |
| `payload-engine` | Stack-aware payload selection for fuzzing and harness planning |
| `security-graph` | Local-first operational intelligence graph with deterministic node/edge IDs |
| `mg-report` | Shared report-generation library used by the CLI and harness endpoint |

## Integration Smoke Test

`tests/integration/pipeline-smoke.sh` is present, but its referenced
`tests/target/docker-compose.yml` fixture is absent from the current checkout.
The Docker-backed integration smoke path and the matching CI steps are therefore
not reproducible yet. Do not treat that gate as passing until the fixture is
restored or the workflow is replaced and exercised.

## Requirements

- A current stable Rust toolchain with edition 2024 support. Rust 1.90 is used
  for the current Linux verification path.
- Docker for the intentionally vulnerable integration target and Linux checks.
- Optional LLM credentials only when deliberately using a remote backend. The
  harness can use local Ollama; never commit API keys or target credentials.

## Workspace inventory

The remaining tables document the repository’s broad experimental surface.
They are not a promise that every binary is safe, complete, reachable through
the default profile, or independently verified. The harness classifies endpoint
risk and exposure; retired, service-internal, lab-only, high-active, and
destructive affordances are deliberately hidden or gated. Treat these entries as
code inventory until a specific path passes focused tests, blind review, and an
authorized-engagement evidence gate.

### Active Vulnerability Detection

| Binary | What it does |
|---|---|
| `mg-xss` | Reflected/DOM XSS — 7-payload set, OOB blind mode |
| `mg-sqli` | SQL injection — error-based (6 DB families) and time-based blind |
| `mg-ssrf` | SSRF — cloud metadata payloads with OOB correlation |
| `mg-ssti` | SSTI fingerprinting — Jinja2/Twig/FreeMarker/ERB with RCE probe |
| `mg-xxe` | XXE injection — file disclosure and blind OOB payloads |
| `mg-traversal` | Path traversal/LFI — 9 bypass payloads, OS-keyed detection |
| `mg-redirect` | Open redirect — 20 redirect-prone param names, 7 bypass payloads |
| `mg-csrf` | CSRF — token presence, SameSite, tampered-Origin probe |
| `mg-cmdinject` | OS command injection — error-based, time-based, OOB |
| `mg-smuggle` | HTTP request smuggling — CL.TE, TE.CL, TE.TE via raw TCP/TLS |
| `mg-cache-poison` | Cache poisoning — unkeyed header injection, fat GET, cache detection |
| `mg-proto-pollute` | Prototype pollution — JSON body and URL param injection |
| `mg-deser` | Deserialization detection — Java/PHP/Python magic byte scanner |

### Authentication & Authorization

| Binary | What it does |
|---|---|
| `mg-jwt` | JWT attacks — alg confusion (RS256→HS256), brute force, claim override |
| `mg-oauth` | OAuth 2.0 — state CSRF, redirect_uri bypass, PKCE downgrade |
| `mg-authz` | IDOR/BOLA — multi-role request replay, ownership-scoped URL detection |
| `mg-brute` | Login brute force — rate-limit and lockout detection |
| `mg-session-audit` | Session fixation, entropy, cookie flags, invalidation testing |
| `mg-artifact-audit apikey` | API key extraction — 11-pattern regex scan across crawl corpus |

### Recon & OSINT

| Binary | What it does |
|---|---|
| `mg-takeover` | Subdomain takeover — 13-service fingerprint table |
| `mg-dns-enum` | DNS enumeration — zone transfer, wildcard, DNSSEC, SRV, PTR sweep |
| `mg-dns-history` | Historical DNS — SecurityTrails/HackerTarget; flags forgotten infra |
| `mg-dns-rebind` | DNS rebinding payload generator with TTL-aware HTML attack page |
| `mg-cname-chain` | Full CNAME chain — detects circular refs and hijackable intermediates |
| `mg-vhost` | Virtual host brute force — 50-prefix built-in list, Host injection |
| `mg-whois` | WHOIS, ASN lookup, BGP prefix enumeration |
| `mg-shodan` | Shodan host lookup, CVE correlation, port/banner summary |
| `mg-github` | GitHub org dork search for exposed secrets and config files |
| `mg-cloud-enum` | S3/GCS/Azure bucket enumeration — 36 candidate names |
| `mg-social` | GitHub org member enumeration, email pattern derivation |
| `mg-artifact-audit metadata` | Document metadata extraction from PDF/DOCX/XLSX/JPEG |
| `mg-google-dork` | 14 targeted Google dork queries with optional CSE execution |
| `mg-breach` | HIBP domain breach lookup with password-data classification |

### API & Modern Protocols

| Binary | What it does |
|---|---|
| `mg-graphql` | GraphQL introspection, batch abuse, depth limit testing |
| `mg-openapi` | OpenAPI/Swagger spec parser — auto-replays every endpoint |
| `mg-grpc` | gRPC reflection probe, service enumeration, unauthenticated call detection |
| `mg-websocket` | WebSocket CSWSH test, unauthenticated access, message fuzzing |
| `mg-cors-exploit` | Active CORS — reflection, null-origin, subdomain bypass |
| `mg-csp` | CSP header analyzer — unsafe-inline, wildcards, JSONP bypass domains |

### Artifact Analysis (merged: `mg-artifact-audit`)

The `mg-artifact-audit` binary merges six passive artifact analyzers into one subcommand-routed tool. Each subcommand stays on its original harness endpoint (e.g. `js.analyze`, `apk.analyze`), and `artifact.audit` runs multiple types per call.

| Subcommand | What it does |
|---|---|
| `mg-artifact-audit js` | Static JS analysis — endpoints, secrets, JWT tokens, source maps |
| `mg-artifact-audit sourcemap` | Source map downloader — reconstructs original source, scans for secrets |
| `mg-artifact-audit apikey` | API key extraction — 11-pattern regex scan across crawl corpus |
| `mg-artifact-audit metadata` | Document metadata extraction from PDF/DOCX/XLSX/JPEG |
| `mg-artifact-audit apk` | Android APK static analysis — manifest flags, DEX secrets, network config |
| `mg-artifact-audit ipa` | iOS IPA static analysis — ATS config, entitlements, binary string extraction |
| `mg-artifact-audit audit` | Run multiple analyzers in one pass (`--types js,apikey,...`) |

### Infrastructure & Protocol Auditing

| Binary | What it does |
|---|---|
| `mg-tls-scan` | TLS/SSL audit — protocol, cipher, cert validity via rustls |
| `mg-ssh-audit` | SSH config audit — banner, KEX/cipher/MAC weakness detection |
| `mg-udp-scan` | UDP scanner — service probes for DNS/NTP/SNMP/mDNS/SSDP |
| `mg-smtp` | SMTP enumeration — VRFY/EXPN user enum, open relay, header injection |
| `mg-snmp` | SNMP community string brute force and OID walk |
| `mg-smb` | SMB2 NEGOTIATE probe — signing check and null-session detection |
| `mg-http2` | HTTP/2 — h2c upgrade, ALPN check, rapid-reset heuristic |

### Cloud & Container Security

| Binary | What it does |
|---|---|
| `mg-aws` | AWS SSRF chain — IMDSv1/v2 metadata to IAM credential extraction |
| `mg-gcp` | GCP SSRF chain — project ID, service account, OAuth token |
| `mg-azure` | Azure IMDS SSRF — managed identity token, subscription info |
| `mg-k8s` | Kubernetes — API, etcd, kubelet, dashboard exposure checks |
| `mg-docker` | Docker API exposure detection with container/image enumeration |
| `mg-serverless` | Lambda/GCP SSRF chain — runtime API and IAM credential probe |

### Post-Exploitation

| Binary | What it does |
|---|---|
| `mg-privesc-linux` | Linux privesc enumeration — SUID, sudo, caps, cron, NFS |
| `mg-privesc-windows` | Windows privesc enumeration — token privs, unquoted paths, registry |
| `mg-loot` | Post-access credential harvesting — SSH keys, AWS, git, Docker, kubectl |

### OOB & Interoperability

| Binary | What it does |
|---|---|
| `mg-oob` | HTTP OOB callback server — blind SSRF/XXE/CMDi/SQLi detection |
| `mg-secret-validate` | Live secret validation — AWS, GitHub, Stripe, Slack |
| `mg-nuclei-bridge` | Runs Nuclei against scope, imports findings as structured JSON |

### Engagement Workflow

| Binary | What it does |
|---|---|
| `mg-screenshot` | Headless bulk screenshotter with HTML index grid |
| `mg-engagement` | Engagement scope, program import, session metadata, traffic corpus, and audit workflow |
| `mg-harness` | Policy-metadata-backed local AI tool endpoint registry for autonomous hunting |
| `mg-hunt` | Assisted autonomous hunt planner with budgets, approval gates, resume hashes, and safety stops |
| `mg-evidence` | Immutable evidence bundle writer with semantic diffs and redacted browser snapshots |
| `mg-diff` | Scan-over-scan diff — new subdomains, ports, endpoints, status changes |
| `mg-notify` | Finding webhook push to Slack/Discord/ntfy.sh |
| `mg-timeline` | Chronological engagement timeline reconstructed from workspace files |
| `mg-leak-monitor` | Continuous GitHub secret monitoring with state persistence |

## License

MIT
