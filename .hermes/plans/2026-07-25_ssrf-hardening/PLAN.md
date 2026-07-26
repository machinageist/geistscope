# PLAN — SSRF hardening slice

Dated: 2026-07-25. Slice 2 of the post-SSRF roadmap. Deepens the shipped SSRF class; no new class.
Living PLAN (`[ ]`/`[~]`/`[x]`).

## Why

The SSRF slice's live path injects only the OOB URL into `injection_params.first()`, so
`SsrfResponseLeak` is unreachable (the OOB listener returns an empty 200 — no metadata markers), and
header-position SSRF isn't tested. This slice reaches the response-leak verdict via real
internal-metadata probes, adds header injection positions (now that the runner is header-aware after
Slice 1), and probes all params. Salvage: `crates/mg-webscan/src/ssrf.rs` (payloads, keywords,
headers), `crates/payload-engine`. Local-only tests.

## Tasks (TDD; commit each)

- [~] **0. Scaffold** — this PLAN.md + METHODOLOGY.md.
- [ ] **1. Header-injection builder** (`replay-engine`) — `build_header_injected_request` (payload into
  a named header, secrets stripped), sibling to `build_injected_request`. Gate: `cargo test -p
  replay-engine` + clippy.
- [x] **2. Multi-probe SSRF execution** (`mg-hunt`) — per candidate, run a bounded probe set: OOB URL
  into each `injection_param` and each injectable header (blind), plus a metadata-URL probe per param
  inspecting the body for cloud-metadata markers (reaches `SsrfResponseLeak`). Aggregate the strongest
  verdict; evidence records the decisive probe. Constants salvaged from `mg-webscan`. Gate: `cargo
  test -p mg-hunt` + clippy.
- [ ] **3. E2E + status** — local axum lab: (a) a fetch endpoint reflecting metadata body for an
  internal-metadata sentinel → `SsrfResponseLeak`; (b) header-position (`X-Forwarded-For`) SSRF →
  `SsrfOobConfirmed`. Update checklist. Gate: E2E passes; full `cargo test`; `git diff --check`.

## Salvaged constants (from `mg-webscan/src/ssrf.rs`)

Metadata payloads (169.254.169.254 AWS/Azure, metadata.google.internal, 100.100.100.200 Alibaba,
loopback, `[::1]`); metadata keywords (`ami-id, instance-id, computeMetadata, imdsv2, instanceId,
local-ipv4, security-credentials`); injectable headers (`X-Forwarded-For, X-Real-IP, Referer, Host`).

## Safety

127.0.0.1-only; live sends only through the runner for approved plans. A metadata probe targets a
**local sentinel** host mapped by the lab, never a real cloud-metadata endpoint. Jeff's conventions.
