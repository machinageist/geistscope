# METHODOLOGY — SSRF hardening slice (living dev-log)

Per task: RED → what failed → GREEN → what the test revealed → adjustment.

## Why this slice, this way

The SSRF slice proved the loop but cut a corner the hardening slice repays: the live path only ever
injects the OOB callback URL into the first query parameter. That makes blind SSRF work, but leaves
two real capabilities on the table — response-based SSRF (an internal-metadata endpoint reflected
into the body) and header-position SSRF (`X-Forwarded-For` and friends), which many real targets are
vulnerable to. The verdict class `SsrfResponseLeak` even exists but is dead code in the live path.
This slice turns one probe into a bounded probe *set* and makes that verdict reachable, reusing the
payloads/positions/keywords the old `mg-webscan` scanner already encoded. Slice 1's header-aware
runner is the prerequisite that makes header injection possible now.

## Task 0 — Scaffold

Wrote this dev-log and the slice PLAN. Salvage constants identified in `mg-webscan/src/ssrf.rs`.

## Task 1 — Header-injection builder

**Goal.** A pure builder that puts an SSRF payload into a named request header (`X-Forwarded-For`,
etc.), so header-position SSRF becomes testable now that the runner sends headers.

**Design.** `build_header_injected_request` — a third sibling to `build_injected_request` (query) and
`build_swapped_request` (identity). It drops secret headers *and any existing copy of the target
header*, then sets the injected value once — so the probe controls exactly one header and never
double-sends it. Reuses the shared `is_sensitive_header` filter.

**RED → GREEN.** One test: injecting into `X-Forwarded-For` overwrites a pre-existing XFF with the
payload (exactly one copy), preserves benign headers, and leaves the URL untouched. replay-engine
17/17, clippy clean.

**Adjustment.** None. Task 2 loops this over the salvaged `INJECTABLE_HEADERS`.

---

## Task 2 — Multi-probe SSRF execution

**Goal.** Turn the single OOB-into-first-param probe into a bounded probe set that also reaches the
response-leak verdict and header positions.

**Design.** `execute_ssrf_test` now mints one plan-bound token and runs **blind probes** — the OOB URL
into every `injection_param` and every `SSRF_INJECTABLE_HEADER` — then waits once for a callback. If
none arrives, it runs **response probes**: each param injected with a real internal-metadata URL
(`SSRF_METADATA_PAYLOADS`), inspecting the body for cloud-metadata markers via the existing
`classify_ssrf`. Verdict priority: a correlated callback → `SsrfOobConfirmed`; else a metadata marker
in a response → `SsrfResponseLeak`; else `SsrfNoSignal`. The decisive probe's outcome is what the
evidence bundle records. Two small helpers (`ssrf_blind_probes`, `ssrf_response_probe`) keep the
orchestrator readable.

**RED → GREEN.** The existing SSRF blind E2E still passes unchanged (its param probe triggers the
callback; the four header probes don't, since that lab only fetches the `url` param) — so no
regression, 14/14. `SsrfResponseLeak` is now reachable in the live path; Task 3's E2E exercises it.

**What it revealed.** Sending five probes made the blind E2E slow (~20s): the header probes leave the
`url` param pointed at a benign host the lab tries to fetch, and the shared client's retry/backoff
turns each failed fetch into seconds. Real signal that a hardened probe set needs fast-failing test
targets — Task 3 points the benign URL at a closed loopback port and/or a no-retry client.

**Adjustment.** Task 3 must make lab fetches fail fast to keep the suite quick.
