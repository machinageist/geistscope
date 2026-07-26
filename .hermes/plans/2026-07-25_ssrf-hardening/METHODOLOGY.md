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
