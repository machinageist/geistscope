# GeistScope Tool-Pack Collapse Implementation Plan

Goal: start collapsing the large GeistScope tool chest without deleting useful code prematurely, by adding harness-visible pack/exposure metadata, documenting where pruned tools should be repurposed, and syncing mg-server to describe the current direction.

Slice 1 — Harness metadata scaffold
- Add `ToolPack` and `ToolExposure` enums to `crates/mg-harness/src/lib.rs`.
- Add pack/exposure/repurpose fields to endpoint registry output.
- Add tests that verify risky tools are not default-profile tools and that prune candidates point at a repurposing pack.
- No binary deletion yet.

Slice 2 — Repurpose map
- Encode a small, reviewable `endpoint_repurpose_note()` mapping for tools that would otherwise be pruned:
  - brute -> identity-audit rate-limit/lockout analysis
  - snmp brute -> protocol-audit SNMP audit mode
  - loot/privesc -> redteam-lab artifact inventory / persistence triage only
  - dns-rebind -> vuln-scan SSRF planning/OOB mode
  - notify/oob -> eventing service infrastructure
  - exploit scaffold -> redteam-lab/CVE lab mode
- Keep dispatch behavior unchanged for now; this is a safe inventory layer.

Slice 3 — Docs sync in GeistScope
- Update `research/tool-chest-rationalization.md` with the new rule: repurpose first, prune only after capability is available under the target pack.

Slice 4 — mg-server sync
- Update the current GeistScope state/update content in `/Users/machinageist/mg-server` so public docs reflect the pack-collapse and repurpose-first direction.

Validation
- Run targeted mg-harness tests.
- Run markdown/content checks where available for mg-server.
- Finish with git status for both repos.
