# GS-4.1 Baseline — Immutable SSRF Evidence and Result Promotion

Date: 2026-08-13
Baseline commit: 486c4cf
Active specification: `.hermes/plans/2026-07-31_ssrf-vertical-slice/agent-specs/04-immutable-evidence-and-results.md`

## Current passing behavior

- `evidence-core` has a legacy immutable-run writer used by `mg-hunt` and `mg-evidence`.
- Legacy writer rejects an existing final run and redacts summaries/DOM snapshots.
- `hunt-engine` has deterministic evidence requirements/references, local canonical-path/hash validation, and crate-private verified-result construction.
- Policy, bounded HTTP execution, callback correlation, and SSRF assessment are independently tested.

## Baseline commands

- `cargo test -p evidence-core`: PASS, 6 tests.
- `cargo test -p hunt-engine`: PASS, 75 tests across unit/integration targets.
- Existing warning: `EvidenceContract::validate_local` is unused, confirming result promotion is not wired.

## Proven gap

The legacy evidence writer creates the final directory before all writes succeed, does not stage and atomically rename a complete run, and manifests only raw artifacts/screenshots rather than every fixed structured artifact. `hunt-engine` does not yet commit a complete SSRF run, construct references to committed files, revalidate those files, or map assessment classes into stable results bound to run/plan/bundle/manifest identity.

## Legacy salvage record

| Legacy path | Demonstrated value | Safety/contract gap | Disposition |
|---|---|---|---|
| `crates/evidence-core/src/lib.rs::EvidenceBundleWriter` | Existing callers, no-overwrite check, redaction, hashing helpers, browser/raw support | Direct writes to final path; partial final bundles possible; incomplete manifest; authorization-specific fixed names | Adapt by adding a backward-compatible generic atomic API first; migrate old callers later |
| `crates/hunt-engine/src/lib.rs::EvidenceContract` | Canonical root containment, kind/id matching, SHA-256 verification | Private/dead until a committed bundle supplies references | Retain and wire after generic writer passes |
| `crates/hunt-engine/src/lib.rs::HuntResult` | Verified constructor is crate-private; non-verified classes distinct | Missing run/plan/bundle/manifest identity | Extend only through evidence result slice |
| `crates/mg-hunt/src/main.rs::write_replay_evidence` | Existing SSRF/IDOR evidence flow and local E2E fixtures | Old replay engine, response-leak heuristics, metadata payloads, direct finding emission | Quarantine as parity/fixture source until new engine path replaces it |

## First RED target

A generic evidence request containing named structured artifacts must either commit all supplied artifacts plus a complete manifest via same-filesystem atomic rename, or leave no final run directory. Existing final paths, unsafe paths, duplicates, and symlink escapes must fail before promotion.
