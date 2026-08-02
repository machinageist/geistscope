# Slice 7 — Thin CLI Integration and First Pruning Pass

Status: blocked until Slice 6 decision and Checkpoint 5
Depends on: approved local API/persistence boundary

## Goal

Expose one operator-facing SSRF campaign command as a thin engine client, then classify and remove/quarantine only the old SSRF/OOB paths demonstrably replaced by the proven slice.

## CLI behavior

The command must:

- accept engagement/run identifiers and references needed by the approved API;
- never accept arbitrary risk overrides, callback destinations, or raw executable payloads;
- submit/start through the engine boundary rather than calling target HTTP directly;
- stream or poll structured state transitions according to the approved API;
- emit stable JSON for automation and concise human output for terminals;
- return non-zero for blocked/invalid/engine failures, while negative tests remain successful completed hunts with no finding;
- print evidence/result references, not raw secrets or response bodies.

Choose the exact binary/subcommand only after inspecting the approved architecture. Do not place orchestration in `main.rs`.

## Stable output contract

At minimum expose:

- campaign/run/candidate IDs;
- final result class;
- plan hash;
- policy verdict/reason code;
- bounded execution/correlation status;
- engagement-relative evidence bundle and result paths;
- error code suitable for scripts.

Human prose may be presentation-only. JSON field meaning must come from engine types.

## Pruning decision

Compare the completed engine behavior against:

- `crates/mg-webscan/src/ssrf.rs`;
- `crates/mg-oob/src/main.rs`;
- old fixture-backed SSRF paths in `mg-hunt` or related docs.

Classify each as:

- adapter/thin worker over the new API;
- quarantined legacy surface, excluded from default operator guidance;
- deleted because the replacement covers its legitimate behavior.

Do not preserve payload spraying, cloud metadata probes, permissive TLS, response-keyword finding emission, raw callback files, or direct finding construction merely for compatibility.

## Documentation updates

Update README and implementation/progress docs to distinguish:

- working callback-only SSRF campaign behavior;
- deferred SSRF escalation techniques;
- quarantined/deleted legacy commands;
- exact offline benchmark command;
- evidence and safety guarantees.

Remove claims that imply broad autonomous hunting is complete.

## Behavior-first tests

Prove:

1. CLI invokes a fake/real local engine boundary, not target HTTP directly.
2. Valid vulnerable benchmark output points to verified evidence.
3. Secure benchmark reports completed negative with no finding.
4. Blocked plan exits non-zero and reports zero execution.
5. JSON contains no callback token, query secret, cookie, auth header, or body.
6. CLI interruption/cancellation follows the approved engine semantics.
7. Removed/quarantined legacy commands are absent from default help/docs as intended.
8. Workspace builds after member/bin pruning.
9. Missing fixture/outcome data cannot synthesize HTTP success or a completed hunt.
10. Legacy OOB output cannot be imported as authoritative verified evidence.
11. CLI orchestration delegates to the same application service exercised by E2E/API tests.

## Non-goals

- No TUI redesign.
- No HackerOne submission.
- No additional vulnerability classes.
- No remote multi-user service.
- No compatibility shim unless Jeff explicitly approves it.

## Verification

Exact commands depend on the approved binary, but must include:

```bash
cargo test -p <cli-crate>
cargo clippy -p <cli-crate> --all-targets -- -D warnings
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo test --workspace
cargo fmt -p <cli-crate> -p hunt-engine -- --check
git diff --check
```

## Done means

One documented operator command exercises the engine without duplicated authority, and obsolete SSRF/OOB surfaces are explicitly adapted, quarantined, or deleted based on proven replacement coverage.
