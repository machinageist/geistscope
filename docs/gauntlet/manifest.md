# GeistScope Gauntlet Manifest

Updated: 2026-08-13

| Feature | Parent | Owner | State | Spec iteration | Impl iteration | Authoritative artifact | Last verified commit | Last commands | Blocker | Next action |
|---|---|---|---|---:|---:|---|---|---|---|---|
| GS-0.1 Durable gauntlet protocol | GS-0 | integration owner | slice-pass | 1 | 1 | `docs/gauntlet/PLAN.md` | a920d69 | committed; project-local path checks pass | none | maintain with each slice |
| GS-0.2 Product-state inventory | GS-0 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-0.1 | inventory shipped/prototype/quarantined/deferred |
| GS-0.3 Install/diagnostics/release gates | GS-0 | unassigned | pending | 0 | 0 | — | — | NOT RUN | core slices | baseline release path |
| GS-4.1 SSRF vertical slice | GS-4 | integration owner | spec-pass / root-locator-series-red | 4 | 1 | `docs/gauntlet/specs/GS-4.1-ssrf.md` | a31ad07 | successor fingerprint `47a4db57...` REQUEST_CHANGES; user authorized separate root-locator series | writer and `ArtifactStore` follow symlinked caller-supplied root before no-follow open | strict-TDD public root-symlink regressions; fresh blind iteration 1 |
| GS-4.2 IDOR vertical slice | GS-4 | unassigned | pending | 0 | 0 | `.hermes/plans/2026-07-25_idor-slice/PLAN.md` | — | NOT RUN | GS-4.1 | baseline after SSRF pass |
| GS-4.3 Critical injection slice | GS-4 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1/4.2 contracts | draft after IDOR pass |
| GS-1.5 Persistence boundary | GS-1 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1 transitions | derive from benchmark |
| GS-6.1 Versioned local API | GS-6 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1 transitions | derive from benchmark |
| GS-6.2 Thin CLI | GS-6 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-6.1 | expose SSRF campaign |
| GS-7.1 Legacy classification | GS-7 | integration owner | inventory-complete | 1 | 0 | `docs/gauntlet/run-logs/GS-4.1-legacy-ssrf-oob-salvage.md` | a920d69 | read-only source/test audit complete | replacement parity + Checkpoint 5 | preserve scenarios; decide final dispositions after thin client |
| GS-3 Adaptive loop | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | three proven slices | scheduler/coverage/resume |
| GS-2 Traffic foundation | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | engine contracts | capture/corpus/replay |
| GS-5 Evidence/reporting | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1 | generalize after SSRF |
| GS-8 Capability packs | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | first-release spine | migrate full recon→exploit breadth |

Only an independent verifier may change a state to `spec-pass`, `slice-pass`, or `complete`.
