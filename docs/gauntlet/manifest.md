# GeistScope Gauntlet Manifest

Updated: 2026-08-13

| Feature | Parent | Owner | State | Spec iteration | Impl iteration | Authoritative artifact | Last verified commit | Last commands | Blocker | Next action |
|---|---|---|---|---:|---:|---|---|---|---|---|
| GS-0.1 Durable gauntlet protocol | GS-0 | integration owner | implementation-review | 1 | 1 | `docs/gauntlet/PLAN.md` | 486c4cf | evidence-core 6 pass; hunt-engine 75 pass | independent documentation review | verify and commit bootstrap |
| GS-0.2 Product-state inventory | GS-0 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-0.1 | inventory shipped/prototype/quarantined/deferred |
| GS-0.3 Install/diagnostics/release gates | GS-0 | unassigned | pending | 0 | 0 | — | — | NOT RUN | core slices | baseline release path |
| GS-4.1 SSRF vertical slice | GS-4 | unassigned | implementation-in-progress | 1 | 1 | `.hermes/plans/2026-07-31_ssrf-vertical-slice/SPEC.md` | a140fa7 | Tasks through 4.2 recorded passing | immutable bundle not implemented | implement Task 4.3 |
| GS-4.2 IDOR vertical slice | GS-4 | unassigned | pending | 0 | 0 | `.hermes/plans/2026-07-25_idor-slice/PLAN.md` | — | NOT RUN | GS-4.1 | baseline after SSRF pass |
| GS-4.3 Critical injection slice | GS-4 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1/4.2 contracts | draft after IDOR pass |
| GS-1.5 Persistence boundary | GS-1 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1 transitions | derive from benchmark |
| GS-6.1 Versioned local API | GS-6 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1 transitions | derive from benchmark |
| GS-6.2 Thin CLI | GS-6 | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-6.1 | expose SSRF campaign |
| GS-7.1 Legacy classification | GS-7 | unassigned | pending | 0 | 0 | — | — | NOT RUN | replacement evidence | inventory SSRF/OOB first |
| GS-3 Adaptive loop | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | three proven slices | scheduler/coverage/resume |
| GS-2 Traffic foundation | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | engine contracts | capture/corpus/replay |
| GS-5 Evidence/reporting | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | GS-4.1 | generalize after SSRF |
| GS-8 Capability packs | root | unassigned | pending | 0 | 0 | — | — | NOT RUN | first-release spine | migrate full recon→exploit breadth |

Only an independent verifier may change a state to `spec-pass`, `slice-pass`, or `complete`.
