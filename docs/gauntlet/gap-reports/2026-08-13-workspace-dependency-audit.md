# Workspace Dependency Audit Gap — 2026-08-13

Status: OPEN
Scope: release/AAA gate; not introduced by the GS-4.1 evidence-writer slice

## Command

```text
cd crates && cargo audit --deny warnings
```

## Result

FAIL:

- RUSTSEC-2026-0204: `crossbeam-epoch` 0.9.18; fixed in 0.9.20 or later.
- RUSTSEC-2026-0185: `quinn-proto` 0.11.14; fixed in 0.11.15 or later; high severity remote memory exhaustion.
- Denied warning RUSTSEC-2025-0057: `fxhash` 0.2.1 unmaintained.
- Denied warning RUSTSEC-2024-0436: `paste` 1.0.15 unmaintained.
- Denied warning RUSTSEC-2026-0190: `anyhow` 1.0.102 unsound.
- Denied warnings RUSTSEC-2026-0253 and RUSTSEC-2026-0002: `lru` 0.12.5 unsound.

## Dependency paths observed

- `crossbeam-epoch` enters through `crossbeam-deque`/Rayon and through Moka/Hickory.
- `quinn-proto` is target-dependent and did not appear in the native inverse tree; it remains present in `Cargo.lock`.
- `anyhow` is used across much of the workspace.
- `lru` enters through Ratatui/`mg-tui`.

## Atomic-slice boundary

The final GS-4.1 generic evidence-writer snapshot changes neither `Cargo.toml` nor `Cargo.lock`, so it does not introduce these advisories or trigger the manifest/lockfile paths in `.github/workflows/audit.yml`. The audit debt must still be resolved before product-level AAA/release completion.

## Required remediation

1. Update the two vulnerable crates through the narrowest compatible parent upgrades.
2. Determine maintained/fixed replacements or accepted upstream upgrades for all denied warnings.
3. Run workspace tests, strict Clippy, locked build, and `cargo audit --deny warnings`.
4. Record dependency diffs and any behavior changes in a separate atomic dependency-security slice.

No waiver is accepted for final AAA completion.
