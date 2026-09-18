# Quickstart: Validating Rust Best Practices Adoption

**Feature**: `003-rust-best-practices` | **Date**: 2026-09-17

This guide proves the feature works end-to-end. It contains no implementation code — only runnable validation. Details live in [data-model.md](data-model.md) and [contracts/](contracts/).

## Prerequisites

- Pinned toolchain active: `rustc --version` shows `1.97.1` (via `rust-toolchain.toml`).
- `cargo-nextest` installed (used by `cargo nextest run`).
- Clean tree baseline: `git status --short` shows only intended files.

## Scenario 1: Per-unit verification loop (repeat for each Bounded Area)

1. Read the area's doc-map row (`AGENTS.md`) and load the area's governing skills from the [data model](data-model.md).
2. Record the baseline:
   - `cargo fmt --check`
   - `cargo clippy -p <pkg> --all-targets --all-features -- -D warnings`
   - `cargo nextest run -p <pkg>` (plus affected `tests-conformance` / `tests-chains` cases)
3. Apply the skill rules to the area (one area per unit; migrate internal callers in the same unit).
4. Re-run the step-2 commands. **Expected**: all pass, zero new warnings, zero regressions vs baseline.
5. If the unit claims a behavioral improvement, demonstrate it the way a caller does (loopback/stubbed peer, mock transport, or CLI invocation) and record literal expected vs observed output.
6. If the unit touches versioned surfaces, run `cargo xtask abi-diff` and the parity/round-trip tests (`cli_api_parity`, `abi_consumer`, `import_roundtrip`, `imported_chain`). **Expected**: abi-diff clean, all pass.
7. Fill the per-unit [Verification Record](contracts/verification-record.md).

## Scenario 2: Sweep-final gate (once, before done)

1. `cargo xtask ci`. **Expected**: full pass (this is what CI runs).
2. `cargo xtask abi-diff`. **Expected**: clean (no breaking changes per FR-012).
3. Guidance trial: give an unfamiliar contributor a small task in a remediated area; they locate the governing row and fastest command in `docs/rust-practices.md` unaided within 5 minutes. **Expected**: success; record contributor, task, time, date. The guidance doc itself MUST satisfy the [guidance schema](contracts/guidance-schema.md) (15 areas exactly once, cited conventions, executed commands).
4. Finding count in claimed-done areas is zero; anything unfinished is a dated follow-up, not a half-applied change.

## Scenario 3: Regression probe (spot check)

1. Pick one Wave-1 area (e.g., `diag`) and one Wave-3 area (e.g., `session`).
2. Run their fastest verification commands from the guidance doc. **Expected**: pass with no findings on re-review (spot-check the fixed finding classes: secret-bearing diagnostics, panicky fallible paths, untyped surfaces, missing caller-perspective tests).
