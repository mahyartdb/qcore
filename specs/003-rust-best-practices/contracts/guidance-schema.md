# Contract: Permanent Guidance Schema (FR-015)

**Feature**: `003-rust-best-practices` | **Date**: 2026-09-17

`docs/rust-practices.md` MUST satisfy this schema so SC-005 (unaided trial-task discovery) is checkable.

## Required structure

1. **Header**: purpose (one paragraph), precedence note (constitution wins; conflicts surfaced per FR-010), how to use this doc for a new task (3 steps max).
2. **Per-area table**: exactly one row per Bounded Area in [data-model.md](data-model.md) (15 rows), each with:
   - Area ID + location
   - Governing skills (from the R3 mapping; skill names verbatim)
   - Key conventions (2–6 bullets, each citing its skill)
   - Fastest verification command (copy-pasteable, e.g., `cargo clippy -p qcore-core --all-targets --all-features -- -D warnings && cargo nextest run -p qcore-core`)
   - Known accepted exceptions (or "none")
3. **Verification appendix**: the per-unit loop + final-gate procedure (pointing to [quickstart.md](quickstart.md)), and the no-break guard list (abi-diff, cli_api_parity, abi_consumer, import round-trips).

## Acceptance checks

- [ ] All 15 Bounded Areas present exactly once, IDs matching the data model.
- [ ] Every convention cites a governing skill; no uncited house rules.
- [ ] Every "fastest verification command" was executed at least once during the sweep (evidence in the unit's Verification Record).
- [ ] A trial contributor performing an unfamiliar small task in a remediated area locates the row and the command unaided within 5 minutes (SC-005 test, recorded with date and task).
- [ ] `AGENTS.md` Skills section gains a one-line pointer to this doc (pointer only; no restructuring).
