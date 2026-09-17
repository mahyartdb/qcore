# Contract: Verification Record (FR-013)

**Feature**: `003-rust-best-practices` | **Date**: 2026-09-17

Every implementation unit MUST produce a record with exactly these fields (reported in the unit's completion note and summarized in `tasks.md` Notes). Re-reading code is not evidence.

## Per-unit record fields

| Field | Required content |
|-------|------------------|
| `area_id` | Bounded Area ID from [data-model.md](data-model.md) |
| `skills applied` | Skill names loaded for this unit (subset of the area's governing set) + any deviation with reason |
| `baseline` | Pre-change: `cargo fmt --check` status, scoped `cargo clippy -p <pkg> --all-targets --all-features -- -D warnings` output summary, related nextest outcomes |
| `commands run` | Exact invocations (scoped fmt, scoped clippy, related `cargo nextest run -p …` / conformance / chains cases) |
| `outcomes` | Pass/fail per command; deltas vs baseline (new warnings MUST be 0; regressions MUST be 0 per SC-002) |
| `behavior demonstration` | Required when the unit claims a behavioral improvement: the loopback/stub-peer, mock-transport, or CLI invocation run, with literal expected vs observed output |
| `no-break evidence` | Required when the unit touches versioned surfaces: `cargo xtask abi-diff` result + relevant parity/round-trip test outcomes |
| `follow-ups` | Explicit list (or "none"); unfinished work is never half-applied |

## Sweep-final record fields (once, before done)

| Field | Required content |
|-------|------------------|
| `full gate` | One full `cargo xtask ci` pass (log location or output summary) |
| `abi guard` | `cargo xtask abi-diff` clean |
| `guidance trial` | SC-005 trial result (contributor, task, time-to-locate, date) |
| `residual findings` | Count MUST be 0 for claimed-done areas; anything else listed as dated follow-ups |

## Acceptance checks

- [ ] Every unit record present with all applicable fields filled; no "verified by review" entries.
- [ ] Zero new warnings and zero regressions in every unit delta.
- [ ] Sweep-final record contains the full-gate pass, clean abi-diff, and guidance trial result.
