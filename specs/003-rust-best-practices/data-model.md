# Data Model: Rust Best Practices Adoption

**Feature**: `003-rust-best-practices` | **Date**: 2026-09-17

This feature adds no runtime data. The entities below are the working model for executing and tracking the sweep; they shape `tasks.md` units, the guidance document, and verification evidence.

## Entity 1: Bounded Area

A unit of remediation scope — one crate, module group, or CLI command family. The full roster (from the `AGENTS.md` code map) is fixed; every roster entry appears exactly once in `docs/rust-practices.md`:

| Area ID | Location | Governing skills (from R3) |
|---------|----------|----------------------------|
| transport-api | `crates/qcore-transport-api/src/` | mastery, ownership, error-handling, type-system, api-design, design-patterns |
| registry-chain | `crates/qcore-core/src/registry.rs`, `src/chain/` | error-handling, type-system, api-design, design-patterns, testing, ecosystem |
| config | `crates/qcore-core/src/config/` | ownership, error-handling, type-system, api-design, design-patterns, security |
| session | `crates/qcore-core/src/session/` | async, concurrency, networking, observability, error-handling |
| identity | `crates/qcore-core/src/identity/` | async, networking, observability, error-handling, security |
| scan | `crates/qcore-core/src/scan/` | async, concurrency, networking, observability, performance |
| diag | `crates/qcore-core/src/diag/` | security, observability, error-handling |
| transports | `crates/qcore-transports/transport-*/` | async, networking, performance, memory-optimization, testing |
| facade | `crates/qcore/src/` | api-design, type-system, design-patterns |
| cli | `crates/qcore-cli/src/` | cli, error-handling, observability, security |
| ffi | `crates/qcore-ffi/src/` | unsafe, api-design, error-handling |
| profiles | `profiles/` | design-patterns (data-not-branches), testing |
| conformance-tests | `tests/conformance/tests/` | testing |
| chains-tests | `tests/chains/tests/` + `tests/fixtures/` | testing |
| examples-xtask | `examples/`, `xtask/src/` | cli, ecosystem, error-handling |

**Validation rules**:
- Roster is closed: a unit MUST NOT invent areas or silently merge two rows; cross-area fallout spawns a new unit (R7).
- Wave assignment follows R2 (Wave 1: diag, config-secret, identity-store/report, session-report, cli-key-input; Wave 2: config, registry-chain, transport-api, ffi-boundary; Wave 3: session, scan, identity-net, transports, diag-events; Wave 4: perf/memory/unsafe leftovers, cli polish, facade, profiles, examples-xtask, test suites).

## Entity 2: Skill Rule Set

The normative rules governing one Bounded Area (the row's governing skills, interpreted through FR-001–FR-009).

- **Attributes**: `area_id`, `skills[]`, `key conventions[]` (area-specific, e.g., "imported configs round-trip byte-identical except documented normalization"), `allowed exceptions[]` (each with reason + narrowest scope, e.g., FFI `unsafe` invariants).
- **Validation rules**: every convention MUST cite its skill; every exception MUST carry a reason and scope; constitution conflicts resolve for the constitution and are surfaced (FR-010).
- **State transitions**: proposed → ratified (recorded in guidance doc) → superseded only by a new ratified version; no silent drift.

## Entity 3: Conformance Finding

One gap between current code and the area's Skill Rule Set.

- **Attributes**: `id`, `area_id`, `location` (file:line), `violated rule` (FR-00x + skill), `severity` (critical: secret/parity/chain-correctness; major: error-handling/boundary/async misuse; minor: style/nit — all severities in scope per clarified Option A), `blast radius` (callers/tests affected), `remediation` (fix | migrate-callers-then-delete | document-and-keep with reason), `status` (open → fixed → verified, or accepted-exception with reason while the area stays not-done per SC-003).
- **Validation rules**: fix-every-finding bar — an area is done only when zero open findings remain; accepted exceptions keep the area not-done (SC-003) but unblock sequencing when recorded as explicit follow-ups at sweep level.

## Entity 4: Verification Record

Execution evidence for one unit plus the sweep-final gate (shape defined in [contracts/verification-record.md](contracts/verification-record.md)).

- **Attributes**: `unit/area_id`, `baseline` (pre-change fmt/clippy/test outcomes), `commands run` (exact invocations), `outcomes` (pass/fail + deltas vs baseline), `behavior demonstration` (for behavioral claims: loopback/stub peer, mock, or CLI run with literal expected output), `follow-ups[]`.
- **Validation rules**: re-reading is not evidence — every record MUST contain executed-command output; SC-002 deltas (new warnings, regressions) MUST be zero; the sweep-final record MUST contain one full `cargo xtask ci` pass plus `cargo xtask abi-diff` clean.
