# Research: Rust Best Practices Adoption

**Feature**: `003-rust-best-practices` | **Date**: 2026-09-17

All Technical Context items were known (toolchain, dependencies, storage, testing, targets, project type, constraints); no `NEEDS CLARIFICATION` remained. Research below resolves the methodology decisions for executing the sweep.

## R1: Skill-loading strategy for implementation units

- **Decision**: Each implementation unit loads only the Rust skills governing its area (per the R3 mapping) at the start of that unit's work, plus the relevant principle skills when the unit touches validation, errors, or structure.
- **Rationale**: Full upfront loading of all ~16 Rust skills burns context on rules irrelevant to the area at hand and degrades snippet fidelity; per-unit loading keeps the active rule set tight and auditable in the Verification Record.
- **Alternatives considered**: Load all skills once at sweep start and rely on memory — rejected (context cost, stale recall across a long sweep, unverifiable "which rules applied" claim breaks SC-001). Rely on model priors with no skill loads — rejected (violates the feature's core requirement and `AGENTS.md` Skills rule).

## R2: Risk-first area ordering

- **Decision**: Execute in four waves: Wave 1 — secret hygiene + error handling (`qcore-core/src/diag/`, `qcore-core/src/config/secret.rs`, identity store/report, session report, CLI key-input paths); Wave 2 — types/boundaries (config parsing/import/export/chain_file, chain parse/preset/validate, transport-api boundary, FFI boundary); Wave 3 — async/observability/networking (session lifecycle/net/reconnect, scan, identity https/register/renew/masque/gool, transports, diag events); Wave 4 — performance/memory/unsafe + CLI polish + remaining (transports hot paths, FFI `unsafe` invariants, CLI help/text, facade docs, xtask/examples/tests).
- **Rationale**: Matches the Assumptions priority and puts the constitution-critical properties (IV secret hygiene, error paths that mask parity/chain failures) first, so any session truncation still banked the highest-value conformance.
- **Alternatives considered**: Alphabetical/crate order — rejected (defers the riskiest surfaces). Single-pass file order — rejected (unreviewable diffs, violates FR-011 small-units rule).

## R3: Rule-to-area mapping (normative for tasks)

- **Decision**: The governing rule sets per area are:
  - `config/` + chain parse/validate + import/export + `transport-api` boundary → ownership, error-handling, type-system, API design, design patterns (rust-mastery, rust-ownership, rust-error-handling, rust-type-system, rust-api-design, rust-design-patterns).
  - `session/`, `scan/`, `identity/` (https/register/renew/masque/gool), transports → async, concurrency, networking, observability (rust-async, rust-concurrency, rust-networking, rust-observability) plus error-handling and mastery.
  - `diag/redact.rs`, `diag/events.rs`, identity store/report, session report, CLI license/register/renew key input → security, error-handling, observability (rust-security, rust-error-handling, rust-observability).
  - Transports hot paths, scan cache/seeds → performance, memory optimization (rust-performance, rust-memory-optimization); `qcore-ffi` (+ `jni.rs`) and any `unsafe` → rust-unsafe with documented invariants.
  - `qcore-cli` (clap commands, help text, config-file handling) → rust-cli plus error-handling and observability.
  - Everywhere → ecosystem (fmt/clippy/workspace hygiene), testing (caller-perspective tests, rust-testing) for each behavioral touch.
  - Excluded unless the code actually uses those domains: axum, dioxus, wasm, embedded, database, ML, fintech (per spec Assumptions).
- **Rationale**: Derives directly from FR-001–FR-009 and the code map; gives each task an explicit, checkable rule set so SC-001 ("state which rules applied within 5 minutes") is trivially satisfiable.
- **Alternatives considered**: Uniform "all skills apply everywhere" — rejected (unenforceable, produces noise findings outside a skill's domain). Per-file free choice by implementer — rejected (inconsistent bar across units, breaks User Story 1).

## R4: Verification strategy (scoped per unit + full gate once)

- **Decision**: Per unit: `cargo fmt --check` (or `cargo fmt` then diff review), `cargo clippy --all-targets --all-features -- -D warnings` scoped to the affected package(s) via `-p`, and the related nextest target(s) (`cargo nextest run -p <pkg>` plus affected `tests-conformance`/`tests-chains` cases); behavioral claims additionally demonstrated via loopback/stubbed peer, mock transport, or CLI invocation. Before done: one full `cargo xtask ci` plus `cargo xtask abi-diff` (no-break guard for FR-012). Baselines (scoped clippy warning count, related test outcomes) are recorded before each unit so SC-002 "zero new warnings, zero regressions" is falsifiable.
- **Rationale**: Implements clarified Option B with the project's own commands from `AGENTS.md`; `abi-diff` makes the no-breaking-changes clarification mechanically checkable rather than a review promise.
- **Alternatives considered**: Full `xtask ci` after every unit — rejected (clarified Option C was not chosen; cost without added signal). Scoped checks only, no final gate — rejected (misses cross-crate breaks from a full sweep; clarified Option A was not chosen).

## R5: Permanent guidance shape (FR-015)

- **Decision**: Single new document `docs/rust-practices.md` conforming to [contracts/guidance-schema.md](contracts/guidance-schema.md): one row per bounded area with governing skills, the area's key conventions, and the fastest verification command. Linked from `AGENTS.md` Skills section with a one-line pointer (pointer edit only, no restructuring of `AGENTS.md`).
- **Rationale**: Single-document mapping is the smallest artifact satisfying SC-005's unaided trial-task test; schema makes completeness checkable (every data-model area appears exactly once).
- **Alternatives considered**: Per-area doc files — rejected (discoverability fragmentation, harder SC-005 test). Encoding rules as new lint config only — rejected (many adopted rules are not machine-lintable; docs carry the rationale and fastest-check pointer).

## R6: No-break enforcement for versioned surfaces

- **Decision**: Guard FR-012 with three checks: `cargo xtask abi-diff` clean, `cli_api_parity` + `abi_consumer` conformance tests passing, and config round-trip tests (`import_roundtrip`, `imported_chain`, fixtures `standard-wg.conf`/`awg.conf`/`bogus.conf`) passing for every unit touching those surfaces. Any desired break is recorded as a follow-up and excluded from the diff.
- **Rationale**: Turns the clarified "no breaking changes" answer into executable gates using existing suite coverage rather than reviewer vigilance.
- **Alternatives considered**: Manual review checklist only — rejected (silent breaks are the exact failure mode; existing `abi-diff` + parity tests already mechanize it).

## R7: Baseline and sequencing protocol

- **Decision**: Each unit records its pre-change baseline (fmt status, scoped clippy output, related test results) in its Verification Record before editing, works on exactly one bounded area, migrates internal callers in the same unit (migrate-callers-then-delete, no shims), and stops at area boundaries. Cross-area fallout spawns a new unit rather than expanding the diff.
- **Rationale**: Operationalizes FR-011 (small verifiable units), FR-013 (evidence), and SC-004 (no undeclared behavior change) for a fix-every-finding sweep that stays reviewable.
- **Alternatives considered**: Sweep-then-verify at the end — rejected (unfalsifiable SC-002, unreviewable blast radius).
