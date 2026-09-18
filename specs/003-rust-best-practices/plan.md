# Implementation Plan: Rust Best Practices Adoption

**Branch**: `003-rust-best-practices` | **Date**: 2026-09-17 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/003-rust-best-practices/spec.md`

## Summary

Adopt the applicable Rust skill rules across the full `qcore` workspace (all 17 members: core engine, chain, config, session, identity, scan, transports, CLI, FFI, facade, examples, xtask, test suites). Work is sequenced risk-first (secret hygiene and error handling → types/boundaries → async/observability → performance/memory) in small independently verifiable units per bounded area. Every finding in a claimed-done area is fixed (no breaking changes to versioned surfaces); each unit is proven by scoped checks (fmt, clippy `-D warnings`, related nextest targets) plus a behavior demonstration for behavioral claims, with the full `cargo xtask ci` gate passing once before the feature is called done. The effort leaves permanent contributor guidance (FR-015) mapping each area to its governing rules and fastest verification command. Approach details and rejected alternatives are recorded in [research.md](research.md).

## Technical Context

**Language/Version**: Rust stable 1.97.1 (pinned in `rust-toolchain.toml` with `rustfmt` + `clippy` components), edition 2021, workspace resolver v2

**Primary Dependencies**: tokio (async runtime), boringtun (WireGuard), quinn + rustls/ring + h2 (MASQUE), arti-client + tor-proto (Tor), `inventory` (transport registry), serde/TOML/JSON (configs/reports), clap v4 derive (CLI), keyring + libsqlite3-sys bundled (identity store). No new runtime dependencies planned; any addition requires provenance pinning + rejected-alternatives note per Consolidation Bias.

**Storage**: OS keyring + bundled SQLite (identity), TOML profiles in `profiles/`, JSON/NDJSON state and diagnostic reports. Secret-hygiene rules apply to all of these surfaces.

**Testing**: `cargo nextest run --all-features` (unit + contract), `cargo nextest run -p tests-conformance` (matrix: wireguard, masque, tor_psiphon, failure_report, single_stack, scan, obfuscation, extensibility, cli_api_parity, secret_hygiene, abi_consumer, throughput, registration/renewal/masque_enroll), `tests/chains` (orderings, rejections, grammar, import round-trips). Behavior proof uses loopback/stubbed peers, mock transport, CLI invocation, and test doubles — never live networks as gates.

**Target Platform**: 9-target release contract in `xtask/src/targets.toml` (windows x86/x64/arm64, linux x86/x64/arm64/arm, android arm64/arm) delivering CLI archives, cdylib (`dll`/`so`/JNI), termux-cli. Delivery surfaces: embeddable Rust library (`crates/qcore`), pure CLI (`crates/qcore-cli`), C ABI (`crates/qcore-ffi` + `qcore.h` + `abi-version.txt` + `jni.rs`).

**Project Type**: Multi-crate Rust workspace (embeddable library + CLI + FFI + xtask + conformance/chains test suites). No new crate, module, or public trait is introduced by this feature.

**Performance Goals**: No regressions: the `throughput` conformance test and per-area behavior baselines must pass unchanged; no unmeasured optimization; hot-path allocation/complexity changes require measurement evidence.

**Constraints**: (1) Constitution v1.1.0 wins over any skill rule on conflict, conflicts surfaced explicitly. (2) Zero breaking changes to versioned surfaces (Rust API, C ABI, config/report schemas, CLI contracts) — desired breaks become follow-ups. (3) Dual-stack parity preserved on every touched transport/scanner/chain path. (4) `cargo fmt --check` clean and `cargo clippy --all-targets --all-features -- -D warnings` clean for every touched area. (5) Fix-every-finding bar per claimed-done area (clarified Option A).

**Scale/Scope**: Full workspace sweep (clarified Option C): ~17 workspace members, ordered by risk, each unit independently verifiable. Unfinished areas recorded as explicit follow-ups, never half-applied.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Protocol-Agnostic Transport Core**: PASS — no transport-specific logic is added; remediation inside transports stays behind the existing `Descriptor`/`Dialer`/`RunningHop`/`HopFactory` boundary, and the chain engine/scanner are not branched on transport kind.
- **II. Dual-Stack Parity (NON-NEGOTIABLE)**: PASS — parity is a protected property: every touched transport/scanner/chain path keeps its loopback/stubbed-peer v4+v6 verification; any IPv4-only assumption found is treated as a defect to fix, not as style.
- **III. Composable, Declarative Chaining**: PASS — chain declarations stay validated data; no imperative rewiring; capability-before-instantiation preserved.
- **IV. Boundary Discipline and Secret Hygiene**: PASS — this principle is the highest-priority workstream (typed config surfaces, typed-field-first redaction); diagnostics/state/errors touched by the sweep must pass the `secret_hygiene` conformance test plus the dynamic no-leak capture.
- **V. Observable, Reproducible Behavior**: PASS — scan/obfuscation profiles stay data; structured NDJSON diagnostics preserved; any test seeding behavior kept deterministic.
- **VI. Verified Protocol Behavior**: PASS — caller-perspective contract tests required for every behavioral change; conformance suite stays registry-generated.
- **Security constraints** (lawful use, secret classification fail-closed, confidence reporting, pinned deps, vetted crypto, round-trip imports, telemetry off, sidecar trust boundary): PASS — sweep introduces no evasion defaults, no new crypto, no telemetry change, no sidecar change; untrusted-input handling is hardened only.
- **Workflow gates** (PR review, build+unit+conformance+chains+lint+secret-scan, release integrity, independent versioning, target list, dual-stack harness, consolidation bias, platform delivery, emergency path): PASS — per-unit scoped checks plus one full `cargo xtask ci` before done; no target-list change; no new crate (consolidation bias satisfied trivially); no versioned-surface breaks so no deprecation window is triggered.

No gate violations. Complexity Tracking stays empty.

## Project Structure

### Documentation (this feature)

```text
specs/003-rust-best-practices/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
│   ├── guidance-schema.md      # FR-015: what permanent guidance must contain
│   └── verification-record.md  # FR-013: evidence shape per unit + final gate
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

Existing workspace — no new crates or top-level layout changes. Bounded areas for the sweep (from `AGENTS.md` code map):

```text
crates/qcore-transport-api/src/   plugin boundary
crates/qcore-core/src/
├── registry.rs / chain/          transport registry + chain engine
├── config/                       hop, import, export, obfuscation, secret, chain_file
├── session/                      lifecycle, net, report, reconnect
├── identity/                     model, store, https, register, renew, masque, gool, inject, report
├── scan/                         Scanner, seeds, cache
└── diag/                         redact, events (NDJSON)
crates/qcore-transports/transport-*/  wireguard, masque, relay, tor, psiphon, mock
crates/qcore/src/                 embedder facade
crates/qcore-cli/src/             main, cmd/*, help (lawful-use text)
crates/qcore-ffi/src/             lib (11 qcore_* fns), qcore.h, abi-version.txt, jni.rs
profiles/                         scan.toml, obfuscation.toml, compositions.toml, warp.toml
tests/conformance/tests/ + tests/chains/tests/ + tests/fixtures/
examples/embed-host/ + examples/c-abi-consumer/ + xtask/src/
docs/
└── rust-practices.md             # FR-015 permanent guidance (NEW - single doc file)
```

**Structure Decision**: Keep the existing workspace layout exactly. The only new file is `docs/rust-practices.md` (per-area rule-to-check mapping). Per Consolidation Bias: a new crate/module/trait was considered for "practices infrastructure" and rejected — there is no shared code to extract; the deliverables are remediated code in place plus one guidance document. A per-area multi-doc layout was considered and rejected in favor of one document so the mapping stays discoverable in a single place (SC-005 trial-task test).

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| — | — | — |

*Post-Phase-1 re-check (2026-09-17): no violations introduced by the design. Research, data model, contracts, and quickstart add documentation only; no new crates, dependencies, targets, telemetry, crypto, or versioned-surface changes.*
