# Implementation Plan: WARP Registration & Endpoint Scan

**Branch**: `002-warp-registration-scan` | **Date**: 2026-09-16 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-warp-registration-scan/spec.md`
(4 stories, 14 FRs, 7 SCs; all clarifications resolved 2026-09-16)

## Summary

Give the engine a live front door: provider identity registration/renewal
(WARP, GOOL outer+inner, MASQUE enrollment) owned by the core, plus built-in
endpoint candidates with traffic-verified, RTT-ranked scanning feeding the
existing scan cache. Thin CLI orchestrates (`register`, `renew`, extended
`scan`); the design follows the researched split (Aether core owns it,
Oblivion/PattNG orchestrate it).

Three structural decisions drive everything:

1. **Core owns registration and discovery; CLI orchestrates.** A new
   `qcore-core/src/identity/` module holds the registration client, the
   atomic identity store, and renewal classification. CLI commands are thin
   (FR-003c parity holds: every flow is public-API reachable).
2. **Candidates ship as data.** Built-in WARP/MASQUE ranges, seeds, and port
   pools live in a new `profiles/warp.toml` beside the existing profile
   files (FR-014, FR-028); the scanner stays a sieve — it just finally gets
   candidates.
3. **Renewal is classified, not blanket.** Only explicit provider-refusal
   signals plus MASQUE expiry trigger re-registration; every other failure
   keeps the identity and rescans (FR-004, restricted-network safety).

## Technical Context

**Language/Version**: Rust stable, pinned MSRV in `rust-toolchain.toml`
(1.97.1), edition 2021 — same workspace, no new toolchain.

**Primary Dependencies**: existing workspace only, plus small pure-Rust
adds, all already in the lockfile (zero new locked crates): `rcgen`
(self-signed P-256 MASQUE credential generation), `base64` (key encoding),
and `tokio-rustls` (thin TLS adapter over the already-vetted
`rustls`/`tokio` — not an HTTP stack; registration uses a minimal vendored
HTTPS/1.1 client, see research.md R1). X25519 keygen reuses `boringtun`;
randomness reuses `getrandom`; secrets reuse the keyring +
zeroizing wrappers.

**Storage**: Profile dir (FR-028 model): `identity-warp.toml`,
`identity-warp-inner.toml` (GOOL), MASQUE credential alongside, all
user-readable-only + atomic write; existing `endpoints.json`
last-known-good cache reused for winners; `profiles/warp.toml` shipped
defaults (replaceable without touching secrets).

**Testing**: `cargo nextest`; gating tests use a loopback fixture double
(refused-identity fixture, fake registration endpoint) per constitution II
— live provider tests are nightly-only, non-blocking.

**Target Platform**: existing 9-target matrix, unchanged.

**Project Type**: Rust workspace engine core + thin CLI (unchanged).

**Performance Goals**: SC-001 registration < 60 s on unblocked networks;
scan budgets reuse existing profile `rtt_budget_ms` bounds; connect-time
auto-registration/rotation MUST NOT push cold start past SC-003 (< 2 min).

**Constraints**: Direct-only provider connections (FR-011, fail closed with
blocked-vs-refused distinction); secrets never in logs/reports/exports
(FR-012, secret-hygiene suite extended); dual-stack everywhere with family
reported (FR-013); license key per-operation, never persisted (FR-010).

**Scale/Scope**: Single user/device; bounded candidate space (shipped
ranges + seeds + port pools); two identities max (GOOL outer+inner).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|---|---|---|
| I. Protocol-Agnostic Transport Core | PASS | Registration is provider plumbing under the engine, not a transport branch; validator untouched; new transports still need zero engine edits. |
| II. Dual-Stack Parity | PASS | FR-013; gating tests use loopback doubles; live tests nightly-only. |
| III. Composable, Declarative Chaining | PASS | Auto-register/rotate happen pre-start inside existing validation flow; chains stay declared data. |
| IV. Boundary Discipline and Secret Hygiene | PASS | Identity parsed at boundary; keyring + zeroizing storage; central redaction extended to new artifacts; license key never persisted; dynamic hygiene test extended. |
| V. Observable, Reproducible Behavior | PASS | Candidates + default profile ship as data; RegistrationReport is machine-readable; scan bounds explicit. |
| VI. Verified Protocol Behavior | PASS | Caller-level tests with refused-identity + fake-endpoint fixtures before complete. |
| Security: lawful use | PASS | Registration is an ordinary account signup flow; no evasion defaults (FR-011 direct-only). |
| Security: pinned deps + provenance | PASS | Two small pure-Rust adds pinned via workspace + denylist. |
| Workflow: consolidation bias | PASS | Registration client extends `qcore-core` (`identity/` module); scanner gains candidates, not a second scanner; CLI gains commands, not a second binary. |
| Governance: AGENTS.md | PASS (action) | AGENTS.md doc-map gains the 002 row on completion. |

**Gate result: PASS.** No violations requiring justification; Complexity
Tracking stays empty.

## Project Structure

### Documentation (this feature)

```text
specs/002-warp-registration-scan/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   ├── cli.md           # register/renew/scan/enroll surface + RegistrationReport JSON
│   └── profiles.md      # warp.toml + identity record formats
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

Feature adds (existing workspace untouched in shape):

```text
crates/qcore-core/src/identity/   # NEW: mod.rs, register.rs (HTTPS client +
                                  #   signup/refresh/re-register), store.rs
                                  #   (atomic TOML, 0600), renew.rs (refusal
                                  #   classification), masque.rs (enroll/rotate)
crates/qcore-core/src/scan/       # EXTEND: seed provider reads profiles/warp.toml
crates/qcore-cli/src/cmd/         # EXTEND: register.rs, renew.rs; scan profiles list grows
profiles/warp.toml                # NEW: shipped candidates/seeds/ports + defaults (FR-014)
tests/conformance/tests/          # NEW: registration.rs (fixture double), scan_providers.rs
```

**Structure Decision**: One new module (`identity/`) inside `qcore-core`
— the engine already owns config, secrets, and scan, so a sibling module
keeps the plugin boundary honest without a new crate. No new binary; CLI
commands are thin wrappers (FR-003c).

## Complexity Tracking

> No constitution violations. Section intentionally empty.

## Phase 0: Research

Consolidated in [research.md](./research.md): HTTPS client shape (R1),
identity store format (R2), renewal classification table (R3), MASQUE
credential lifecycle (R4), candidate/seed data model (R5), GOOL dual
identity (R6), license-key handling (R7).

## Phase 1: Design & Contracts

- [data-model.md](./data-model.md) — ProviderIdentity, RegistrationReport,
  endpoint cache entries, GOOL pair.
- contracts/: [cli.md](./contracts/cli.md),
  [profiles.md](./contracts/profiles.md).
- [quickstart.md](./quickstart.md) — offline-gating run (fixture doubles)
  plus nightly live run.

## Post-Phase-1 Constitution Re-check

Re-run of the gate above after design: still PASS. No new crates, no new
binaries, no transport/validator/CLI-schema edits for future transports;
the two added dependencies are pinned pure-Rust.
