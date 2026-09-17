# Tasks: WARP Registration & Endpoint Scan

**Input**: Design documents from `specs/002-warp-registration-scan/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/
**Tests**: INCLUDED — spec SC-004 requires a refused-identity fixture test, SC-005 extends the secret-hygiene suite, and quickstart.md defines an offline gating run. Tests are therefore mandatory for this feature.
**Organization**: Tasks grouped by user story (US1 P1 → US2 P1 → US3 P2 → US4 P3).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1)
- Include exact file paths in descriptions

## Path Conventions

Rust workspace per plan.md (extends the 001 layout, no new crates/binaries):
- `crates/qcore-core/src/identity/` — NEW module (register/store/renew/masque)
- `crates/qcore-core/src/scan/` — seed provider + cache extension
- `crates/qcore-cli/src/cmd/` — register.rs, renew.rs; scan.rs extension
- `profiles/warp.toml` — shipped candidate/seed/port data
- `tests/conformance/` — fixture double + story suites

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Pinned dependencies and shipped data both stories build on

- [X] T001 Add `rcgen` to workspace dependencies and `qcore-core` deps, pinned with provenance (research R4: self-signed P-256 MASQUE credential generation)
- [X] T002 [P] Create shipped `profiles/warp.toml` defaults (warp/masque ranges, per-family seeds, port pools in listed order, `scan_profile = "balanced"`) per contracts/profiles.md

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Identity types, atomic store, HTTPS client, report type — MUST complete before ANY user story

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T003 Implement ProviderIdentity types in `crates/qcore-core/src/identity/model.rs` (device id uniqueness key, zeroizing access token + private key, peer key, interface v4+v6, `refused` bool, `license_upgraded` bool with the key itself never stored)
- [X] T004 Implement atomic identity store in `crates/qcore-core/src/identity/store.rs` ("readable only by the user", temp-file + rename writes, corrupt/partial reads as missing, exactly-one-winner on races)
- [X] T005 [P] Implement minimal vendored HTTPS/1.1 client over workspace `rustls`/`tokio` in `crates/qcore-core/src/identity/https.rs` (research R1: JSON POST/GET/PATCH only, no new HTTP stack)
- [X] T006 [P] Implement RegistrationReport type + redacted rendering in `crates/qcore-core/src/identity/report.rs` (actions `registered|reused|refreshed|re_registered|rotated|refused|blocked`, identity device_id only, no credentials ever)
- [X] T007 Wire `identity/` module into `qcore-core` lib + Engine load/store accessors in `crates/qcore-core/src/api/engine.rs`, including creating `crates/qcore-core/src/identity/mod.rs` with all `pub mod` declarations
- [X] T008 Create loopback fake-provider fixture double in `tests/conformance/src/fixture.rs` + `pub mod fixture;` in `tests/conformance/src/lib.rs` (modes: accept, refuse-identity, timeout, empty — offline gating for all stories; runs after T003 shapes land)

**Checkpoint**: Foundation ready — identity lifecycle primitives exist against fixtures; user story implementation can now begin

---

## Phase 3: User Story 1 - Register a WARP identity and connect (Priority: P1) ★ MVP

**Goal**: Fresh-profile registration with no manual keys, reuse-on-connect, auto-register inside connect, GOOL outer+inner pair (spec FR-001/002/003/009/010, SC-001)

**Independent Test**: On a fresh profile, register against the fixture double, then connect `wireguard peer=warp` through it; disconnect cleanly. LICENSE-key path verified redacted.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T009 [P] [US1] Fixture test: register stores exactly one identity with no half-written state in `tests/conformance/tests/registration.rs`; registration attempted over both families with family reported
- [X] T010 [P] [US1] Auto-register-on-connect test (no stored identity → registered inline → connected) in `tests/conformance/tests/auto_register.rs`
- [X] T011 [US1] License-key test: flag/prompt/file all apply the upgrade with zero key bytes in outputs in `tests/conformance/tests/registration.rs` (same file as T009, runs after it)

### Implementation for User Story 1

- [X] T012 [P] [US1] Implement signup/refresh client in `crates/qcore-core/src/identity/register.rs` (X25519 keygen via `boringtun`, register + refresh calls, license applied per-operation only)
- [X] T013 [P] [US1] Implement GOOL pair provisioning (independent outer + inner records, independently renewable) in `crates/qcore-core/src/identity/gool.rs`
- [X] T014 [US1] Implement Engine integration in `crates/qcore-core/src/api/engine.rs` (reuse healthy identity, auto-register when none stored, GOOL pair resolution for gool chains)
- [X] T015 [US1] Implement `register` CLI command in `crates/qcore-cli/src/cmd/register.rs` (flag/prompt/file key input, one-line stderr warning on flag use, `--gool` pair flag, `--json` RegistrationReport)
- [X] T016 [US1] Wire `register` into `crates/qcore-cli/src/main.rs` (depends on T015)

**Checkpoint**: US1 fully functional — fresh profile registers and connects (against fixtures offline; against the provider nightly)

---

## Phase 4: User Story 2 - Scan for working endpoints (Priority: P1)

**Goal**: Seeded, traffic-verified, RTT-ranked scanning with cache-winner fast path and exit-4 empties (spec FR-006/007/008/014, SC-002/003/007)

**Independent Test**: Scan over loopback candidates returns ranked latencies; winner cached and re-verified first; empty candidate set exits 4 with no fallback.

### Tests for User Story 2

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T017 [P] [US2] Seeded-scan ranking test (loopback candidates, RTT order, handshake+traffic verified only) in `tests/conformance/tests/scan_providers.rs`; cases over ipv4-only, ipv6-only, and dual loopback candidates with family reported
- [X] T018 [P] [US2] Cache-winner re-verify + eviction test in `tests/conformance/tests/scan.rs` (extend existing suite, different file from T017)

### Implementation for User Story 2

- [X] T019 [P] [US2] Implement seed provider in `crates/qcore-core/src/scan/seeds.rs` (reads `profiles/warp.toml` ranges/seeds/ports, fail-closed naming file+field on shape errors, compiled-in fallback of identical shape)
- [X] T020 [P] [US2] Implement cache-winner re-verify-first + eviction in `crates/qcore-core/src/scan/cache.rs` (per-transport winners, `verified_at` ordering, failure evicts to full scan)
- [X] T021 [US2] Wire zero-config default profile into connect in `crates/qcore-core/src/session/reconnect.rs` (empty cache → seeded scan → winner; SC-007 path)
- [X] T022 [US2] Extend `scan` CLI for warp|masque transports in `crates/qcore-cli/src/cmd/scan.rs` (no new flags; profiles list shows warp defaults)

**Checkpoint**: US1 + US2 both work — register, scan, and connect form the zero-config loop

---

## Phase 5: User Story 3 - Renew an identity (Priority: P2)

**Goal**: Refusal-only re-registration with settings preserved and midway-failure safety (spec FR-004, SC-004)

**Independent Test**: Refused-identity fixture renews to working with unrelated settings byte-identical; timeout fixture keeps identity and rescans instead.

### Tests for User Story 3

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T023 [P] [US3] Refused-fixture renewal test (fresh identity, old discarded, settings untouched) in `tests/conformance/tests/renewal.rs`
- [X] T024 [US3] Timeout-fixture keeps-identity test + healthy-renew no-op test in `tests/conformance/tests/renewal.rs` (same file as T023, runs after it)

### Implementation for User Story 3

- [X] T025 [P] [US3] Implement refusal classifier in `crates/qcore-core/src/identity/renew.rs` (re-register ONLY on explicit provider-refusal signals; timeouts/handshake-silence/TLS-errors/empty-scans keep identity and rescan/retry — Aether-type table, research R3)
- [X] T026 [US3] Implement renewal flow in `crates/qcore-core/src/identity/renew.rs` (refresh-in-place when accepted, fresh re-register on refusal, previous identity intact on midway failure — same file as T025, runs after it)
- [X] T027 [US3] Implement `renew` CLI command (+ `--masque-only`) in `crates/qcore-cli/src/cmd/renew.rs`; GOOL pairs renew per-hop (outer/inner selectable via `--hop`; default renews every stored identity, never demanding a pair), never touching the sibling identity
- [X] T028 [US3] Implement mid-connect auto re-register-once on refusal in `crates/qcore-core/src/api/engine.rs` (extends T014 integration)

**Checkpoint**: US1 + US2 + US3 work — identities survive hostile networks without churn

---

## Phase 6: User Story 4 - MASQUE enrollment (Priority: P3)

**Goal**: Enroll + auto-rotate the MASQUE credential; h3 and h2 connect through scanned endpoints (spec FR-005, SC-006)

**Independent Test**: Enroll against the fixture, force the rotation window, connect (auto-rotates), then connect `masque alpn=h3` and `alpn=h2` through scanned endpoints.

### Tests for User Story 4

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [X] T029 [P] [US4] Enroll + rotation-window test against fixture in `tests/conformance/tests/masque_enroll.rs`
- [X] T030 [US4] h3/h2 live-path test through scanned endpoints in `tests/conformance/tests/masque_enroll.rs` (same file as T029, runs after it; nightly-gated where network is required)

### Implementation for User Story 4

- [X] T031 [P] [US4] Implement P-256 enroll/rotate in `crates/qcore-core/src/identity/masque.rs` (rcgen self-issued credential, provider enroll call, `issued_at` + lifetime/renew-before window math) — landed early (US3 `renew --masque-only` dependency); unit-tested in-file, conformance in T029/T030
- [X] T032 [US4] Implement connect-time auto-rotate integration in `crates/qcore-core/src/api/engine.rs` (extends T014/T028 integration)
- [X] T033 [US4] Wire enrollment into `register` flow in `crates/qcore-cli/src/cmd/register.rs` (extends T015 file)

**Checkpoint**: All user stories independently functional — register, scan, renew, MASQUE

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Hygiene, docs, and the gating run

- [X] T034 [P] Extend secret-hygiene suite to registration artifacts in `tests/conformance/tests/secret_hygiene.rs` (identity store files, RegistrationReports, license paths, refusal causes — SC-005)
- [X] T035 [P] Add the 002 row to the AGENTS.md doc-map in `AGENTS.md`
- [X] T036 Run quickstart.md gating validation in `specs/002-warp-registration-scan/quickstart.md` (fixture-double run offline; live provider run nightly, non-blocking)
- [X] T037 Full local gate: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, workspace tests, `cargo xtask smoke --target native`, `cargo xtask abi-diff`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately (T001 pin blocks T031's rcgen use but nothing else)
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories (T003 model → T004 store → T007 engine wiring; T005 HTTPS + T006 report parallel with the model chain; T008 runs after T003 shapes land)
- **User Stories (Phases 3–6)**: All depend on Foundational completion
  - US1 (P1) first — identity must exist before scanning/renewal/enrollment use it
  - US2 (P1) after Foundational — scanner independent of US1 at runtime but sequenced for the zero-config loop; uses T008 fixture, not US1 code
  - US3 (P2) after US1 — renewal operates on US1-provisioned identities
  - US4 (P3) after US1 — enrollment extends the US1 identity
- **Polish (Phase 7)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational — owns registration + GOOL pair + auto-register
- **User Story 2 (P1)**: Needs Foundational only — seed provider + cache; connect wiring touches US1's engine integration additively
- **User Story 3 (P2)**: Needs US1 identities — classifier + flow + CLI + mid-connect hook
- **User Story 4 (P3)**: Needs US1 identity — credential enroll/rotate + connect hook

### Within Each User Story

- Tests MUST be written and FAIL before implementation (T009–T011 before T012–T016; T017–T018 before T019–T022; etc.)
- Types before flows; flows before engine integration; engine before CLI; CLI wiring last
- Story complete (checkpoint green) before moving to next priority

### Parallel Opportunities

- Phase 1: T002 parallel with T001 (different files)
- Phase 2: T005/T006 parallel with the T003→T004 chain; T008 parallel once T003 lands
- US1: T009/T010 parallel (separate files); T012/T013 parallel (separate modules)
- US2: T017/T018 parallel (separate files); T019/T020 parallel (separate files)
- US3: T025 then T026 same file (sequential); T027 parallel with T025
- US4: T031 parallel with T029 test authoring
- Polish: T034/T035 parallel (different files)

---

## Parallel Example: User Story 1

```bash
# Tests together (fail-first, separate files):
Task: "Fixture registration test in tests/conformance/tests/registration.rs"
Task: "Auto-register-on-connect test in tests/conformance/tests/auto_register.rs"

# Implementations together (separate modules):
Task: "Signup/refresh client in crates/qcore-core/src/identity/register.rs"
Task: "GOOL pair provisioning in crates/qcore-core/src/identity/gool.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (pinned rcgen + warp.toml data)
2. Complete Phase 2: Foundational (identity types, store, HTTPS, report, fixture)
3. Complete Phase 3: US1 registration (T009–T016, incl. GOOL pair + auto-register)
4. **STOP and VALIDATE**: fresh profile registers against fixture in < 60 s shape; `wireguard peer=warp` connects; `cargo xtask ci` green
5. Demo if ready — live registration works end-to-end before any scanning

### Incremental Delivery

1. Setup + Foundational → identity primitives ready (fixture-proven)
2. Add US1 → test independently → Demo (MVP: register + connect, GOOL pair)
3. Add US2 → test independently → Demo (zero-config scan loop, SC-007 path)
4. Add US3 → test independently → Demo (refusal-only renewal, no churn)
5. Add US4 → test independently → Demo (MASQUE h3 + h2 live)
6. Polish → hygiene proof (SC-005), quickstart gating, full gate green
7. Each story adds value without breaking previous stories (workspace suite stays green)

### Parallel Team Strategy

With multiple developers (after Foundational):

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 registration (T012–T016) + US4 MASQUE (T031–T033)
   - Developer B: US2 scanning (T019–T022) + US3 renewal (T025–T028)
3. Stories complete and integrate independently; workspace suite arbitrates conflicts

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability (spec US numbers kept; phases ordered by priority P1→P2→P3)
- Data-model constraints quoted verbatim in task text (e.g. "readable only by the user", "refused=true MUST NOT be used for connects", "independently renewable")
- Contracts coverage: cli.md → T015/T016/T022/T027/T033; profiles.md → T002/T019
- Constitution gates honored: no new crates/binaries (consolidation bias), thin CLI (FR-003c parity), central redaction extended (IV), loopback-gated tests with nightly live (II/VI), profiles-as-data (V)
- Each story independently completable and testable (checkpoints list exact proofs from quickstart.md)
- Commit after each task or logical group; stop at any checkpoint to validate story independently
- Avoid: vague tasks, same-file conflicts, cross-story dependencies that break independence
- Implementation notes (post-task additions, all committed):
  - Bring-up injection (`identity/inject.rs`, unlisted at plan time): stored
    identities + cached endpoints merge into warp/masque hop configs in
    `Engine::start` — without it live connects fail demanding keys (the
    "identity store milestone" the old error named).
  - `preconnect_identity` was engine-only until live-test prep showed
    `connect` never called it; wired into `run_connect` (fail-closed exit 2).
  - rustls dual-provider panic (quinn `ring` vs arti `aws-lc-rs`): explicit
    provider in the registration TLS client + regression test.
  - Live 2026-09-17: registration, handshake, and MASQUE discovery verified
    against the provider; data-plane egress stalls on the pre-existing 001
    exit-translation gap (spec Assumptions record it; new-cycle candidate).
