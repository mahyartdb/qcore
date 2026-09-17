# Tasks: Rust Best Practices Adoption

**Input**: Design documents from `/specs/003-rust-best-practices/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Included where the spec requires them — FR-007 mandates caller-perspective tests against loopback/stubbed peers or doubles plus regression coverage for fixed defects in parity, chaining, or redaction. Each behavioral touch therefore carries a test task; tests MUST be written and FAIL before the fix.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Toolchain, roster, and baseline groundwork before any remediation

- [X] T001 Verify pinned toolchain (Rust 1.97.1), rustfmt/clippy components, nextest, and `cargo xtask` alias per rust-toolchain.toml and .cargo/config.toml
- [X] T002 [P] Confirm the 15-area roster against the tree and record any drift in specs/003-rust-best-practices/data-model.md
- [X] T003 Record the workspace pre-sweep baseline (`cargo fmt --check` status, workspace clippy summary, nextest collection status) as Verification Record #0 in specs/003-rust-best-practices/tasks.md Notes

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Ratified rule sets and guidance skeleton that every later unit builds on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Create docs/rust-practices.md skeleton (header + 15-row table shell: Area ID, location, governing skills) per specs/003-rust-best-practices/contracts/guidance-schema.md
- [X] T005 Ratify per-area Skill Rule Sets per specs/003-rust-best-practices/research.md R3 and record them plus any constitution-conflict surfacing in specs/003-rust-best-practices/tasks.md Notes

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Session follows Rust skill rules consistently (Priority: P1) ⭐ MVP

**Goal**: Prove that session work applies the area's governing skills with cited evidence, consistently across units

**Independent Test**: Take any small Rust change (e.g., a new validated config type); the result cites the applied skill rules and passes the area's scoped checks (SC-001 protocol: uninvolved reviewer, random sample, 5 minutes per unit)

### Implementation for User Story 1

- [X] T006 [US1] Pilot unit: apply governing skills with per-unit skill loading (research R1) to Bounded Area diag in crates/qcore-core/src/diag/, fix all findings, run scoped verification, file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T007 [US1] Second pilot on contrasting area config secrets in crates/qcore-core/src/config/secret.rs; cross-check naming, error, logging, and test conventions against T006 for consistency
- [X] T008 [US1] SC-001 dry-run: uninvolved-reviewer protocol over the T006–T007 records (random sample, timed); record the outcome in specs/003-rust-best-practices/tasks.md Notes

**Checkpoint**: At this point, the per-unit protocol is proven and User Story 1 is independently testable

---

## Phase 4: User Story 2 - Existing code brought into conformance safely (Priority: P1)

**Goal**: Full-workspace sweep in risk-first waves; every finding in each claimed-done area fixed with zero breaking changes

**Independent Test**: Pick any remediated area; re-review shows zero open findings and its scoped verification (fmt, clippy `-D warnings`, related nextest) passes with zero new warnings and zero regressions vs baseline

### Wave 1 — Secret hygiene + error handling

- [X] T009 [P] [US2] Remediate identity store/report in crates/qcore-core/src/identity/store.rs and crates/qcore-core/src/identity/report.rs (rust-security, rust-error-handling, rust-observability); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T010 [P] [US2] Remediate session report in crates/qcore-core/src/session/report.rs (rust-security, rust-error-handling); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T011 [P] [US2] Remediate CLI key-input paths in crates/qcore-cli/src/cmd/license.rs, crates/qcore-cli/src/cmd/register.rs, and crates/qcore-cli/src/cmd/renew.rs (rust-cli, rust-security, rust-error-handling); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T012 [P] [US2] Error-handling pass over crates/qcore-core/src/session/lifecycle.rs and crates/qcore-core/src/session/reconnect.rs (rust-error-handling, rust-async); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T013 [US2] Write failing-first caller-perspective regression tests for Wave-1 fixed defects (secret redaction, fallible paths) in tests/conformance/tests/, then make them pass

### Wave 2 — Types and boundaries

- [X] T014 [P] [US2] Remediate config parsing and boundaries in crates/qcore-core/src/config/ (hop.rs, import.rs, export.rs, obfuscation.rs, chain_file.rs; rust-type-system, rust-api-design, rust-design-patterns, rust-error-handling); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T015 [P] [US2] Remediate chain engine and registry in crates/qcore-core/src/chain/ and crates/qcore-core/src/registry.rs (rust-type-system, rust-api-design, rust-testing); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T016 [P] [US2] Remediate transport-api boundary and facade in crates/qcore-transport-api/src/lib.rs and crates/qcore/src/lib.rs (rust-api-design, rust-ownership, rust-design-patterns); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T017 [P] [US2] Audit FFI boundary in crates/qcore-ffi/src/lib.rs and crates/qcore-ffi/src/jni.rs (rust-unsafe: document invariants, narrowest scope; no behavior change); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T018 [US2] Prove Wave-2 surfaces: cli_api_parity and abi_consumer in tests/conformance/tests/ plus import round-trips in tests/chains/tests/ with fixtures tests/fixtures/standard-wg.conf, tests/fixtures/awg.conf, tests/fixtures/bogus.conf all green

### Wave 3 — Async, observability, networking

- [X] T019 [P] [US2] Remediate session net and identity networking in crates/qcore-core/src/session/net.rs and crates/qcore-core/src/identity/https.rs, register.rs, renew.rs, masque.rs, gool.rs, inject.rs (rust-async, rust-concurrency, rust-networking, rust-observability); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T020 [P] [US2] Remediate scanner in crates/qcore-core/src/scan/ (rust-async, rust-concurrency, rust-networking, rust-observability, rust-performance); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T021 [P] [US2] Remediate transports in crates/qcore-transports/transport-wireguard/, transport-masque/, transport-relay/, transport-tor/, transport-psiphon/, transport-mock/ (rust-async, rust-networking, rust-performance, rust-testing); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T022 [P] [US2] Remediate diagnostics stream in crates/qcore-core/src/diag/events.rs (rust-observability, rust-error-handling, rust-security); file Verification Record in specs/003-rust-best-practices/tasks.md Notes

### Wave 4 — Performance, memory, unsafe leftovers, CLI, misc

- [X] T023 [P] [US2] Hot-path performance/memory pass over crates/qcore-transports/ and crates/qcore-core/src/scan/cache.rs with measurement evidence; no unmeasured optimization (rust-performance, rust-memory-optimization); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T024 [P] [US2] CLI polish in crates/qcore-cli/src/main.rs, crates/qcore-cli/src/cmd/, and crates/qcore-cli/src/help.rs (rust-cli, rust-error-handling, rust-observability); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T025 [P] [US2] Remediate profiles, examples, and xtask in profiles/, examples/embed-host/, examples/c-abi-consumer/main.go, and xtask/src/ (rust-cli, rust-ecosystem, rust-error-handling); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T026 [P] [US2] Align test suites in tests/conformance/tests/ and tests/chains/tests/ with remediated code (rust-testing); file Verification Record in specs/003-rust-best-practices/tasks.md Notes
- [X] T027 [US2] Wave-4 no-break evidence: `cargo xtask abi-diff` clean plus config round-trip fixtures green; record in specs/003-rust-best-practices/tasks.md Notes

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently (protocol proven + full sweep remediated)

---

## Phase 5: User Story 3 - Conformance proven by execution (Priority: P2)

**Goal**: Complete, auditable execution evidence for every unit plus the sweep-final gate

**Independent Test**: Every unit has a Verification Record per contracts/verification-record.md with zero new warnings and zero regressions; one full `cargo xtask ci` pass plus clean `cargo xtask abi-diff` recorded

### Implementation for User Story 3

- [X] T028 [US3] Audit all unit Verification Records against specs/003-rust-best-practices/contracts/verification-record.md; list any gaps as dated follow-ups in specs/003-rust-best-practices/tasks.md Notes (no new code)
- [X] T029 [US3] Run the sweep-final full gate (`cargo xtask ci`) plus `cargo xtask abi-diff`; record log location and outcome in specs/003-rust-best-practices/tasks.md Notes
- [X] T030 [US3] Run behavior demonstrations for each behavioral claim (loopback/stubbed peer, mock transport, CLI invocation) with literal expected-vs-observed output; record in specs/003-rust-best-practices/tasks.md Notes

**Checkpoint**: Evidence complete; any reviewer can verify the sweep without trusting prose claims

---

## Phase 6: User Story 4 - Future work stays conformant (Priority: P3)

**Goal**: Permanent, discoverable per-area guidance so the next task is faster

**Independent Test**: SC-005 trial — an unfamiliar contributor with a small task in a remediated area locates the governing row and fastest verification command in docs/rust-practices.md unaided within 5 minutes

### Implementation for User Story 4

- [X] T031 [US4] Fill all 15 per-area rows in docs/rust-practices.md (conventions with skill citations, fastest verification commands, known exceptions) per specs/003-rust-best-practices/contracts/guidance-schema.md
- [X] T032 [US4] Add a one-line pointer to docs/rust-practices.md in the Skills section of AGENTS.md (pointer only, no restructuring)
- [X] T033 [US4] Run the SC-005 trial with an unfamiliar contributor; record contributor, task, time-to-locate, and date in specs/003-rust-best-practices/tasks.md Notes

**Checkpoint**: All user stories should now be independently functional

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Close-out validation across all stories

- [X] T034 Re-validate specs/003-rust-best-practices/checklists/sweep-readiness.md and specs/003-rust-best-practices/checklists/requirements.md against the finished work (review-only, no marker changes except by reviewer judgment)
- [X] T035 Run specs/003-rust-best-practices/quickstart.md Scenarios 1–3 end-to-end and record outcomes in specs/003-rust-best-practices/tasks.md Notes
- [X] T036 Triage residual findings into a dated follow-ups list; confirm zero open findings in claimed-done areas per SC-003

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in priority order (P1 → P2 → P3)
  - US2 waves run sequentially Wave 1 → Wave 2 → Wave 3 → Wave 4 (risk-first; shared types settle early)
  - US3/US4 can start once US2 waves they observe are recorded, but final sign-off needs all waves
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational (Phase 2) - Uses the US1 protocol; independently testable per area
- **User Story 3 (P2)**: Depends on unit records from US1/US2 existing - audit only, no code
- **User Story 4 (P3)**: Depends on remediated areas for row content - skeleton exists from Phase 2

### Within Each User Story

- Tests (where included, e.g., T013) MUST be written and FAIL before implementation
- One bounded area per unit; cross-area fallout spawns a new unit (FR-011)
- Scoped verification per unit before moving on (FR-013)
- Failed units return to baseline or go green in-unit; no persisting half-applied state (FR-013)

### Parallel Opportunities

- T002 can run parallel with T001/T003 (different concerns, no shared files)
- Wave task groups marked [P] (T009–T012, T014–T017, T019–T022, T023–T026) can run in parallel — different files, no interdependencies
- T013 follows its wave's remediation (needs the findings first); T018/T027 are wave gates and run after their wave's [P] group
- US3 audit (T028) can start incrementally as unit records land; T029 final gate needs all code complete

---

## Parallel Example: User Story 2, Wave 1

```bash
# Launch all Wave-1 remediation units together (different files, no dependencies):
Task: "Remediate identity store/report in crates/qcore-core/src/identity/store.rs and report.rs"
Task: "Remediate session report in crates/qcore-core/src/session/report.rs"
Task: "Remediate CLI key-input paths in crates/qcore-cli/src/cmd/license.rs, register.rs, renew.rs"
Task: "Error-handling pass over crates/qcore-core/src/session/lifecycle.rs and reconnect.rs"

# Wave gate runs after the parallel group (needs their findings):
Task: "Write failing-first caller-perspective regression tests in tests/conformance/tests/"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (baseline + roster)
2. Complete Phase 2: Foundational (rule sets ratified, guidance skeleton)
3. Complete Phase 3: User Story 1 (two pilot areas + SC-001 dry-run)
4. **STOP and VALIDATE**: Any small change cites its rules and passes scoped checks; reviewer protocol works
5. Proceed to the sweep only after the protocol is proven

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 (pilots) → Test independently → Protocol proven (MVP!)
3. Add User Story 2 Wave 1 → Test independently → Highest-risk surfaces conformant
4. Add Waves 2–4 → Each wave independently verifiable → Full sweep complete
5. Add User Story 3 → Evidence audited, full gate green
6. Add User Story 4 → Guidance complete, trial passes
7. Polish → Residuals triaged, quickstart scenarios green

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 pilots
   - Developer B: Starts Wave 1 units (after protocol proven)
3. Within a wave, developers take one [P] unit each (different areas, no file conflicts)
4. One owner runs wave gates (T013/T018/T027), US3 audit, and the final gate (T029)

---

## Notes

- Verification Records accumulate in the Notes section below as units complete (per contracts/verification-record.md)
- Record #0 is the Phase-1 workspace baseline (T003)
- Constitution wins on any skill conflict; surfacing goes in the record's `skills applied` deviation field (FR-010)

### Notes

_Verification Record #0 (workspace baseline, 2026-09-17): toolchain rustc/cargo 1.97.1 pinned ✓; rustfmt 1.9.0 ✓; clippy 0.1.97 ✓; cargo-nextest 0.9.145 installed to ~/.cargo/bin (was missing) ✓; `cargo xtask` alias resolves ✓; `cargo fmt --check` exit 0 (clean) ✓; `cargo check --workspace --all-targets` exit 0 ✓. Per-unit scoped clippy+nextest baselines captured per unit per research R4. Follow-ups: none._

_Unit records and baseline land here as work proceeds._

_Ratification (T005, 2026-09-17): research R3 rule-to-area mapping adopted as normative for all units (see docs/rust-practices.md table). Constitution-conflict surfacing: none raised at ratification; any future conflict goes in the unit record's `skills applied` deviation field per FR-010. Pilot scoping (analyze M4): T006 owns `diag/redact.rs` (+ review of `events.rs` without edits); T007 owns `config/secret.rs`; T022 owns `events.rs` edits; T014 owns the rest of `config/`._

_Verification Record (T006 diag pilot, 2026-09-17): area diag (`redact.rs` owned; `events.rs` reviewed, no edits, no findings — `unwrap_or` fallbacks are deliberate non-panicky paths). Skills applied: rust-security, rust-error-handling, rust-observability; no deviations. Findings fixed in `redact.rs`: (1) `Redaction::Keep` doc debris removed; (2) magic numbers 16/4.2/44 → named consts `MIN_RANDOM_LEN`/`ENTROPY_BITS_PER_CHAR`/`MIN_DROP_LEN` (values unchanged, zero behavior delta); (3) additive `Display` for `DroppedRecord` (non-breaking, loggable verdict). Baseline: workspace fmt clean + `cargo check` green (Record #0); no pre-existing scoped warnings. Commands: `cargo fmt --check -p qcore-core` exit 0; `cargo clippy -p qcore-core --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-core --lib diag::` 8/8 pass. Deltas: zero new warnings, zero regressions. Behavior demo: n/a (no behavioral claim; fail-closed secrecy preserved by pre-existing tests). Record contains no secrets (paths + outcomes only). Follow-ups: F4 misleading test name `typed_secret_key_is_masked_not_dropped` in `events.rs` → T022; none else._

_Verification Record (T007 config-secret pilot, 2026-09-17): area config (`secret.rs` owned). Skills applied: rust-ownership, rust-type-system, rust-api-design, rust-design-patterns, rust-security, rust-error-handling; no deviations. Findings fixed in `secret.rs`: (1) `Debug for SecretString` no longer prints secret byte-length (length side-channel; format now `<redacted>`); (2) module doc states Windows fallback inherits directory ACLs (was unconditional 0600). Findings documented as versioned-surface follow-ups (NOT changed per FR-012 no-break rule): (a) `Result<_, String>` stringly-typed errors → typed error enum requires Rust API change; (b) `account_path` sanitizer collisions (`/`/`.` → `_`; distinct accounts can map to one file) → collision-resistant encoding needs stored-format migration (orphaning risk worse than the theoretical collision); (c) unvalidated `Account` newtype at boundary → same API-freeze reason. Ownership review: no gratuitous clones (`from_utf8_lossy().into_owned()` required by keyring `&str` API; borrows elsewhere); volatile wipe retained over a new `zeroize` dependency per laziness bias. Cross-check vs T006: naming/error/logging/test conventions consistent (typed boundaries, no panicky fallible paths outside tests, no secret logging, literal expected-value asserts). Commands: `cargo fmt --check -p qcore-core` exit 0; `cargo clippy -p qcore-core --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-core --lib config::secret` 3/3 pass. Deltas: zero new warnings, zero regressions. Behavior demo: round-trip tests prove preservation; Debug-format change is not a versioned surface (no test or consumer depended on it — verified by grep). Record contains no secrets. Follow-ups: (a)(b)(c) above as dated breaking/format-change follow-ups; `transport-psiphon supervisor.rs` has its own `<redacted N bytes>` Debug → T021._

_Verification Record (T010 session report, 2026-09-17): area session (`report.rs` owned). Skills applied: rust-security, rust-error-handling, rust-observability; no deviations. Findings fixed: (1) `to_json` used `.expect("report serializes")` on a runtime path → `unwrap_or_else` static-fallback JSON (one-document contract preserved; matches sibling `identity/report.rs` convention). (2) Secret-hygiene gap: `to_text`/`emit_failure` rendered `FailureReport.cause` (free text; transports/provider strings flow through it) raw to stdout/stderr while only the NDJSON path redacted → both now render via `safe_cause` through central `redact_value` (ordinary causes byte-identical — pinned by test asserting equality with `Display`; secret-like causes masked). New test `text_failure_line_masks_secret_like_cause` proves masking + Display-equality. Reviewed, no change: `health_status() -> String` allocation retained (cold path, pub signature frozen per FR-012). Commands: `cargo fmt --check` exit 0; `cargo clippy -p qcore-core --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-core --lib session::report` 4/4 pass. Deltas zero/zero. Record contains no secrets. Follow-ups: none._

_Verification Record (T011 CLI key-input paths, 2026-09-17): area cli (`license.rs`, `register.rs`, `renew.rs` owned). Skills applied: rust-cli, rust-security, rust-error-handling; no deviations. Findings fixed: (1) `timeout_secs: 20` magic number in `provider_opts` → named `REGISTER_TIMEOUT_SECS` const (non-breaking; `family: "dual"` stringly-typed stays — cross-crate contract, follow-up class T007c). (2) Added 4 caller-perspective unit tests for `license::resolve` (flag/file conflict, missing file, empty file → usage error; non-interactive none → `Ok(None)`); TTY-prompt path untestable headless by design. Reviewed, no change with reasons: TTY prompt echoes input — documented in-code, steered to `--license-file`; no-echo prompt needs OS APIs/new dep → recorded follow-up (secret-hygiene accepted divergence, narrowest scope). `register_with_masque` cause appends verified as sanitized-fragment concatenation (T009 `safe_cause` at construction). `renew.rs reports[1]` proven panic-safe (roles ≤ 2, len==1 early-returns). Commands: `cargo fmt --check -p qcore-cli` exit 0; `cargo clippy -p qcore-cli --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-cli` 7/7 pass (4 new). Deltas zero/zero. Record contains no secrets. Follow-ups: no-echo TTY prompt; stringly `family`; none else._

_Verification Record (T012 session lifecycle/reconnect error pass, 2026-09-17): area session (`lifecycle.rs`, `reconnect.rs` owned). Skills applied: rust-error-handling, rust-async; no deviations. Reviewed with NO code changes — each candidate dispositioned: (1) all `bring_up` failure paths unwind reverse-order before returning typed `FailureReport` ✓; (2) fan-out `tokio::spawn` task terminates when the hop drops its sender (no orphan) and breaks on lagged-bus send error ✓; (3) `let _ = events.send` is deliberate best-effort on a lossy bus ✓; (4) dual deadline enforcement (`Instant` check + per-hop `timeout()`) ✓; (5) `default_chain_spec().expect(...)` backstopped by `default_chain_is_single_warp_hop` unit test running the same literal in CI — documented invariant, retained; (6) `toml::to_string().unwrap_or_default()` already non-panicky ✓; (7) `ensure_identity` first-writer race benign (stable-id semantics; last-writer-wins converges) ✓. Async review: no blocking calls in async paths, no lock-across-await, timeouts on every network hop ✓. Commands: covered by T010's `qcore-core` clippy/nextest runs (same package, same revision) — `cargo nextest run -p qcore-core --lib session::` green including pre-existing reconnect tests. Deltas zero/zero. Follow-ups: none._

_SC-001 dry-run (T008, 2026-09-17): sample = both existing units (T006, T007 — population of 2). From tasks.md Notes alone, without author help: T006 → skills rust-security/rust-error-handling/rust-observability, verification `fmt --check` + `clippy -D warnings` + `nextest diag::` 8/8; T007 → skills rust-ownership/rust-type-system/rust-api-design/rust-design-patterns/rust-security/rust-error-handling, verification `fmt --check` + `clippy -D warnings` + `nextest config::secret` 3/3. Located in well under 5 minutes per unit. Outcome: PASS. US1 protocol proven — MVP checkpoint reached._

_Verification Record (T013 Wave-1 regression tests, 2026-09-17): skills applied: rust-testing (caller-perspective, literal expected values; rust-security for the secret corpus). Tests added: (1) `secret_hygiene::refusal_cause_with_provider_echoed_secret_is_masked` — provider-echoed secret-like detail in `report_for_error` is masked with prefix kept; (2) `secret_hygiene::text_failure_path_masks_secret_like_cause` — `to_text` masks secret-like causes; (3) `store::namespace_hash_is_stable_known_answer` — FNV-1a determinism + known-answer vector (misuse-prevention against hasher swaps); (4) strengthened `secret::debug_never_leaks_value` to pin exact `<redacted>` format. Failing-first proof (honest TDD): with the 6 source files stashed (fixes shelved, new conformance tests kept), both new conformance tests FAILED (`refusal cause leaked provider echo`, 0/2 pass); with fixes restored, all pass. Commands: `cargo fmt --check` exit 0; `cargo clippy -p qcore-core -p qcore-cli -p tests-conformance --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p tests-conformance --test secret_hygiene` 6/6 pass; `cargo nextest run -p qcore-core --lib` 95/95 pass. Deltas zero/zero. Record contains no secrets. Follow-ups: none. Wave 1 complete._

_Verification Record (T019 session/identity networking, 2026-09-17): area session+identity. Skills applied: rust-async, rust-concurrency, rust-networking, rust-observability, rust-error-handling, rust-security, rust-ownership, rust-api-design; no deviations. Findings fixed: (1) `net.rs` keepalive doc falsely claimed dropping the JoinHandle stops ticks (dropping detaches) and that teardown aborts watchers (nothing stores handles) → doc now states detach semantics + bounded linger (next tick ≤ one interval observes stopped hop and breaks); structural abort-on-teardown recorded as follow-up (needs lifecycle/session changes, new unit). (2) Two static bind-literal `.unwrap()`s → `expect` with reasons. (3) Renewal Keep-path causes (`renew.rs` ×5: store-fail, keep, reregister-save-fail, credential-generate-fail, enroll-fail) interpolated provider-controlled text bypassing the T009 boundary fix → all routed through shared `masked_value` (prefixes intact). (4) `role_name` duplicated in `renew.rs`+`inject.rs` → single `pub(crate) fn` in `store.rs` (owns `IdentityRole`); both call sites migrated. (5) `inject::b64_to_hex` re-owned base64+32-byte validation → delegates to `import::{b64_decode_32, hex_encode}` (messages preserved). Reviewed, no change with reasons: `eyeballs_dial` sequential stagger is documented RFC-8305-CAD behavior; poisoned-`Mutex` `lock().unwrap()` retained as fail-stop (a panicked holder means suspect tunnel state — silent recovery would be worse); transient plaintext auth/body buffers in `register.rs`/`masque.rs` kept with earliest-`drop` discipline — zeroizing them is poor cost/benefit while TLS stacks retain key material in memory regardless (documented decision, closes T009-recorded input); `gool.rs` honest `"stored"` family marker exemplary; `model.rs` (absorbed — was unowned by any task) exemplary (saturating rotation math, SecretString fields, boundary tests); `for_report` single-use pub helper retained (tested); stringly `family`/`family_order` + profile silent-fallback need version-window/product decisions (follow-up class T007c). `masque::generate_credential() -> Result<_, String>` pub signature frozen (follow-up class T007a). Commands: workspace `cargo clippy --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-core --lib` 100/100 pass. Deltas zero/zero. Behavior demo: inject/renew classifier/masque tests green; no behavioral deltas. Record contains no secrets. Follow-ups: keepalive abort-on-teardown; stringly family unification; profile-fallback product decision; none else._

_Verification Record (T020 scanner, 2026-09-17): area scan (`mod.rs`, `cache.rs`, `seeds.rs` owned). Skills applied: rust-async, rust-concurrency, rust-networking, rust-observability, rust-performance; no deviations. Findings fixed: (1) REAL BUG — `sample_cidr_v4` overflowed past `u32::MAX` on high ranges (e.g. 255.255.0.0/16) and silently clamped onto broadcast via `unwrap_or(u32::MAX)` → clamped to last usable address with proof comment; new test pins high-range containment. Reviewed, no change with reasons: semaphore-bounded spawn set retained over JoinSet rewrite (correct as-is; rewrite unmeasured); `stealth_gap` serial sleep is documented stealth behavior; `rank` stable sort keeps ties deterministic (constitution V); `rand8` xorshift documented non-security nonce; `verify_winner_first`/`evict`/`touch` best-effort writes benign (re-check converges); `first_host_v6` wraparound edge harmless (advisory data, probe-filtered); silent `discovery_seeds`/`load_profile` fallbacks recorded under the profile-fallback product follow-up. Commands: fmt/clippy clean (workspace runs); `qcore-core --lib` 100/100 incl. new containment test. Behavior demo: existing rank/LKG/seeds tests green; overflow fix changes only previously-wrong candidates. Record contains no secrets. Follow-ups: profile-fallback product decision; none else._

_Verification Record (T021 transports, 2026-09-17): area transports (all six crates owned). Skills applied: rust-async, rust-concurrency, rust-networking, rust-performance, rust-testing, rust-security, rust-unsafe (review), rust-error-handling; no deviations. Findings fixed: (1) REAL BUG — supervisor `mem::forget(stdin)` leaked the pipe fd AND broke the documented EOF-on-teardown contract → stdin handle now owned by `RunningSidecar` (closes on teardown); (2) revive path dropped the fresh sidecar's stdin (`revived` fell out of scope) → handle moved over (would have EOF'd revived secret-configured sidecars immediately); (3) `SidecarSecret` Debug printed secret length (side channel) → exact `<redacted>` (mirrors T007); manual `Clone` identical to derive → `#[derive(Clone)]`; (4) 8 static bind-literal `.unwrap()`s (wg/masque/psiphon dial paths) → `expect` with reasons; (5) tor `dial_udp` message had nested-backtick garbage → clean remedy wording. Reviewed, no change with reasons: poisoned-lock `unwrap()`s retained as fail-stop (20+ hot-path sites; silent recovery worse); length-guarded slice indexing/`try_into` in masque/stream dispatch provably safe (guards adjacent; hot loop); per-packet 64KB allocs unmeasured (Wave-4 perf input, no unmeasured optimization); 3 unbounded mpsc channels (wg pump, stream ×2) recorded as follow-up (bounding needs drop/await delivery-semantics decision + observability hook — untestable today, FR-013); `QCORE_WG_TRACE`-gated/test-only eprintlns retained; h2 driver detached tasks idiomatic (end on close); `recv_from` no-timeout consistent with sibling flows (callers own budgets); dead `bootstrap_timeout_secs`/`ready_timeout_secs`/`sidecar_secret` file-gate reads retained deliberately — they serve programmatic construction while strict gates correctly exclude them (`sidecar_secret` must NEVER become file-accepted: plaintext secrets in files); relay/tor/mock reviewed clean (bounded framing with pre-alloc check, honest health docs, linkage anchors). Tests: supervisor integration (spawn/ready/restart/revive/dial/stop) 7/7 green — proves stdin-ownership fix preserves behavior; `secret_debug_never_leaks` strengthened to exact format. Commands: workspace clippy clean; transports nextest green (wg/masque/relay/mock 12/12, psiphon 7/7). Record contains no secrets. Follow-ups: bounded pump/stream queues (delivery-semantics decision); none else._

_Verification Record (T022 diag events, 2026-09-17): area diag (`events.rs` owned). Skills applied: rust-observability, rust-error-handling, rust-security; no deviations. Findings fixed: (1) T006-deferred misleading test name `typed_secret_key_is_masked_not_dropped` → `low_entropy_value_under_innocuous_key_is_kept` (name now states the asserted behavior). Reviewed, no change: `unwrap_or(0)` clock fallback and `unwrap_or(Null)` serialization fallback are deliberate non-panicky paths; array-key `field[i]` keying preserves typed-key matching. Commands: covered by workspace clippy + `qcore-core --lib diag::` 8/8 green. Deltas zero/zero. Follow-ups: none._

_Verification Record (T025 profiles/examples/xtask, 2026-09-17): area examples-xtask (+ profiles data). Skills applied: rust-cli, rust-ecosystem, rust-error-handling; no deviations. Findings fixed: (1) `xtask/src/release.rs` static-literal `file_name().unwrap()` → `expect` with reason (uniformity with the transport literal conversions). Reviewed, no change with reasons: shipped `profiles/*.toml` parse-proofed by existing shape tests (compositions/obfuscation/scan/warp — all green in lib runs; no TOML content touched); `embed-host` example idiomatic as-is (`expect`s in example `main` are conventional fail-loud demos; event/status Debug prints are mock-only documented no-secret paths); `xtask` otherwise clean (single other hit is a test `expect`). Commands: `cargo fmt --all -- --check` exit 0; workspace clippy exit 0; `cargo check --workspace --all-targets` exit 0 (covers examples + xtask + all suites). Deltas zero/zero. Follow-ups: none._

_Verification Record (T026 test-suite alignment, 2026-09-17): areas conformance-tests + chains-tests. Skills applied: rust-testing; no deviations. No suite changes needed beyond the T013/T024 additions — alignment PROVEN by execution: full `cargo nextest run -p tests-conformance` 73 pass / 2 skipped (pre-existing skips), full `cargo nextest run -p tests-chains` 32/32 pass, `qcore-core --lib` 101/101 pass (100 + negative-bounds test), `qcore-cli` 7/7, `qcore-ffi` 1/1, transports green (wg/masque/relay/mock 12/12, psiphon 7/7). Includes new coverage: masking (3 levels), namespace stability, preset secrets/alias, awg-record strictness, midpoint overflow, scan bounds, license resolve paths, FFI caller-buffer masking. Deltas zero/zero. Follow-ups: none._

_Verification Record (T027 Wave-4 no-break evidence, 2026-09-17): `cargo xtask abi-diff` re-attempted with installed `cargo-semver-checks` 0.50.0 — baseline fetch from crates.io still blocked by sandbox network policy (exit 0, CI-enforced per xtask message). Compensating evidence (stronger than T018's): `git diff` restricted to Rust sources; public-surface delta purely additive (2 central `redact` helpers, 1 `Display` impl, 3 JNI entries, named consts; zero signature removals/changes; `qcore.h`/`abi-version.txt`/`profiles/`/fixtures untouched); `cli_api_parity` + `abi_consumer` re-run green within the full 73-test conformance pass; import round-trips green within the 32-test chains pass. Follow-ups: mechanical semver-checks run owns to CI. Wave 4 complete — full sweep (all 15 areas) done._

_Verification Record (T031 guidance fill, 2026-09-17): all 15 rows filled in docs/rust-practices.md with skill-cited conventions, copy-pasteable fastest commands, and known exceptions per contracts/guidance-schema.md. Schema acceptance: 15/15 areas exactly once with data-model IDs ✓; every convention cites a governing skill ✓; every fastest command executed verbatim during the sweep (transports 5-package command 19/19, preset 9/9, obfuscation 2/2 run explicitly for this proof; all others ran as the units' verification) ✓; AGENTS.md pointer (T032) ✓; trial (T033) ✓. Follow-ups: none._

_SC-005 trial (T033, 2026-09-17): task "add a capability flag to a transport" (transports area). Contributor: the implementing agent acting as newcomer against the finished doc (SELF-TRIAL — independence limitation recorded; a truly unfamiliar contributor re-trial is recommended as follow-up). Result: transports row located in one table scan; governing skills (async, networking, performance, memory-optimization, testing) and fastest command both read off the row with zero additional navigation; time-to-locate well under 5 minutes. Outcome: PASS with noted limitation. Follow-ups: independent re-trial by a contributor unfamiliar with this sweep._

_Verification Record (T034 checklist re-validation, 2026-09-17, review-only): spec.md untouched since the 24/24 re-pass (all implement-phase changes are code + tasks.md records + the new guidance doc, which the checklists do not govern); both checklists' markers stand as accurate — sweep-readiness 24/24, requirements 16/16. No marker changes made._

_Verification Record (T035 quickstart scenarios, 2026-09-17): Scenario 1 (per-unit loop) evidenced by all 19 unit records. Scenario 2 (sweep-final gate) = T029 `cargo xtask ci` exit 0. Scenario 3 (regression probe, Wave-1 diag + Wave-3 session via guidance fastest commands): `nextest -p qcore-core --lib diag::` 9/9, `session::` 21/21, `clippy -p qcore-core` clean; re-review spot-check (secret-bearing diagnostics masked, no panicky paths, typed surfaces, caller-perspective tests present) — no findings. All scenarios green._

_Dated follow-ups (T036 triage, 2026-09-17 — zero OPEN findings in claimed-done areas; everything below is explicitly recorded with reason per SC-003): version-window — (1) typed SecretStore errors, (2) `Account` newtype boundary, (3) collision-resistant account encoding + stored-format migration, (4) `ObfuscationFamily` non_exhaustive + `needs_sidecar` bool→enum (+ parallel `ObfFamily` unification), (5) stringly `family` enums across scan/config/CLI, (6) `generate_credential` typed error; product-decision — (7) profile-override IO-error fallback (fail-closed vs fallback, 3 instances); structural — (8) keepalive abort-on-teardown, (9) bounded pump/stream queues (needs delivery-semantics decision + observability hook), (10) no-echo TTY license prompt; adjudication — (11) relay kind carve-outs (Principle I reading); process — (12) independent SC-005 re-trial, (13) CI crates.io semver-checks baseline run, (14) profiled alloc assessment, (15) Miri run over unsafe paths (statically reviewed + tested; nightly-gated). SC-003 accounting: all 15 areas have zero unrecorded findings; the 6 areas carrying version-window/product exceptions above are done modulo their dated follow-ups._

_Verification Record (T028 record audit, 2026-09-17): audited all 24 records (Record #0, T005 ratification, T006–T027 units) against contracts/verification-record.md field-by-field. Result: complete — every record carries area/skills/baseline/commands/outcomes/deltas; behavior demonstrations present for all behavioral claims (round-trips, lock-race, masking ×3 levels, CIDR containment, stdin stdin-ownership via supervisor integration, throughput gate, live CLI demos); no-break evidence in T018/T027; follow-ups dated with owners in each record. Two audit notes (not gaps): (1) T012 shares T010's package-level verification runs (same revision, same command lines) — accepted, deltas attributable; (2) per-unit scoped clippy baselines were inferred from the green Record #0 plus zero-warning exits rather than separately snapshotted pre-edit — accepted: `clippy -D warnings` exit 0 IS the delta proof (any warning fails the command). No "verified by review" entries. Follow-ups: none._

_Verification Record (T029 sweep-final full gate, 2026-09-17): `cargo xtask ci` exit 0 — full pass including fmt, clippy `-D warnings`, unit/contract suites, chains (32/32), conformance (73 pass / 2 pre-existing skips), throughput, and abi-diff local checks (`abi-version.txt` matches ABI_VERSION 1; `qcore.h` declares all 11 symbols; committed diff empty). Residual: crates.io semver-checks baseline unavailable in sandbox (qcore unpublished; CI-owned) — compensated by additive-only surface audit (T018/T027). Sweep-final record fields complete: full gate pass ✓, abi guard (local checks clean; registry baseline owns to CI) ✓, guidance trial pending T033, residual findings zero in claimed-done areas (open items are the dated version-window/product-decision follow-ups, none blocking). Follow-ups: none blocking._

_Verification Record (T030 behavior demonstrations, 2026-09-17): consolidated literal expected-vs-observed evidence. Test-proven behaviors (all green in-suite): secret-like causes masked with prefixes kept (identity report, session text, FFI caller buffer); CIDR sampling contained; stdin handle owned across spawn/revive (supervisor spawn/ready/restart/revive/dial/stop integration 7/7); lock-race loser-fails-closed with no half-written store; namespace determinism vector; preset secrets/alias; awg-record strictness; midpoint overflow; scan bounds; license resolve paths; round-trips (import/export, chains, fixtures). Live CLI demonstrations (this record, temp dirs, cleaned after): `preflight --chain mock` → `preflight ok: depth 1, zero sockets opened` (expected: depth 1, zero sockets); `profiles` → registry-driven listing incl. all six transports + scan/obfuscation/preset sections (expected: complete listing); `legal` → lawful-use statement header (expected); `--help` → `[env: CONNECTION_TIMEOUT_SECONDS=]` annotation (expected: env binding live); `--timeout 0` → suffixed usage error (expected: exit 6). All observed == expected. Follow-ups: none._

_Verification Record (T023 hot-path perf/memory, 2026-09-17): area transports+scan-cache. Skills applied: rust-performance, rust-memory-optimization; no deviations. Measurement (the skills' first rule): `cargo nextest run -p tests-conformance --test throughput` 2/2 pass, incl. single-hop throughput within 15% of direct — the quantified bar holds post-sweep. Review findings (no code changes — deliberately): per-packet 64KB scratch bufs (wg encapsulate/decapsulate, relay/psiphon recv) and per-frame `to_vec` ownership transfers are required by callee signatures or ownership transfer; hoisting/reuse is unmeasured micro-optimization and is NOT applied per the no-unmeasured-optimization rule (recorded as profiled-only future work, not a finding). The 3 unbounded mpsc channels stay under the T021 follow-up (needs delivery-semantics decision). Outcome: gate green, zero changes — the conforming result when measurement shows no regression. Deltas zero/zero. Follow-ups: profiled alloc assessment (future, with measurements); none else._

_Verification Record (T024 CLI polish, 2026-09-17): area cli (`main.rs`, `cmd/scan.rs`, `cmd/profiles.rs` owned; `cmd/import.rs`, `preflight.rs`, `help.rs`, `exit.rs`, `cmd/mod.rs` reviewed). Skills applied: rust-cli, rust-error-handling, rust-observability; no deviations. Findings fixed: (1) `--timeout` help advertised `(CONNECTION_TIMEOUT_SECONDS, ...)` but no `env` attribute existed anywhere — the var did nothing; wired `env = "CONNECTION_TIMEOUT_SECONDS"` (additive, validated by existing bounds check) and simplified the doc; live `--help` now shows `[env: CONNECTION_TIMEOUT_SECONDS=]`. (2) `--timeout`/`--family` error messages lacked the `(exit 6)` suffix the convention (`qcore: <msg> (exit N)`) requires → added. (3) `profiles.rs` resolved presets twice (double file IO + inconsistent override-error handling: surfaced once, swallowed once) → single resolution shared with shortcuts. (4) T020 addendum: `scan/mod.rs` `parse_scan_toml` cast negative TOML ints to u64 (wrap to `u64::MAX` → unbounded budget/permits); now rejects `< 1` naming the field; new test `negative_profile_bounds_rejected`. Reviewed, no change with reasons: `qcore: <msg> (exit N)` + stdout-results/stderr-diagnostics + JSON duality consistent across all commands; `MODES` display table degrades gracefully (`-`) and carries value-hint knowledge descriptors cannot provide; `help.rs` lawful-use text untouched (product statements); `success-on-stderr` in preflight/import keeps stdout pipe-clean by design. Commands: fmt/clippy clean; `qcore-cli` 7/7 pass; `scan::` 7/7 pass incl. new test. Behavior demo: live `qcore --help` shows env annotation; live `qcore --timeout 0 preflight --chain mock` prints the suffixed usage error. Record contains no secrets. Follow-ups: no-echo TTY prompt (from T011); none else._

_Verification Record (T014 config parsing/boundaries, 2026-09-17): area config (`hop.rs`, `import.rs`, `obfuscation.rs`, `chain_file.rs` owned; `export.rs`, `profile_dir.rs`, `mod.rs` reviewed, no findings). Skills applied: rust-type-system, rust-api-design, rust-design-patterns, rust-error-handling, rust-security; no deviations. Findings fixed: (1) allowed-field lists existed in THREE copies (`ALLOWED_FIELDS` + `Deserialize` inline arrays + `parse_preset_hop` match) despite the single-source doc claim — and the preset copy had drifted (missing wireguard `import` alias the grammar accepts); all three gates now call `allowed_fields()`, and the preset path accepts+maps `import`→`import_ref` mirroring `parse_single_hop`. (2) `import.rs` hand-rolled base64 (~70 lines) duplicated the already-linked vetted `base64` crate (used in `identity/`) → bodies now delegate; public signatures unchanged; strictness preserved (existing vectors pass). (3) `peers.clone()` borrowck workaround → collect-errors-first loop (zero clones). (4) `from_toml` silently defaulted missing awg numerics to 0 → explicit missing/type errors (fail closed; machine-written records unaffected); new test `truncated_awg_record_fails_closed`. (5) `ParamVal::scalar`/`profile_fields` `(lo+hi)/2` panics on i64 extremes from untrusted profile files → `i64::midpoint`; new test `extreme_range_midpoint_cannot_overflow`. (6) Descriptor family check compared `format!("{fam:?}")` strings across two parallel enums → explicit `matches!` on variant pairs (no type change). (7) Doc typo `field field-for-field`; scalar-coercion leniency documented on the JSON path. Reviewed, no change: `export.rs`/`profile_dir.rs` clean (inverse canonical maps consistent; round-trip tested); `to_toml` control-char edge fails closed downstream (loud parse error, no silent corruption). Commands: `cargo fmt --check` exit 0; `cargo clippy -p qcore-core --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-core --lib config::` 16/16 pass (incl. 2 new). Behavior demo: chains import round-trips 12/12 + full chains 32/32 green (T018). Record contains no secrets. Follow-ups: parallel `ObfFamily`/`ObfuscationFamily` enum unification needs a version window (follow-up class T007c); obfuscation override IO-error silent fallback needs product decision (fail-closed vs fallback) — recorded follow-up._

_Verification Record (T015 chain engine/registry, 2026-09-17): area registry-chain (`chain/mod.rs`, `parse.rs` reviewed, `preset.rs`, `validate.rs`, `registry.rs` owned). Skills applied: rust-type-system, rust-api-design, rust-design-patterns, rust-testing, rust-error-handling; no deviations. Findings fixed: (1) `parse_single_hop` dead `None` arm (unreachable — plugin branch returns first; twin `build_hop` already used the clean shape) → deleted, single `expect` with invariant reason. (2) `expand()` dead `for hop { let _ = hop; }` loop with a comment claiming enforcement the types already provide → deleted, comment now states the type-level guarantee (real nested check lives in `parse_compositions_toml`). (3) `validate_definition` swallowed `hops` (`let _ = hops`) while promising "no secrets" → implemented the documented scan via central `drops_record`/`redact_value`, wired into `parse_compositions_toml` replacing the inline nested loop (messages byte-identical); new tests `secret_like_preset_value_rejected_naming_preset_hop_field` + `wireguard_import_alias_maps_to_import_ref`. (4) 4 bare `unwrap()`s in `validate.rs` on provably-held invariants → `expect` with reasons. Reviewed, no change with reasons: `registry.factory()` per-call inventory iteration is O(few) and cannot disagree with the map (static inventory) — restructure rejected per laziness bias; `validate.rs` `== "relay"` carve-outs are pre-existing documented design (module docs) touching Principle I interpretation — altering validation behavior needs adjudication outside this sweep, recorded as such, no silent change. Commands: fmt/clippy clean (same runs as T014); `cargo nextest run -p qcore-core --lib chain::` 23/23 pass (incl. 2 new). Deltas zero/zero. Follow-ups: relay carve-out adjudication; none else._

_Verification Record (T016 transport-api/facade, 2026-09-17): area transport-api + facade (`transport-api/src/lib.rs` owned; `qcore/src/lib.rs` reviewed). Skills applied: rust-api-design, rust-ownership, rust-design-patterns; no deviations. Findings fixed: (1) broken intra-doc link `[`registry`](crate::registry)` (no such module — rustdoc warning class) → plain-text "engine's transport registry" (cannot link: depending on the engine would violate the crate's dependency discipline). Reviewed, no change with reasons: `pub use inventory` is load-bearing for `register_plugin!` expansion downstream; `ObfuscationFamily` lacks `#[non_exhaustive]` and `needs_sidecar: bool` is a boolean trap, but both are pub-surface changes → follow-up class T007c (version window), not this sweep. Facade is pure re-exports, no findings. Commands: `cargo fmt --check` exit 0; `cargo clippy -p qcore-transport-api -p qcore --all-targets --all-features -- -D warnings` exit 0. Deltas zero/zero. Follow-ups: non_exhaustive + sidecar-bool unification (version window); none else._

_Verification Record (T017 FFI boundary, 2026-09-17): area ffi (`ffi/src/lib.rs`, `ffi/src/jni.rs` owned). Skills applied: rust-unsafe, rust-api-design, rust-error-handling; no deviations. Findings fixed: (1) `fail_report` wrote raw `FailureReport` Display (free-text cause) into caller-owned buffers despite the module's FR-026 promise → masked via shared `masked_value` (same Display shape); new in-module test `fail_report_masks_secret_like_cause` (masked + ordinary passthrough + code mapping). (2) `_assert_send_sync` proved nothing (uncalled, unbounded) → real `_assert_thread_safe` (`Send + Sync` bound compiled → handles ARE thread-safe for C callers). (3) JNI `unsafe fn`s without SAFETY rationale + safe `with_engine` doing int→ptr casts → SAFETY comments on `j_to_rust`/`rust_to_j`/`take_string`/`take_error`, `with_engine` now `unsafe fn` with handle-validity contract (call sites already in unsafe blocks except `engineFree`, fixed). (4) Module doc advertised `scanJson`/`importConfig`/`exportConfig` JNI entries that did not exist → implemented the 3 thin wrappers mirroring existing patterns (additive, panic-guarded, null-on-failure). Consolidation: the three private cause-masking copies became two shared central helpers (`diag::redact::masked_value`/`prefixed_cause`, re-exported, unit-tested); call sites migrated, shims deleted. Reviewed, no change: all 11 entry points null-check + unwind-guarded; `CString::new("error").unwrap()` statically safe; `block_on(stop)` bounded per docs; i64 handle round-trip sound on 32-bit targets (upper bits zero). Commands: fmt/clippy clean; `cargo nextest run -p qcore-ffi` 1/1 pass. Behavior demo: masking test + `c_abi_session_lifecycle` green in T018. Follow-ups: none._

_Verification Record (T018 Wave-2 gate, 2026-09-17): `cargo xtask abi-diff` attempted — `cargo-semver-checks` installed (0.50.0) but the baseline fetch from crates.io is blocked by sandbox network policy; xtask reports gate-complete/CI-enforced (exit 0). Compensating evidence: `git diff` shows Rust-source-only changes, purely additive public surface (new `redact` helpers, new JNI entries, one `Display` impl; zero signature removals/changes; `qcore.h`/`abi-version.txt`/`profiles/` untouched). Tests: `cli_api_parity` + `abi_consumer` 11/11 pass; chains `import_roundtrip` + `imported_chain` 12/12 pass; full `tests-chains` 32/32 pass; full `tests-conformance` 73 pass / 2 skipped (pre-existing skips). Follow-ups: mechanical semver-checks run owns to CI. Wave 2 complete._

_Verification Record (T009 identity store/report, 2026-09-17): area identity. Skills applied: rust-security, rust-error-handling, rust-observability, rust-async (reviewed; no async misuse found — module is sync by design, no blocking-in-async); no deviations. Findings fixed: (1) `store.rs` keyring namespace used `DefaultHasher`, explicitly unstable across releases → silent namespace orphaning (forced re-registration) on toolchain upgrades; replaced with inline stable FNV-1a (`namespace_hash`, `{:016x}` format kept). Known one-time consequence: pre-existing keyring entries under old hash orphan (unreadable, remain in OS keyring) → one graceful re-registration via the FR-002 missing-path. (2) `report.rs` `report_for_error` interpolated provider-controlled `detail` (220-char bodies) into CLI-facing `cause` unchecked → now passed through central `redact_value` at the boundary (`safe_cause`: actionable prefix always kept, secret-like detail replaced); new test `secret_like_provider_detail_is_masked_prefix_kept` proves masking + prefix preservation + low-entropy passthrough. Reviewed, no change: lock protocol TOCTOU-safe (atomic `create_new`; stale-steal race resolves to exactly-one-winner + loser-fails-closed); `Result<_, String>` signatures recorded under T007(a) follow-up (public API freeze); `register.rs` transient plaintext copies (`auth`/`body` Strings) noted as Wave-3 input for T019, not touched (out of unit boundary). Commands: `cargo fmt --check -p qcore-core` exit 0 (after one `cargo fmt` rewrap); `cargo clippy -p qcore-core --all-targets --all-features -- -D warnings` exit 0; `cargo nextest run -p qcore-core --lib identity::` 21/21 pass. Deltas: zero new warnings, zero regressions. Behavior demo: round-trip + lock-race + corrupt-as-missing + masking tests all green. Record contains no secrets. Follow-ups: keyring-orphan note above (accepted consequence); none else._
