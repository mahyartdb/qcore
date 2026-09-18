# Feature Specification: Rust Best Practices Adoption

**Feature Branch**: `003-rust-best-practices`

**Created**: 2026-09-17

**Status**: Draft

**Input**: User description: "i want to aplly the best practices and the rules in the rust skills in this sesison to this rust codebase."

## Clarifications

### Session 2026-09-17

- Q: Which parts of the codebase should this best-practices effort actually change in this session? → A: Full workspace sweep of all crates regardless of session tasks (Option C)
- Q: How strictly should the skill rules be enforced on the existing code? → A: Fix every finding including low-value style nits before calling an area done (Option A)
- Q: What verification must pass before an area counts as done? → A: Scoped checks per unit plus the full project gate once before done (Option B)
- Q: May this effort make breaking changes to versioned surfaces like the public API, C ABI, config formats, or CLI contracts? → A: No breaking changes; keep all versioned surfaces compatible (Option A)
- Q: What lasting record should this effort leave so future work stays conformant? → A: Code fixes plus new permanent contributor guidance docs (Option C)

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Session follows Rust skill rules consistently (Priority: P1)

A contributor (human or agent) working in this session on the `qcore` Rust codebase gets code, reviews, and fixes that consistently follow the rules from the applicable Rust skills (ownership, error handling, async, API design, types, concurrency, security, testing, observability, CLI, networking, performance, unsafe, ecosystem).

**Why this priority**: This is the core ask — "in this session" means every edit/review in this working period must honor the same bar instead of ad-hoc style.

**Independent Test**: Can be fully tested by asking for any small Rust change (e.g., a new validated config type or an error-path fix) and confirming the result cites the applied skill rules and passes the session's checks; delivers a predictable review bar even if no legacy code is touched.

**Acceptance Scenarios**:

1. **Given** a session task that writes or edits Rust code, **When** the contributor delivers the change, **Then** the change follows the applicable skill rules for ownership, error handling, types, async/concurrency, and API shape, and any deliberate deviation is called out with a reason.
2. **Given** two similar tasks done at different times in the session, **When** both results are reviewed, **Then** they apply the same naming, error, logging, and test conventions rather than contradicting each other.

---

### User Story 2 - Existing code is brought into conformance safely (Priority: P1)

A maintainer reviews the existing `qcore` crates (core engine, chain, config, session, identity, scan, transports, CLI, FFI facade) and sees known best-practice gaps identified, fixed incrementally, and proven to preserve behavior.

**Why this priority**: Adopting rules only for new code leaves the bulk of the codebase inconsistent; value comes from raising the existing code without breaking tunnels, chains, registration, or scanning behavior.

**Independent Test**: Can be fully tested by selecting one bounded area (e.g., one config module or one CLI command), applying the skill rules to it, and showing the area's existing acceptance checks still pass with no user-visible behavior change except the documented improvement; delivers value per area.

**Acceptance Scenarios**:

1. **Given** a bounded codebase area with a known gap (e.g., panicky error path, untyped config surface, or missing behavior test), **When** the gap is remediated under skill rules, **Then** the area's observable behavior is preserved (or the intended behavior change is explicitly documented) and the gap no longer reproduces on review.
2. **Given** a remediation that touches shared types or public surfaces, **When** it is proposed, **Then** affected callers are migrated together and no stale compatibility shim is left behind unless the constitution's deprecation rule requires it.

---

### User Story 3 - Conformance is proven by execution, not by reading (Priority: P2)

A reviewer verifies adoption by running checks and observing behavior, rather than trusting a claim that "rules were applied".

**Why this priority**: The project constitution and working rules require verification through execution; without this, adoption is unverifiable.

**Independent Test**: Can be fully tested by running the project's standard verification for a changed area and confirming clean results plus a behavior demonstration; delivers trust independently of how many files were touched.

**Acceptance Scenarios**:

1. **Given** a change made under this feature, **When** the scoped verification for that area is run (format check, lint, relevant tests), **Then** it passes and the evidence (commands run and outcomes) is reported.
2. **Given** a change that claims a behavior improvement (e.g., clearer error, no secret leak, graceful shutdown), **When** exercised the way a caller/user does (loopback/stubbed peer, CLI invocation, or test double), **Then** the claimed observable behavior is demonstrated.

---

### User Story 4 - Future work stays conformant with less effort (Priority: P3)

A future contributor can discover which Rust rules apply to which area and get fast feedback when they drift.

**Why this priority**: One-session cleanup regresses unless the rules remain discoverable and cheap to check.

**Independent Test**: Can be fully tested by onboarding a new small task (e.g., "add a transport capability flag") and confirming the contributor can state the applicable rules and the fastest check that would catch drift; delivers lasting value beyond the session.

**Acceptance Scenarios**:

1. **Given** a new task in a previously remediated area, **When** the contributor starts work, **Then** they can locate the applicable conventions and the verification command for that area in permanent contributor guidance without asking the original author.
2. **Given** a new violation of an adopted rule, **When** standard checks run, **Then** the violation is surfaced before merge (by lint, test, or review checklist).

### Edge Cases

- What happens when a Rust skill rule conflicts with the project constitution (e.g., a suggested abstraction vs. Consolidation Bias, or a telemetry suggestion vs. off-by-default)? Constitution wins; the conflict is surfaced, never silently resolved in favor of the skill.
- How does the effort handle areas where the current code deliberately diverges (e.g., `unsafe` FFI boundary, performance-critical hot loop, sidecar trust boundary)? Divergence must be documented with the reason and the narrowest scope, not "fixed" by removing a load-bearing constraint.
- What happens when applying a rule would change a public API, C ABI, config format, or CLI contract? The change follows the project's independent-versioning and deprecation rules; silent breaking changes are rejected.
- How are large cross-cutting cleanups prevented from becoming unreviewable? Work is sequenced into small verifiable units per area; a change that cannot be verified in isolation is split.
- What happens when a skill recommendation needs a dependency, toolchain, or target-list change? It is treated as a dependency/platform decision under the constitution (pinned provenance, 9-target contract), not applied casually.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Session work on Rust code MUST apply the applicable skill rules for ownership and borrowing (move semantics, borrowing, lifetimes, `Copy` vs `Clone`, no excessive cloning to silence the borrow checker).
- **FR-002**: Session work MUST apply the error-handling rules (typed errors at boundaries via `Result`/`Option` and `?`, library-typed errors vs application-context errors, no `unwrap`/`expect` on fallible paths except with a documented why, panics only for truly unreachable invariants).
- **FR-003**: Session work on asynchronous code MUST apply the async and concurrency rules (correct runtime and task usage, cancellation/timeout/shutdown behavior, no blocking inside async contexts, disciplined shared-state and channel use, `Send`/`Sync` correctness).
- **FR-004**: Session work on public surfaces MUST apply API-design, type-system, and pattern rules (make invalid states unrepresentable, brand semantic primitives, parse and validate external input at boundaries into trusted types, keep business logic in pure functions over validated types, prefer deletion and smallest change over new abstraction).
- **FR-005**: Session work on user-facing and service behavior MUST apply CLI, networking, and observability rules (predictable CLI arguments/subcommands/config-file handling with help text, correct socket/TLS/timeout/backpressure handling appropriate to an outbound client, structured observable diagnostics with traceable request context, no secret or personal data in logs).
- **FR-006**: Session work MUST apply security and secret-hygiene rules (typed-field-first secret classification with redaction in diagnostics/state/errors, no credentials in logs or persistence, vetted cryptography only, safe handling of untrusted input/paths/subprocesses, dependency provenance respected).
- **FR-007**: Session work MUST apply testing and behavior-proof rules (tests that exercise code the way callers do against loopback/stubbed peers or doubles, asserting observable behavior with literal expected values; regression coverage for fixed defects in parity, chaining, or redaction).
- **FR-008**: Session work MUST apply performance, memory, and `unsafe` rules (no unmeasured optimization, no hidden quadratic behavior or gratuitous allocation in hot paths, justified data-structure choices; `unsafe` only with documented invariants and narrowest scope, verified where tooling supports it).
- **FR-009**: Session work MUST apply ecosystem and toolchain rules (stable toolchain as pinned, `cargo fmt` clean, `cargo clippy --all-targets --all-features -- -D warnings` clean for touched areas, workspace/feature-flag hygiene, documented crate choice when adding a dependency).
- **FR-010**: Where a skill rule conflicts with the constitution, `AGENTS.md` routing, or an area doc-map decision, the constitution and its precedence order MUST win, and the conflict MUST be surfaced explicitly rather than resolved silently. Surfacing means recording the conflict and the decision in the unit's Verification Record `skills applied` deviation field.
- **FR-011**: Remediation MUST cover the full workspace (all crates) regardless of which areas session tasks touch, sequenced into small independently verifiable units per bounded area (crate or module or command), each preserving observable behavior unless the behavior change is explicitly declared, justified, and covered by an acceptance check. Cross-area fallout discovered mid-unit spawns a new unit; a unit MUST NOT expand past its area boundary.
- **FR-012**: Versioned surfaces (Rust API, C ABI, config/report schemas, CLI contracts) MUST remain compatible under this feature: no breaking changes; internal caller cleanups still migrate together with removal of the legacy path in the same wave, and any desired break MUST be recorded as a follow-up under the project's versioning and deprecation discipline instead of being folded in. Compatibility is decided by `cargo xtask abi-diff` (clean) plus the `cli_api_parity`, `abi_consumer`, and config import round-trip tests passing.
- **FR-013**: Every change under this feature MUST be verified through execution: scoped format, lint, and test commands plus a behavior demonstration where the claim is behavioral for each unit, and the full project gate once before the feature is called done; the evidence MUST be reported; re-reading code is not verification. A unit whose verification fails MUST be returned to its recorded baseline or brought to green within the same unit; unverifiable intermediate state MUST NOT persist.
- **FR-014**: Out of scope for this feature: adding new tunnels/protocols, changing the 9-target release contract, changing telemetry defaults, introducing new cryptographic constructions, or altering lawful-use posture. Such needs MUST be recorded as follow-ups, not folded in.
- **FR-015**: The effort MUST leave new permanent contributor guidance recording the per-area rule-to-check mapping (which skill rules govern each area and the fastest verification command), so future work stays conformant without tribal knowledge.

### Key Entities

- **Skill Rule Set**: The subset of Rust skill rules applicable to a bounded area (e.g., error-handling + types for config parsing; async + observability + networking for session/scan). Attributes: area it governs, normative rules, allowed narrow exceptions with reasons.
- **Conformance Finding**: A specific gap between current code and the applicable rule set. Attributes: location, violated rule, severity/blast radius, remediation approach (fix, migrate-callers-then-delete, or document-and-keep with reason), verification that proves it.
- **Verification Record**: The execution evidence for a unit of work. Attributes: commands run, scope covered, outcome, behavior demonstration for behavioral claims, known gaps or follow-ups.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An uninvolved reviewer, given a random sample of 3 units, can state for each which skill rules were applied and which verification was run within 5 minutes per unit, without asking the author.
- **SC-002**: Every remediated area passes its scoped verification (format check, lint with warnings denied, and relevant tests) with zero new warnings and zero regressions versus the pre-change baseline, the throughput conformance test passes unchanged, and the full project gate passes once before the feature is called done.
- **SC-003**: Every finding in each area in scope (including low-value style nits) is remediated before the area is called done; any exception requires an explicitly recorded reason and is treated as the area not yet done.
- **SC-004**: No user-visible behavior (tunnel establishment, chain composition, registration/renewal, scanning selection, CLI exit codes and help output, C ABI signatures, per-address-family (IPv4/IPv6) behavior on touched transport/scanner/chain paths) changes except where explicitly declared and demonstrated; undeclared behavior changes are treated as defects.
- **SC-005**: Follow-up work in a remediated area takes less review effort: the applicable rules and fastest verification command for that area are discoverable without tribal knowledge (measured by a new contributor locating both unaided on a trial task).

## Assumptions

- Applicable skills are the Rust-focused set relevant to this codebase (mastery, ownership, error-handling, async, concurrency, API design, type system, design patterns, CLI, networking, observability, security, testing, performance, memory optimization, unsafe, ecosystem), not every skill in the catalog (e.g., web-framework, embedded, ML, fintech, and WASM/mobile rules apply only if the touched code actually uses those domains).
- Reasonable defaults from the skills are adopted (e.g., `thiserror` for libraries / `anyhow` with context for applications only where the codebase already follows that split; structured tracing with span context; `tokio` discipline as already chosen) rather than re-litigating settled choices.
- The constitution (v1.1.0) is the final arbiter; `AGENTS.md` code-map and doc-map rows are read before touching an area.
- Full `cargo xtask ci` is the release gate but scoped commands (`cargo fmt --check`, `cargo clippy`, `cargo nextest run`) are acceptable per-unit verification during the session; the full gate runs before any merge claim.
- No new runtime dependencies are added without provenance pinning and a recorded rejected-alternatives note per Consolidation Bias.
- Scope covers the full workspace in this session: areas are ordered by risk (secret hygiene and error handling first, then types/boundaries, then async/observability, then performance/memory), and any area that cannot be completed is recorded as an explicit follow-up rather than half-applied. (Ordering is sequencing only; the done-bar is fix-all per SC-003.)
