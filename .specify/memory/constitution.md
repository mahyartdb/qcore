<!--
Sync Impact Report
- Version change: 1.0.0 -> 1.1.0
- Modified principles:
  - I. Protocol-Agnostic Transport Core (expanded: plugin OR managed sidecar)
  - II. Dual-Stack Parity (scope aligned: harness requirement added; the
        resolver/NAT-traversal parity claim replaced by socket setup, endpoint
        resolution, routing/AllowedIPs, resolver transport, and MTU)
  - V. Observable, Reproducible Behavior (scanning non-determinism made explicit)
- Added sections/clauses:
  - Development Workflow: Release Integrity, Independent Versioning,
    Platform Parity & Target List, Consolidation Bias, Dual-Stack Harness,
    Secret-Scan Scope
  - Security: Sidecar Trust Boundary
- Removed sections: none
- Follow-up TODOs: none (RATIFICATION_DATE retained as 2026-09-14)
- Direction honored: no license/legal-grant language was added.
-->

# qcore Constitution

## Core Principles

### I. Protocol-Agnostic Transport Core

Every transport MUST be a plugin behind one uniform transport interface covering
capability declaration, lifecycle (configure, start, stop, health), address-family
support, and egress handoff. A transport MAY be an in-process plugin or a **managed
child process** that exposes a local proxy; both satisfy the same interface, and the
managed process is governed by the Sidecar Trust Boundary below. Protocol-specific
logic MUST NOT leak into the core, the chain engine, or the scanner: the engine
reads transport descriptors from a registry and MUST NOT branch on a transport kind.
Each transport MUST be independently testable in isolation from the others.

Rationale: the project's value is the composition of many protocols, so the core
must not accumulate per-protocol branches it cannot reason about as a whole.

### II. Dual-Stack Parity (NON-NEGOTIABLE)

Every transport, scanner strategy, obfuscation profile, and chain MUST support IPv4
and IPv6 on equal footing. A feature is not "done" until it is verified on both
address families. IPv4-only assumptions in address parsing, socket setup, endpoint
resolution, routing and allowed-address handling, resolver transport, and MTU
handling MUST be treated as defects. Verification MUST use a deterministic loopback
or stubbed peer, and the verification matrix MUST include a per-target
address-family capability check for every transport. A host that has only one family
available degrades explicitly and reports which family it used; that is a host
condition, not a transport defect.

Rationale: parity is a property of the transport implementation and must be
falsifiable without depending on a live external network. NAT traversal (STUN, ICE,
TURN, hole punching, inbound reachability) is explicitly out of scope because this
is an outbound client; parity instead covers the socket-level and routing surfaces
an outbound client actually owns.

### III. Composable, Declarative Chaining

Tunnels MUST compose through a single chain abstraction that supports nesting,
including tunnel-in-tunnel, and mixed protocols. Chains MUST be declared as
validated data, never as imperative wiring. Any transport satisfying the interface
MUST be chainable without modifying the chain engine. Capabilities MUST be known
before a hop is instantiated, so invalid combinations fail with an actionable error
and zero side effects before any tunnel starts.

### IV. Boundary Discipline and Secret Hygiene

All external input — user configuration, imported WireGuard configs, endpoints,
scanner results, DNS responses, and network frames — MUST be parsed and validated
at the boundary before use; internal code MUST trust validated types. Config
surfaces MUST be typed: an untyped free-form options map MUST NOT carry
transport-specific configuration. Credentials, private keys, tokens, and derived
secrets MUST NOT be logged, committed, or persisted unencrypted, and MUST be
redacted in all diagnostics, state files, and error output.

### V. Observable, Reproducible Behavior

Endpoint-scanning and obfuscation profiles MUST be data, not code branches. Every
run MUST emit structured, machine-readable diagnostics sufficient to explain
transport selection, chain composition, and failure cause. For identical inputs and
profiles, behavior MUST be deterministic except where the network makes it
inherently non-deterministic (scanning, retries); that non-determinism MUST be
explicit, bounded by the profile, and reproducible in tests through a fixed seed or
a recorded peer.

### VI. Verified Protocol Behavior

Each transport, scanner strategy, and chain path MUST have contract tests that
exercise it the way a caller does — against loopback or a stubbed peer — before it
is considered complete. Tests MUST assert observable behavior (packets, streams,
state, emitted config), not internal wiring. The conformance suite SHOULD be
generated from the transport registry so every registered transport inherits it.
Regressions in address-family parity, chaining, or secret redaction MUST be covered
by tests.

## Security & Compliance Constraints

- Lawful use: features that bypass network controls MUST be documented as intended
  for authorized, lawful use only; the project MUST NOT ship evasion defaults that
  are illegal in the user's stated jurisdiction.
- **Secret classification**: redaction MUST be typed-field-first, with
  entropy-and-denylist scanning as a second layer; heuristic masking MUST NOT be the
  sole control. A value that cannot be classified as safe and cannot be proven
  secret MUST NOT be emitted: the record is dropped and a placeholder written (fail
  closed).
- **Confidence reporting**: a probe result not backed by an end-to-end check MUST be
  labeled uncertain and MUST NOT be recorded as last-known-good or presented as
  verified.
- Dependencies: third-party components and any bundled upstream binaries MUST be
  pinned and recorded with their provenance before bundling.
- Cryptography: primitives and TLS stacks MUST come from vetted upstream
  libraries; custom cryptographic constructions are prohibited.
- Configuration: imported configuration formats MUST be documented and round-trip
  without lossy conversion; arbitrary third-party WireGuard configs MUST import
  without silent rewriting.
- Telemetry: off by default. Endpoint, identity, and usage data MUST NOT leave the
  device unless the user explicitly opts in.
- **Sidecar trust boundary**: a transport implemented as a child process MUST be
  spawned with an explicit executable path and a minimal environment, MUST complete
  a readiness handshake before use, MUST be torn down on session end and on drop,
  MUST cap restarts, and MUST receive no secret that is not required for it to
  function.

## Development Workflow & Quality Gates

- All changes land through reviewed pull requests; no direct commits to the main
  branch.
- Required checks before merge: build, unit tests, dual-stack conformance matrix,
  chain acceptance tests, lint/typecheck, and a secret scan.
- **Secret-scan scope**: the repository, CI logs, emitted reports, state files,
  release artifacts, and crash output. Static scanning alone is insufficient; a
  dynamic capture test MUST assert that a trace-level run leaks no secret.
- **Release Integrity**: every distributed artifact MUST be signed, MUST carry
  build provenance and an SBOM, and no release MAY ship if any required target
  fails its build or smoke test.
- **Independent Versioning**: the Rust API, the C ABI, and the configuration/report
  schemas are versioned independently. A breaking change to any surface MUST be
  reported to consumers and MUST follow a documented deprecation window.
- **Platform Parity & Target List**: the supported target list is a release
  contract. Target lists MUST have one authoritative source consumed by CI and
  documentation; removing or demoting a target requires a constitution amendment.
- **Dual-Stack Harness**: satisfying Principle II requires a deterministic stub
  peer and a per-target family-capability check; live-network tests are
  supplementary, not the gate.
- **Consolidation Bias**: a new crate, module, or public trait MUST state the
  existing structure it could have extended and why it did not. Simpler rejected
  alternatives MUST be recorded.
- **Platform delivery**: a platform's delivery surface MUST be stated (for example a
  CLI, an embedding library, or both) and each surface MUST have a defined smoke
  test. Where a platform cannot run one surface, the reason MUST be documented.
- **Emergency release**: a security fix MAY use a reduced gate, but signing, the
  secret scan, a dependency-audit pass, and a build plus smoke test on the affected
  platform MUST still run, and the release authority is two named roles (a release
  manager and a security maintainer).
- Added complexity MUST be justified in the change description; simpler alternatives
  MUST be explicitly rejected when a more complex design is chosen.
- Releases follow semantic versioning, keep a changelog, and publish build
  provenance for distributed artifacts.

## Governance

- This constitution supersedes all other project practices; where guidance
  conflicts, this document wins.
- Amendments: propose a change to `.specify/memory/constitution.md` in a pull
  request that includes the Sync Impact Report, the rationale, and any migration
  plan. Amendments require approval before merge.
- Versioning: governance versions follow semantic versioning. MAJOR for
  incompatible removals or redefinitions of principles, MINOR for a new principle
  or materially expanded guidance, PATCH for clarifications and non-semantic edits.
- Compliance: every review MUST verify compliance with these principles; reviewers
  MAY block a change that violates them. Any deviation MUST be documented and
  time-boxed.
- Runtime development guidance for agents lives in `AGENTS.md`, which MUST exist and
  MUST stay consistent with this constitution; it MUST record the build, test,
  release, and target-list commands.

**Version**: 1.1.0 | **Ratified**: 2026-09-14 | **Last Amended**: 2026-09-14