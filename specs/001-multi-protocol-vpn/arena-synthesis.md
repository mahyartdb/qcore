# Arena Synthesis Note

Artifact: refined implementation plan for qcore.
Rubric: traceability, consolidation/YAGNI, justified additions, release pipeline,
constitution assessment, extensibility.
Runners: 3 subagents, distinct lenses (consolidation, release, functionality).
Cross-judge: none spawned (single model family; parent read all three end-to-end).

## Convergence (all three candidates)

1. GOOL and MIM are chain **compositions**, not transports. Modeling them as
   `TransportKind`s forces protocol knowledge into the validator (Principle I
   violation) and creates the "2 layers" special case. Aliases/presets remove it.
2. WARP, imported WireGuard, and AmneziaWG are **one WireGuard kind with modes**.
3. MASQUE h2 and h3 are **one kind with an ALPN option**.
4. The proposed `Hop` trait is defective: it returns a concrete OS socket
   (impossible for a smoltcp-backed inner hop) and mixes `&self` data paths with
   `&mut self` lifecycle. Nesting is unimplementable as written.
5. The release pipeline is undecided; the constitution has real, enumerable gaps.
6. A deterministic stub peer plus a `cargo xtask` lever is what makes the target
   and dual-stack matrix runnable and reproducible.

Strong convergence on the shape → ship the consensus; no re-run needed.

## Base

**Candidate 3** (functionality/extensibility lens). Its `qcore-transport-api` +
registry + facade boundary is the only design that discharges Principle I/III
structurally ("any transport satisfying the interface MUST be chainable without
modifying the chain engine") and principle VI ("independently testable in
isolation"). Its abstract `Dialer`/`RunningHop`/`HopFactory` split fixes defects 4.

## Grafts

| From | Graft | Why |
|---|---|---|
| C2 | `TransportSpec`/descriptor table as single source of truth for validation, profile compatibility, `--help`, test matrix, docs | Kills the class of bug where two hand-maintained capability tables disagree |
| C2 | Concrete release pipeline (job graph, runner selection, artifact scheme, cosign/SLSA-3/CycloneDX, semver automation, secret-scan two-layer) | Open ask #5; R9 was four sentences |
| C2 | Traceability matrix FR/SC → CI gate | Makes SC-002a and FR-003f executable, not aspirational |
| C2 | `cargo xtask` as the lever | Reviewer can rerun the exact release steps |
| C2 | Timeboxed single-TLS-provider spike, then commit to one provider | Removes the permanent dual crypto surface |
| C2 | Defect catch: plan said "10 build targets"; FR-003e lists 9 | Fixed |
| C1 | Aggressive deletion discipline and the deleted/added ledger | Direct application of the laziness protocol |
| C1 | `qcore doctor` + `connect --dry-run` preflight | Exercises fail-closed validation with zero side effects |
| C1 | Durable session state file; `status` without a daemon | Removes a daemon that was never needed |
| C1 | Loopback/stub peer as an explicit deliverable | Reused from C3/C2; C1 states the traceability best |
| C1 | Consolidated single default-format config layout | Removes three overlapping profile file systems |

## Merged / consolidated (parent decision)

- Crate count: C1 said 1 package, C3 said 9, C2 said 4. **Chosen: 6 crates** —
  `qcore-transport-api`, `qcore-core`, `qcore-transports`, `qcore`, `qcore-cli`,
  `qcore-ffi`. Smallest set that keeps the plugin boundary (plugin authors pull no
  engine code) without C3's over-split (`qcore-chain`/`qcore-registry` folded in).
- Scan profiles: consensus delete `ironclad`. **Chosen: 3** (`turbo`, `balanced`
  default, `stealth`) — the minimum that still differs in thoroughness, speed, and
  stealth, matching FR-015.

## Rejected grafts (scope contradictions)

| Rejected | From | Reason |
|---|---|---|
| Defer AmneziaWG wire obfuscation to v1.1 | C1 D9 | User explicitly requires AmneziaWG in scope |
| Drop `i686-pc-windows-msvc` / demote it out of the gating matrix | C1 D16, C2 D1 | User explicitly requires 32-bit Windows |
| Replace quiche with quinn unconditionally on day one | C1 D3 | MASQUE h3/h2 quality must be validated; adopted as a timeboxed spike with a pre-decided fallback instead |
| Full stream multiplexing as a v1 feature | C3 A5 | The UDP-in-TCP relay covers the required ordering; full mux is deferrable |
| MTU auto-discovery | C3 A8 | YAGNI for v1: shrink-and-report, not probe-and-cache |
| Bounded `reconfigure` (hot profile reload) | C3 A11 | YAGNI for v1; profiles are read at start |
| Drop JNI entirely | C1 D4 | User requires Android; JNI is a thin wrapper over the C ABI (kept, but no per-transport JNI) |

## Dropouts

None. All three candidates completed.

## Verification

Synthesized plan re-checked against every FR/SC and the constitution. Spec
amendments required by the consensus shape are listed in the plan's
"Spec Amendments" section. Two contradictions the arena surfaced are fixed:
the plan's "10 targets" vs FR-003e's 9, and Principle II's "resolver/NAT
traversal" parity vs the spec's silence.