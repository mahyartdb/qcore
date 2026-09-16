# Chain Composition & Transport Plugin Contract Checklist: Multi-Protocol Tunnel Client

**Purpose**: Exhaustive requirements-quality review of chain composition, the transport plugin boundary, ordering semantics, and depth validation.
**Created**: 2026-09-14
**Feature**: [spec.md](../spec.md)

**Review Ownership**: This checklist is a reviewer-owned requirements-quality review artifact. Mark an item `[x]` only when the reviewer determines the requirements-quality criterion is satisfied.
**Marker Semantics**: `[x]` means the criterion has been reviewed and satisfied for requirements quality. It does not mean implementation work is complete.

## Requirement Completeness

- [ ] CHK001 Are all transport kinds and their modes explicitly enumerated (wireguard warp/imported/awg, masque h2/h3, tor, psiphon)? [Completeness, Spec §FR-004]
- [ ] CHK002 Are composition presets defined with their exact hop expansions and expansion timing? [Completeness, Spec §Key Entities]
- [ ] CHK003 Is every capability used for pre-start validation declared as data available before a hop starts? [Completeness, Spec §FR-006a]
- [ ] CHK004 Are the carrier/egress capability fields each individually defined (accepts TCP carrier, accepts UDP carrier, dials TCP, dials UDP)? [Completeness, Spec §FR-006a]
- [ ] CHK005 Is exit-hop semantics (last hop = effective public path) defined unambiguously? [Completeness, Spec §FR-011]
- [ ] CHK006 Are requirements defined for reporting the full ordered chain after preset expansion? [Completeness, Spec §FR-011, Spec §FR-025]
- [ ] CHK007 Is the set of invalid-chain categories exhaustively enumerated (over-depth, cycle, port conflict, carrier mismatch)? [Completeness, Spec §FR-010]
- [ ] CHK008 Are both the default max depth and the configurable hard limit specified? [Completeness, Spec §FR-010a]
- [ ] CHK009 Is plugin registration defined such that adding a transport requires no engine, chain, CLI, or schema edits? [Completeness, Spec §FR-006]
- [ ] CHK010 Are requirements defined for how imported-config hops participate in a chain? [Completeness, Spec §FR-009]

## Requirement Clarity

- [ ] CHK011 Is "arbitrarily ordered" quantified by the explicit allowed orderings (both directions for each named pair)? [Clarity, Spec §FR-008]
- [ ] CHK012 Is chain depth defined as hop count after preset expansion, with a worked example? [Clarity, Spec §FR-010a]
- [ ] CHK013 Is the rejection error contract specified (which hop, which reason, what layer)? [Clarity, Spec §FR-010, Spec §FR-025]
- [ ] CHK014 Are "carrier" and "egress" defined as distinct concepts for a hop? [Clarity, Spec §Key Entities]
- [ ] CHK015 Is "usable on its own" defined with explicit entry and exit criteria? [Clarity, Spec §FR-005]
- [ ] CHK016 Is "zero side effects before any hop starts" defined with observable criteria? [Clarity, Spec §FR-010]

## Requirement Consistency

- [ ] CHK017 Do FR-004 (presets are compositions) and FR-010a (depth is hop count) agree on how gool/mim are counted? [Consistency, Spec §FR-004, Spec §FR-010a]
- [ ] CHK018 Are transport naming conventions consistent across spec, data-model, and contracts? [Consistency]
- [ ] CHK019 Do the chain-report requirements align with the ConnectionReport entity fields? [Consistency, Spec §FR-025, data-model.md]
- [ ] CHK020 Is the UDP-after-TCP-only rule consistent between the Edge Cases section and FR-010? [Consistency]
- [ ] CHK021 Do the binding-order requirements (FR-007/FR-008) agree with the ordering semantics in config-formats? [Consistency, contracts/config-formats.md]

## Acceptance Criteria Quality

- [ ] CHK022 Can "adds a transport with zero engine edits" be objectively verified? [Measurability, SC-002c]
- [ ] CHK023 Can "zero side effects before any hop starts" be objectively measured? [Measurability, SC-002d]
- [ ] CHK024 Are acceptance scenarios defined for both orderings of every named composition? [Acceptance Criteria, Spec §User Story 3]
- [ ] CHK025 Is each chain success criterion (SC-002) traceable to a specific acceptance scenario? [Traceability, SC-002]

## Scenario Coverage

- [ ] CHK026 Are requirements defined for generic tunnel-in-tunnel nesting, not only the gool/mim presets? [Coverage, Spec §FR-007]
- [ ] CHK027 Are requirements defined for mixed tunnel-plus-proxy chains? [Coverage, Spec §FR-008]
- [ ] CHK028 Are requirements defined for a chain whose inner hop requires a UDP carrier? [Coverage, Spec §FR-006a]
- [ ] CHK029 Are alternate-flow requirements defined when a hop in the middle of a chain is unavailable? [Coverage, Gap]
- [ ] CHK030 Are requirements defined for a single-hop chain (no composition) as a degenerate case? [Coverage, Gap]

## Edge Case Coverage

- [ ] CHK031 Is depth-cap behavior specified when a preset expansion pushes a chain over the cap? [Edge Case, Spec §FR-010a]
- [ ] CHK032 Is behavior specified when two hops claim the same local port or address range? [Edge Case, Spec §FR-010]
- [ ] CHK033 Is behavior specified for cyclic chains (a hop targeting its own listener)? [Edge Case, Spec §FR-010]
- [ ] CHK034 Is MTU handling across nested layers specified and made reportable? [Edge Case, Gap]
- [ ] CHK035 Is behavior specified for a chain composed entirely of the same transport kind? [Edge Case, Gap]

## Dependencies & Assumptions

- [ ] CHK036 Is the transport self-registration mechanism documented as a dependency with a stated failure mode? [Dependency, Gap]
- [ ] CHK037 Is the assumption that every transport satisfies one interface validated by a named artifact? [Assumption, Spec §FR-006]

## Ambiguities & Conflicts

- [ ] CHK038 Is the chain-expression syntax unambiguous for expressing per-hop typed options? [Ambiguity, contracts/cli.md]
- [ ] CHK039 Is it explicit that composition presets cannot themselves contain presets (no recursion)? [Ambiguity, Gap]
- [ ] CHK040 Is the ownership of depth validation unambiguous (validator vs registry vs preset expansion)? [Ambiguity, Gap]

## Notes

- Mark items `[x]` only after review confirms the requirement-quality criterion is satisfied
- Leave items unchecked when they still require clarification, correction, or reviewer evaluation
- `/speckit.implement` reads checklist checkbox state as a gate and must not modify markers
- `checklists/requirements.md` has a separate built-in lifecycle maintained by `/speckit.specify` and `/speckit.clarify`
- Items are numbered sequentially for easy reference