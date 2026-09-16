# Dual-Stack Parity Checklist: Multi-Protocol Tunnel Client

**Purpose**: Exhaustive requirements-quality review of IPv4/IPv6 parity across transports, chains, scanning, and reporting.
**Created**: 2026-09-14
**Feature**: [spec.md](../spec.md)

**Review Ownership**: This checklist is a reviewer-owned requirements-quality review artifact. Mark an item `[x]` only when the reviewer determines the requirements-quality criterion is satisfied.
**Marker Semantics**: `[x]` means the criterion has been reviewed and satisfied for requirements quality. It does not mean implementation work is complete.

## Requirement Completeness

- [ ] CHK001 Are dual-stack requirements stated for every transport kind and mode? [Completeness, Spec §FR-012]
- [ ] CHK002 Is the address-family selection surface defined (ipv4, ipv6, dual) with a documented default? [Completeness, Spec §FR-013]
- [ ] CHK003 Are per-hop family-reporting requirements defined? [Completeness, Spec §FR-013]
- [ ] CHK004 Are dual-stack requirements defined for endpoint scanning, including per-family ordering? [Completeness, Spec §FR-014]
- [ ] CHK005 Are dual-stack requirements defined for every chain path, not just single hops? [Completeness, Spec §FR-012]
- [ ] CHK006 Is the address-family capability of each transport exposed as pre-start descriptor data? [Completeness, Spec §FR-006a]
- [ ] CHK007 Are requirements defined for Address-family handling in imported configs (Address/AllowedIPs)? [Completeness, Spec §FR-023]

## Requirement Clarity

- [ ] CHK008 Is "on equal footing" defined with observable, testable criteria? [Clarity, constitution Principle II]
- [ ] CHK009 Is "family actually used" defined as a reportable field with a defined source? [Clarity, Spec §FR-013]
- [ ] CHK010 Is the one-family-available degradation path defined explicitly as a host condition, not a defect? [Clarity, constitution, Spec Edge Cases]
- [ ] CHK011 Is DNS/resolver family policy specified or explicitly excluded? [Clarity, Gap]

## Requirement Consistency

- [ ] CHK012 Do dual-stack requirements align between spec, constitution Principle II, and quickstart scenarios? [Consistency]
- [ ] CHK013 Is the constitution's Principle II wording consistent with the feature's actual dual-stack scope? [Consistency, constitution]
- [ ] CHK014 Are family-selection requirements consistent between chain hops and the session-level default? [Consistency]

## Acceptance Criteria Quality

- [ ] CHK015 Can "every transport passes a dual-stack run" be objectively verified per target? [Measurability, SC-001]
- [ ] CHK016 Is the dual-stack verification gate defined as deterministic and offline? [Measurability, constitution Dual-Stack Harness]
- [ ] CHK017 Is a per-target family-capability check required, not just a single-host check? [Measurability, SC-002a]

## Scenario Coverage

- [ ] CHK018 Are requirements defined for IPv4-only hosts? [Coverage, Spec Edge Cases]
- [ ] CHK019 Are requirements defined for IPv6-only hosts? [Coverage, Gap]
- [ ] CHK020 Are requirements defined for hosts where one family is present but non-functional? [Coverage, Spec Edge Cases]
- [ ] CHK021 Are requirements defined for dual-stack hosts where families have differing reachability? [Coverage, Gap]
- [ ] CHK022 Are requirements defined for family selection inside a nested chain? [Coverage, Gap]

## Edge Case Coverage

- [ ] CHK023 Is behavior specified when a transport cannot provide the requested family? [Edge Case, Gap]
- [ ] CHK024 Is behavior specified when an imported config offers only one family? [Edge Case, Gap]
- [ ] CHK025 Is MTU interaction with address family specified? [Edge Case, Gap]
- [ ] CHK026 Is behavior specified when DNS resolves to both families but only one is reachable? [Edge Case, Gap]

## Non-Functional Requirements

- [ ] CHK027 Are performance expectations defined per family where they differ? [Non-Functional, Gap]
- [ ] CHK028 Is the verification matrix's family coverage stated as a required gate? [Non-Functional, constitution]

## Dependencies & Assumptions

- [ ] CHK029 Is the assumption that scanners and endpoints exist in both families documented? [Assumption, Gap]
- [ ] CHK030 Is the deterministic stub peer required to serve both families? [Dependency, constitution Dual-Stack Harness]

## Ambiguities & Conflicts

- [ ] CHK031 Is "dual" defined unambiguously (simultaneous use vs preferred-then-fallback)? [Ambiguity, Spec §FR-013]
- [ ] CHK032 Is the interaction between per-hop family and session family unambiguous? [Ambiguity, Gap]
- [ ] CHK033 Is it explicit whether NAT traversal parity is in scope (constitution names it, spec does not)? [Conflict, constitution Principle II]

## Notes

- Mark items `[x]` only after review confirms the requirement-quality criterion is satisfied
- Leave items unchecked when they still require clarification, correction, or reviewer evaluation
- `/speckit.implement` reads checklist checkbox state as a gate and must not modify markers
- `checklists/requirements.md` has a separate built-in lifecycle maintained by `/speckit.specify` and `/speckit.clarify`
- Items are numbered sequentially for easy reference