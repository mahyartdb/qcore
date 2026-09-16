# Release Pipeline & Platform Matrix Checklist: Multi-Protocol Tunnel Client

**Purpose**: Exhaustive requirements-quality review of release integrity, target matrix, artifact/versioning policy, verification gating, and supply-chain provenance.
**Created**: 2026-09-14
**Feature**: [spec.md](../spec.md)

**Review Ownership**: This checklist is a reviewer-owned requirements-quality review artifact. Mark an item `[x]` only when the reviewer determines the requirements-quality criterion is satisfied.
**Marker Semantics**: `[x]` means the criterion has been reviewed and satisfied for requirements quality. It does not mean implementation work is complete.

## Requirement Completeness

- [ ] CHK001 Is the authoritative supported target list defined in exactly one place? [Completeness, constitution Platform Parity]
- [ ] CHK002 Is the exclusion of Windows 32-bit ARM stated with its rationale? [Completeness, AGENTS.md]
- [ ] CHK003 Are requirements defined for building and smoke-testing every listed target before release? [Completeness, SC-002a]
- [ ] CHK004 Are artifact naming, checksums, and header-publishing requirements specified? [Completeness, plan Release Pipeline]
- [ ] CHK005 Are signing, provenance, and SBOM requirements stated? [Completeness, constitution Release Integrity]
- [ ] CHK006 Is the release-blocking condition defined (any required target fails build or smoke)? [Completeness, constitution]
- [ ] CHK007 Are versioning requirements defined for the Rust API, C ABI, and config/report schemas independently? [Completeness, Spec §FR-003f]
- [ ] CHK008 Is a deprecation-window policy specified for breaking changes? [Completeness, constitution Independent Versioning]
- [ ] CHK009 Is the changelog and release-cadence requirement stated? [Completeness, gap]
- [ ] CHK010 Are reproducibility requirements specified (pinned toolchain, locked deps, deterministic builds)? [Completeness, constitution]

## Requirement Clarity

- [ ] CHK011 Is "required target" defined versus "best-effort target"? [Clarity, Gap]
- [ ] CHK012 Is "smoke test" defined with concrete, deterministic operations? [Clarity, plan Release Pipeline]
- [ ] CHK013 Is the ABI compatibility rule quantified (what change forces which bump)? [Clarity, Spec §FR-003f]
- [ ] CHK014 Is "published build provenance" defined operationally? [Clarity, constitution]
- [ ] CHK015 Is the C ABI version surface defined (function and header constant)? [Clarity, contracts/c-abi.md]

## Requirement Consistency

- [ ] CHK016 Do the target lists in spec, plan, AGENTS.md, and quickstart agree? [Consistency, SC-002a]
- [ ] CHK017 Do the versioning requirements align across spec, constitution, and the release plan? [Consistency]
- [ ] CHK018 Is the required-checks list consistent between the constitution and the planned CI pipeline? [Consistency, constitution Development Workflow]

## Acceptance Criteria Quality

- [ ] CHK019 Can "0 listed targets ship unbuilt or untested" be objectively verified? [Measurability, SC-002a]
- [ ] CHK020 Can "an external consumer uses only the documented API" be objectively verified for both Rust and non-Rust hosts? [Measurability, SC-002b]
- [ ] CHK021 Is the secret-scan gate's pass condition measurable across named surfaces? [Measurability, SC-006]

## Scenario Coverage

- [ ] CHK022 Are requirements defined for a partial release failure (some targets pass, some fail)? [Coverage, Exception Flow]
- [ ] CHK023 Are requirements defined for an ABI breaking change release? [Coverage, Gap]
- [ ] CHK024 Are requirements defined for a security-fix emergency release? [Coverage, Gap]
- [ ] CHK025 Are requirements defined for artifact re-publication or yanking? [Coverage, Recovery Flow, Gap]
- [ ] CHK026 Are requirements defined for the nightly/real-network tier vs the gating tier? [Coverage, plan Release Pipeline]

## Edge Case Coverage

- [ ] CHK027 Is behavior specified when a target's runner is unavailable? [Edge Case, Gap]
- [ ] CHK028 Is behavior specified when the generated C header drifts from the ABI version? [Edge Case, contracts/c-abi.md]
- [ ] CHK029 Is behavior specified when a dependency advisory appears mid-release? [Edge Case, Gap]
- [ ] CHK030 Is behavior specified for signing-key or attestation-service unavailability? [Edge Case, Gap]

## Non-Functional Requirements

- [ ] CHK031 Are build-time/cache requirements specified for the matrix? [Non-Functional, Gap]
- [ ] CHK032 Is artifact retention specified or explicitly excluded? [Non-Functional, Gap]
- [ ] CHK033 Are supply-chain checks (advisories, bans, sources) specified as required gates? [Non-Functional, constitution]
- [ ] CHK034 Is Windows code signing addressed or explicitly deferred with a rationale? [Non-Functional, plan Release Pipeline]

## Dependencies & Assumptions

- [ ] CHK035 Are cross-build toolchains named and pinned (cross-rs, cargo-ndk, zigbuild, MSVC)? [Dependency, plan Build Matrix]
- [ ] CHK036 Is the assumption of one TLS provider after the spike documented with its fallback? [Assumption, research R4]
- [ ] CHK037 Is the presence of `AGENTS.md` with commands and the target list required? [Dependency, constitution Governance]

## Ambiguities & Conflicts

- [ ] CHK038 Is the relationship between "SC-002a" and "release is blocked" unambiguous? [Ambiguity, SC-002a]
- [ ] CHK039 Is the ownership of the target list unambiguous (one source consumed by CI and docs)? [Ambiguity, constitution Platform Parity]
- [ ] CHK040 Is it explicit whether Android ships a Termux CLI, a cdylib/JNI library, or both, and how each is smoke-tested? [Ambiguity, Spec §FR-003e]

## Notes

- Mark items `[x]` only after review confirms the requirement-quality criterion is satisfied
- Leave items unchecked when they still require clarification, correction, or reviewer evaluation
- `/speckit.implement` reads checklist checkbox state as a gate and must not modify markers
- `checklists/requirements.md` has a separate built-in lifecycle maintained by `/speckit.specify` and `/speckit.clarify`
- Items are numbered sequentially for easy reference