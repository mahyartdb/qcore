# Security & Secret Hygiene Checklist: Multi-Protocol Tunnel Client

**Purpose**: Exhaustive requirements-quality review of secret handling, input boundaries, the sidecar trust boundary, fail-closed behavior, and security-relevant non-functional requirements.
**Created**: 2026-09-14
**Feature**: [spec.md](../spec.md)

**Review Ownership**: This checklist is a reviewer-owned requirements-quality review artifact. Mark an item `[x]` only when the reviewer determines the requirements-quality criterion is satisfied.
**Marker Semantics**: `[x]` means the criterion has been reviewed and satisfied for requirements quality. It does not mean implementation work is complete.

## Requirement Completeness

- [ ] CHK001 Are the secret categories enumerated (private keys, pre-shared keys, tokens, credentials)? [Completeness, Spec §FR-026]
- [ ] CHK002 Are all surfaces where secrets could leak enumerated (logs, exports, state files, crash output, CI logs, reports)? [Completeness, Spec §FR-026]
- [ ] CHK003 Are the permitted secret-at-rest mechanisms specified (for example OS keyring vs plaintext)? [Completeness, Gap]
- [ ] CHK004 Are secret-handling requirements defined for imported WireGuard/AmneziaWG configs? [Completeness, Spec §FR-022, Spec §FR-024]
- [ ] CHK005 Are secret-handling requirements defined for what the Psiphon sidecar receives? [Completeness, constitution Sidecar Trust Boundary]
- [ ] CHK006 Is the sidecar trust boundary fully specified (pinned executable path, minimal environment, readiness handshake, teardown on drop, restart cap)? [Completeness, constitution]
- [ ] CHK007 Are input-validation requirements defined for every external boundary (config, endpoints, DNS, frames, scan results)? [Completeness, constitution Principle IV]
- [ ] CHK008 Is fail-closed behavior specified for each validation-failure category? [Completeness, Spec §FR-027]
- [ ] CHK009 Is the secret-scan scope defined for both static and dynamic checks? [Completeness, constitution]
- [ ] CHK010 Are lawful-use and jurisdiction statements specified? [Completeness, Spec Legal & Compliance]
- [ ] CHK011 Is default-off telemetry specified? [Completeness, constitution]
- [ ] CHK012 Is the cryptography sourcing rule documented (vetted libraries, no custom constructions)? [Completeness, constitution]

## Requirement Clarity

- [ ] CHK013 Is central redaction specified as the single enforcement point rather than per-call-site? [Clarity, Spec §FR-026]
- [ ] CHK014 Is credential handling during config export explicitly defined (redaction in emitted output)? [Clarity, Spec §FR-024]
- [ ] CHK015 Is "unknown field" rejection defined precisely enough to be security-meaningful? [Clarity, Spec §FR-023]
- [ ] CHK016 Is the distinction between identity secrets and non-secret endpoint data clearly drawn? [Clarity]
- [ ] CHK017 Is "bounded" defined for sidecar restarts and scan concurrency? [Clarity, constitution]

## Requirement Consistency

- [ ] CHK018 Do the secret-hygiene requirements agree across spec, constitution, and quickstart? [Consistency]
- [ ] CHK019 Are fail-closed requirements consistent between FR-027 and the Edge Cases section? [Consistency]
- [ ] CHK020 Do the sidecar requirements align between FR-001, the Assumptions, and the constitution clause? [Consistency]

## Acceptance Criteria Quality

- [ ] CHK021 Can "zero secrets in logs, exports, and crash output" be objectively verified? [Measurability, SC-006]
- [ ] CHK022 Is a dynamic capture test required (not only static scanning) to prove no leakage? [Measurability, constitution]
- [ ] CHK023 Is the secret-scan pass condition quantified (zero findings across named surfaces)? [Measurability, SC-006]

## Scenario Coverage

- [ ] CHK024 Are requirements defined for a secret-bearing failure (for example a failed state-file write)? [Coverage, Recovery Flow]
- [ ] CHK025 Are requirements defined for sidecar startup failure and restart exhaustion? [Coverage, Exception Flow, Gap]
- [ ] CHK026 Are requirements defined for secret exposure via process arguments or environment? [Coverage, Gap]
- [ ] CHK027 Are requirements defined for handling a config that contains unexpected credential fields? [Coverage, Spec §FR-023]

## Edge Case Coverage

- [ ] CHK028 Is behavior specified when redaction encounters an unrecognized secret format? [Edge Case, Gap]
- [ ] CHK029 Is behavior specified when a crash occurs mid-write of a secret-bearing file? [Edge Case, Gap]
- [ ] CHK030 Are local file permission/ownership requirements for config and state specified? [Edge Case, Gap]

## Non-Functional Requirements

- [ ] CHK031 Is a threat model documented and are requirements traced to it? [Traceability, Gap]
- [ ] CHK032 Are rate-limiting / resource-bound requirements specified for scanning and sidecar restarts? [Non-Functional, Gap]
- [ ] CHK033 Are log-retention and audit requirements defined or explicitly excluded? [Non-Functional, Gap]
- [ ] CHK034 Are encryption-at-rest requirements for local state defined or explicitly excluded? [Non-Functional, Gap]
- [ ] CHK035 Is authentication/authorization addressed or explicitly declared out of scope? [Non-Functional, Gap]
- [ ] CHK036 Is a breach/incident-response requirement defined or explicitly excluded? [Exception Flow, Gap]

## Dependencies & Assumptions

- [ ] CHK037 Is the dependency-pinning and provenance requirement objectively checkable? [Measurability, constitution]
- [ ] CHK038 Is the assumption of "no third-party telemetry" validated by a named check? [Assumption, Gap]
- [ ] CHK039 Is the assumption that the sidecar is user-supplied rather than bundled stated explicitly? [Assumption]

## Ambiguities & Conflicts

- [ ] CHK040 Is "no secrets persisted" unambiguous when the OS keyring is unavailable? [Ambiguity, Gap]
- [ ] CHK041 Is the boundary between "required to function" and "must not receive" for sidecar secrets explicit? [Ambiguity, constitution]

## Notes

- Mark items `[x]` only after review confirms the requirement-quality criterion is satisfied
- Leave items unchecked when they still require clarification, correction, or reviewer evaluation
- `/speckit.implement` reads checklist checkbox state as a gate and must not modify markers
- `checklists/requirements.md` has a separate built-in lifecycle maintained by `/speckit.specify` and `/speckit.clarify`
- Items are numbered sequentially for easy reference