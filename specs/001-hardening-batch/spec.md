# Spec: qcore Hardening + Consistency Batch

## Problem Statement

As an operator and embedder, I hit inconsistent failure modes: panics where a typed error is expected, silent fallbacks where fail-closed is expected, CLI shortcuts that ignore globals, FFI scan that diverges from CLI scan, weak loopback bearer tokens, world-readable control state, slow stealth scans, unbounded teardown, and CI that only gates Linux while shipping Windows artifacts.

## Solution

Tighten failure contracts without changing the public ABI/exit-code surface: poison-tolerant session registry, cryptographic control tokens with hardened control files, fail-closed profile loading, staggered stealth scheduling, unified CLI/FFI scan pipeline, enum-based failure mapping, complete FFI error reporting, bounded teardown, panic-free detach, corrected FFI transport-set docs, shortcut globals threading, unified test runner, and a Windows gate leg.

## User Stories

1. As an embedder, I want start / session_report / stop_session to return errors on lock poisoning, so that a poisoned session map never panics my host.
2. As a security reviewer, I want control bearer tokens drawn from the OS RNG, so that a loopback peer cannot enumerate them.
3. As an operator, I want the control rendezvous file written atomically with owner-only permissions, so that the bearer token is not exposed or half-written.
4. As an operator, I want corrupt/unreadable scan profiles to fail closed instead of silently using shipped defaults, so that misconfiguration is visible.
5. As an operator, I want discovery seed load failures to be explicit (empty vs. fallback), so that adversarial profile dirs cannot silently disable discovery.
6. As an operator, I want stealth scans to stagger inside spawned probes rather than serially before spawn, so that large candidate sets complete inside the overall deadline.
7. As a CLI user, I want chain shortcuts to honor timeout/family/scan/quiet/verbose like connect does, so that shortcut and explicit-chain behavior match.
8. As a mobile embedder, I want FFI scan to use the same winner fast-path, seed expansion, and cache persist/evict pipeline as CLI scan, so that identical inputs give identical results.
9. As an FFI embedder, I want failure-to-code mapping based on the typed failure layer, so that message rewording cannot silently remap exit classes.
10. As a C caller, I want interior-NUL string failures to populate the error out-param, so that I never get a code with no message.
11. As a C caller, I want engine free / session teardown bounded by the engine budget, so that a hung session cannot hang my process indefinitely.
12. As a CLI user, I want detach to return a typed hop-failure when the log fallback is unwritable, so that a full temp dir never panics.
13. As a mobile embedder, I want FFI config docs to accurately state the linked transport set and worker-threads knob, so that binary size and backend expectations are correct.
14. As a CLI user, I want header/CLI docs to list the full status code set including dead/no-session/unverifiable, so that scripts can handle all cases.
15. As a maintainer, I want the local release gate to use the same workspace-wide nextest invocation as CI, so that local and CI results agree.
16. As a CI maintainer, I want a Windows gate leg running the native subset, so that Windows-only linkage/permission/keyring failures surface on PRs.
17. As a maintainer, I want nightly live-egress to use the nextest ignored-mode rather than the bare test runner, so that retries and config apply uniformly.
18. As a maintainer, I want cross-target matrix generation driven from the single targets manifest, so that YAML and manifest cannot drift.
19. As a maintainer, I want the empty Tor/UDP conformance stub implemented or removed, so that the suite asserts something or stays clean.
20. As a maintainer, I want standalone relay conformance plus aggressive/off obfuscation paths, so that all shipped transports have offline establishment coverage.
21. As a maintainer, I want an expanded import corpus (multi-peer, IPv6-only, CRLF/BOM/empty, second bad-field variant), so that import strictness is pinned.
22. As a maintainer, I want per-test unique temp dirs and guaranteed-closed ephemeral ports, so that parallel runs do not collide or assume fixed closed ports.
23. As a maintainer, I want the C ABI consumer sample exercised in CI or marked explicitly untested, so that it cannot silently rot.

## Implementation Decisions

- Modules to modify: Engine session registry; session control token + control file I/O; scan profile loader + discovery seeds + scanner scheduler + scan report shape; CLI shortcut dispatch + detach spawn; FFI handle tracking + error mapping + string out-params + engine lifecycle + scan entry + config docs; transport-set docs; release automation; CI workflows.
- Session registry: replace panicking lock access with poison-tolerant restore; clone session handles out from under the lock before building reports.
- Control auth: switch token derivation to OS RNG bytes hex-encoded; keep 128-bit length and existing file location; keep constant-fold token compare.
- Control file: atomic temp-plus-rename write with owner-only permissions on Unix and best-effort hardening note on Windows; no schema change.
- Profile loading: fail closed on IO/parse errors except missing-file fallback; align discovery-seed loader with obfuscation loader semantics; preserve zero-socket preflight guarantee.
- Scanner: stagger stealth delay inside probe tasks (token-bucket style) instead of serial pre-spawn sleep; keep overall deadline + bounded-parallel + truncation cap semantics.
- CLI shortcuts: thread validated globals (timeout, quiet, verbose, scan intent) into shortcut path; keep canonical-expression detach re-spawn working.
- Detach: replace panicking fallback with typed hop-failure return; forward report-out when detached or reject combination explicitly.
- FFI errors: map from typed failure layer with string match only as fallback; always populate error out-param including interior-NUL path; bound free/stop by engine timeout.
- FFI/CLI scan: extract one shared scan-request pipeline in core (winner fast-path, seed expansion, verify, persist/evict) called by both surfaces; keep exit-4 empty-scan contract and single-JSON-doc stdout contract.
- Docs: correct linked-transport-set statement and worker-threads field; complete status-code list in header and CLI help; no ABI version bump.
- Automation: unify local release gate on workspace nextest; generate release matrix from targets manifest; add Windows native gate leg; fix nightly ignored-mode invocation.
- Architectural stance: keep facade + plugin boundary (Engine never matches on transport kind); keep stdout-results / stderr-diagnostics split; keep secrets-redacted reporting; keep preflight zero-socket.

## Testing Decisions

- What makes a good test: assert external behavior only — exit codes, single-JSON shapes, error messages naming the field/fix, file perms/atomicity observable effects, timing bounds, no-panic under poisoned/failing inputs. Do not assert internal lock types, RNG internals, or task layout.
- Seams (highest-first): CLI process boundary; Engine public API; C ABI boundary; control channel wire + file; scanner + profile loader.
- Prior art: lifecycle unwind/stop tests; control query helpers + secret hygiene suite; scan profile-bounds/cap/evict tests; chains grammar/rejection tests; CLI API parity suite + native smoke matrix; in-crate FFI unit tests + Rust ABI consumer test.

## Out of Scope

- New transports, new presets, or profile schema migration.
- ABI version bump or breaking JSON/exit-code changes.
- Live egress expansion, Android emulator runs, musl delivery.
- Connection reuse for multiplexed transports.
- Full JNI diagnostics rework beyond documenting string-subset contract.
- Secret-scanner config and operator profile-dir audit command (tracked separately).

## Further Notes

- Ordering: registry/token/control-file/scan-fallback first (panic + security + silent-fallback risk), then pipeline/unification/mapping, then docs/CI/coverage.
- Main regression risks: stealth rescheduling changing timing flakiness; shared scan pipeline changing FFI cache behavior (intended); poison-tolerant locks masking real bugs — keep logging on restore.

## Tickets

- T1 engine-registry-poison (stories 1)
- T2 control-token-file (stories 2, 3)
- T3 scan-failclosed-stealth (stories 4, 5, 6)
- T4 cli-shortcut-detach (stories 7, 12)
- T5 ffi-errors-lifecycle-docs (stories 9, 10, 11, 13, 14)
- T6 scan-pipeline-unify (story 8)
- T7 ci-xtask-coverage (stories 15–23)
