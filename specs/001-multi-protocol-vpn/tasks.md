# Tasks: Multi-Protocol Tunnel Client (Rust / Aether fork)

**Input**: Design documents from `specs/001-multi-protocol-vpn/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/
**Tests**: INCLUDED — spec FR-003/SC-001/SC-002/SC-004/SC-008 explicitly require a passing dual-stack suite per ported capability before it is marked complete. Tests are therefore mandatory, not optional, for this feature.
**Organization**: Tasks grouped by user story. Stories ordered by priority (P1 first), keeping spec US numbers for traceability: US1 (P1) → US3 (P1) → US2 (P2) → US4 (P3) → US5 (P3).
**Audit status**: Three-reviewer audit applied (spec / plan+research+constitution / data-model+contracts+quickstart). All FAIL items repaired: 5 doc contradictions, 6 mislabels + 1 duplication, 2 order violations, all missing coverage, verbatim constraint quoting. Adjudications recorded in Notes.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

Rust workspace per plan.md §Project Structure (not web-app `src/`/`tests/`):
- `crates/qcore-transport-api/`, `crates/qcore-core/`, `crates/qcore-transports/`, `crates/qcore/`, `crates/qcore-cli/`, `crates/qcore-ffi/`
- `tests/conformance/`, `tests/chains/`, `tests/fixtures/`, `examples/`, `profiles/`, `xtask/`, `.github/workflows/`
- Network policy (family selection, DNS, keepalive, roaming) lives under the listed `session/` module as `session/net.rs` — no new top-level module invented (consolidation bias)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Workspace skeleton, Aether base record, toolchain pins, release lever, CI shell

- [X] T001 Create Rust workspace layout per plan.md in Cargo.toml (resolver 2, members: qcore-transport-api, qcore-core, qcore-transports, qcore, qcore-cli, qcore-ffi, xtask, tests/conformance, tests/chains)
- [X] T002 Pin stable MSRV toolchain in rust-toolchain.toml with single pinned version
- [X] T003 [P] Record Aether fork base per FR-002/research R1 in docs/BASE.md (fork of CluvexStudio/Aether; retained transports WireGuard, MASQUE h3/h2, Tor via arti, scanner, noize obfuscation)
- [X] T004 [P] Configure cargo-deny policy in denylist.toml (pinned deps + provenance bans)
- [X] T005 [P] Implement xtask release lever skeleton in xtask/src/main.rs (build|smoke|package|release|abi-diff subcommands)
- [X] T006 [P] Pin cross-build backends per research R9 in xtask/src/build.rs (cross-rs for Linux, cargo-ndk for Android, cargo-zigbuild for static musl; native MSVC runners for Windows)
- [X] T007 [P] Create authoritative target list single source per constitution Platform Parity in xtask/src/targets.toml (all 9 targets; 9 platform/arch combos — gnu+musl are libc variants of one target, not separate targets; consumed by CI, smoke, docs and release; removal/demotion requires constitution amendment)
- [X] T008 [P] Create CI workflow shells in .github/workflows/ci.yml (fmt, clippy -D warnings, nextest, conformance, chain matrix, ABI consumer test, secret scan, cargo-deny, semver-checks, qcore.h diff)
- [X] T009 [P] Create release and nightly workflow shells in .github/workflows/release.yml and .github/workflows/nightly.yml (tag → matrix build → smoke → sign → publish; nightly real-egress non-blocking; conventional commits → release-plz/git-cliff changelog on release.yml)
- [X] T010 [P] Run timeboxed (2–3 day) TLS-provider spike per research R4 on i686-pc-windows-msvc and armv7-linux-androideabi and record single-provider decision (quiche vs quinn+rustls/ring+h2; "commit to exactly one provider; do not ship two") in specs/001-multi-protocol-vpn/research.md
- [X] T011 Configure release profile for reproducibility in Cargo.toml (locked, SOURCE_DATE_EPOCH, remap-path-prefix)
- [X] T012 [P] Create WG/AWG config fixture corpus seeds in tests/fixtures/ (standard-wg.conf, awg.conf covering Jc/S1/H1/AllowedIPs dual-stack addresses)
- [X] T013 [P] Create transports meta-crate root per plan.md in crates/qcore-transports/Cargo.toml (feature-gated members wireguard/masque/relay/tor/psiphon/mock)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Plugin boundary, registry, chain validator, session core, diag redaction, family/DNS policy, stub peer — MUST complete before ANY user story

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T014 Implement transport plugin boundary traits in crates/qcore-transport-api/src/lib.rs (TransportDescriptor with kind as "registry key, not an enum" plus obfuscation_families as "compatibility source of truth" plus config_schema plus needs_sidecar "only psiphon"; Capabilities; Dialer::dial_tcp/dial_udp/capabilities; RunningHop::descriptor/dialer/health/events/stop; HopFactory::descriptor/build(cfg, carrier); ByteStream/UdpFlow abstract with "no OS socket" so smoltcp-backed inner hops work)
- [X] T015 [P] Implement HopError/HopHealth/HopEvent/FailureReport types in crates/qcore-transport-api/src/error.rs (FailureReport layer enum "validation, transport, chain, scan, config" plus hop_id plus cause "actionable, redacted" plus kind enum driving static remedy table)
- [X] T016 [P] Define per-transport build features per FR-003g in crates/qcore-transports/transport-*/Cargo.toml (hosts compile only the transports they embed; target matrix stays tractable)
- [X] T017 Implement inventory registry in crates/qcore-core/src/registry.rs (TransportRegistry built from register_plugin!, engine never matches on a kind)
- [X] T018 Implement typed HopConfig enum in crates/qcore-core/src/config/hop.rs (#[serde(tag="kind")] variants wireguard/masque/tor/psiphon/mock with per-variant fields "import_ref, obfuscation, family, endpoint" and "alpn (h3|h2)" and "sidecar_path"; "unknown fields are deserialization errors")
- [X] T019 Implement ChainSpec parse + composition-preset expansion in crates/qcore-core/src/chain/preset.rs (presets "expand exactly one level"; "a preset reference inside a preset definition is a validation error naming both names"; presets MUST NOT embed secrets)
- [X] T020 Implement chain validator in crates/qcore-core/src/chain/validate.rs (sole owner of depth: "Depth = total hops after expansion", "Default 3, configurable to hard limit of 5"; HopSpec id "unique in chain; used in reports/errors"; "index 0 = outermost carrier"; "internal listeners use ephemeral ports"; rejects cycles, port conflicts, duplicate id, over-depth with "over-depth error naming the hop"; UDP-carrier-after-TCP-only without relay rejected naming insertion "insert `relay` after `tor`" — relay recognized from registry descriptors, so no build dependency on the relay crate; zero side effects before start)
- [X] T021 Implement ChainBuilder::build public op in crates/qcore-core/src/chain/mod.rs (expands presets, validates depth/cycles/ports/carrier compatibility from descriptors; returns Result<Chain, ChainError> before any start)
- [X] T022 Implement address-family + DNS policy in crates/qcore-core/src/session/net.rs (dual = Happy Eyeballs v2 RFC 8305, Connection Attempt Delay default 250 ms configurable 10 ms–2 s, Resolution Delay 50 ms, preferred family default IPv4 configurable to IPv6; honor AllowedIPs exactly with warning on missing family default route; DNS routed through tunnel or refuse to start; resolver prefers IPv6 with penalty-based fallback; synthesis "only for IPv4 literals (RFC 7050 Pref64 / RFC 6052 embedding)" and "as the RFC 8305 2 s last resort"; "never synthesize AAAA when real AAAA answers exist"; IPv6-present-but-broken detected during validation with fallback/report, never black-hole)
- [X] T023 Implement profile-dir resolution per FR-028 in crates/qcore-core/src/config/profile_dir.rs (scan/obfuscation/composition profiles live in application profile directory, "replaceable without editing configuration that embeds secrets")
- [X] T024 Implement secret storage per research R11 in crates/qcore-core/src/config/secret.rs (secrets parsed at boundary, held in zeroizing wrappers, stored via OS keyring when available)
- [X] T025 Implement version constants in crates/qcore-core/src/api/version.rs (API_VERSION, ABI_VERSION, SCHEMA_VERSION surfaced independently)
- [X] T026 Implement Engine::preflight + Engine::start/stop/status/subscribe skeleton in crates/qcore-core/src/api/engine.rs (preflight opens zero sockets; start returns Session or FailureReport and fails closed per FR-027; status returns ConnectionReport; subscribe returns push-not-poll HopEvent stream; stop tears down all hops and the sidecar; start enforces the CONNECTION_TIMEOUT_SECONDS budget (default 30), reported per hop)
- [X] T027 Implement central secret redaction in crates/qcore-core/src/diag/redact.rs (typed-field-first, entropy+denylist second, heuristic masking never sole control; unclassifiable value drops record and emits placeholder with metadata only; never persist/export/log credentials, private keys, tokens in plaintext)
- [X] T028 Implement Session state machine in crates/qcore-core/src/session/mod.rs (id, validated chain, family_policy + preferred + delays, state "validating -> starting -> up -> (degraded) -> stopped" with "validating|starting|up -> failed", started_at, failure "present when failed"; "no transition from failed without a new session"; durable session.json with status dead vs unverifiable)
- [X] T029 Implement preflight/check command in crates/qcore-cli/src/cmd/preflight.rs (validates chain + profiles + config, opens zero network sockets per FR-029/SC-002d; refusal exit 2 naming offending hop)
- [X] T030 [P] Implement deterministic loopback stub peer in crates/qcore-transports/transport-mock/src/stub_peer.rs (connection counter proving preflight opens zero sockets; modes ipv4/ipv6/dual)
- [X] T031 [P] Implement mock transport conformance double in crates/qcore-transports/transport-mock/src/lib.rs (register_plugin! mock kind, test-only, UDP egress yes)
- [X] T032 [P] Create profiles directory + schema-version registry in profiles/ (directory layout + SCHEMA_VERSION record only; per-file data owned by T053/T067/T072 story tasks — no duplication)
- [X] T033 [P] Implement generated dual-stack conformance harness macro in tests/conformance/src/matrix.rs (reads TransportRegistry after T017, emits per-transport ipv4/ipv6/dual cases incl. per-target family-capability check)

**Checkpoint**: Foundation ready — transport API frozen, validator total, stub peer deterministic; user story implementation can now begin

---

## Phase 3: User Story 1 - Connect on a single transport (Priority: P1) ★ MVP

**Goal**: Each transport (WARP WireGuard, MASQUE h3/h2, imported WG, AWG, Tor, Psiphon) connects standalone with healthy tunnel over IPv4 and IPv6 (spec FR-004/FR-005/FR-012/FR-013, SC-001/SC-003).

**Independent Test**: For each transport on a dual-stack host: connect, confirm healthy tunnel + correct egress on IPv4 and IPv6, disconnect cleanly; unreachable transport reports name + actionable cause; v4-only/v6-only hosts connect on the available family; zero-config `qcore up` reaches a session in <2 min without editing files.

### Tests for User Story 1

- [X] T034 [P] [US1] Dual-stack acceptance test for wireguard peer=warp in tests/conformance/tests/wireguard.rs (ipv4 + ipv6 connect, egress check, clean stop)
- [X] T035 [P] [US1] Dual-stack acceptance test for masque h3/h2 in tests/conformance/tests/masque.rs (alpn=h3 and alpn=h2 independently, no other transport configured)
- [X] T036 [P] [US1] Dual-stack acceptance test for tor and psiphon sidecar in tests/conformance/tests/tor_psiphon.rs (each establishes independently; failure names transport + cause)
- [X] T037 [P] [US1] Failure-report test for unreachable transport in tests/conformance/tests/failure_report.rs (report names failing layer + cause SC-007; exit 3 transport-or-hop failure names hop + cause)
- [X] T038 [P] [US1] Single-family availability test in tests/conformance/tests/single_stack.rs (v4-only and v6-only stub modes connect on the available family with reported family, session does not fail)

### Implementation for User Story 1

- [X] T039 [P] [US1] Implement wireguard transport (boringtun data plane, WARP peer mode) in crates/qcore-transports/transport-wireguard/src/lib.rs
- [X] T040 [P] [US1] Implement masque transport (single QUIC provider from T010 spike, alpn h3/h2 modes) in crates/qcore-transports/transport-masque/src/lib.rs
- [X] T041 [P] [US1] Implement tor transport via arti-client in crates/qcore-transports/transport-tor/src/lib.rs (TCP-only capabilities: dials_udp=false)
- [X] T042 [P] [US1] Implement psiphon sidecar supervisor in crates/qcore-transports/transport-psiphon/src/supervisor.rs (explicit exe_path never resolved from PATH by default, minimal environment, readiness handshake, capped restarts with fail-closed named cause, teardown on session end and on drop, secrets via inherited pipe/fd with stdin second and env only when platform requires, never argv)
- [X] T043 [US1] Implement Engine::start single-hop bring-up in crates/qcore-core/src/session/lifecycle.rs (carrier Dialer handoff, declared order, per-hop family reporting; multi-hop nesting/MTU in T058)
- [X] T044 [US1] Implement per-hop keepalive + endpoint roaming in crates/qcore-core/src/session/net.rs (keepalive per-hop, configurable, default off, ~25 s advisory; endpoint roaming)
- [X] T045 [US1] Implement qcore connect/up + status/stop CLI skeleton in crates/qcore-cli/src/main.rs (thin consumer of Engine API; --family/--prefer/--json/--report-out/--log-level; zero-config `qcore up` = wireguard peer=warp, dual, default discovery (full scan-cache wired in US4 T068), bind 127.0.0.1:0; multi-hop chain inputs wired in T056)
- [X] T046 [US1] Implement detach + durable session in crates/qcore-cli/src/main.rs (-d/--detach spawns detached process writing session.json; status/stop locate it through that file plus token-authenticated local control socket)
- [X] T047 [US1] Implement --bind listener flag in crates/qcore-cli/src/main.rs (host:port local proxy listener, default 127.0.0.1:0)
- [X] T048 [US1] Implement reconnect + cold start in crates/qcore-core/src/session/reconnect.rs (first `qcore up` creates identity.toml and connects via default endpoint without editing a file per SC-003; scan-once-and-cache plus verified-endpoint preference wired in US4 T068, consumed here)
- [X] T049 [US1] Implement ConnectionReport + FailureReport emission in crates/qcore-core/src/session/report.rs (ordered chain, per-hop kind/family/endpoint/status, exit_hop_id, secret_redaction always true; stdout=results, stderr=diagnostics; --json exactly one JSON document; active-profile fields populated by T068/T073)

**Checkpoint**: US1 fully functional — every transport connects standalone dual-stack and single-stack; MVP demonstrable via `qcore up --chain "wireguard peer=warp" --family dual --json`

---

## Phase 4: User Story 3 - Chain and nest any transports in any order (Priority: P1)

**Goal**: Arbitrary ordered chains (tor-warp, warp-tor, warp-psiphon, psiphon-warp, mim, gool, mixed) establish in declared order with last hop as exit; impossible chains rejected before any hop starts with reason (spec FR-006/FR-007/FR-008/FR-010/FR-011, SC-002/SC-002d).

**Independent Test**: Declare each named composition in both orders, connect, confirm egress through declared final hop; confirm invalid chains rejected pre-start (stub-peer connection counter unchanged).

### Tests for User Story 3

- [X] T050 [P] [US3] Chain acceptance matrix test in tests/chains/tests/orderings.rs (tor-warp preset, wireguard peer=warp→tor, warp→psiphon exit, psiphon→warp exit, mim, gool, explicit tor,relay,wireguard peer=warp; asserts exit_hop_id == last hop)
- [X] T051 [P] [US3] Invalid-chain rejection test in tests/chains/tests/rejections.rs (gool,gool = 4 hops over-depth; bare tor,wireguard peer=warp rejected naming relay insertion; gool,psiphon,tor over cap; cycles; port conflicts — all exit 2, zero hops started)

### Implementation for User Story 3

- [X] T052 [P] [US3] Implement relay UDP-over-TCP framing adapter transport in crates/qcore-transports/transport-relay/src/lib.rs (first-class registered transport, no per-transport CLI flags)
- [X] T053 [P] [US3] Implement composition presets gool/mim/tor-warp in profiles/compositions.toml (gool = two wireguard peer=warp hops, mim = two masque alpn=h3 hops, tor-warp = tor,relay,wireguard peer=warp; single-hop and all-same-kind chains valid subject to depth)
- [X] T054 [US3] Implement chain grammar parser in crates/qcore-core/src/chain/parse.rs (chain := hop ("," hop)*, hop := name (key=value)* [@label]; last hop is exit FR-011; values containing ","/whitespace/"="/quotes MUST be quoted; reordering hops is the entire FR-008 mechanism, there is no --before/--after; typed per-transport options, unknown key fails closed naming field; --hop argv-order equivalent)
- [X] T055 [P] [US3] Implement chain TOML declaration parsing in crates/qcore-core/src/config/chain_file.rs ([chain] max_depth, [[chain.hop]] kind/id/peer/family/sidecar_path, last hop is exit FR-011; backs --chain-file and positional chain.toml operand)
- [X] T056 [US3] Wire multi-hop chain CLI inputs in crates/qcore-cli/src/main.rs (--chain expression, --chain-file path, positional chain.toml file, repeatable --hop in argv order; --max-depth owned by T083)
- [X] T057 [US3] Implement generated chain shortcuts in crates/qcore-cli/src/cmd/shortcuts.rs (minted iff all six hold: 1. every hyphen-segment resolves to exactly one registry token, 2. expanded chain within depth cap with over-depth parsing-but-unadvertised, 3. no collision with command alias/subcommand/global flag, 4. pure alias with identical ConnectionReport and exit code, 5. generated from registry with zero CLI edits, 6. never encodes mode-with-options such as masque-h2; unknown tokens exit 6, never fuzzy-resolved; ls lists advertised)
- [X] T058 [US3] Implement nested-hop bring-up in crates/qcore-core/src/session/lifecycle.rs (smoltcp-backed inner-hop streams carrying the next hop; per-layer inner-MTU shrink with PMTU RFC 4821, reported per layer)

**Checkpoint**: US1 + US3 both work — single transports and all named bidirectional orderings establish; invalid chains fail closed pre-start

---

## Phase 5: User Story 2 - Import and chain WireGuard-family configs through WARP (Priority: P2)

**Goal**: Standard WG and AmneziaWG configs import field-for-field, round-trip export equivalently, and chain with WARP in both orders (spec FR-009/FR-022/FR-023/FR-024, SC-004).

**Independent Test**: Import standard WG + AWG configs; connect each alone, then chained with WARP in both orders; field-for-field round-trip export diff clean; malformed config fails closed naming offending field.

### Tests for User Story 2

- [X] T059 [P] [US2] Config round-trip property test over corpus in tests/chains/tests/import_roundtrip.rs (100% fidelity: no field lost, added, or altered per SC-004; unknown/malformed fields rejected by name FR-023)
- [X] T060 [P] [US2] Imported-hop chaining test in tests/chains/tests/imported_chain.rs (imported WG alone, AWG alone, personal-WG-inside-WARP, WARP-inside-personal-WG; egress through declared exit)

### Implementation for User Story 2

- [X] T061 [US2] Implement ConfigImport::parse in crates/qcore-core/src/config/import.rs (source_format wireguard vs amneziawg, path, parsed field map, awg_params "present for amneziawg only", import_verdict "accepted vs rejected"; preserves every recognized field incl. dual-stack Address and AllowedIPs exactly; absent AWG keys ⇒ standard WireGuard behavior; "unknown_fields non-empty => reject, naming each" FR-023; AwgParams jc/jmin/jmax with "jmax < MTU", s1..s4, h1..h4 "non-overlapping", i1..i5, header_protection_key AWG-peers-only)
- [X] T062 [US2] Implement ConfigImport::export in crates/qcore-core/src/config/export.rs ("export MUST reproduce parsed equivalently" FR-024; private keys/secrets redacted, never plaintext FR-026)
- [X] T063 [US2] Implement wireguard peer=imported and peer=awg modes in crates/qcore-transports/transport-wireguard/src/modes.rs (AmneziaWG obfuscation decorator over boringtun data plane; server-negotiated AWG params forbidden on plain wireguard/WARP FR-021)
- [X] T064 [US2] Implement qcore import/export CLI commands in crates/qcore-cli/src/cmd/import.rs (`import <file>` parse+preserve, `export <import-ref>` reproduce; exit 5 on import rejection)

**Checkpoint**: US1 + US3 + US2 work — user-owned credentials are first-class chainable hops with lossless round-trip

---

## Phase 6: User Story 4 - Scan for working endpoints (Priority: P3)

**Goal**: Three scan profiles discover and traffic-validate endpoints, return ranked latency+verdict list, and feed reconnects (spec FR-014/FR-015/FR-016/FR-017, SC-005).

**Independent Test**: Run turbo/balanced/stealth; confirm ranked list with latency + reachability verdict; handshake-only-but-no-traffic endpoint rejected; empty scan fails without silent unverified fallback; next connect uses scanned endpoint; balanced scan < 30 s for ≥90%.

### Tests for User Story 4

- [X] T065 [P] [US4] Scan profile test in tests/conformance/tests/scan.rs (each profile yields ranked candidates with latency_ms + reachability; handshake-only marked uncertain never promoted to last-known-good; empty scan exits 4 with no silent reuse; balanced scan under 30 s for ≥90% per SC-005)

### Implementation for User Story 4

- [X] T066 [US4] Implement Scanner::scan in crates/qcore-core/src/scan/mod.rs (EndpointCandidate address "IP + port", family "ipv4 vs ipv6", latency_ms measured, reachability "passed vs failed" data-traffic validated, confidence "verified vs uncertain" with uncertain never promoted; failed endpoints discarded and not reused; verified candidates persisted as last-known-good; first-up scan-once-and-cache plus verified-endpoint reconnect preference wired here, feeding the US1 T048 sink)
- [X] T067 [P] [US4] Implement scan profiles data in profiles/scan.toml (exactly "turbo", "balanced" (default), "stealth" with concurrency = 32, rtt_budget_ms = 400, probe_kind data-plane vs handshake, family_order = ["ipv4", "ipv6"], stealth = false)
- [X] T068 [US4] Implement qcore scan CLI command in crates/qcore-cli/src/cmd/scan.rs (--transport/--profile/--family/--output table|json|ndjson; endpoints are property of transport+family not chain; --scan/--no-scan on connect; first `up` scans once and caches the verified endpoint, feeding US1 T048 reconnect)

**Checkpoint**: US4 works — scans produce validated ranked endpoints and reconnects prefer last-known-good verified candidates

---

## Phase 7: User Story 5 - Apply obfuscation profiles (Priority: P3)

**Goal**: noize and AmneziaWG profiles apply per-transport as data without hand-editing low-level params; incompatible selections rejected with reason (spec FR-018/FR-019/FR-020/FR-021).

**Independent Test**: Connect MASQUE/WARP with noize profile (params applied + reported); connect AWG peer with AWG profile (params applied + reported, e.g. `--chain "wireguard peer=awg import=awg-home" --obfuscation awg-balanced`); incompatible profile (e.g. awg-balanced on wireguard peer=warp) rejected with clear reason; no AWG server-negotiated params sent to plain WARP peer.

### Tests for User Story 5

- [X] T069 [P] [US5] Obfuscation compatibility test in tests/conformance/tests/obfuscation.rs (compatible applies+reports; incompatible rejects FR-021; AWG-on-WARP-edge forbidden; measured against controlled peer per research R7)

### Implementation for User Story 5

- [X] T070 [P] [US5] Apply noize params from ObfuscationProfile data in crates/qcore-transports/transport-masque/src/obfuscate.rs (pre-handshake junk train + obfuscated CPS packets for masque and wireguard modes; profiles are data per T072, this code only applies them)
- [X] T071 [P] [US5] Apply AwgParams from ObfuscationProfile data in crates/qcore-transports/transport-wireguard/src/awg.rs (ported from Go: Jc/Jmin/Jmax, S1–S4, H1–H4, I1–I5, header protection, content padding 0–96, random trailers, disable_cookies, randomized timings; "only against a supporting peer")
- [X] T072 [P] [US5] Implement obfuscation profiles data in profiles/obfuscation.toml (family noize|awg with compatible_modes; shipped defaults masque-balanced, awg-balanced, awg-off plus spec-authorized masque-aggressive/awg-aggressive entries; awg-balanced pins header protection on, S1–S4 16–32, Jc 6, Jmin/Jmax 64/256, I1–I3 mimicry, content padding 0–96, random trailers, cookies disabled, randomized timing ranges; masque-aggressive pins noize balanced + HTTP/2 + fragmentation; selecting a profile whose compatible_modes excludes the hop mode MUST be rejected FR-021)
- [X] T073 [US5] Wire --obfuscation/-O flag and profiles/ls listing in crates/qcore-cli/src/cmd/profiles.rs (lists transports+modes, three scan profiles, obfuscation profiles, presets, shortcuts; active profile reported in ConnectionReport; AWG hops referenced canonically as wireguard peer=awg import=<ref>)

**Checkpoint**: All user stories independently functional — single transport, arbitrary chains, imports, scanning, obfuscation

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Embedding surfaces, full CLI polish, release integrity, secret hygiene proof, docs

- [X] T074 Implement public facade crate re-export in crates/qcore/src/lib.rs (single stable import path for embedders; public types only)
- [X] T075 [P] Implement C ABI surface in crates/qcore-ffi/src/lib.rs (opaque handle types only; catch_unwind at each entry; explicit qcore_*_free ownership; strings UTF-8 length-prefixed-or-NUL-terminated per call; int32 status code plus out-param error struct; no secrets ever written to caller buffers FR-026; never blocks with long operations cancellable-or-bounded; every Rust API capability reachable through the ABI FR-003c/FR-003d; functions qcore_abi_version, qcore_engine_new, qcore_engine_free, qcore_engine_start, qcore_engine_status_json, qcore_engine_stop, qcore_scan, qcore_import_config, qcore_export_config, qcore_string_free, qcore_error_free; JSON boundary matching ConnectionReport/EndpointCandidate/ConfigImport)
- [X] T076 [P] Set FFI crate types per research R8 in crates/qcore-ffi/Cargo.toml (crate-type cdylib + staticlib)
- [X] T077 Generate C header via cbindgen in crates/qcore-ffi/qcore.h (MSVC 32-bit struct-alignment audit for 64-bit fields; qcore.h diff as CI gate)
- [X] T078 Emit ABI version file from the same ffi build in crates/qcore-ffi/abi-version.txt (plan: qcore.h + abi-version.txt from one build)
- [X] T079 [P] Implement Android JNI wrapper over C ABI in crates/qcore-ffi/src/jni.rs (no Android-only code paths in core FR-003d)
- [X] T080 [P] Implement embed-host example in examples/embed-host/main.rs (Rust host: start session, subscribe events, read status, stop using only public types; SC-002b)
- [X] T081 Implement ABI consumer test with Rust harness in tests/conformance/tests/abi_consumer.rs plus Go harness in examples/c-abi-consumer/main.go (both hosts start session, read state, stop via documented API only with no internal-type access; qcore_abi_version reported; SC-002b)
- [X] T082 Implement remaining CLI surface in crates/qcore-cli/src/cmd/mod.rs (qcore help [command]; version reports engine+API+ABI+schema+target with --json; status always prints expanded chain with states up/degraded/not_running exit10/dead exit1/unverifiable exit12 fail-closed; validation error format with stable code + field path + expected-vs-got redacted + offending hop index + fix suggestion)
- [X] T083 Implement global CLI flags in crates/qcore-cli/src/main.rs (--config path auto, --profile-dir path auto FR-028, --max-depth integer default 3 (hard limit 5), --timeout seconds default 30 (CONNECTION_TIMEOUT_SECONDS), --no-color honoring NO_COLOR and auto-off when not a TTY, --quiet/-q suppress non-error stderr, --verbose/-v repeatable non-secret diagnostics, --non-interactive never prompt with missing values exit 6, --yes required for destructive off-TTY)
- [X] T084 [P] Implement CLI→public-API parity audit test in tests/conformance/tests/cli_api_parity.rs (every CLI capability reachable through the public Rust API per FR-003c; fails on CLI-only paths)
- [X] T085 [P] Implement structured diag + HopEvent NDJSON stream in crates/qcore-core/src/diag/mod.rs (machine-readable chain/family/profiles/endpoint/failure per FR-025; versioned alongside public API)
- [X] T086 Implement per-target smoke command in xtask/src/smoke.rs (consumes xtask/src/targets.toml single source: `cargo xtask smoke --target <triple>` runs version --json then stub-peer connect over ipv4/ipv6/dual for all 9 targets incl. Termux CLI emulator execution + cdylib exported-symbol check; SC-002a)
- [X] T087 [P] Implement static secret scan gate in .github/workflows/ci.yml (gitleaks/trufflehog over repo, CI logs, reports, state files, artifacts, crash output)
- [X] T088 [P] Implement dynamic trace-level secret-capture test in tests/conformance/tests/secret_hygiene.rs (run at trace, assert zero secrets in stdout/logs/state/exports incl. fail-closed placeholder path; SC-006)
- [X] T089 Implement release packaging + signing in xtask/src/release.rs (artifact names qcore-<ver>-<target>, SHA256SUMS+.sig, cosign keyless, SLSA attestation, CycloneDX SBOM; blocked unless full Tier C matrix green; emergency path on release/x.y with two-role authority release-manager + security-maintainer, advisory + signing + secret-scan + audit + affected-platform smoke mandatory, patch bump never re-tag, yank only broken versions never to retract secrets, advisory-affects-mid-release Tier C rule)
- [X] T090 [P] Add cargo-semver-checks + abi-diff gates in xtask/src/abi_diff.rs (Rust API major on break with deprecation window; C ABI break → major + one minor retaining old symbol; schema break → SCHEMA_VERSION bump + migration note; FR-003f)
- [X] T091 Run quickstart.md full validation in specs/001-multi-protocol-vpn/quickstart.md (scenarios 1–8 offline against stub peer as gating run; live egress supplementary nightly)
- [X] T092 [P] Document lawful-use + jurisdiction statements in crates/qcore-cli/src/help.rs (WARP lawful-use only; Psiphon authorized integration; Tor no legal-protection claims; no jurisdiction-tuned evasion defaults)
- [X] T093 [P] Implement throwaway-transport extensibility proof in tests/conformance/tests/extensibility.rs (new transport crate via register_plugin! passes the generated conformance macro; zero edits to engine, chain, CLI, or schemas; SC-002c)
- [X] T094 [P] Implement throughput benchmark harness in tests/conformance/tests/throughput.rs (single-hop throughput vs boringtun/direct baseline on x64, assert within ~15%; chain-setup timing assertion; plan Performance Goals)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately (T010 spike result feeds T040 but does not block T001–T009/T011–T013)
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories (T014 API → T017 registry → T018–T022 chain/config/net; T027 redaction before any transport work; T030 stub peer before any conformance test; T033 matrix only after T017 registry exists)
- **User Stories (Phases 3–7)**: All depend on Foundational completion
  - US1 (P1) first — transports must exist before chains/imports/scans/obfuscation use them
  - US3 (P1) after US1 — ordering logic rides on working single hops; relay adapter (T052) only here; validator (T020) recognizes relay from registry descriptors so no build-order inversion
  - US2 (P2) after US1 — import modes extend the wireguard transport from T039
  - US4 (P3) after Foundational — scanner independent of US2/US3 but sequenced after P1 stories for MVP focus; T068 scan-cache wiring feeds the US1 reconnect sink (T048)
  - US5 (P3) after US1/US2 — AWG application extends T039/T063 wireguard modes; noize data applied by T040's transport
- **Polish (Phase 8)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational — no dependencies on other stories; owns cold start (T048) so MVP needs no P3 task
- **User Story 3 (P1)**: Needs US1 transports present — otherwise independently testable via chain matrix
- **User Story 2 (P2)**: Needs US1 wireguard transport — import/round-trip testable independently once present
- **User Story 4 (P3)**: Needs Foundational only — scanner + profiles independently testable
- **User Story 5 (P3)**: Needs US1 (noize) + US2 (AWG modes) — compatibility gate independently testable

### Within Each User Story

- Tests MUST be written and FAIL before implementation (T034–T038 before T039–T049; T050–T051 before T052–T058; etc.)
- Transports/modes before engine wiring; engine wiring before CLI; CLI before report polish
- Story complete (checkpoint green) before moving to next priority

### Parallel Opportunities

- Phase 1: T003–T010 + T012–T013 all parallel (different files)
- Phase 2: T015/T016/T030/T031/T032 parallel with the T014→T017 chain; T033 parallel with T030–T032 once T017 lands
- US1: T034–T038 tests parallel; T039–T042 implementations parallel (separate transport crates)
- US3: T050/T051 parallel; T052/T053/T055 parallel (separate crates/files)
- US2: T059/T060 parallel
- US4/US5: data + test tasks (T065/T067, T069–T072) parallel with implementations
- Polish: T075/T076/T079/T080/T084/T085/T087/T088/T090/T092/T093/T094 parallel (different files)

---

## Parallel Example: User Story 1

```bash
# Launch all US1 acceptance tests together (fail-first):
Task: "Dual-stack test wireguard in tests/conformance/tests/wireguard.rs"
Task: "Dual-stack test masque in tests/conformance/tests/masque.rs"
Task: "Dual-stack test tor+psiphon in tests/conformance/tests/tor_psiphon.rs"
Task: "Failure-report test in tests/conformance/tests/failure_report.rs"
Task: "Single-stack test in tests/conformance/tests/single_stack.rs"

# Launch all US1 transport implementations together (separate crates):
Task: "Wireguard transport in crates/qcore-transports/transport-wireguard/src/lib.rs"
Task: "Masque transport in crates/qcore-transports/transport-masque/src/lib.rs"
Task: "Tor transport in crates/qcore-transports/transport-tor/src/lib.rs"
Task: "Psiphon supervisor in crates/qcore-transports/transport-psiphon/src/supervisor.rs"
```

## Parallel Example: User Story 3

```bash
# Chain matrix + rejection tests together:
Task: "Chain orderings in tests/chains/tests/orderings.rs"
Task: "Invalid-chain rejections in tests/chains/tests/rejections.rs"

# Relay adapter + presets + chain TOML together (different files):
Task: "Relay adapter in crates/qcore-transports/transport-relay/src/lib.rs"
Task: "Presets in profiles/compositions.toml"
Task: "Chain TOML parsing in crates/qcore-core/src/config/chain_file.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001–T013, incl. Aether base record + TLS spike decision + targets single source)
2. Complete Phase 2: Foundational (T014–T033 — plugin boundary, validator, DNS/family policy, stub peer)
3. Complete Phase 3: US1 single-transport connect (T034–T049, incl. cold start T048 on default discovery; full scan-cache lands in US4 T068)
4. **STOP and VALIDATE**: `qcore up` zero-config → connected in <2 min; `qcore up --chain "wireguard peer=warp" --family dual --json` → healthy tunnel both families; repeat per transport; `cargo xtask ci` green on native host
5. Deploy/demo if ready — ported base works end-to-end before any chaining

### Incremental Delivery

1. Setup + Foundational → foundation ready (validator total, stub peer deterministic)
2. Add US1 → test independently → Demo (MVP: every transport connects standalone dual-stack + single-stack, cold start without file edits)
3. Add US3 → test independently → Demo (differentiator: arbitrary bidirectional chains + fail-closed validation)
4. Add US2 → test independently → Demo (user-owned WG/AWG configs as chainable hops)
5. Add US4 → test independently → Demo (scanning feeds reconnects, balanced < 30 s for ≥90%)
6. Add US5 → test independently → Demo (obfuscation as data, incompatibility rejected)
7. Polish → release integrity (signed artifacts, SBOM, per-target smoke from single target source, secret-hygiene proof, CLI↔API parity)
8. Each story adds value without breaking previous stories (regression: conformance + chain matrices stay green)

### Parallel Team Strategy

With multiple developers (after Foundational):

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 transports (T039–T044) + US5 obfuscation (T070–T071)
   - Developer B: US3 chains (T052–T058) + US2 import (T061–T063)
   - Developer C: US4 scanner (T066–T068) + Polish FFI/embed (T075–T081)
3. Stories complete and integrate independently; chain + conformance matrices arbitrate conflicts

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability (spec US numbers kept; phases ordered by priority P1→P2→P3)
- Each user story independently completable and testable (checkpoints list exact CLI proofs from quickstart.md)
- Data-model constraints quoted verbatim in task text (e.g. "jmax < MTU", "non-overlapping", "expand exactly one level", "never promoted", "only psiphon")
- Contracts coverage: cli.md → T029/T045–T047/T056–T057/T064/T068/T073/T082–T083; public-api.md → T021/T026/T043/T061–T062/T066; c-abi.md → T075–T079; config-formats.md → T019/T053–T055/T061/T067/T072
- Constitution gates honored: plugin boundary (I), stub-peer dual-stack matrix (II), declarative chains + pre-start validation (III), typed configs + central redaction (IV), data profiles + machine-readable reports (V), caller-level contract tests (VI), sidecar trust boundary, release integrity, independent versioning, secret-scan scope
- Audit adjudications (reviewer flags resolved against stronger sources):
- 5. SC-002c enablement (T093): the pre-existing typed `HopConfig` enum plus
- per-kind field tables in the grammar/preset/chain-file gates meant a new
- transport required schema edits, contradicting SC-002c. Fixed once at the
- framework level — generic `HopConfig::Plugin` variant (opaque
- family+fields, factory-validated at build), registry-driven fallback in
- all four authoring gates, manual `{"kind", ...fields}` serde preserving
- the wire shape. Adding a transport is again its own crate + one feature
- line; the throwaway proof in `extensibility.rs` touches no engine, chain,
- CLI, or schema files.
  1. masque-aggressive/awg-aggressive live as data entries per spec.md Obfuscation Design profile set; config-formats "shipped set" of three = defaults. Fixed violation was profiles-as-code (T070–T072 now data-applied).
  2. quickstart `--import <file>` on connect has no cli.md flag; canonical form is the cli-reference token option `wireguard peer=awg import=<ref>` (T073) — no new flag invented.
  3. Validator/relay build order: T020 recognizes relay from registry descriptors (data-driven), so T052 can stay in US3 with no inversion.
  4. Network policy consolidated under listed `session/` module (session/net.rs); ABI Go harness under `examples/` per embed-host precedent since plan tests/ enumerates only conformance/chains/fixtures.
- Commit after each task or logical group; stop at any checkpoint to validate story independently
- Avoid: vague tasks, same-file conflicts, cross-story dependencies that break independence
