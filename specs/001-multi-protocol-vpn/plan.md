# Implementation Plan: Multi-Protocol Tunnel Client (Rust / Aether fork)

**Branch**: `001-multi-protocol-vpn` | **Date**: 2026-09-14 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-multi-protocol-vpn/spec.md`

**Refinement note**: This plan is the synthesized output of a three-candidate arena
(see [arena-synthesis.md](./arena-synthesis.md)). The base is the
functionality/extensibility candidate; the release pipeline and traceability matrix
are grafted from the release-engineering candidate; the deletion ledger, preflight,
and state file are grafted from the consolidation candidate.

## Summary

Build an embeddable, cross-platform Rust tunnel **engine core** plus a pure CLI that
composes WARP/WireGuard, MASQUE (h3/h2), MASQUE-in-MASQUE, WARP-in-WARP, Tor,
Psiphon (Cfon), and imported WireGuard/AmneziaWG configs into user-declared,
validated, arbitrarily ordered chains (before/after, nested), over IPv4 and IPv6.
Base is a fork of Aether (Rust). Cfon/Psiphon and AmneziaWG are ported in. The core
exposes a Rust crate and a C ABI (cdylib) for non-Rust hosts.

Three structural decisions drive everything:

1. **Transport plugin boundary.** A transport is a plugin behind a stable
   `qcore-transport-api` interface, self-registered into a registry. The engine,
   chain validator, CLI, ABI, and schemas are never edited to add a transport.
2. **GOOL and MIM are chain compositions, not transports.** They are presets that
   expand to `wireguard,wireguard` and `masque,masque`. Depth becomes plain hop
   counting; the "costs 2 layers" special case is deleted.
3. **Abstract async egress.** Hops expose an abstract `Dialer`, not a concrete OS
   socket, so a `smoltcp`-backed inner hop can carry the next hop. This is what makes
   arbitrary nesting actually implementable.

## Technical Context

**Language/Version**: Rust stable; one pinned MSRV in `rust-toolchain.toml`.

**Primary Dependencies**:
- Async runtime: `tokio`
- QUIC/H3/H2: `quiche` (primary, MASQUE) with a **timeboxed single-provider spike**;
  fallback is `quinn` + `rustls`/`ring` + `h2`. One provider ships.
- WireGuard data plane: `boringtun` (one implementation serving WARP, imported WG,
  and AmneziaWG modes)
- Userspace TCP/IP: `smoltcp` (inner-hop streams)
- Tor: `arti-client`
- TLS: `rustls` (`ring` provider) unless the quiche spike wins on all targets
- Plugin registration: `inventory` (pure Rust, no `ctor`, no target gaps)
- Serde/TOML/JSON; `cbindgen` for the C header; `jni` for the Android wrapper only

**Storage**: Local files under one config dir — `identity.toml`, `profiles.toml`
(`[scan.*]`, `[obfuscation.*]`, `[compositions.*]`), `endpoints.json`,
`session.json` (durable state), `logs/`. No database, no daemon.

**Testing**: `cargo nextest` (unit + contract); generated **dual-stack conformance
matrix** per registered transport; chain acceptance matrix; property tests for
config round-trip and chain validation; a deterministic loopback **stub peer**;
static + dynamic secret scanning; per-target build + smoke matrix.

**Target Platform**: Windows x86/x64/ARM64, Linux x86/x64/ARM/ARM64, Android
ARM/ARM64 (Termux CLI + C ABI/JNI). Windows 32-bit ARM excluded (EOL, no Rust
target).

**Project Type**: Rust workspace — plugin API crate, engine, transport meta-crate,
facade, CLI, FFI. Not a web/mobile app. No GUI.

**Performance Goals**:
- Balanced scan yields a traffic-validated endpoint < 30 s for ≥ 90% of scans
  (SC-005).
- Single-hop throughput within ~15% of the underlying transport baseline on x64.
- Chain setup (≤ 3 layers) completes within the connection timeout; no unbounded
  hops.
- Cold start to first connection attempt < 2 min without editing files (SC-003).

**Constraints**:
- Rust-only runtime except the Psiphon sidecar process (FR-001).
- Chain depth default 3 tunnel layers; over-depth chains rejected before start.
- Zero secrets in logs/exports/state/crash output (SC-006).
- Fail closed on unverifiable validation (FR-027).
- Rust API, C ABI, and config/report schemas versioned independently (FR-003f).
- The target list is a release contract; it does not shrink silently (SC-002a).

**Scale/Scope**: ~6 transport implementations, 3 scan profiles, 2 obfuscation
profile families, 9 build targets, one public Rust API, one stable C ABI, first
release single-user/single-device.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|---|---|---|
| I. Protocol-Agnostic Transport Core | PASS | The `qcore-transport-api` plugin boundary makes "plugin" literal; the engine reads descriptors from a registry and never matches on a kind. |
| II. Dual-Stack Parity (NON-NEGOTIABLE) | PASS (with spec amendment) | FR-012/013 plus a generated dual-stack conformance suite per transport. The arena surfaced a gap: Principle II names "resolver" and "NAT traversal" parity, which the spec does not require. Resolved by amending the constitution to match scope (see Constitution Amendments). |
| III. Composable, Declarative Chaining | PASS | Chains are validated data; composition presets expand before validation; capabilities are known pre-start, so invalid chains fail with zero side effects. |
| IV. Boundary Discipline and Secret Hygiene | PASS | Typed `HopConfig` replaces an untyped options map; import parsed at the boundary; redaction is central and dynamically tested. |
| V. Observable, Reproducible Behavior | PASS | Profiles are static data; push-based `HopEvent` stream and machine-readable report; scan non-determinism explicitly bounded per profile. |
| VI. Verified Protocol Behavior | PASS | The conformance matrix is **generated from the registry**, so every registered transport inherits its suite. The stub peer is a named deliverable. |
| Security: lawful use documented | PASS | Spec's Legal & Compliance section retained. |
| Security: dependencies pinned + provenance | PASS | `cargo-deny` + CycloneDX SBOM as required checks. |
| Security: vetted crypto only | PASS | rustls/ring or BoringSSL-via-quiche; boringtun; no custom crypto. |
| Security: config round-trip without lossy conversion | PASS | Property tests over the WG/AWG corpus. |
| Security: telemetry off by default | PASS | No telemetry designed in. |
| Workflow: PR-only + required checks | PASS (extended) | Added: ABI consumer test, cross-target build+smoke, semver check, SBOM/provenance, two-layer secret scan. |
| Workflow: complexity justified | PASS | Deletions outnumber additions; each kept abstraction names the requirement it serves. |
| Governance: `AGENTS.md` consistent | PASS (action) | `AGENTS.md` will be created in Phase 0 and hold build/test/release/target commands. |

**Gate result: PASS.** No violations requiring a complexity justification. The
constitution is amended (MINOR) to close the gaps the arena surfaced; see
Constitution Amendments.

**Post-Phase-1 re-check**: still PASS.

## Project Structure

### Documentation (this feature)

```text
specs/001-multi-protocol-vpn/
├── plan.md              # This file
├── arena-synthesis.md   # Arena record: base, grafts, rejections
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   ├── cli.md
│   ├── public-api.md
│   ├── c-abi.md
│   └── config-formats.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 (/speckit.tasks)
```

### Source Code (repository root)

```text
qcore/
├── Cargo.toml                    # [workspace]; resolver 2
├── rust-toolchain.toml           # pinned MSRV
├── denylist.toml                 # cargo-deny config
├── crates/
│   ├── qcore-transport-api/      # PUBLIC plugin boundary: traits, descriptors, errors, events
│   ├── qcore-core/               # engine facade, session supervisor, scanner, registry, chain validate, config, diag
│   │   └── src/
│   │       ├── api/              # Engine, Session, version constants
│   │       ├── registry.rs       # TransportRegistry built from inventory
│   │       ├── chain/            # ChainSpec, parse, validate, composition presets
│   │       ├── session/          # lifecycle, state file, reconnect, report, net policy
│   │       ├── scan/             # discovery, validation, ranking, profiles
│   │       ├── config/           # WG/AWG import/export, typed HopConfig, chain-file, profile-dir, secrets
│   │       └── diag/             # redaction, structured JSON, events
│   ├── qcore-transports/         # meta-crate: feature-gated builtin transports
│   │   ├── transport-wireguard/  # wg + AWG obfuscation decorator + WARP preset
│   │   ├── transport-masque/     # h3/h2 via ALPN
│   │   ├── transport-relay/      # UDP-over-TCP framing adapter
│   │   ├── transport-tor/        # arti
│   │   ├── transport-psiphon/    # Cfon sidecar supervisor (bounded)
│   │   └── transport-mock/       # conformance double + stub-peer harness
│   ├── qcore/                    # thin facade crate re-exported for embedders
│   ├── qcore-cli/                # thin CLI binary (cmd/ per command)
│   └── qcore-ffi/                # cdylib + cbindgen qcore.h + JNI wrapper
├── examples/embed-host/          # Rust host proving SC-002b with public types only
├── profiles/                     # scan/obfuscation/compositions data + schema versions
├── tests/
│   ├── conformance/              # generated dual-stack matrix per registered transport
│   ├── chains/                   # composition acceptance matrix
│   ── fixtures/                 # WG/AWG config corpus
├── xtask/                        # the release lever: build|smoke|package|release|abi-diff
└── .github/workflows/
    ├── ci.yml                    # PR gates
    ├── release.yml               # tag -> build -> smoke -> sign -> publish
    └── nightly.yml               # real-egress, non-blocking
```

**Structure Decision**: Six crates — the smallest set that keeps the plugin boundary
honest (`qcore-transport-api` must not transitively pull in the engine) without the
over-split of a crate per concept. The CLI and FFI are thin adapters; the facade
crate gives embedders one stable import path.

## The Transport Interface (the core refactor)

Replaces the defective `Hop` trait (concrete OS sockets, `&mut self` lifecycle,
capability hidden in return values).

```rust
// crate: qcore-transport-api — depends on tokio + tokio-util only.

pub struct TransportDescriptor {
    pub kind: &'static str,                    // "wireguard", "masque", "tor", "psiphon"
    pub capabilities: Capabilities,            // known WITHOUT building an instance
    pub obfuscation_families: &'static [ObfuscationFamily],
    pub config_schema: &'static str,
    pub needs_sidecar: bool,                   // only psiphon
}

pub struct Capabilities {
    pub accepts_tcp_carrier: bool,
    pub accepts_udp_carrier: bool,
    pub dials_tcp: bool,
    pub dials_udp: bool,     // false => a later UDP hop needs the relay
}

pub trait Dialer: Send + Sync {            // what hop n+1 receives
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError>;
    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError>;
    fn capabilities(&self) -> Capabilities;
}

pub trait RunningHop: Send + Sync {
    fn descriptor(&self) -> &'static TransportDescriptor;
    fn dialer(&self) -> Arc<dyn Dialer>;
    fn health(&self) -> HopHealth;
    fn events(&self) -> broadcast::Receiver<HopEvent>;
    async fn stop(&self) -> Result<(), HopError>;
}

pub trait HopFactory: Send + Sync {        // the plugin boundary
    fn descriptor(&self) -> &'static TransportDescriptor;
    async fn build(&self, cfg: HopConfig, carrier: Arc<dyn Dialer>)
        -> Result<Arc<dyn RunningHop>, HopError>;
}
```

`ByteStream`/`UdpFlow` are abstract (async read/write, datagram send/recv), so an
inner hop can return a `smoltcp`-backed stream with no OS socket. Capabilities are
descriptor data, so the validator rejects impossible chains **before any hop
starts**. Three public traits, not a framework.

### Plugin registration

Transport crates depend only on `qcore-transport-api` and call
`register_plugin!(WireguardPlugin)`, collected via `inventory` into a
`TransportRegistry`. Validation, the scanner, `profiles`, help text, and the
conformance matrix all read from the registry — never from a `match kind`.

Adding a transport: one crate, one `HopFactory` impl, one feature line, run the
conformance macro. Zero edits to engine, chain, CLI, ABI, or schemas.

### Composition presets (replaces GOOL/MIM transports)

```toml
[compositions.gool]  hops = [{ kind = "wireguard", peer = "warp" }, { kind = "wireguard", peer = "warp" }]
[compositions.mim]   hops = [{ kind = "masque",    alpn = "h3"    }, { kind = "masque",    alpn = "h3"    }]
```

Expanded at parse time, so `gool` = 2 hops, `gool,gool` = 4 → over cap, `gool,tor`
= 3 → allowed. Depth is `hops.len()` after expansion. No layer-cost field, no
special case.

## Complexity Tracking

> No constitution violations. Section intentionally empty.

The arena's net effect is deletion, not addition: 9 transport kinds → 4
(`wireguard`, `masque`, `tor`, `psiphon`) plus presets/modes; one optional relay
rather than per-transport framing; one TLS provider rather than two.

## Phase 0: Research

Consolidated in [research.md](./research.md). Unknowns resolved there, plus the
arena's open items:
- R4 amended: single TLS provider via a **timeboxed spike** with a pre-decided
  fallback.
- R9 expanded into a decided release pipeline.

## Phase 1: Design & Contracts

- [data-model.md](./data-model.md) — registry descriptors, `HopConfig`, `ChainSpec`,
  `ConfigImport`, profiles, `EndpointCandidate`, `Session`, `ConnectionReport`.
- contracts/: [cli.md](./contracts/cli.md), [public-api.md](./contracts/public-api.md),
  [c-abi.md](./contracts/c-abi.md), [config-formats.md](./contracts/config-formats.md).
- [quickstart.md](./quickstart.md) — deterministic validation scenarios (offline
  stub peer for the gating run).

## Release Pipeline (decided)

R9 previously decided build *tooling* only. This decides versioning, naming,
signing, provenance, and the flow.

### Versioning

- Single workspace version `X.Y.Z` (semver) for crate, CLI, and cdylib.
- Three independently versioned surfaces, all surfaced in `--json`:
  `API_VERSION`, `ABI_VERSION` (`qcore_abi_version()`), `SCHEMA_VERSION`.
- Compatibility policy (FR-003f): C ABI break → major bump + one minor of
  deprecation retaining the old symbol; Rust API break → semver major; config or
  report schema break → `SCHEMA_VERSION` bump + changelog migration note.
- Conventional commits → `release-plz`/`git-cliff` changelog; tag `vX.Y.Z` on
  protected `main`.

### Build matrix

| Runner | Targets | Artifacts |
|---|---|---|
| `windows-2022` | `i686-pc-windows-msvc`, `x86_64-pc-windows-msvc` | CLI `.zip`, `.dll` |
| `windows-11-arm` | `aarch64-pc-windows-msvc` | CLI `.zip`, `.dll` |
| `ubuntu-22.04` + `cross` | `x86_64`/`i686`/`aarch64`/`armv7` linux (gnu; musl libc variant future — see `xtask/src/targets.toml:1-4`) | CLI `.tar.gz`, `.so` |
| `ubuntu-22.04` + `cargo-ndk` | `aarch64-linux-android`, `armv7-linux-androideabi` | Termux CLI + `libqcore.so` |

With a single TLS provider there are no per-target crypto exceptions.

### Naming, provenance, gates

```text
qcore-<ver>-<target>.zip|.tar.gz          # CLI
libqcore-<ver>-<target>.so | qcore-<ver>-<target>.dll
qcore.h, abi-version.txt                   # from the same ffi build
SHA256SUMS (+ .sig), sbom.cdx.json, provenance.intoto.jsonl
```

- **Smoke gate (deterministic, offline)**: `qcore version --json`, then connect
  through the engine to the in-process stub peer over `ipv4`, `ipv6`, `dual`.
  Real-network egress (WARP/MASQUE/Tor/Psiphon) runs **nightly, non-blocking** —
  connecting to Cloudflare/Tor from every runner is flaky and impossible on the
  Android emulator.
- **Signing**: cosign keyless (Sigstore). Windows Authenticode deferred and
  documented, not silently omitted.
- **Provenance**: SLSA attestation per artifact + CycloneDX SBOM.
- **Reproducibility**: pinned toolchain, `--locked`, `SOURCE_DATE_EPOCH`,
  `--remap-path-prefix`, release profile.
- **Secret scan, two layers**: static (`gitleaks`/`trufflehog`) + a dynamic
  capture test that runs at `trace` level and asserts clean captured output.
- **Release is blocked** if any required target fails build or smoke.

### Flow

```text
PR  -> ci.yml: fmt, clippy -D warnings, nextest, conformance matrix,
     chain matrix, ABI consumer test (Rust+C+Go), secret scan, cargo-deny,
     cargo-semver-checks, qcore.h diff
main -> tag vX.Y.Z -> release.yml: matrix build -> per-target smoke ->
     package -> checksums -> cosign + attest + SBOM -> GitHub Release + cargo publish
     (blocked on any required-target failure)
nightly -> real-egress dual-stack + legacy-target best-effort (non-blocking)
```

## Arena Gap Resolutions (applied)

The four exhaustive checklists surfaced 10 requirements-quality gaps. All are now
resolved in spec/plan/research/data-model/constitution.

| # | Gap | Resolution | Where |
|---|---|---|---|
| 1 | DNS/resolver family policy unspecified; "dual" ambiguous | `dual` = RFC 8305 Happy Eyeballs v2, IPv4-preferred default, 250 ms/50 ms delays; DNS routed through tunnel or refuse to start; synthesis only for v4 literals + 2 s last resort | FR-013a/013c, R13 |
| 2 | Constitution names NAT traversal; spec silent | Principle II narrowed to socket setup, endpoint resolution, routing/AllowedIPs, resolver transport, MTU; STUN/ICE/TURN/hole-punching explicitly out of scope | constitution II, FR-013d, R14 |
| 3 | Preset recursion undefined | Presets expand exactly one level; nested preset is a validation error naming both | FR-007a, R18 |
| 4 | Depth-validation ownership ambiguous | Owned solely by the chain validator; transports/presets never declare depth | FR-010a, R18 |
| 5 | Single-hop and all-same-kind chains unaddressed | Both explicitly valid subject to depth | FR-007, R18 |
| 6 | Sidecar startup failure / restart exhaustion unaddressed | Bounded supervisor; readiness handshake, capped restarts, fail closed with named cause; secrets via pipe/fd never `argv` | FR-001a/001b, SidecarSupervisor |
| 7 | Redaction behavior for unrecognized secret format undefined | Typed-first then entropy+denylist; fail closed with placeholder | FR-026a/026b, constitution Secret classification |
| 8 | Required vs best-effort target tiers undefined | Tier A per-PR, Tier B nightly, Tier C pre-release; publish blocked until all targets built+smoked | SC-002a, Release Tiers, R15 |
| 9 | Emergency/security-fix release path undefined | Two-role authority; mandatory advisory/signing/secret-scan/audit/affected-platform smoke; patch on `release/x.y`; yank only broken versions | Emergency Release Path, R16 |
| 10 | Android delivery/smoke ambiguity | Both Termux CLI (emulator-executed smoke) and cdylib/JNI (exported-symbol smoke) | FR-003e, Assumptions, constitution Platform delivery |

Two additional robustness clauses were added from the research: uncertain
scan results are labeled and never promoted to last-known-good (constitution
Confidence reporting), and an advisory-affects-mid-release rule during Tier C.

## Spec Amendments Required by the Refinement

Apply before `/speckit.tasks` so the spec and plan do not disagree.

| Requirement | Change | Why |
|---|---|---|
| FR-004 | MIM/GOOL are chain presets over existing transports, not separate transports; transports are `wireguard`, `masque`, `tor`, `psiphon`. | Consolidation; removes the protocol leak into the validator. |
| FR-010a | Delete the "GOOL/MIM cost 2 layers" special case; depth = hops after preset expansion. | Same, and it falls out of plain depth math. |
| FR-020/FR-021 | AmneziaWG is a WireGuard **mode** (obfuscation decorator), not a transport. | One data plane. |
| FR-003d | Android embedding is a **JNI wrapper over the C ABI**, not a parallel surface. | Removes an Android-only code path in the core. |
| FR-006 | Every transport is registered as a plugin; adding one MUST NOT require engine edits. | Makes Principle I/III testable. |
| FR-015 | Exactly 3 scan profiles (`turbo`, `balanced`, `stealth`). | Minimum that meets "differ in thoroughness, speed, stealth". |
| FR-004/010 | Added a registered `relay` adapter (UDP-over-TCP). Bare TCP-only-then-UDP chains are rejected with the insertion named; `tor-warp` preset includes it, resolving the FR-008 vs Edge-Case contradiction. | FR-008 requires Tor-in-WARP to be valid; the Edge Case forbade it. |

## Constitution Amendments (MINOR → v1.1.0)

The arena found the constitution solid in intent with real delivery/trust gaps. See
the amended `.specify/memory/constitution.md`:

1. **Principle I** extended: a transport is an in-process plugin *or* a
   managed child process exposing a local proxy; both satisfy one interface.
2. **Sidecar trust boundary** clause (Security): pinned executable path, minimal
   env, readiness handshake, kill-on-drop, restart cap.
3. **Release Integrity** clause (Workflow): signed artifacts, SLSA provenance,
   CycloneDX SBOM, and no release if any required target fails its smoke test.
4. **Versioning** clause: Rust API, C ABI, and config/report schemas version
   independently, with a deprecation window.
5. **Platform Parity & Target List** clause: the target list is the release
   contract and changes only by amendment.
6. **Dual-stack harness** requirement: a deterministic stub peer and a per-target
   family-capability check are required to satisfy Principle II.
7. **Consolidation bias** (Development Workflow): a new crate, module, or trait must
   name the existing structure it could have extended and why it did not.
8. **Bounded non-determinism** clarified for scanning under Principle V.
9. Principle II wording aligned to actual scope (remove "NAT traversal" parity claim
   unless a requirement is added).
10. Secret-scan scope and `AGENTS.md` obligation made actionable.