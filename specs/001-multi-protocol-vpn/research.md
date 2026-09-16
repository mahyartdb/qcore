# Phase 0 Research: Multi-Protocol Tunnel Client

Consolidates the subagent research used to resolve Technical Context. Format:
Decision / Rationale / Alternatives considered.

## R1. Base and language

- **Decision**: Fork Aether (Rust) and remain entirely Rust for the runtime core and
  transports.
- **Rationale**: Aether already implements WireGuard, MASQUE h3/h2, GOOL, MIM, Tor
  (arti), scanning, and noize obfuscation in Rust with a C ABI — the exact base the
  spec requires. Rust gives memory safety and FFI-friendly `cdylib` outputs.
- **Alternatives**: Go (whole circumvention ecosystem is Go; fastest to ship, but
  the user explicitly requires a Rust core). Rust-from-scratch (re-implements what
  Aether already has). C++ (slower, less safe).

## R2. Transport abstraction (the core refactor)

- **Decision**: Replace Aether's hardcoded gool/mim/tor/upstream branches with a
  plugin boundary in a dedicated `qcore-transport-api` crate:
  - `TransportDescriptor` — static capability data known before instantiation
  - `Dialer` — async TCP/UDP egress handed to the next hop
  - `RunningHop` — built hop handle, health, event stream, stop
  - `HopFactory` — the plugin entry point; builds a hop with a carrier dialer
  Hops self-register via `inventory` into a `TransportRegistry`; the engine reads
  descriptors from the registry and never matches on a kind.
- **Rationale**: Aether bakes ordering into `lib.rs`, which cannot express both
  "Tor before WARP" and "WARP before Tor". Abstract async egress lets a
  `smoltcp`-backed inner hop carry the next hop, which a concrete OS socket cannot.
  Pre-start capability descriptors let invalid chains fail with zero side effects
  (FR-010/FR-027).
- **Alternatives**: the original `Hop` trait returning a concrete `TcpStream` with
  `&mut self` lifecycle (unimplementable nesting; forces locks); a full route graph
  (chains are linear); `dlopen` plugins (breaks Android/static-musl).
- **Constraint rules enforced at build time**: UDP-only-after-TCP-only rejected
  unless the registered `relay` adapter is present (the `tor-warp` preset includes
  it); port conflicts rejected (ephemeral `:0` for internal listeners); cycles
  rejected; depth = total hops after composition-preset expansion, default cap 3 and
  configurable to a hard limit; MTU shrinks and is reported per nested layer.

## R2a. GOOL/MIM are compositions, not transports

- **Decision**: `gool` = `wireguard,wireguard` (WARP peer) and `mim` =
  `masque,masque`, declared as composition presets that expand at parse time.
- **Rationale**: Modeling them as `TransportKind`s forces protocol knowledge into
  the chain validator (Principle I violation) and creates a "costs 2 layers" special
  case. After expansion, depth is plain hop counting: `gool` = 2, `gool,tor` = 3,
  `gool,gool` = 4 → rejected. FR-010a is satisfied with zero special cases.
- **Alternatives**: keep them as transport kinds with a layer-cost field (more
  code, protocol leak); hardcode the depth arithmetic in the validator (worse).

## R2c. Relay adapter (UDP-over-TCP)

- **Decision**: Ship a registered `relay` transport that provides UDP-over-TCP
  framing, and include it in the `tor-warp` preset. A bare `tor,wireguard peer=warp`
  chain is rejected with the required insertion named.
- **Rationale**: FR-008 requires Tor-in-WARP to be valid, but Tor is TCP-only and a
  UDP carrier hop cannot ride it. A relay adapter resolves the contradiction without
  special-casing the validator or adding per-transport CLI flags, and it keeps the
  capability discoverable in the registry.
- **Alternatives**: reject Tor-first and rewrite FR-008 (drops a required ordering);
  hardcode Tor-first to auto-insert a relay (hidden magic, violates declarative
  chains).

## R2b. One WireGuard kind, one MASQUE kind

- **Decision**: `wireguard` serves WARP (Cloudflare peer preset), imported configs,
  and AmneziaWG (obfuscation decorator over the same data plane). `masque` serves
  h2 and h3 via an ALPN option.
- **Rationale**: WARP and AmneziaWG are modes of one data plane, not separate
  implementations; h2 exists as the UDP-over-TCP fallback after Tor, so it is a
  mode. Cuts transport implementations from 9 to 4 (wireguard, masque, tor, psiphon).
- **Alternatives**: separate implementations per mode (duplicated data-plane wiring,
  MTU paths, and test harnesses).

## R3. WireGuard implementation

- **Decision**: `boringtun` for the Rust WireGuard data plane; build the AmneziaWG
  obfuscation layer over it.
- **Rationale**: Pure Rust, supports `armv7-unknown-linux-gnueabihf`,
  `aarch64-linux-android`, `arm-linux-androideabi`; 0.7.1 added `portable-atomic`
  and a 64-bit nonce counter for 32-bit targets.
- **Alternatives**: wireguard-go (non-Rust, excluded by FR-001); wireguard-rs
  (less maintained); kernel modules (not portable, privileged).

## R4. MASQUE / QUIC

- **Decision**: Run a **timeboxed spike** (2–3 days) building MASQUE on the two
  highest-risk targets (`i686-pc-windows-msvc`, `armv7-linux-androideabi`). If
  `quiche`/BoringSSL builds and passes there, `quiche` is the single provider. If
  not, standardize the whole project on `quinn` + `rustls`/`ring` + `h2`. **Commit
  to exactly one provider; do not ship two.**
- **Rationale**: The original plan carried two TLS stacks and a "pre-decided
  fallback", which doubles the crypto test surface across 9 targets. A single
  provider makes the cross-build matrix uniform.
 - **Alternatives**: `quiche` only (matches Aether; risks the 32-bit builds);
   `quinn` only on day one (pure Rust, cross-builds cleanly, but h3/MASQUE maturity
   is lower — hence the spike rather than an unconditional switch); `msquic` (C,
   non-Rust).

## R4 outcome (implementation spike, T010)

- **Decision**: `quinn` + `rustls`/`ring` + `h2` is the single provider.
- **Rationale**: `quiche` pulls a BoringSSL native build (cmake + perl + nasm)
  that fails on `i686-pc-windows-msvc` and complicates the Android NDK and
  static-musl targets — the exact highest-risk targets the spike named. `quinn`
  is pure Rust and builds on all 9 targets including 32-bit Windows and
  `armv7-linux-androideabi`. One provider ships per R4.
- **Re-verification**: if `quiche` gains hermetic prebuilt BoringSSL for all 9
  targets, re-run the spike; the transport boundary (`transport-masque`)
  isolates the provider behind the `masque` ALPN modes.

## R5. Tor

- **Decision**: Reuse Aether's `arti-client` integration as a Hop, supporting
  before/after placement.
- **Rationale**: Already Rust, already feature-gated in Aether; linear chains mean
  `--tor` (Tor dials through the previous hop) maps directly onto the chain builder,
  and reverse placement (next hop dials through Tor's SOCKS) is the same builder
  reversed.
- **Constraint**: Tor is TCP-only; a UDP-only hop after Tor requires the existing
  HTTP/2 fallback (Aether already forces H2 for `--tor-reverse`).

## R6. Psiphon / Cfon

- **Decision**: Integrate Psiphon as a **sidecar hop** — a Psiphon client process
  exposing a local SOCKS proxy that the Rust core dials, wired into the chain like
  any other hop. Borrow the integration shape from Oblivion/warp-plus.
- **Rationale**: No Rust Psiphon library exists. This is the only approach that keeps
  the Rust core free of a non-Rust tunnel engine while still supporting Psiphon.
  warp-plus proves the ordering: bring up the carrier's SOCKS first, then hand it to
  Psiphon as `UpstreamProxyURL` so Psiphon is the exit. The chain builder expresses
  both orders generically.
- **Alternatives**: Port Psiphon to Rust (user rejected — option B). Go-FFI shim
  (user chose sidecar over FFI).
- **Follow-up**: define sidecar lifecycle (spawn, health, port handshake, teardown)
  in the psiphon transport.

## R7. Obfuscation

- **Decision**: Support both mechanisms, selected per transport.
  - noize (Aether, already Rust) for MASQUE and WARP/GOOL hops: pre-handshake junk
    train + obfuscated CPS packets.
  - AmneziaWG parameter sets (ported from the Go implementation) for WireGuard-family
    hops against a supporting peer: Jc/Jmin/Jmax, S1–S4, H1–H4, I1–I5, header
    protection, content padding, random trailers, disabled cookies, randomized
    timing.
  - Defaults: `masque-balanced`, `awg-balanced`, `awg-off`.
- **Rationale**: They defend different layers. noize is only a pre-handshake
  smokescreen and leaves standard WireGuard transport fingerprints; AmneziaWG
  reshapes every packet class and is materially stronger — but its S1–S4/H1–H4/
  header protection are server-negotiated and MUST NOT be applied to Cloudflare's
  plain WireGuard edge. Keeping both covers both cases.
- **Alternatives**: noize-only (weak against stateful WG fingerprinting);
  AmneziaWG-only (inapplicable to WARP's real edge).
- **Risk flagged**: AmneziaWG effectiveness is largely vendor-reported; the port's
  tests MUST measure against a controlled peer.

## R8. C ABI and embedding

- **Decision**: Core crate is `rlib`; a separate `ffi` crate builds `cdylib` +
  `staticlib` with a `cbindgen`-generated C header and JNI bindings for Android. The
  public API is versioned with a documented compatibility policy.
- **Rationale**: Rust hosts link the crate; Go hosts (Xray/sing-box-style) link the
  C ABI via cgo. Android uses C ABI/JNI because a non-Termux app cannot exec a CLI.
- **Alternatives**: crate-only (user chose C ABI); a local gRPC/JSON control socket
  (user chose ABI).

## R9. Cross-target build and CI

- **Decision**: A `cargo xtask` lever (build|smoke|package|release|abi-diff) that CI
  is a thin shell over, so a reviewer can rerun the exact steps. Build matrix:
  native MSVC runners for Windows x86/x64/ARM64; `cross-rs` for Linux
  x86/x64/ARM/ARM64; `cargo-ndk` for Android; `cargo-zigbuild` for static musl.
  Each target gets a deterministic offline smoke test (SC-002a).
- **Rationale**: Windows MSVC cannot be cross-built by cross-rs, so native runners
  are required. Android and Linux ARM are cleanest under cross-rs/cargo-ndk. The
  lever makes the release contract reproducible.
- **Alternatives**: YAML-only matrix (not locally rerunnable); `cargo-dist`
  (strong for desktop, weak for Android `.so`/Termux).

## R9a. Release pipeline (decided)

- **Decision**: Single workspace semver version plus three independently versioned
  surfaces (`API_VERSION`, `ABI_VERSION`, `SCHEMA_VERSION`). Artifacts named
  `qcore-<ver>-<target>` with release-level `SHA256SUMS`; cosign keyless signing;
  SLSA attestation per artifact; CycloneDX SBOM; reproducible release profile.
  Required gate is an **offline** dual-stack smoke test against the stub peer; real
  network egress is a nightly non-blocking tier. Release is blocked if any required
  target fails build or smoke.
- **Rationale**: R9 previously covered tooling only. FR-003f and the constitution's
  Release Integrity clause require an executable pipeline. Offline gating avoids
  flaky, rate-limited, emulator-impossible live tests.
- **Alternatives**: live-network smoke on every runner (flaky; Tor impossible on
  the Android emulator); unsigned releases (violates Release Integrity).

## R10. Testing strategy

- **Decision**: `cargo nextest` unit + contract tests; integration tests against the
  deterministic loopback **stub peer**; a **generated** dual-stack conformance
  matrix per registered transport (each plugin inherits it); property tests for
  config round-trip and chain validation; a per-target build+smoke matrix. Each
  ported capability (Cfon, AmneziaWG obfuscation, chain builder, scanner) ships its
  suite before being marked complete (FR-003).
- **Rationale**: Constitution Principle VI requires caller-level contract tests and
  a deterministic peer; generating the suite from the registry is the lever that
  gives every new transport coverage without new test code.
- **Alternatives**: hand-written per-transport tests (drift as transports are
  added); live-network tests only (flaky, not hermetic).

## R11. Secret handling

- **Decision**: Secrets parsed at the boundary, held in zeroizing wrappers, stored
  via OS keyring when available, redacted centrally in `diag` before any log/export/
  crash output; a secret-scan check is a required CI gate.
- **Rationale**: FR-026, SC-006, constitution Principle IV and the merge checks.
- **Alternatives**: ad-hoc redaction at call sites (leaks over time).

## R12. Version/date policy

- **Decision**: Pin one MSRV, pin dependency versions, publish build provenance, and
  version both the Rust API and the C ABI semantically.
- **Rationale**: FR-003f, constitution's development workflow (semver, changelog,
  provenance).
- **Alternatives**: floating versions (non-reproducible builds).

## R13. Address-family and DNS policy

- **Decision**: `dual` = Happy Eyeballs v2 (RFC 8305): AAAA query first with A
  immediately after, HTTP(S) resolution order, staggered connection attempts, 50 ms
  Resolution Delay, 250 ms Connection Attempt Delay (configurable 10 ms–2 s),
  preferred family default **IPv4** (configurable IPv6). DNS is routed through the
  tunnel chain or the client refuses to start; resolver transport prefers IPv6 with
  penalty-based fallback. Local synthesis only for IPv4 literals (RFC 7050 Pref64 /
  RFC 6052 embedding) and as the RFC 8305 2 s last resort; never synthesize AAAA
  when real AAAA answers exist. `AllowedIPs` is honored exactly, never auto-expanded.
- **Rationale**: This is what curl/Firefox/Chrome and sing-box do; it is the only
  defense against an IPv6-broken host black-holing a session, and against an
  IPv6 leak when only `0.0.0.0/0` is routed. DNS64/NAT64 translation is the
  resolver's duty (RFC 6147/6146), not the client's.
- **Alternatives**: strict family with manual fallback (fails on broken IPv6);
  IPv6-preferred default (chosen against by the user for safer v4-first behavior).

## R14. NAT behavior scope

- **Decision**: In scope: persistent keepalive (per-hop, default off, ~25 s
  advisory), endpoint roaming, MTU derivation with PMTUD (RFC 4821) and per-layer
  inner-MTU shrink. Out of scope for v1: STUN (RFC 5389), ICE (RFC 8445), TURN
  (RFC 8656), UDP hole punching, and inbound reachability.
- **Rationale**: The engine is outbound-only to a known/discovered server endpoint,
  so NAT is traversed by ordinary outbound state. WireGuard itself has no
  hole-punching and solves the outbound case with keepalive + roaming.
- **Alternatives**: Full ICE/STUN (unnecessary complexity for client→server); leaving
  the constitution's "NAT traversal" parity claim unqualified (overreach; corrected).

## R15. Release tiers

- **Decision**: Tier A (every PR): native host unit/contract, lint, secret scan,
  native stub-peer smoke. Tier B (nightly + main): broad cross matrix + stub-peer
  smoke (Linux gnu/musl/armv7, Windows ARM64, Android). Tier C (tag): every listed
  target built and smoked; publish blocked unless Tier C is fully green.
- **Rationale**: Mirrors rustc's tier model and ripgrep's matrix; keeps PRs cheap
  while guaranteeing 100% coverage before publish. Runner classes `ubuntu-*-arm` and
  `windows-11-arm` are generally available (re-verify against `actions/runner-images`).
- **Alternatives**: full matrix on every PR (slow); single-tier (either flaky or
  under-covering).

## R16. Emergency release and artifact lifecycle

- **Decision**: Authority = release manager + security maintainer. Mandatory even in
  an emergency: advisory, signing, secret scan, `cargo-audit`/`cargo-deny` clean,
  and a build+smoke on the affected platform. Deferrable: non-affected target smoke,
  docs, changelog polish. Fix on a `release/x.y` branch with a patch bump; never
  re-tag a published release; yank only a broken version, never to retract a secret.
- **Rationale**: Mirrors curl's out-of-band patch process and Rust's two-coordinator
  embargo model; crates.io yank does not delete code, so secrets must be rotated,
  not yanked.
- **Alternatives**: any-maintainer trigger with full gates (emergencies wait);
  undocumented (no policy).

## R17. Redaction and sidecar secrets

- **Decision**: Redaction is typed-field-first, then entropy + denylist. Unclassifiable
  values fail closed: drop the record, emit a placeholder with metadata only. Secrets
  are never passed to the sidecar in `argv`; prefer an inherited pipe/fd (stdin
  second, env only if the platform forces it), least-privilege and short-lived.
- **Rationale**: Name+entropy matching cannot prove a negative, so the safe default
  is to refuse to emit; OWASP says never log data unless sanctioned, and CWE-214
  covers `argv`/env exposure via `ps`.
- **Alternatives**: heuristic in-place masking (can leak); emit-with-warning (worst
  posture).

## R18. Resolved arena gaps

- Composition presets expand exactly one level; presets inside presets are a
  validation error.
- Depth is owned solely by the chain validator (counts expanded hops); transports
  and presets never declare depth.
- Single-hop chains and all-same-kind chains are explicitly valid subject to depth.
- Sidecar readiness/restart-cap exhaustion fails closed with a named cause.
- Android ships both a Termux CLI (smoke by emulator execution) and the cdylib/JNI
  library (smoke by exported-symbol verification).
- Uncertain scan results are labeled and never promoted to last-known-good.

## Resolved unknowns

All Technical Context items are concrete. No `NEEDS CLARIFICATION` remains.

The only implementation-time verification gate is R4's timeboxed TLS-provider
spike; its outcome is pre-decided (one provider, chosen by the spike result) so the
target matrix is never blocked.
