# Feature Specification: Multi-Protocol Tunnel Client (Rust / Aether fork)

**Feature Branch**: `001-multi-protocol-vpn`

**Created**: 2026-09-14

**Status**: Draft

**Input**: User description: "i want rust. core completley should be rust. we port everything and test them each extensivley after porting. as we stand we need too fork aether and add cfon to it + the capability to chain other wireguard configs using warp. i also want to be able to chain warp and masque and psiphon and tor both before and after too for example tor in warp and warp in tor or warp first then exit with psiphon or psiphon first exit with warp. etc. 1 thing im not sure is whats the best obfescation? noize profiles of aether or amnezia values? also mim is maque in masque yes. psiphon is not blocked for me i have premision no need to mention psiphon blocked in specs and plans just say borrow from oblivion integrate into aether."

## Glossary

Kind names are lowercase throughout the plan and tasks. `Cfon` = the Psiphon sidecar
transport, kind `psiphon`. `GOOL` = preset `gool` = two `wireguard peer=warp` hops
(WARP-in-WARP). `MIM` = preset `mim` = two `masque alpn=h3` hops (MASQUE-in-MASQUE).

## Decisions Locked

- **Rust, all the way.** The core and every transport are Rust. No Go, C++, or C in
  the shipped runtime. One narrow exception: the Psiphon/Cfon hop is an external
  sidecar client the Rust core dials (see Clarifications).
- **Fork Aether as the base.** `CluvexStudio/Aether` (Rust) is the
  starting point, not just a reference.
- **Port everything, then test each ported transport extensively.** Each capability
  added by porting gets its own dual-stack test suite before it is considered done.
- **Add Cfon (Psiphon) to the fork**, borrowed from the Oblivion / warp-plus
  approach and integrated into Aether's transport model.
- **Chain other WireGuard configs through WARP** — arbitrary WireGuard-family
  configs become chainable hops.
- **Arbitrary ordering, both directions.** Any of WARP, MASQUE, Psiphon, Tor, and
  imported WireGuard/AmneziaWG configs can sit before or after each other:
  Tor-in-WARP, WARP-in-Tor, WARP then exit via Psiphon, Psiphon then exit via WARP,
  and deeper nesting.
- **MIM = MASQUE-in-MASQUE**, confirmed.
- **Relay-adapter model**: UDP-in-TCP is supported by a registered `relay` adapter
  hop. A bare TCP-only-then-UDP chain is rejected with the insertion named; the
  shipped `tor-warp` preset already includes the relay, so Tor-first chains are
  valid (resolves the FR-008 vs Edge-Case conflict).
- **Obfuscation: support both** Aether's noize profiles and AmneziaWG parameter
  sets, selected per transport (rationale in "Obfuscation Design" below).
- **Psiphon is authorized for this project**; it is treated as a first-class
  transport to integrate, not a downstream legal caveat.
- **This is an engine core, not an app.** It ships as a reusable core plus a pure
  CLI. No GUI. The core MUST be embeddable by other applications (for example an
  Aether-style client, Xray-style proxy, or sing-box-style router host).

## Clarifications

### Session 2026-09-14

- Q: How should the Psiphon hop be implemented given there is no Rust Psiphon library and the spec forbids running non-Rust tunnel engines? → A: Treat the Psiphon client as an external hop process exposing a local proxy; the Rust core dials it. Relax FR-001 to allow this one sidecar.
- Q: What interface should the first release ship: CLI, desktop GUI, or both? → A: Pure CLI over an embeddable engine core. No GUI. The core must be consumable by other apps (Aether, Xray, sing-box-like hosts).
- Q: What embedding surface should the engine expose so other apps (including Go hosts like Xray/sing-box) can use it? → A: Rust crate + C ABI (cdylib): Rust hosts link directly, Go/C hosts link via cgo/FFI.
- Q: Which platforms/architectures must the CLI support? → A: All of Windows x86/x64/ARM64, Linux (x86/x64/ARM/ARM64), and Android (ARM/ARM64). Windows 32-bit ARM is dropped (end-of-life, no usable Rust target). Android CLI runs in Termux as an Android-target or static-musl binary; in-app embedding uses the C ABI/JNI.
- Q: What is the maximum chain nesting depth? → A: 3 tunnel layers. GOOL and MIM each consume 2 layers because they are themselves tunnel-in-tunnel; so GOOL alone leaves room for one more hop, and GOOL-in-GOOL or GOOL+MIM (4 layers) is rejected. *(Superseded by the preset model in the next answer and FR-010a: depth is counted in hops after preset expansion; no layer-cost field exists.)*
- Q: How are GOOL, MIM, and the WireGuard family modeled after plan refinement? → A: GOOL and MIM are chain composition presets (`wireguard,wireguard` / `masque,masque`), not transports. Transport kinds are `wireguard` (WARP, imported, AmneziaWG modes), `masque` (h2/h3 via ALPN), `tor`, `psiphon`. Depth is plain hop counting after preset expansion; the "costs 2 layers" special case is removed.
- Q: How is the FR-008 (Tor-in-WARP must work) vs Edge-Case (Tor is TCP-only, so a UDP hop after it is rejected) contradiction resolved? → A: Add a first-class registered `relay` adapter hop (UDP-over-TCP framing). A bare `tor,wireguard` chain is rejected with the insertion named; the shipped `tor-warp` preset includes the relay, so Tor-first chains are valid.
- Q: What CLI shape was selected? → A: `connect`/`stop` canonical with `up`/`down` exact aliases; `--chain "<expr>"` (comma-separated, `key=value` per hop) canonical plus `--chain-file` TOML and a script-friendly repeated `--hop`; typed options with unknown keys failing closed; zero-config `qcore up`; generated chain shortcuts gated by six rules; durable `session.json` with `status` distinguishing dead vs unverifiable.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Connect on a single transport (Priority: P1)

A person runs the client, picks one transport (WARP, MASQUE-over-HTTP/3,
MASQUE-over-HTTP/2, standard WireGuard, an imported AmneziaWG config, Tor, or
Psiphon/Cfon), and connects. The client finds a working endpoint, brings the
tunnel up, and carries traffic over IPv4 and IPv6.

**Why this priority**: The ported base must work end-to-end before any chaining.

**Independent Test**: For each transport, connect on a host with both address
families, confirm a healthy tunnel and correct egress on IPv4 and IPv6, then
disconnect cleanly.

**Acceptance Scenarios**:

1. **Given** no prior configuration, **When** the user selects WARP and connects,
   **Then** the client finds a reachable endpoint and reports a healthy tunnel
   within 30 seconds (CONNECTION_TIMEOUT_SECONDS, default 30).
2. **Given** each supported transport, **When** it is selected and connected,
   **Then** it establishes independently with no other transport configured.
3. **Given** a connected session, **When** the user reaches IPv4 and IPv6
   destinations, **Then** both succeed through the tunnel.
4. **Given** an unreachable transport, **When** it fails, **Then** the client
   reports the transport name and an actionable cause.

---

### User Story 2 - Import and chain WireGuard-family configs through WARP (Priority: P2)

A person imports their own WireGuard or AmneziaWG configuration and uses it as a
hop — either alone, or chained through WARP (for example, a personal WireGuard
config carried inside a WARP tunnel, or WARP carried inside a personal WireGuard
tunnel).

**Why this priority**: It turns user-owned credentials into chainable hops and
proves the hop contract accepts externally-produced inputs.

**Independent Test**: Import a standard WireGuard config and an AmneziaWG config;
connect with each alone, then chain each with WARP in both orders; confirm healthy
tunnels and a field-for-field round-trip export.

**Acceptance Scenarios**:

1. **Given** a standard WireGuard `.conf`, **When** imported and connected,
   **Then** it establishes with no unknown-field errors.
2. **Given** an AmneziaWG `.conf` with obfuscation parameters, **When** imported,
   **Then** every parameter is preserved and applied and a round-trip export
   reproduces the original values.
3. **Given** a personal WireGuard config, **When** declared as an inner hop of a
   WARP chain, **Then** its traffic egresses through WARP and the chain reports
   healthy.
4. **Given** a malformed config, **When** imported, **Then** the client fails closed
   naming the offending field.

---

### User Story 3 - Chain and nest any transports in any order (Priority: P1)

A person declares an ordered chain of two or more transports or proxies and
connects. The order is free: Tor-in-WARP, WARP-in-Tor, WARP then exit via
Psiphon, Psiphon then exit via WARP, MASQUE-in-MASQUE, WireGuard-in-WireGuard, or
mixed. The client validates the chain before starting and refuses impossible
combinations with a clear reason.

**Why this priority**: Arbitrary bidirectional ordering is the product's core
differentiator and the reason the transport model must be a generic hop graph.

**Independent Test**: Declare each named composition in both orders, connect,
confirm egress is through the declared final hop, and confirm invalid chains are
rejected before any hop starts.

**Acceptance Scenarios**:

1. **Given** the `tor-warp` preset (Tor carrier, relay adapter, WARP exit), **When**
   connected, **Then** the tunnel egress is WARP and Tor is the carrier.
2. **Given** WARP placed before Tor, **When** connected, **Then** the tunnel egress
   is Tor and WARP is the carrier.
3. **Given** a bare `tor,wireguard peer=warp` chain with no relay, **When** submitted,
   **Then** it is rejected with the required relay insertion named.
4. **Given** WARP then Psiphon as exit, **When** connected, **Then** egress is
   Psiphon reached over WARP.
5. **Given** Psiphon then WARP as exit, **When** connected, **Then** egress is WARP
   reached over Psiphon.
6. **Given** MASQUE nested in MASQUE, **When** connected, **Then** both hops start
   in the declared order and the chain reports healthy.
7. **Given** an impossible chain, **When** submitted, **Then** the client rejects
   it before starting any hop and explains which hop and why.

---

### User Story 4 - Scan for working endpoints (Priority: P3)

A person runs an endpoint scan under a chosen profile (speed/thoroughness/stealth
trade-off), gets a ranked list of traffic-validated endpoints, and reconnects
using the best one.

**Independent Test**: Run each scan profile; confirm a ranked list with measured
latency and a reachability verdict, and that the next connection uses a scanned
endpoint.

**Acceptance Scenarios**:

1. **Given** a balanced scan, **When** it completes, **Then** the client presents
   ranked endpoints with latency and reachability.
2. **Given** an endpoint that handshakes but passes no traffic, **When** validated,
   **Then** it is rejected.
3. **Given** a scan that finds nothing, **When** it completes, **Then** the client
   reports the failure and does not silently use an unverified endpoint.

---

### User Story 5 - Apply obfuscation profiles (Priority: P3)

A person picks an obfuscation profile appropriate to the transport and network
(for example a noize profile for MASQUE/WARP, or an AmneziaWG parameter set for a
self-hosted peer), connects, and the client applies it without hand-editing
low-level parameters.

**Acceptance Scenarios**:

1. **Given** a selected noize profile, **When** connected on a supporting
   transport, **Then** the profile's junk disguise parameters are applied and
   reported.
2. **Given** a selected AmneziaWG profile, **When** connected to a supporting
   peer, **Then** its header/padding/timing parameters are applied and reported.
3. **Given** a profile incompatible with the selected transport, **When** selected,
   **Then** the client rejects it with a clear reason.

---

### Edge Cases

- Only one address family is available: connect on the available family, do not
  fail the session.
- IPv6 present but broken: detect during validation, fall back or report; never
  connect into a black hole.
- Endpoint handshakes but passes no traffic: reject it.
- Two hops claim the same local port or address range: detect before starting.
- A TCP-only hop cannot directly carry a hop that needs a UDP carrier (for example
  Tor before WireGuard): the client MUST reject the chain and name the required
  relay insertion (`tor,relay,wireguard peer=warp`). The shipped `tor-warp` preset
  already includes the relay, so "Tor-in-WARP" remains selectable and valid.
- Nested tunnels exhaust the MTU: shrink inner MTU per hop and validate.
- Nesting beyond the supported depth cap: enforce and explain. Depth counts hops
  after composition-preset expansion, default max 3; GOOL and MIM each expand to two
  hops (GOOL alone = 2, GOOL plus one exit hop = 3, GOOL-in-GOOL = 4 and rejected).
- Chain cycles (a hop targeting its own listener): reject before starting.
- Imported config with unknown credential fields: fail closed naming the field.

## Requirements *(mandatory)*

### Functional Requirements

**Rust core and porting discipline**

- **FR-001**: The shipped runtime core and all tunnel transports MUST be
  implemented in Rust; the client MUST NOT link or embed a non-Rust tunnel engine.
  The single permitted exception is the Psiphon/Cfon hop, which runs a Psiphon
  client as a separate sidecar process exposing a local proxy that the Rust core
  dials as a hop; the core MUST NOT link Psiphon code.
- **FR-001a**: The sidecar MUST have a bounded supervisor: explicit executable path,
  minimal environment, readiness handshake before use, and teardown on session end
  and on drop. Restarts MUST be capped; when the cap is exhausted or readiness
  fails, the session MUST fail closed and the report MUST name the sidecar, its
  failure cause, and the exhausted bound.
- **FR-001b**: Secrets MUST NOT be passed to the sidecar in `argv`. The client MUST
  prefer an inherited pipe or file descriptor (stdin second-best; environment only
  when the platform requires it), with least-privilege, short-lived values.
- **FR-002**: The project MUST be a fork of Aether, with Aether's WireGuard,
  MASQUE h3/h2, and Tor transports retained and built on, and its GOOL/MIM
  orderings retained as composition presets (not transports).
- **FR-003**: Each capability introduced by porting (Cfon/Psiphon, AmneziaWG,
  arbitrary chaining, any ported scanner/profile) MUST ship with its own
  dual-stack test suite, and that suite MUST pass before the capability is
  considered complete.
- **FR-003a**: The product MUST be an embeddable engine core plus a pure CLI, with
  no GUI, and the CLI MUST be a thin consumer of the core's public API rather than
  the only way to reach the engine.
- **FR-003b**: The core MUST be consumable as a library by other applications
  (for example an Aether-style client, an Xray-style proxy, or a sing-box-style
  router host) without forking the core, exposing a documented, versioned public
  API for configuring and starting a session and observing its state.
- **FR-003c**: The core MUST expose its session, chain, profile, and scan
  operations through the same public API the CLI uses; no capability may be
  reachable only through the CLI.
- **FR-003g**: A capability introduced by porting MUST be behind a build feature so
  hosts can compile only the transports they embed, and the target matrix stays
  tractable.
- **FR-003d**: The core MUST expose a stable C ABI (for example a cdylib with a C
  header) in addition to the Rust crate, so that non-Rust hosts such as Go
  applications can consume it via cgo/FFI without forking. Android embedding MUST
  be a JNI wrapper over that same C ABI; the core MUST NOT contain an
  Android-only code path.
- **FR-003e**: The CLI and core MUST build and run on all of: Windows x86, x64,
  and ARM64; Linux x86, x64, ARM, and ARM64; and Android ARM and ARM64. Every
  listed target MUST be built and smoke-tested before release. Android support
  means a CLI that runs under Termux (built for the Android Bionic target, with a
  static-musl variant where useful) plus the C ABI/JNI library for in-app
  embedding; a non-Termux application cannot exec a CLI from app storage.
- **FR-003f**: The public API and C ABI MUST be versioned, and a documented
  compatibility policy MUST state how breaking changes are communicated to
  embedding applications.

**Transport coverage**

- **FR-004**: The client MUST support as selectable transports: WireGuard in WARP,
  imported, and AmneziaWG modes; MASQUE over HTTP/3 and HTTP/2 (an ALPN option);
  Tor; Psiphon (Cfon); and a **relay adapter** providing UDP-over-TCP framing. The
  relay adapter is a first-class registered transport with no per-transport CLI
  flags; it exists so a hop requiring a UDP carrier can be placed after a TCP-only
  hop. MASQUE-in-MASQUE (MIM), WARP-in-WARP (GOOL), and Tor-carried-WARP
  (`tor-warp`, which includes the relay) MUST be selectable as chain composition
  presets over those transports.
- **FR-005**: Every transport MUST be usable on its own with no other transport
  present.

**Arbitrary bidirectional chaining**

- **FR-006**: The client MUST model every transport as a registered plugin behind
  one uniform interface, so any hop can be placed before or after any other, and
  adding a transport MUST NOT require modifying the engine, chain validator, CLI,
  or schemas.
- **FR-006a**: Transports MUST declare their carrier and egress capabilities (for
  example whether they accept a TCP or UDP carrier, and whether they provide UDP
  egress) as data available before the hop starts, so chain validation is total and
  side-effect free.
- **FR-007**: The client MUST accept a user-declared ordered chain of two or more
  hops and establish them in the declared order. A single-hop chain is valid
  (explicit supported degenerate case). An all-same-kind chain of distinct hops is
  valid subject to depth (the GOOL/MIM presets are exactly this shape).
- **FR-007a**: Composition presets MUST expand exactly one level; a preset MUST NOT
  contain another preset. A preset reference inside a preset definition is a
  validation error naming both names. Presets MUST NOT embed secrets; `tor-warp`
  MUST be preserved as a shipped WARP preset because the preset encodes protocol
  knowledge, not composition knowledge.
- **FR-008**: The client MUST support at minimum, in both orders where meaningful:
  Tor-in-WARP, WARP-in-Tor, WARP-then-Psiphon (exit), Psiphon-then-WARP (exit),
  MASQUE-in-MASQUE, and WireGuard-in-WireGuard.
- **FR-009**: The client MUST support chaining user-imported WireGuard-family
  configs through WARP and WARP through user-imported configs.
- **FR-010**: The client MUST validate a declared chain before starting any hop,
  rejecting impossible combinations, port conflicts, cycles, and over-depth chains,
  each with a specific reason. When a hop requiring a UDP carrier follows a TCP-only
  hop and no relay adapter is present, the client MUST reject the chain with a
  message naming the required insertion point (for example:
  "insert `relay` after `tor`").
- **FR-010a**: Chain depth MUST be the number of hops after composition presets are
  expanded, with a default maximum of 3 layers. Because GOOL and MIM expand to two
  hops, GOOL or MIM alone leaves room for one further hop, while GOOL-in-GOOL,
  MIM-in-MIM, or GOOL+MIM (4 hops) MUST be rejected with a specific over-depth
   reason. The cap MUST be configurable upward to a documented hard limit of 5. Depth is
  owned by exactly one place: the chain validator, which counts the expanded hop
  list; transports and presets MUST NOT declare or compute depth.
- **FR-011**: The client MUST expose the chain's final egress (exit hop) as the
  session's effective public path and report the full ordered chain.

**Dual-stack**

- **FR-012**: Every transport, scan, and chain MUST work over IPv4-only,
  IPv6-only, and dual-stack hosts.
- **FR-013**: The address family MUST be an explicit user choice (IPv4, IPv6, both)
  with a documented default, and the client MUST report the family actually used
  per hop.
- **FR-013a**: `dual` MUST mean Happy Eyeballs v2 racing (RFC 8305): staggered
  connection attempts across families, never true simultaneous equal-race. The
  Connection Attempt Delay MUST default to 250 ms (configurable 10 ms–2 s) and the
  Resolution Delay to 50 ms; the preferred family MUST default to IPv4 and be
  configurable to IPv6.
- **FR-013b**: The client MUST honor WireGuard `AllowedIPs` exactly as declared and
  MUST NOT silently add a missing family's default route; when a dual session lacks
  one family's default route, the client MUST surface a warning.
- **FR-013c**: The client MUST route DNS through the tunnel chain or refuse to
  start (fail closed). Resolver transport MUST prefer IPv6 with penalty-based
  fallback; local name synthesis is permitted only for IPv4 literals (RFC 7050/6052
  Pref64 embedding) and as the RFC 8305 2-second last resort. The client MUST NOT
  synthesize AAAA answers when real AAAA answers exist.
- **FR-013d**: Per-hop NAT behavior in scope is persistent keepalive (per-hop,
  configurable, default off), endpoint roaming, and MTU derivation with PMTU
  handling (RFC 4821) including per-layer inner-MTU shrink. STUN, ICE, TURN, UDP
  hole punching, and inbound reachability are out of scope for the first release.

**Endpoint scanning**

- **FR-014**: The client MUST discover and traffic-validate reachable endpoints for
  a chosen transport without a manual endpoint.
- **FR-015**: The client MUST provide exactly three scanning profiles (`turbo`,
  `balanced` default, `stealth`) that differ in thoroughness, speed, and stealth,
  and MUST apply the selected profile.
- **FR-016**: Scan results MUST be a ranked list with measured latency and an
  explicit reachability verdict per endpoint, and failed endpoints MUST be
  discarded and not reused.
- **FR-017**: The client MUST prefer a previously verified endpoint on reconnect.

**Obfuscation**

- **FR-018**: The client MUST provide selectable obfuscation profiles as data, not
  user-entered low-level parameters.
- **FR-019**: The client MUST support Aether's noize profile set for the transports
  it applies to (MASQUE and WireGuard/GOOL).
- **FR-020**: The client MUST support an AmneziaWG obfuscation parameter set as a
  WireGuard mode, ported from the Go implementation, applicable against a
  supporting peer.
- **FR-021**: The client MUST reject an obfuscation profile incompatible with the
  selected transport mode, and MUST NOT apply AmneziaWG server-negotiated parameters
  to a plain WireGuard/WARP peer.

**Configuration import/export**

- **FR-022**: The client MUST import standard WireGuard and AmneziaWG configs
  without user edits.
- **FR-023**: Import MUST preserve every recognized field, including AmneziaWG
  obfuscation parameters, and reject unknown/malformed fields by name.
- **FR-024**: Exporting an imported config MUST reproduce its values equivalently.

**Observability, secrets, and fail-closed behavior**

- **FR-025**: The client MUST report in machine-readable form: selected chain in
  order, each hop's transport and address family, active profiles, endpoint in
  use, and the cause of any failure.
- **FR-026**: The client MUST never persist, export, or log credentials, private
  keys, or tokens in plaintext, and MUST redact them from all diagnostics.
- **FR-026a**: Redaction MUST be typed-field-first (always redact secret fields by
  key), entropy-and-denylist scanning second for free-form values, and heuristic
  masking MUST NOT be the sole control.
- **FR-026b**: A value that cannot be classified as safe and cannot be proven secret
  MUST NOT be emitted: the client MUST drop the whole record and emit a redaction
  placeholder with metadata only (fail closed).
- **FR-027**: The client MUST fail closed: when a required validation cannot
  complete, it MUST refuse to connect rather than connect unverified.
- **FR-028**: Chain composition presets, obfuscation profiles, and scanning profiles
  MUST live in an application profile directory and MUST be replaceable without
  editing configuration that embeds secrets.
- **FR-029**: The client MUST provide a preflight check that validates a chain,
  profiles, and configuration without starting any hop or opening any network
  socket.

### Key Entities *(include if feature involves data)*

- **Hop**: One transport instance in a chain, exposing a uniform egress contract
  (TCP connect and, where supported, UDP associate). Carries identity, accepted
  address families, obfuscation capability, and carrier/egress capabilities declared
  before it starts.
- **Composition Preset**: A named expansion of a chain fragment (for example `gool`
  → two WireGuard hops, `mim` → two MASQUE hops). Presets are data and expand before
  validation.
- **Chain Declaration**: A user-authored ordered list of hops (each optionally
  configured with the previous hop as its carrier) that is validated before use.
- **Transport**: A registered plugin of one kind: `wireguard` (WARP, imported, and
  AmneziaWG modes), `masque` (h2/h3), `tor`, `psiphon`, or `relay` (UDP-over-TCP
  framing adapter). Carries a static descriptor used by validation, the scanner, and
  help output.
- **Config Import**: A user-supplied WireGuard-family config with its parsed,
  field-preserving representation and import verdict.
- **Scan Profile**: A named endpoint-probing strategy (thoroughness, speed,
  stealth).
- **Obfuscation Profile**: A named disguise parameter set; either a noize profile
  or an AmneziaWG parameter set, with a declared set of compatible transports.
- **Endpoint Candidate**: A discovered endpoint with address family, measured
  latency, reachability verdict, and last-known-good status.
- **Connection Report**: The machine-readable session record: ordered chain, per-hop
  transport/family, profiles, endpoint, and outcome.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every supported transport, ported or original, passes its own
  dual-stack acceptance suite: a successful IPv4 and IPv6 connection on one build.
- **SC-002**: 100% of the named bidirectional chain compositions establish in
  automated checks, and 100% of impossible chains are rejected before any hop
  starts.
- **SC-002a**: Every listed target (Windows x86/x64/ARM64, Linux
  x86/x64/ARM/ARM64, Android ARM/ARM64) has a published build that passes a
  smoke test connecting at least one transport; 0 listed targets ship unbuilt or
  untested. Coverage MAY be tiered (fast per-PR subset, nightly broad matrix, full
  matrix pre-release), but publishing MUST be blocked until every listed target has
  built and smoked, regardless of tier.
- **SC-002b**: An external consumer (a Rust host and a non-Rust host using the C
  ABI) can start a session, read its state, and stop it using only the documented
  public API, with no access to internal types.
- **SC-002c**: Adding a new transport to the codebase requires zero edits to the
  engine, chain validator, CLI, or schemas; verified by adding a throwaway transport
  in a test build.
- **SC-002d**: A preflight run of an invalid chain is rejected with the offending hop
  named, and opens zero network sockets (verified against the stub peer's connection
  counter).
- **SC-003**: A new user reaches a connected tunnel using a self-discovered
  endpoint in under 2 minutes without editing a file.
- **SC-004**: Import round-trip fidelity is 100% across the project's standard
  WireGuard and AmneziaWG config corpus: no field lost, added, or altered.
- **SC-005**: Balanced-profile endpoint scanning yields a traffic-validated
  endpoint within 30 seconds for at least 90% of scans.
- **SC-006**: Zero secrets appear in logs, exports, or crash output across the full
  acceptance suite, including the fail-closed placeholder path for unclassifiable
  values.
- **SC-007**: A failed transport or hop produces a report naming the failing layer
  and cause in 100% of induced failure cases.
- **SC-008**: Every ported capability has a passing test suite before it is marked
  complete; 0 ported capabilities ship without one.

## Assumptions

- **Base = fork of Aether** (Rust).
- **AmneziaWG is ported to Rust from the Go implementation**; the obfuscation
  parameter handling is reimplemented over the Rust WireGuard core.
- **Psiphon/Cfon integration**: Aether has no Rust Psiphon library, so the Psiphon
  hop is a separate sidecar Psiphon client exposing a local proxy, wired into
  Aether's hop model as an ordinary hop — the same integration shape used by
  Oblivion/warp-plus. No Psiphon code is linked into the Rust core, it is spawned
  under the bounded sidecar supervisor, and secrets reach it via inherited pipe/fd
  rather than `argv`. Psiphon use here is authorized for this project.
- **Tor** uses Aether's existing arti-based integration and is treated as a hop
  that can precede or follow another hop.
- **Hop model**: a hop exposes an abstract async egress (TCP dial and, where
  supported, UDP associate); the next hop is constructed with a dialer for the
  previous hop's egress. Chains are data, validated at construction. Abstract egress
  (not a concrete OS socket) is what makes `smoltcp`-backed inner hops implementable.
- **Address family**: `dual` means Happy Eyeballs v2 racing with an IPv4-preferred
  default; `AllowedIPs` is honored exactly; DNS is routed through the tunnel or the
  client refuses to start. NAT behavior in scope is keepalive, endpoint roaming, and
  PMTU handling.
- **Cross-platform core + CLI on Windows (x86/x64/ARM64), Linux
  (x86/x64/ARM/ARM64), and Android (ARM/ARM64; Termux CLI plus C ABI/JNI for
  in-app use)**, all present from the first release. Windows 32-bit ARM is
  excluded (end-of-life OS, no usable Rust target). A GUI and dedicated router
  firmware are out of scope for the first release. Android ships **both** a
  Termux-runnable CLI (Android Bionic target) and the cdylib/JNI embedding library;
  the CLI is smoke-tested by execution on an emulator, the library by verifying its
  exported symbols.

## Release Tiers

- **Tier A (every PR):** native host unit/contract tests, lint, secret scan, and a
  smoke test of the native artifact against the stub peer.
- **Tier B (nightly + main):** the broad cross-build matrix and stub-peer smoke for
  Linux gnu/musl/armv7, Windows ARM64, and Android.
- **Tier C (pre-release/tag):** every listed target built and smoke-tested; publish
  is blocked unless the entire Tier C matrix is green.

## Emergency Release Path

- **Authority:** a release manager plus a security maintainer (two people).
- **Mandatory even in an emergency:** the advisory, artifact signing, the secret
  scan, `cargo-audit`/`cargo-deny` clean, and a build plus smoke test on at least
  the platform affected by the issue.
- **May be deferred:** non-affected target smoke, documentation, and changelog polish.
- **Mechanics:** fix on a `release/x.y` branch, patch version bump (a new version,
  never a re-tag of a published release), then notify consumers via a security
  advisory and dependency alerts. A version is yanked only if broken, never to
  retract a leaked secret.

## Out of Scope (First Release)

- A desktop GUI, a mobile application UI shell, or dedicated router firmware (the
  Android Termux CLI binary and the C ABI/JNI library are in scope; an Android app
  UI is not).
- Operating Tor relays or exit nodes.
- A hosted/cloud control plane or account service.
- Server-side deployment of WARP, MASQUE, or Psiphon infrastructure.
- Any guarantee of anonymity; this is a connectivity tool and says so.

## Obfuscation Design

Both mechanisms are supported because they defend different transports:

- **noize** (Aether, already Rust): a pre-handshake junk-packet smokescreen plus
  obfuscated CPS packets. Applied to MASQUE and WireGuard/GOOL hops. Cheap to
  keep and extend.
- **AmneziaWG parameters** (ported from Go): reshapes every WireGuard packet
  class — junk packets, header size/type randomization, header protection,
  content padding, randomized timings, trailers. Materially stronger for a
  WireGuard-family hop, but only valid against a peer that supports it; it MUST
  NOT be applied to Cloudflare's plain WireGuard edge.

Profile set:

- `masque-balanced` (default for MASQUE): real QUIC/H3, ECH auto, noize `light`;
  `--h2` variant enables fragmentation.
- `masque-aggressive`: noize `balanced` + HTTP/2 + fragmentation.
- `awg-balanced` (default for a self-hosted AmneziaWG hop): header protection on,
  S1–S4 16–32, Jc 6, Jmin/Jmax 64/256, I1–I3 mimicry, content padding 0–96,
  random trailers, cookies disabled, randomized timing ranges.
- `awg-aggressive`: larger junk/padding, full I1–I5, wider timings.
- `awg-off`: stock WireGuard for compatibility with plain peers.

AmneziaWG effectiveness is largely vendor-reported; the port's test suite MUST
measure against a controlled peer rather than rely on vendor claims.

## Legal & Compliance Constraints

- **WARP**: features are positioned as lawful-use only; the client does not
  circumvent provider controls.
- **Psiphon**: integrated under this project's authorization, borrowing the
  integration approach from Oblivion/warp-plus.
- **Tor**: the client surfaces Tor's own documentation and MUST NOT claim Tor
  provides legal protection.
- **Circumvention**: use is jurisdiction-dependent; the client MUST state this and
  MUST NOT ship evasion defaults tuned to a specific jurisdiction.
