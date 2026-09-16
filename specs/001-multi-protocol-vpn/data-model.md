# Data Model: Multi-Protocol Tunnel Client

Derived from the feature spec's Key Entities and Functional Requirements. Logical
model; storage is local files (no database).

## TransportKind (registry descriptor)

Four implementations; modes and presets carry the rest of the catalogue.

| Value | Modes/options | UDP egress | Obfuscation family |
|---|---|---|---|
| `wireguard` | `peer=warp` \| `peer=imported` \| `peer=awg` | yes | noize or AmneziaWG |
| `masque` | `alpn=h3` \| `alpn=h2` | yes (h3) / no (h2 carrier) | noize |
| `tor` | — | no (TCP only) | n/a |
| `psiphon` | — | via sidecar proxy | n/a |
| `relay` | — | provides UDP-over-TCP framing | n/a |
| `mock` | test only | yes | n/a |

`TransportDescriptor` (static, known before instantiation):

| Field | Type | Notes |
|---|---|---|
| `kind` | `&'static str` | Registry key, not an enum |
| `capabilities` | Capabilities | See below |
| `obfuscation_families` | `&'static [ObfuscationFamily]` | Compatibility source of truth |
| `config_schema` | `&'static str` | Typed config identity |
| `needs_sidecar` | bool | Only `psiphon` |

`Capabilities`: `accepts_tcp_carrier`, `accepts_udp_carrier`, `dials_tcp`,
`dials_udp`. Declared before start, so pre-start validation is total (FR-006a).

## Composition Preset

| Field | Type | Notes |
|---|---|---|
| `name` | string | e.g. `gool`, `mim` |
| `hops` | list<HopConfig> | Expands before validation |

`gool` = two `wireguard` hops (`peer=warp`); `mim` = two `masque` hops (`alpn=h3`).
Depth = total hops after expansion.

## HopConfig (typed, replaces the untyped options map)

`#[serde(tag = "kind")]` enum. Unknown fields are deserialization errors (Principle
IV), not silently-carried strings.

| Variant | Fields |
|---|---|
| `wireguard` | `peer` (warp\|imported\|awg), `import_ref`, `obfuscation`, `family`, `endpoint` |
| `masque` | `alpn` (h3\|h2), `obfuscation`, `family`, `endpoint` |
| `tor` | `family` |
| `psiphon` | `sidecar_path`, `family` |
| `mock` | test-only |

## HopSpec (user-declared, one chain entry)

| Field | Type | Required | Notes |
|---|---|---|---|
| `config` | HopConfig | yes | Typed, kind-tagged |
| `id` | string | yes | Unique in chain; used in reports/errors |

Validation:
- Presets expanded first; depth = hop count.
- Obfuscation incompatible with the mode => reject (FR-021).
- Duplicate `id` => reject.
- AmneziaWG server-negotiated params forbidden on plain `wireguard`/WARP (FR-021).

## Chain

| Field | Type | Notes |
|---|---|---|
| `hops` | ordered list<HopSpec> | Index 0 = outermost carrier; last = exit |
| `depth` | integer | Hops after preset expansion |
| `max_depth` | integer | Default 3, configurable to hard limit |

Validation before any hop starts (FR-009, FR-010, FR-010a):
- Presets expanded; `depth <= max_depth`, else over-depth error naming the hop.
- No cycles (a hop targeting its own listener).
- No local port conflicts; internal listeners use ephemeral ports.
- A hop needing a UDP carrier placed after a TCP-only hop is rejected unless the
  relay hop is present (capabilities come from descriptors, so this is decided
  before any start).
- MTU budget shrinks and is reported per nested layer.

## ConfigImport

| Field | Type | Notes |
|---|---|---|
| `source_format` | enum(wireguard, amneziawg) | Detected or declared |
| `path` | string | Local file |
| `parsed` | field map | Field-for-field preservation |
| `unknown_fields` | list<string> | Non-empty => reject, naming each (FR-023) |
| `awg_params` | AwgParams | Present for amneziawg only |
| `import_verdict` | enum(accepted, rejected) | |

Round-trip: export MUST reproduce `parsed` equivalently (FR-024, SC-004).

## AwgParams (AmneziaWG)

| Field | Type | Notes |
|---|---|---|
| `jc`, `jmin`, `jmax` | uint | Junk packets before handshake; jmax < MTU |
| `s1..s4` | uint | Padding on init/resp/cookie/data |
| `h1..h4` | uint range | Custom headers; non-overlapping |
| `i1..i5` | CPS tag string | Pre-handshake packets |
| `header_protection_key` | secret | Server-negotiated; AWG peers only |
| `content_padding_addition` | uint range | Payload padding |
| `random_trailers`, `disable_cookies` | bool | AWG 3.x |
| rekey/keepalive/timing ranges | uint range | Randomized timers |

Constraints: `header_protection_key`/`s*`/`h*` only against a supporting peer.

## ScanProfile

| Field | Type | Notes |
|---|---|---|
| `name` | string | Exactly `turbo`, `balanced` (default), `stealth` |
| `concurrency` | integer | Probe parallelism (bounded) |
| `rtt_budget_ms` | integer | Discard above threshold |
| `probe_kind` | enum | Handshake-only vs data-plane validated |
| `family_order` | list(ipv4,ipv6) | Scan order per family |
| `stealth` | bool | Reduced/patterned probing |

## ObfuscationProfile

| Field | Type | Notes |
|---|---|---|
| `name` | string | e.g. masque-balanced, awg-balanced, awg-off |
| `family` | enum(noize, awg) | Determines applicable modes |
| `compatible_modes` | list<Mode> | Reject on mismatch (FR-021) |
| `params` | family-specific | noize junk/CPS or AwgParams subset |

## EndpointCandidate

| Field | Type | Notes |
|---|---|---|
| `address` | IP + port | |
| `family` | enum(ipv4,ipv6) | |
| `latency_ms` | integer | Measured |
| `reachability` | enum(passed,failed) | Data-traffic validated |
| `confidence` | enum(verified,uncertain) | Uncertain = handshake-only; never promoted |
| `last_known_good` | bool | Set only for `verified` candidates (FR-017) |

## Session

| Field | Type | Notes |
|---|---|---|
| `id` | string | |
| `chain` | Chain | Validated |
| `family_policy` | enum(ipv4_only,ipv6_only,dual) + `preferred` + delays | FR-013a |
| `state` | enum(validating,starting,up,degraded,failed,stopped) | |
| `started_at` | timestamp | |
| `failure` | FailureReport | Present when failed; fail-closed (FR-027) |

State transitions: `validating -> starting -> up -> (degraded) -> stopped`, with
`validating|starting|up -> failed` on error. No transition from `failed` without a
new session.

## SidecarSupervisor

| Field | Type | Notes |
|---|---|---|
| `exe_path` | path | Explicit; never resolved from PATH by default |
| `readiness` | enum(pending,ready,failed) | Handshake before the hop is usable |
| `restarts` | integer | Capped; exhaustion fails the session closed (FR-001a) |
| `secret_channel` | enum(pipe,fd,stdin,env) | Never `argv` (FR-001b) |
| `teardown` | enum(on_session_end,on_drop) | Guaranteed |

## ConnectionReport (machine-readable, FR-025)

| Field | Type | Notes |
|---|---|---|
| `ordered_chain` | list<HopReport> | In declared order |
| `per_hop` | kind, family, endpoint, profiles, status | Family actually used per hop |
| `exit_hop_id` | string | Effective public path (FR-011) |
| `secret_redaction` | bool | Always true; no secrets emitted (FR-026) |
| `failure` | FailureReport | Layer + cause on failure |

## FailureReport

| Field | Type | Notes |
|---|---|---|
| `layer` | enum(validation, transport, chain, scan, config) | FR-025, SC-007 |
| `hop_id` | string | Which hop |
| `cause` | string | Actionable, redacted |
| `kind` | enum | Typed failure kind driving a static remedy table |