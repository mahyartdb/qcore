# Quickstart: Multi-Protocol Tunnel Client

Validation guide proving the feature works end-to-end. The engine is a CLI over an
embeddable core (no GUI). The gating run is **offline** against a deterministic
stub peer; live-network checks are supplementary.

## Prerequisites

- Rust stable toolchain (pinned MSRV in `rust-toolchain.toml`).
- A host with IPv4 and IPv6 for dual-stack scenarios.
- Optional: a controlled WireGuard/AmneziaWG peer for obfuscation tests.
- Optional: a Psiphon client binary for the sidecar hop.

## Build

```bash
cargo xtask build --release          # core + cli
cargo xtask ci                       # the full local gate (what CI runs)
cargo build -p qcore-ffi --release   # cdylib + qcore.h
```

Windows: `cargo xtask build --target x86_64-pc-windows-msvc`. Android:
`cargo ndk -t arm64-v8a -t armeabi-v7a build --release -p qcore-ffi`.

## Scenario 1 — Single transport, dual stack (P1, SC-001)

```bash
qcore up --chain "wireguard peer=warp" --family dual --json
```

Expected: exit 0; JSON ConnectionReport; session up; `qcore status --json` shows
the family actually used. Repeat for `masque alpn=h3`, `masque alpn=h2`,
`wireguard peer=imported`, `tor`, `psiphon`.

Zero-config check: `qcore up` with no flags also reaches a connected session.

## Scenario 1b — Chain shortcuts and diagnostics (SC-002c)

```bash
qcore ls                 # advertised transports, profiles, presets, shortcuts
qcore tor-warp           # generated shortcut == `qcore up --chain "tor-warp"`
qcore status --json      # expanded chain + per-hop family + exit_hop_id
```

## Scenario 2 — Arbitrary chain order (P1, SC-002)

```bash
qcore up --chain "tor-warp"                     --json  # preset: Tor carrier, relay, WARP exit
qcore up --chain "wireguard peer=warp,tor"      --json  # WARP carrier, Tor exit
qcore up --chain "wireguard peer=warp,psiphon"  --json  # WARP then Psiphon exit
qcore up --chain "psiphon,wireguard peer=warp"  --json  # Psiphon then WARP exit
qcore up --chain "mim"   --json   # MASQUE-in-MASQUE (expands to 2 hops)
qcore up --chain "gool"  --json   # WARP-in-WARP (expands to 2 hops)
qcore up --chain "tor,relay,wireguard peer=warp" --json # explicit relay insertion
```

Expected: exit 0; report lists hops in declared order after preset expansion;
`exit_hop_id` is the last hop; egress address matches that exit.

## Scenario 3 — Invalid chains fail closed (SC-002, SC-002d)

```bash
qcore up --chain "gool,gool"                 --json  # 4 hops => rejected
qcore up --chain "tor,wireguard peer=warp"   --json  # no relay => rejected, insertion named
qcore up --chain "gool,psiphon,tor"          --json  # > cap => rejected
qcore preflight --chain "gool,gool"          --json  # validates, opens no socket
```

Expected: exit 2; error names the offending hop and reason; no hop started. The
no-relay case names the fix (`insert relay` or use `tor-warp`). The stub peer's
connection counter is unchanged after `preflight` (SC-002d).

## Scenario 4 — Import / export round-trip (P2, SC-004)

```bash
qcore import ./fixtures/standard-wg.conf --json
qcore import ./fixtures/awg.conf --json
qcore export awg.conf > out.conf
diff ./fixtures/awg.conf out.conf
```

Expected: import accepted; no unknown-field errors; `diff` shows no value changes.

## Scenario 5 — Endpoint scan (P3, SC-005)

```bash
qcore scan --transport wireguard --profile balanced --family dual --output json
qcore connect --chain "wireguard peer=warp" --json
```

Expected: ranked candidates with latency + reachability; a handshake-only endpoint
with no traffic is marked failed and not reused; subsequent connect uses a validated
endpoint; balanced scan typically under 30 s.

## Scenario 6 — Obfuscation profiles (P3)

```bash
qcore profiles --json
qcore connect --chain "masque alpn=h3" --obfuscation masque-balanced --json
qcore connect --chain "wireguard peer=awg" --import awg.conf --obfuscation awg-balanced --json
qcore connect --chain "wireguard peer=warp" --obfuscation awg-balanced --json  # incompatible
```

Expected: shows which profile is active; incompatible profile => rejected with a
clear reason; no server-negotiated AWG params sent to a plain WARP peer.

## Scenario 7 — Embedding and extensibility (SC-002b, SC-002c)

- Rust host: link the `qcore` facade crate, start a session, subscribe to events,
  read status, stop — using only public types. See `examples/embed-host`.
- Non-Rust host: link the cdylib, call `qcore_engine_start` +
  `qcore_engine_status_json`, free strings.
- Extensibility: add a throwaway transport crate, `register_plugin!`, run the
  conformance macro; no engine/chain/CLI/schema edits (SC-002c).

Expected: both hosts drive a session with no access to internal types;
`qcore_abi_version` reports the ABI version.

## Scenario 8 — Secret hygiene (SC-006)

```bash
qcore connect --chain "wireguard peer=awg" --import awg.conf --log-level trace --json
```

Expected: no private key, token, or credential appears in stdout, logs, state file,
or any export; the dynamic capture test's secret scan passes.

## Target matrix smoke test (SC-002a)

For each target — Windows x86/x64/ARM64, Linux x86/x64/ARM/ARM64, Android
ARM/ARM64:

```bash
cargo xtask smoke --target <triple>
```

Expected: every listed target builds and reaches a connected session against the
stub peer over `ipv4`, `ipv6`, and `dual`; release is blocked if any target fails.