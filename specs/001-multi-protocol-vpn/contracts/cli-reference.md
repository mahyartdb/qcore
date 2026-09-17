# qcore CLI Reference

Worked examples for the decided CLI surface. Normative rules live in
[cli.md](./cli.md); this file is the companion. Decision record: a hybrid of the CLI
arena's strongest parts — `connect`/`up` with aliases, comma chain expressions,
typed per-hop options, zero-config default, generated shortcuts, durable session
state.

## Quick start

```bash
qcore up                                  # zero-config: WARP, dual, balanced scan
qcore up --chain "tor-warp" --json        # preset chain, machine-readable
qcore status --json                       # full ConnectionReport
qcore down                                # stop
```

## Command surface

```
qcore [global-options] <command> [command-options] [operands]
qcore <shortcut>                          # generated chain shortcut
qcore help [command]
```

| Command | Aliases | Purpose |
|---|---|---|
| `connect` | `up` | Validate a chain and bring up a session |
| `register` | — | Provision a WARP identity (+ MASQUE enrollment; `--gool` for the pair) |
| `renew` | — | Refresh in place, re-register on refusal (`--masque-only`, `--hop`) |
| `stop` | `down` | Tear down the current session |
| `preflight` | `check` | Validate with zero sockets (FR-029) |
| `scan` | — | Discover + traffic-validate endpoints |
| `import` | — | Import a WG/AWG config |
| `export` | — | Round-trip an imported config |
| `profiles` | `ls` | List transports, profiles, presets, shortcuts |
| `status` | — | Print the ConnectionReport |
| `version` | — | Engine + API + ABI + schema versions |

## Global flags

| Flag | Short | Values | Default |
|---|---|---|---|
| `--family` | `-f` | `ipv4` \| `ipv6` \| `dual` | `dual` |
| `--prefer` | | `ipv4` \| `ipv6` | `ipv4` |
| `--obfuscation` | `-O` | profile name | per-mode |
| `--max-depth` | | integer | `3` |
| `--json` | `-j` | flag | off |
| `--config` | | path | auto |
| `--profile-dir` | | path | auto |
| `--log-level` | | `error`..`trace` | `info` |
| `--no-color` | | flag | off |
| `--quiet` | `-q` | flag | off |
| `--verbose` | `-v` | repeatable | off |

## Chain expression syntax

Comma-separated hops, left to right; **the last hop is the exit**.

```
hop := name ( key=value )* [ @label ]
```

| Token | Expands to |
|---|---|
| `wireguard` | WireGuard, default peer mode |
| `wireguard peer=warp` | WARP |
| `wireguard peer=imported import=wg-home` | Imported config |
| `wireguard peer=awg import=awg-home` | AmneziaWG mode |
| `masque alpn=h3` | MASQUE over HTTP/3 |
| `masque alpn=h2` | MASQUE over HTTP/2 |
| `tor` | Tor (arti) |
| `psiphon sidecar_path=/opt/psiphon` | Psiphon sidecar |
| `relay` | UDP-over-TCP framing adapter |
| `gool` | Preset → `wireguard peer=warp` ×2 |
| `mim` | Preset → `masque alpn=h3` ×2 |
| `tor-warp` | Preset → `tor,relay,wireguard peer=warp` |

Options are typed per transport; an unknown key is exit 2 naming the field.
Values with `,`, whitespace, `=`, or quotes MUST be quoted.

`--hop` is the argv equivalent: `--hop tor --hop relay --hop "wireguard peer=warp"`.

## Chain shortcuts

A token like `qcore tor-warp` is minted iff all six rules hold: every segment
resolves to a registry token; the expanded chain is within the depth cap; the name
collides with no command/flag; it is a pure alias producing an identical report and
exit code; it is registry-generated with zero CLI edits; and it never encodes
mode-with-options. Unknown tokens are exit 6 and never fuzzy-resolved.

## Worked examples

### Single transport

```bash
qcore up --chain "wireguard peer=warp" --family dual --json
qcore up --chain "masque alpn=h3" --family dual --json
qcore up --chain "masque alpn=h2" --json
qcore up --chain "wireguard peer=imported import=wg-home" --json
qcore up --chain "tor" --json
qcore up --chain "psiphon sidecar_path=/opt/psiphon" --json
```

### Both orders of every pair (FR-008)

```bash
# Tor carrier, WARP exit (preset includes the relay)
qcore up --chain "tor-warp" --json
# Explicit relay insertion
qcore up --chain "tor,relay,wireguard peer=warp" --json
# WARP carrier, Tor exit
qcore up --chain "wireguard peer=warp,tor" --json
# WARP then Psiphon exit
qcore up --chain "wireguard peer=warp,psiphon sidecar_path=/opt/psiphon" --json
# Psiphon then WARP exit
qcore up --chain "psiphon sidecar_path=/opt/psiphon,wireguard peer=warp" --json
```

### Presets

```bash
qcore up --chain "gool" --json            # wireguard,wireguard (2 hops)
qcore up --chain "mim"  --json            # masque,masque (2 hops)
qcore up --chain "gool,psiphon sidecar_path=/opt/psiphon" --json   # 3 hops, at cap
```

### Rejected chains (exit 2, zero sockets)

```bash
qcore up --chain "gool,gool" --json                # 4 hops => over depth
qcore up --chain "tor,wireguard peer=warp" --json  # no relay => insertion named
qcore up --chain "wireguard peer=warp,bogus" --json # unknown transport
qcore preflight --chain "gool,gool" --json         # validates only, opens nothing
```

Error shape:

```
qcore: invalid chain (exit 2)
  hop 0 `tor` -> hop 1 `wireguard` requires a UDP carrier
  cause: no relay hop between a TCP-only carrier and a UDP egress
  fix:   insert `relay`:  --chain "tor,relay,wireguard peer=warp"
         or use the preset: --chain "tor-warp"
```

### Scan

```bash
qcore scan --transport wireguard --profile balanced --family dual --output table
qcore scan --transport wireguard --profile stealth --output ndjson | jq -c .
```

A handshake-only result is labeled `uncertain` and never promoted to last-known-good.

### Import / export

```bash
qcore import ./fixtures/awg.conf --json
qcore export awg-home > out.conf          # values reproduced; secrets redacted
```

### Obfuscation

```bash
qcore up --chain "masque alpn=h3" -O masque-balanced --json
qcore up --chain "wireguard peer=awg import=awg-home" -O awg-balanced --json
qcore up --chain "wireguard peer=warp" -O awg-balanced --json   # exit 2: incompatible
```

### Status, lifecycle, diagnostics

```bash
qcore status --json          # exit 0 up/degraded, 1 dead, 10 none, 12 unverifiable
qcore down                   # idempotent
qcore ls                     # transports, profiles, presets, shortcuts
qcore version --json         # {engine, api, abi, schema, target}
```

### Scripting

```bash
qcore up -d --chain "wireguard peer=warp" && qcore status --json | jq .exit_hop_id
qcore up --chain "gool,psiphon sidecar_path=/opt/psiphon" --report-out /tmp/report.json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid chain / validation failure (nothing started) |
| 3 | Transport or hop failure |
| 4 | Scan found nothing reachable |
| 5 | Config import rejected |
| 6 | Usage error |
| 10 | No session (status/stop) |
| 12 | Session unverifiable — fail closed |