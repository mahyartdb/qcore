# Contract: CLI

The CLI is a thin consumer of the core's public API. Pure CLI, no GUI. This contract
is the decision record for the CLI surface; `cli-reference.md` is the worked-example
companion.

## Invocation model

```
qcore [global-options] <command> [command-options] [operands]
qcore <shortcut>                 # generated chain shortcut, e.g. `qcore tor-warp`
qcore help [command]
qcore --version | -V
```

Rules:

- **stdout is results, stderr is diagnostics.** `qcore export awg.conf > out.conf`
  and `qcore status --json | jq` are correct by construction.
- **`--json` emits exactly one JSON document on stdout.** All human text moves to
  stderr. When set, interactivity is disabled.
- **Foreground by default.** The engine has no resident daemon. `-d/--detach`
  spawns a detached process that writes `session.json`; `status`/`stop` locate it
  through that file plus a token-authenticated local control socket.
- **Fail closed.** Any unverifiable condition exits non-zero and starts nothing.
- **Secrets** are never emitted to stdout, logs, the state file, or exports
  (FR-026); there is no flag to override this.

## Commands

| Command | Aliases | Purpose |
|---|---|---|
| `connect` | `up` | Validate a chain and bring up a session |
| `stop` | `down` | Tear down the current session |
| `preflight` | `check` | Validate chain + profiles + config, open ZERO sockets (FR-029) |
| `scan` | — | Discover and traffic-validate endpoints (FR-014–017) |
| `import` | — | Import a WireGuard/AmneziaWG config (FR-022/023) |
| `export` | — | Round-trip an imported config (FR-024) |
| `profiles` | `ls` | List transports, scan/obfuscation profiles, presets, shortcuts |
| `status` | — | Print the current session's ConnectionReport |
| `version` | — | Engine + API + ABI + schema versions |
| `help` | — | Usage for a command |

Aliases are 1:1, change no argument grammar, and add no capability.

## Global options

| Option | Short | Values | Default | Notes |
|---|---|---|---|---|
| `--family` | `-f` | `ipv4` \| `ipv6` \| `dual` | `dual` | FR-013 |
| `--prefer` | | `ipv4` \| `ipv6` | `ipv4` | Happy Eyeballs v2 preference (FR-013a) |
| `--obfuscation` | `-O` | profile name | per-mode default | Applies only to compatible modes (FR-021) |
| `--max-depth` | | integer | `3` | FR-010a (hard limit 5) |
| `--timeout` | | seconds | `30` | Connection-establishment budget (CONNECTION_TIMEOUT_SECONDS) |
| `--json` | `-j` | flag | off | Machine-readable (FR-025) |
| `--report-out` | | path | — | Write the ConnectionReport |
| `--config` | | path | auto | Identity/config dir |
| `--profile-dir` | | path | auto | Scan/obf/preset data (FR-028) |
| `--log-level` | | `error`..`trace` | `info` | Never logs secrets (FR-026) |
| `--no-color` | | flag | off | Honors `NO_COLOR`; auto-off when not a TTY |
| `--quiet` | `-q` | flag | off | Suppress non-error stderr |
| `--verbose` | `-v` | repeatable | off | Adds non-secret diagnostics |

## connect / up

```
qcore connect [global flags] --chain "<expr>"
qcore connect [global flags] --chain-file chain.toml
qcore connect [global flags] --hop <hop> [--hop <hop> ...]
qcore connect [global flags] chain.toml          # positional file
qcore up                                            # zero-config default
```

| Option | Values | Notes |
|---|---|---|
| `--chain` | chain expression | Canonical inline form (see grammar) |
| `--chain-file` | path | TOML/JSON chain declaration |
| `--hop` | one hop | Repeatable; argv order defines chain order (script-friendly) |
| `-d/--detach` | flag | Background; writes `session.json` |
| `--bind` | `host:port` | Local proxy listener; default `127.0.0.1:0` |
| `--scan` / `--no-scan` | flag | Enable/disable endpoint discovery on connect |
| `--non-interactive` | flag | Never prompt; missing required values are exit 6 |
| `--yes` | flag | Required for any destructive operation off-TTY |

**Zero-config default.** `qcore up` with no flags is a complete, valid, fail-closed
session: `wireguard peer=warp`, family `dual`, scan `balanced`, no obfuscation, bind
`127.0.0.1:0`. First run creates `identity.toml`, scans once, caches the verified
endpoint, and connects.

## preflight / check

Validates chain + profiles + config and opens **zero** network sockets (FR-029,
SC-002d). Same chain inputs as `connect`; a refusal is exit 2 with the offending hop
and reason.

## scan

```
qcore scan --transport <kind> [--profile turbo|balanced|stealth]
           [--family ipv4|ipv6|dual] [--output table|json|ndjson]
```

Endpoints are a property of transport + family, not of a chain. A handshake-only
result is labeled `uncertain` and MUST NOT be promoted to last-known-good.

## import / export

| Command | Behavior |
|---|---|
| `import <file>` | Parse, preserve every field, reject unknown fields by name (FR-023) |
| `export <import-ref>` | Reproduce values equivalently; secrets remain redacted (FR-024, SC-004) |

## status

Output conforms to the `ConnectionReport` entity in data-model.md. `status`
distinguishes session health honestly:

| Situation | State | Exit |
|---|---|---|
| Session up and healthy | `up` | 0 |
| Session degraded but live | `degraded` | 0 |
| No session record in this state dir | `not_running` | 10 |
| Record exists but process is dead | `dead` | 1 |
| Live-looking record, control channel unconfirmed | `unverifiable` | 12 |

`unverifiable` fails closed rather than reporting a false green.

## profiles / ls

Lists registered transports and their modes, the three scan profiles, obfuscation
profiles, composition presets, and the generated chain shortcuts.

## Chain grammar (canonical inline form)

```
chain := hop ( "," hop )*
hop   := name ( ws key "=" value )* [ "@" label ]
```

- Hops are comma-separated, left to right. **The last hop is the exit** (FR-011).
- Per-hop options are space-separated `key=value` pairs. Options are **typed per
  transport**; an unknown key is exit 2 naming the field (no free-form blob).
- Values containing `,`, whitespace, `=`, or quotes MUST be quoted.
- Reordering two hops is the entire mechanism for FR-008; there is no
  `--before`/`--after`.

Examples:

```
wireguard peer=warp
wireguard peer=warp,tor                 # WARP carrier, Tor exit
tor-warp                                # preset: tor,relay,wireguard peer=warp
psiphon,wireguard peer=warp             # Psiphon carrier, WARP exit
gool                                    # preset: wireguard peer=warp x2
mim                                     # preset: masque alpn=h3 x2
tor,relay,wireguard peer=warp           # explicit relay insertion
```

`--hop` is the equivalent argv form: `--hop tor --hop relay --hop "wireguard peer=warp"`.

## Chain shortcuts (generated)

A chain token (`qcore tor-warp`) is minted **iff all six hold**:

1. Every hyphen-separated segment resolves to exactly one registry token (a
   transport kind in its default mode, or a preset).
2. The expanded chain is within the depth cap. Over-depth tokens still parse and
   fail closed (exit 2) but are **not advertised**.
3. The name collides with no command alias, subcommand, or global flag name.
4. It is a pure alias: identical `ConnectionReport` and exit code as the long form.
5. It is generated from the registry with zero CLI edits (satisfies SC-002c).
6. It never encodes a mode-with-options (no `masque-h2` shortcut).

Unknown tokens are exit 6 and are never fuzzy-resolved. `qcore ls` lists the
advertised shortcuts; `status` always prints the expanded chain.

## Validation error format

Errors carry a stable code, the field path, expected vs got, and a suggested fix
with the offending hop index. Secrets are redacted in expected/got values.

```
qcore: invalid chain (exit 2)
  hop 0 `tor` -> hop 1 `wireguard` requires a UDP carrier
  ubuntu: no relay hop between a TCP-only carrier and a UDP egress
  fix:    insert `relay`:  --chain "tor,relay,wireguard peer=warp"
         or use the preset: --chain "tor-warp"
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (session up / command ok) |
| 2 | Invalid chain or validation failure (before any hop started) |
| 3 | Transport or hop failure (names hop + cause) |
| 4 | Scan found nothing reachable |
| 5 | Config import rejected |
| 6 | Usage error (unknown command/flag/field, missing required value off-TTY) |
| 10 | No session (status/stop) |
| 12 | Session unverifiable — fail closed |

## Contract guarantees

- Any capability in the CLI is reachable through the public API (FR-003c).
- Adding a transport adds **zero** CLI flags; it adds a registry row visible to
  `profiles`, help, and shortcuts (FR-006, SC-002c).
- `--json` output and the NDJSON event schema are stable and versioned alongside
  the public API.
- Invalid chains fail before any hop starts and exit `2` (FR-010).