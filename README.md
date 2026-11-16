# qcore

Multi-protocol VPN tunnel core in Rust: an engine with pluggable transports
(WireGuard/WARP, MASQUE, Tor via arti, Psiphon, relay adapter, mock test
double), chain composition with presets (gool, mim, tor-warp), a CLI, and a
C/JNI FFI surface. Edition 2021, pinned toolchain via `rust-toolchain.toml`.

- Engine surface: `qcore_core::api::Engine`; embedders depend only on the
  facade crate `crates/qcore`.
- Plugin boundary: three traits (`HopFactory` / `RunningHop` / `Dialer`) +
  static `TransportDescriptor`. Adding a transport = 7 edit points, see
  [docs/transport-authoring.md](docs/transport-authoring.md).
- CLI contract (streams, exit codes, `--json` discipline): normative text in
  [contracts/cli.md](contracts/cli.md).

## Quickstart

Requires a Rust toolchain matching `rust-toolchain.toml`.

```sh
# Fast local gate: fmt -> clippy -> workspace tests -> conformance -> abi-diff -> smoke
cargo xtask ci

# Per-area suites (nextest, not cargo test)
cargo nextest run -p tests-conformance
cargo nextest run -p tests-chains
cargo nextest run -p qcore-core --lib session::

# Offline smoke of the native target
cargo xtask smoke --target native
```

The `cargo xtask` alias lives in `.cargo/config.toml`; subcommands:
`build|smoke|package|release|abi-diff|ci`. Always pass `--workspace` for
clippy/nextest — `default-members` is only `qcore/cli/ffi`, so the core and
transport suites silently never run without it.

## CLI in one minute

```sh
qcore preflight --chain mock          # validate, zero sockets
qcore connect --chain mock --detach   # bring up a session
qcore status                          # session report
qcore stop                            # tear down
```

`--bind` serves a loopback SOCKS5 proxy through the exit hop; hostname
targets resolve via tunnel-routed DNS (default resolver 1.1.1.1 inside the
tunnel, override with `--dns <ip>`) so domain names never reach the OS
resolver. Exits that resolve hostnames themselves (tor, via remote-side
DNS) dial the name directly.

## Docker

Multi-stage build (builder pinned to the `rust-toolchain.toml` toolchain,
runtime on `debian:bookworm-slim`, non-root user):

```sh
docker build -t qcore .
# Bind 0.0.0.0 INSIDE the container (loopback there is unreachable from
# the host); publish the port instead. Container localhost ≠ host
# localhost, so --expose-lan is not needed for a published port.
docker run --rm -p 1080:1080 qcore connect --chain warp --bind 0.0.0.0:1080
```

Status/stop from the host need the control port published too; run in the
foreground (`--detach` only detaches inside the container). Note the proxy
is an UNAUTHENTICATED endpoint for anything that can reach the published
port — the same warning as `--expose-lan` on the host applies, and the
container adds nothing to the peer filter's reach. Never publish it on an
untrusted network. HEALTHCHECK is omitted by design: a bare TCP probe
cannot authenticate against the control channel, so it would lie.

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | ok |
| 1 | session dead (status verdict) |
| 2 | invalid chain / config (validation, before any hop) |
| 3 | hop failure (transport / chain / sidecar / config) |
| 4 | scan empty (`{"candidates":[]}` on stdout) |
| 5 | import rejected (names each offending field) |
| 6 | usage error (also: `ls --json`) |
| 10 | no session |
| 12 | unverifiable — fail closed, never a false green |

stdout is results (with `--json`, exactly one JSON document), stderr is
diagnostics as `qcore: <msg> (exit N)`. Full contract:
[contracts/cli.md](contracts/cli.md).

## Repository map

- [AGENTS.md](AGENTS.md) — contributor quick rules: commands, architecture
  gotchas, release discipline. Read this first.
- [docs/rust-practices.md](docs/rust-practices.md) — per-area rule-to-check
  mapping with the fastest verification command per area.
- [contracts/cli.md](contracts/cli.md) — normative CLI/exit-code contract the
  code cites.
- [docs/transport-authoring.md](docs/transport-authoring.md) — how to add a
  transport (worked example: transport-mock).
- [profiles/](profiles/) — data, not code: scan/obfuscation/composition
  profiles.
- [SECURITY.md](SECURITY.md) — vulnerability reporting + advisory handling.

## Licensing

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option (`license = "MIT OR Apache-2.0"` across the workspace). The
`docs/BASE.md` provenance notes describe fork history and are separate from
qcore's own licensing, which the two LICENSE files here make explicit.

## Status

Release discipline is deliberately strict: `xtask/src/targets.toml` is the
9-target contract, the tag matrix currently proves 3/9 (Windows-only), and
tagging `v*` is prohibited until the full matrix has a dry-run pass (see
AGENTS.md). Local `cargo xtask release` fails closed without
`--allow-partial-matrix`.
