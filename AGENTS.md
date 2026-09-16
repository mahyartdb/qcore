# AGENTS.md

Runtime development guidance for agents and contributors. Must stay consistent with
`.specify/memory/constitution.md`.

## What this project is

`qcore` is an embeddable, cross-platform Rust tunnel **engine core** plus a pure CLI.
It composes WARP/WireGuard, MASQUE (h3/h2), MASQUE-in-MASQUE, WARP-in-WARP, Tor,
Psiphon (Cfon), and imported WireGuard/AmneziaWG configs into user-declared,
validated, arbitrarily ordered chains over IPv4 and IPv6. No GUI.

## Repository layout

```
crates/qcore-transport-api/   public plugin boundary (traits, descriptors)
crates/qcore-core/            engine, registry, chain, session, scan, config, diag
crates/qcore-transports/      feature-gated builtin transports
crates/qcore/                 facade crate re-exported for embedders
crates/qcore-cli/             thin CLI
crates/qcore-ffi/             cdylib + qcore.h + JNI wrapper
examples/embed-host/          Rust host proving the public API
profiles/                     scan/obfuscation/composition data
xtask/                        the release lever
```

## Commands

| Task | Command |
|---|---|
| Build | `cargo xtask build --release` |
| Full local gate (what CI runs) | `cargo xtask ci` |
| Unit + contract tests | `cargo nextest run --all-features` |
| Conformance matrix | `cargo nextest run -p tests-conformance` |
| Lint | `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings` |
| C ABI diff | `cargo xtask abi-diff` |
| Per-target smoke | `cargo xtask smoke --target <triple>` |
| Release | `cargo xtask release` (tag-driven) |

## Supported targets (release contract)

- Windows: `i686-pc-windows-msvc`, `x86_64-pc-windows-msvc`,
  `aarch64-pc-windows-msvc`
- Linux: `i686`/`x86_64`/`aarch64`/`armv7` (gnu + musl)
- Android: `armv7-linux-androideabi`, `aarch64-linux-android` (Termux CLI + cdylib/JNI)

Windows 32-bit ARM is excluded. Changing this list requires a constitution amendment.

## Rules that bite

- A transport is a plugin. Adding one MUST NOT require edits to the engine, chain
  validator, CLI, or schemas. See `crates/qcore-transports` for the recipe.
- Capabilities are descriptor data known before a hop starts. Never encode
  capability in a return value.
- Chain depth is hop count after composition-preset expansion (default cap 3).
- Never log, persist, or export secrets. Redaction is central in `qcore-core::diag`.
- Profiles are data, not code branches.
- Fail closed: an invalid chain must produce zero side effects before any hop starts.
- Prefer deletion. A new crate/module/trait must name what it could have extended
  and why it did not.