# AGENTS.md

`qcore`: embeddable Rust tunnel engine core + pure CLI (WARP/WireGuard, MASQUE,
Tor, Psiphon sidecar, imported WG/AWG configs) composed into validated chains. No GUI.

Stack: Rust stable (pinned MSRV in `rust-toolchain.toml`), tokio, boringtun,
quinn + rustls/ring + h2, arti-client, `inventory`, serde/TOML/JSON.

Constitution (`.specify/memory/constitution.md`, v1.1.0) wins on any conflict.
Spec tasks T001–T094 are all complete — this file routes; it does not restate.

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

`cargo xtask` resolves via the `[alias]` in `.cargo/config.toml`.

## Doc map (read the row before touching the area)

| File | Decides |
|---|---|
| `.specify/memory/constitution.md` | Non-negotiables (I–VI), security constraints, workflow gates |
| `specs/001-multi-protocol-vpn/spec.md` | FR-001–FR-029, SC-001–SC-008, edge cases, presets, tiers, emergency path |
| `specs/001-multi-protocol-vpn/plan.md` | Architecture, plugin boundary, release pipeline, arena resolutions |
| `specs/001-multi-protocol-vpn/tasks.md` | T001–T094 status + audit adjudications in Notes |
| `specs/001-multi-protocol-vpn/research.md` | R1–R18 decisions (providers, sidecar, obfuscation, xtask) |
| `specs/001-multi-protocol-vpn/data-model.md` | Entities: descriptors, configs, chain, profiles, session, reports |
| `specs/001-multi-protocol-vpn/contracts/` | `cli.md` + `cli-reference.md`, `public-api.md`, `c-abi.md`, `config-formats.md` |
| `specs/001-multi-protocol-vpn/checklists/` | Reviewer-owned quality gates — `requirements.md` passed; the rest are not work markers |
| `specs/001-multi-protocol-vpn/quickstart.md` | Scenarios 1–8 |
| `specs/002-warp-registration-scan/` | WARP/GOOL/MASQUE registration + renewal + seeded scan (spec, plan, tasks T001–T037) |
| `BASE.md` | Aether fork record |
| `xtask/src/targets.toml` | The 9-target release contract (amendment to change) |

## Code map

```
crates/qcore-transport-api/src/lib.rs   plugin boundary (Descriptor, Dialer, RunningHop, HopFactory, register_plugin!)
crates/qcore-core/src/registry.rs       TransportRegistry from inventory
crates/qcore-core/src/chain/            parse.rs, preset.rs, validate.rs, mod.rs
crates/qcore-core/src/config/           hop.rs, import.rs, export.rs, obfuscation.rs, secret.rs, chain_file.rs
crates/qcore-core/src/session/          lifecycle.rs, net.rs, report.rs, reconnect.rs
crates/qcore-core/src/identity/         model.rs, store.rs, https.rs, register.rs, renew.rs, masque.rs, gool.rs, report.rs
crates/qcore-core/src/scan/             mod.rs Scanner, seeds.rs warp.toml candidates, cache.rs per-transport winners
crates/qcore-cli/src/cmd/               register.rs, renew.rs (+ license.rs shared key input)
crates/qcore-core/src/diag/             redact.rs, events.rs (NDJSON stream)
crates/qcore-transports/transport-*/    one crate per transport (mock = test double)
crates/qcore/src/lib.rs                 facade for embedders
crates/qcore-cli/src/                   main.rs + cmd/ per command + help.rs lawful-use text
crates/qcore-ffi/src/                   lib.rs (11 qcore_* fns), qcore.h, abi-version.txt, jni.rs
profiles/                               scan.toml, obfuscation.toml, compositions.toml, warp.toml (002 candidates)
tests/conformance/tests/                matrix_generated, wireguard, masque, tor_psiphon, failure_report,
                                        single_stack, scan, obfuscation, extensibility, cli_api_parity,
                                        secret_hygiene, abi_consumer, throughput,
                                        registration, auto_register, scan_providers, renewal, masque_enroll (002)
tests/chains/tests/                    orderings, rejections, grammar, import_roundtrip, imported_chain
tests/fixtures/                        standard-wg.conf, awg.conf, bogus.conf
examples/embed-host/  examples/c-abi-consumer/main.go
xtask/src/                             build, smoke, package, release, abi_diff
```

## Working rules

- Read the doc-map row for the area before editing; read the file before changing it.
- Verify through execution (`xtask ci` or the scoped command), not by re-reading.
- Docs and code disagree? Code describes behavior, constitution decides policy —
  surface the conflict, never silently pick a side.
