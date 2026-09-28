# AGENTS.md

`qcore`: embeddable Rust tunnel engine core + pure CLI (WARP/WireGuard, MASQUE,
Tor, Psiphon sidecar, imported WG/AWG configs) composed into validated chains. No GUI.

Stack: Rust stable (pinned MSRV in `rust-toolchain.toml`), tokio, boringtun,
quinn + rustls/ring + h2, arti-client, `inventory`, serde/TOML/JSON.

Constitution (`.specify/memory/constitution.md`, v1.2.0) wins on any conflict.
Spec tasks T001-T094 (001) and T001-T037 (002) are all complete; this file routes, it DOES NOT restate.

## Commands

| Task | Command |
|---|---|
| Build | `cargo xtask build --release` |
| Local core gate (fmt, clippy, nextest, conformance, abi-diff) | `cargo xtask ci` |
| Supply chain | `cargo deny --config denylist.toml check` (policy lives in `denylist.toml`, not the deny default) |
| API semver | `cargo semver-checks --baseline-rev <base-sha>` (git baseline; crate unpublished, test suites excluded) |
| Secret scans | gitleaks CLI v8.30.1, trufflehog `--only-verified` (false positives: `.gitleaksignore` fingerprints) |
| Full CI gate | `.github/workflows/ci.yml` = core gate + supply chain + semver + scans + native smoke |
| Unit + contract tests | `cargo nextest run --all-features` |
| Conformance matrix | `cargo nextest run -p tests-conformance` |
| Lint | `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings` |
| C ABI diff | `cargo xtask abi-diff` |
| Per-target smoke | `cargo xtask smoke --target <triple>` |
| Release | `cargo xtask release` (tag-driven; KNOWN GAP triaged in #16, not yet proven end-to-end: release matrix builds 3/9 `targets.toml` entries (Windows-only) — expansion deferred, needs constitution amendment + runner capacity + tag dry-run; do not tag `v*` until complete; publish job already has checkout/toolchain/cosign; bare package/release = native artifact only, per-target publishing awaits dry-run bar, Tier C green defined in release.yml header) |

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
| `docs/BASE.md` | Aether fork record |
| `xtask/src/targets.toml` | The 9-target release contract (amendment to change) |

## Code map

```
crates/qcore-transport-api/src/lib.rs   plugin boundary (Descriptor, Dialer, RunningHop, HopFactory, register_plugin!)
crates/qcore-core/src/registry.rs       TransportRegistry from inventory
crates/qcore-core/src/chain/            parse.rs, preset.rs, validate.rs, mod.rs
crates/qcore-core/src/config/           hop.rs, import.rs, export.rs, obfuscation.rs, secret.rs, chain_file.rs
crates/qcore-core/src/session/          lifecycle.rs, net.rs, report.rs, reconnect.rs
crates/qcore-core/src/identity/         model.rs, store.rs, https.rs, register.rs, renew.rs, masque.rs, gool.rs, inject.rs, report.rs
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

## Skills

Rust: before editing Rust, load your area's row in `docs/rust-practices.md`
(governing skills + fastest verification command).