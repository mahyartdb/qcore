# Adding a transport to qcore — the real checklist

A transport is a plugin behind three traits plus one static descriptor. The
engine reads descriptors from the `inventory`-built
[`TransportRegistry`](../crates/qcore-core/src/registry.rs) and never matches
on a transport kind, so a new transport touches exactly the seven places
below — never the engine, the validator, or the CLI.

Worked example: `transport-mock`
(`crates/qcore-transports/transport-mock/`), the smallest real
implementation. Read it beside this checklist.

## The 7 edit points

1. **The crate** — `crates/qcore-transports/transport-<name>/`
   (`Cargo.toml` + `src/lib.rs`).
   - Dependencies: `qcore-transport-api` + `async-trait` + `tokio`
     (see `transport-mock/Cargo.toml`). Nothing else is allowed to reach the
     engine from here.
   - Define one `static DESCRIPTOR: TransportDescriptor` (`kind`, four
     `Capabilities` booleans, `obfuscation_families`, `config_schema` like
     `"<name>/v1"`, `needs_sidecar`).
   - Implement `HopFactory` (and expose the factory as a static):
     `build(cfg, carrier) -> Result<Arc<dyn RunningHop>, HopError>`.

2. **The `HopFactory` impl** (inside that crate; listed separately because
   it carries hard rules — AGENTS.md "Transport impl rules"):
   - Timeout on EVERY dial/handshake/readiness path.
   - `tokio::Mutex` may be held across await; `std` locks never on async
     paths.
   - `build` must be cancellation-safe: the engine races it with `timeout`;
     any partial sockets/sidecars are owned by the future and released on
     drop.
   - Parse the boundary into typed configs; fail closed naming the field.
     Even the mock is strict here: unknown fields are a `HopErrorKind::Config`
     error, never silently ignored (`transport-mock/src/lib.rs:61-71`).
   - `bare unwrap()` → `expect(reason)`; bind via `unspecified_bind(dst)`,
     never parse `"0.0.0.0:0"` literals.
   - New `HopFactory` trait methods get defaults — never a breaking change
     for existing transports.
   - Register with `qcore_transport_api::register_plugin!(&FACTORY);` and
     expose `pub fn plugin_descriptor() -> &'static TransportDescriptor`
     as the linkage anchor.

3. **The feature line** — `crates/qcore-transports/Cargo.toml`:
   ```toml
   [features]
   <name> = ["dep:transport-<name>"]
   [dependencies]
   transport-<name> = { version = "0.1.0", package = "qcore-transport-<name>", path = "transport-<name>", optional = true }
   ```
   Decide the default set deliberately: current default is
   `wireguard,masque,relay,psiphon,mock`; `tor` is opt-in because of its
   dependency weight (mock is default because tests need it offline).

4. **The dep line / workspace membership** — the new crate joins
   `[workspace] members` in the root `Cargo.toml`
   (`crates/qcore-transports/transport-<name>`), and any test/binary crate
   that exercises it adds its own path dep (see
   `tests/conformance/Cargo.toml` for the `transport-*` pattern with the
   `package = "qcore-transport-<name>"` rename).

5. **`pub use` in the meta-crate** — `crates/qcore-transports/src/lib.rs`:
   ```rust
   #[cfg(feature = "<name>")]
   pub use transport_<name> as <name>;
   ```
   This re-export forces linkage so the crate's `register_plugin!`
   submission survives static-archive GC.

6. **The `linked_kinds()` arm** — same file (`lib.rs`):
   ```rust
   #[cfg(feature = "<name>")]
   Some(<name>::plugin_descriptor().kind),
   ```
   Binaries and tests must call `qcore_transports::linked_kinds()` once at
   startup, or the submissions never reach the registry (AGENTS.md gotcha).
   Missing this arm means the transport builds fine but is silently absent
   from every registry — the matrix test in step 7 is what catches it.

7. **The `canonical_specs()` entry + matrix test** —
   `tests/conformance/src/matrix.rs::canonical_specs()` gets a
   `("<name>", "<name> [opts]")` line, and the conformance matrix tests
   (`tests/conformance/tests/matrix_shapes.rs`) then enforce:
   - `every_registered_kind_has_canonical_spec`: a registered kind with no
     canonical spec FAILS — coverage without new test code.
   - `canonical_specs_preflight_clean`: the spec must preflight `Ok{depth:1}`.
   Two registration traps to know:
   - The conformance crate's default `qcore-transports` features exclude
     `tor`, so the shared matrix silently skipped that kind. If your
     transport is not in the default feature set, add a dedicated test
     target with `required-features` (see `[[test]] name = "tor_preflight"`
     in `tests/conformance/Cargo.toml`) instead of relying on the shared
     matrix.
   - Feature-gated kinds are invisible wherever the feature is off: the
     matrix "skips kinds whose test doubles are not linked", which is a
     pass-with-a-gap, not coverage.

## What you must NOT touch

- `crates/qcore-core/src/chain/validate.rs` — carrier/sidecar/depth rules
  come from descriptors; a transport never requires validator edits (FR-006).
- `crates/qcore-cli` — nothing CLI-side knows transport kinds.
- `allowed_fields()` (`crates/qcore-core/src/config/hop.rs`) only if you add
  a NEW builtin (typed `HopConfig` variant). Plugin transports carry config
  opaquely via `HopConfig::Plugin` and skip this entirely. Builtin additions
  are rare and need the grammar arm + deserialize arm in the same file.

## Verification

```sh
cargo nextest run -p tests-conformance          # matrix incl. canonical preflight
cargo clippy -p qcore-transports --all-targets --all-features -- -D warnings
cargo nextest run -p qcore-transport-<name>
```

CI must link the transport somewhere real (`linked_kinds()` exercised) or it
ships unregistered — the matrix test failing with "registered transport
`<name>` has no canonical spec" or "no canonical spec entry" is the expected
first signal, not a false alarm.
