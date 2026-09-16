# Contract: Public Rust API

The `core` crate exposes a versioned public API. Everything the CLI can do is
reachable here (FR-003c). Internal types are private.

## Stability

- Semver on the crate; breaking changes documented per FR-003f.
- The API is the source of truth; CLI and C ABI are adapters over it.

## Core types (public)

- `Engine` — facade, constructed from config.
- `TransportDescriptor` / `Capabilities` — static, known before instantiation.
- `Dialer` — the egress handed to the next hop:
  ```rust
  pub trait Dialer: Send + Sync {
      async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError>;
      async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError>;
      fn capabilities(&self) -> Capabilities;
  }
  ```
- `RunningHop` — a built hop: `descriptor()`, `dialer()`, `health()`, `events()`,
  `stop()`.
- `HopFactory` — the plugin boundary: `descriptor()`, `build(cfg, carrier)`.
  ```rust
  pub trait HopFactory: Send + Sync {
      fn descriptor(&self) -> &'static TransportDescriptor;
      async fn build(&self, cfg: HopConfig, carrier: Arc<dyn Dialer>)
          -> Result<Arc<dyn RunningHop>, HopError>;
  }
  ```
- `ByteStream` / `UdpFlow` — abstract async stream/datagram, so an inner hop can
  return a `smoltcp`-backed stream with no OS socket.
- `HopConfig`, `ChainSpec`, `CompositionPreset`, `ScanProfile`, `ObfuscationProfile`,
  `ConfigImport`, `EndpointCandidate`, `Session`, `ConnectionReport`,
  `FailureReport` — mirror data-model.md.

Registration: a transport crate calls `register_plugin!(Plugin)`; plugins are
collected by `inventory` into a `TransportRegistry`. Validation, the scanner,
`profiles`, help text, and the conformance suite read the registry, never a
`match kind`.

## Key operations

| Operation | Contract |
|---|---|
| `ChainBuilder::build(specs, max_depth)` | Expands presets, validates depth/cycles/ports/carrier compatibility from descriptors; returns `Result<Chain, ChainError>` before any start (FR-009/010/010a). |
| `Engine::preflight(specs)` | Validates a chain + profiles + config without starting a hop or opening a socket (FR-029). |
| `Engine::start(chain)` | Starts hops in declared order; returns `Session` or `FailureReport` (fail-closed, FR-027). |
| `Engine::status()` | Returns `ConnectionReport` (FR-025). |
| `Engine::subscribe()` | Returns a `HopEvent` stream (push, not poll). |
| `Engine::stop()` | Tears down all hops and the sidecar. |
| `Scanner::scan(kind, profile, family)` | Ranked, traffic-validated candidates (FR-014/016/017). |
| `ConfigImport::parse(bytes)` | Field-preserving; unknown fields rejected by name (FR-023). |
| `ConfigImport::export()` | Equivalent reproduction (FR-024). |

## Guarantees

- No public function logs or returns secrets in plaintext (FR-026).
- Validation is total: an invalid chain never partially starts.
- Address family is explicit and reported per hop (FR-013).
- `Hop` implementors must not require chain-engine changes to be added
  (Principle III); adding a transport touches only its own crate plus one feature
  line — never the engine, chain, CLI, or schemas (FR-006, SC-002c).