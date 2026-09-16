//! qcore facade (T074): single stable import path for embedders.
//!
//! Embedders depend on this crate only and reach every engine capability
//! through the re-exported public types — never through `qcore-core` or a
//! transport crate directly (FR-003c). Transports link via the
//! `qcore-transports` meta-crate (feature-gated); the engine discovers them
//! through the [`registry`], never by matching on a kind.

pub use qcore_core::{api, chain, config, diag, registry, scan, session};

pub use qcore_core::api::{
    Engine, EngineConfig, Preflight, ABI_VERSION, API_VERSION, SCHEMA_VERSION,
};

pub use qcore_transport_api::{
    ByteStream, Capabilities, Dialer, FailureLayer, FailureReport, HopConfig, HopError,
    HopErrorKind, HopEvent, HopFactory, HopHealth, ObfuscationFamily, RunningHop,
    TransportDescriptor, UdpFlow,
};
