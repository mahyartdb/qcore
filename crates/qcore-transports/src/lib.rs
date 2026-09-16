//! Meta-crate: feature-gated builtin transports (T013).
//!
//! Re-exports force linkage so each transport's `register_plugin!`
//! submission reaches the engine registry (FR-006). Adding a transport is
//! one crate + one `HopFactory` + one feature line here.

#[cfg(feature = "masque")]
pub use transport_masque as masque;
#[cfg(feature = "mock")]
pub use transport_mock as mock;
#[cfg(feature = "psiphon")]
pub use transport_psiphon as psiphon;
#[cfg(feature = "relay")]
pub use transport_relay as relay;
#[cfg(feature = "tor")]
pub use transport_tor as tor;
#[cfg(feature = "wireguard")]
pub use transport_wireguard as wireguard;

/// Force linkage of every enabled transport so their `register_plugin!`
/// submissions survive static-archive GC and reach the registry.
/// Call once at binary startup (CLI, tests).
pub fn linked_kinds() -> Vec<&'static str> {
    [
        #[cfg(feature = "wireguard")]
        Some(wireguard::plugin_descriptor().kind),
        #[cfg(feature = "masque")]
        Some(masque::plugin_descriptor().kind),
        #[cfg(feature = "relay")]
        Some(relay::plugin_descriptor().kind),
        #[cfg(feature = "tor")]
        Some(tor::plugin_descriptor().kind),
        #[cfg(feature = "psiphon")]
        Some(psiphon::plugin_descriptor().kind),
        #[cfg(feature = "mock")]
        Some(mock::plugin_descriptor().kind),
    ]
    .into_iter()
    .flatten()
    .collect()
}
