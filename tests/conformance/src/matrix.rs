//! Generated dual-stack conformance harness (research R10, T033).
//!
//! Driven by the [`TransportRegistry`](qcore_core::registry): every registered
//! transport inherits its suite. A newly registered transport with no
//! canonical spec fails `every_registered_kind_has_canonical_spec` until its
//! story adds one — coverage without new test code.

use qcore_core::chain::ExpandedHop;

/// Canonical single-hop authoring per registered kind, used for preflight
/// matrix cases. Stories extend this table with transport-specific suites.
pub fn canonical_specs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("wireguard", "wireguard peer=warp"),
        ("masque", "masque alpn=h3"),
        ("tor", "tor"),
        ("psiphon", "psiphon sidecar_path=/usr/local/bin/psiphon"),
        ("relay", "relay"),
        ("mock", "mock"),
    ]
}

/// Parse a canonical spec line into authored hops.
pub fn parse_canonical(line: &str) -> Vec<ExpandedHop> {
    let (kind, rest) = match line.split_once(char::is_whitespace) {
        Some((k, r)) => (k, r),
        None => (line, ""),
    };
    let spec = qcore_core::api::Engine::parse_single_hop(kind, rest)
        .unwrap_or_else(|e| panic!("canonical spec must parse: {line}: {e}"));
    vec![ExpandedHop::Hop(spec)]
}
