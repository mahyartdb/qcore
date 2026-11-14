//! Conformance matrix shapes: every registered transport preflights its
//! canonical spec, and per-target family modes parse. Real connect suites
//! land per story; this gate guarantees no registered transport ships
//! without one. (Hand-maintained despite the old "generated" name — no
//! generator exists; the file is named for what it checks.)

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::registry::TransportRegistry;
use tests_conformance::matrix::{canonical_specs, parse_canonical};

#[test]
fn every_registered_kind_has_canonical_spec() {
    let _ = qcore_transports::linked_kinds();
    let reg = TransportRegistry::global();
    let table = canonical_specs();
    for kind in reg.kinds() {
        assert!(
            table.iter().any(|(k, _)| *k == kind),
            "registered transport `{kind}` has no canonical spec (add it with its story)"
        );
    }
}

#[test]
fn canonical_specs_preflight_clean() {
    let _ = qcore_transports::linked_kinds();
    let engine = Engine::new(EngineConfig::default());
    for (kind, line) in canonical_specs() {
        // Skip kinds whose test doubles are not linked into this binary.
        if TransportRegistry::global().get(kind).is_none() {
            continue;
        }
        match engine.preflight(parse_canonical(line)) {
            qcore_core::api::engine::Preflight::Ok { depth } => {
                assert_eq!(depth, 1, "{kind}");
            }
            qcore_core::api::engine::Preflight::Rejected(e) => {
                panic!("canonical spec for `{kind}` rejected: {e}")
            }
        }
    }
}

#[test]
fn family_modes_parse_per_target() {
    for mode in ["ipv4", "ipv6", "dual"] {
        qcore_core::session::net::FamilyPolicy::parse(mode, "ipv4")
            .unwrap_or_else(|e| panic!("{mode}: {e}"));
    }
}
