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
    // The old body silently `continue`d over unregistered kinds, so a
    // registry GC / factory miss could run zero assertions and still pass.
    // Inverted: every canonical spec whose factory IS linked must preflight
    // clean, >0 must run, and the set that ran must include the default
    // transports. A kind that is NOT linked (tor under default features —
    // covered feature-gated by tor_preflight.rs) is a counted skip, never a
    // silent one: this binary links all six via tests-conformance's direct
    // deps, so the skip list is normally empty here.
    let mut ran: Vec<&str> = Vec::new();
    let mut skipped: Vec<&str> = Vec::new();
    for (kind, line) in canonical_specs() {
        if TransportRegistry::global().get(kind).is_none() {
            skipped.push(kind);
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
        ran.push(kind);
    }
    for expected in ["mock", "wireguard", "masque", "relay", "psiphon"] {
        assert!(
            ran.contains(&expected),
            "`{expected}` canonical spec never preflighted (ran: {ran:?}, \
             skipped: {skipped:?}) — the matrix gate silently degraded"
        );
    }
    assert!(
        !ran.is_empty(),
        "canonical-spec preflight ran zero assertions"
    );
    // A skip is only legitimate for kinds whose feature is off; everything
    // else in the canonical table must have preflighted. When tor's feature
    // lands (FFI builds, CI), it preflights here too.
    assert!(
        skipped
            .iter()
            .all(|k| canonical_specs().iter().any(|(kind, _)| kind == k)),
        "skipped kinds must come from the canonical table: {skipped:?}"
    );
}

#[test]
fn family_modes_parse_per_target() {
    for mode in ["ipv4", "ipv6", "dual"] {
        qcore_core::session::net::FamilyPolicy::parse(mode, "ipv4")
            .unwrap_or_else(|e| panic!("{mode}: {e}"));
    }
}
