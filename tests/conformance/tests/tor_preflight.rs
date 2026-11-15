//! Tor canonical-spec coverage (fix wave E): the default conformance
//! feature set excludes `tor`, so `canonical_specs_preflight_clean`
//! silently skipped the kind. This target requires
//! `qcore-transports/tor`: the tor descriptor must be registered
//! (linked_kinds carries it) and its canonical spec must preflight clean,
//! depth 1, like every other registered transport. Where tor does not
//! build, nextest skips the whole target — the coverage claim is explicit
//! instead of implicit-by-skip.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::registry::TransportRegistry;
use tests_conformance::matrix::{canonical_specs, parse_canonical};

fn tor_canonical_line() -> &'static str {
    canonical_specs()
        .iter()
        .find(|(k, _)| *k == "tor")
        .map(|(_, line)| *line)
        .expect("tor has a canonical spec entry in the matrix table")
}

#[test]
fn tor_descriptor_is_registered_when_feature_enabled() {
    let linked = qcore_transports::linked_kinds();
    assert!(
        linked.contains(&"tor"),
        "tor feature is on for this target: linked_kinds must carry it ({linked:?})"
    );
    let reg = TransportRegistry::global();
    let d = reg
        .get("tor")
        .expect("tor registered in the transport registry");
    assert_eq!(d.config_schema, "tor/v1");
    assert!(!d.capabilities.dials_udp, "tor is TCP-only");
    assert!(d.capabilities.dials_tcp);
    assert!(!d.needs_sidecar);
}

#[test]
fn tor_canonical_spec_preflights_clean() {
    let _ = qcore_transports::linked_kinds();
    let engine = Engine::new(EngineConfig::default());
    // The registry must actually resolve tor before the preflight claim
    // means anything (guard against a silent descriptor miss like the one
    // this target exists to close).
    assert!(
        TransportRegistry::global().get("tor").is_some(),
        "tor must be registered for this target's preflight to be meaningful"
    );
    match engine.preflight(parse_canonical(tor_canonical_line())) {
        qcore_core::api::engine::Preflight::Ok { depth } => {
            assert_eq!(depth, 1, "canonical tor spec is single-hop");
        }
        qcore_core::api::engine::Preflight::Rejected(e) => {
            panic!("canonical spec for `tor` rejected: {e}")
        }
    }
}
