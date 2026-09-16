//! US3 grammar tests (T054): full chain expressions parse into authored hops
//! with the last hop as exit; quoting, labels, preset rules and failures.

use qcore_core::chain::{parse::parse_chain, preset::builtin_presets, ExpandedHop};

fn parse(expr: &str) -> Result<Vec<ExpandedHop>, String> {
    let _ = qcore_transports::linked_kinds();
    let registry = qcore_core::registry::TransportRegistry::global();
    parse_chain(expr, &registry, &builtin_presets()).map_err(|e| e.to_string())
}

fn kinds(specs: &[ExpandedHop]) -> Vec<String> {
    specs
        .iter()
        .map(|s| match s {
            ExpandedHop::Hop(h) => h.config.kind().to_string(),
            ExpandedHop::Preset(p) => format!("preset:{p}"),
        })
        .collect()
}

#[test]
fn multi_hop_with_options_parses_in_order() {
    let specs = parse("mock,relay,mock family=ipv4").unwrap();
    assert_eq!(kinds(&specs), vec!["mock", "relay", "mock"]);
    // Last hop is the exit; per-hop options land on the right hop.
    let ids: Vec<String> = specs
        .iter()
        .map(|s| match s {
            ExpandedHop::Hop(h) => h.id.clone(),
            ExpandedHop::Preset(p) => p.clone(),
        })
        .collect();
    assert_eq!(ids, vec!["mock-0", "relay-1", "mock-2"]);
}

#[test]
fn label_becomes_hop_id() {
    let specs = parse("mock @edge,relay").unwrap();
    match &specs[0] {
        ExpandedHop::Hop(h) => assert_eq!(h.id, "edge"),
        ExpandedHop::Preset(_) => panic!("expected hop"),
    }
}

#[test]
fn bare_preset_and_bare_kind() {
    assert_eq!(kinds(&parse("gool").unwrap()), vec!["preset:gool"]);
    assert_eq!(kinds(&parse("mock").unwrap()), vec!["mock"]);
}

#[test]
fn quoted_values_survive_commas_and_spaces() {
    let specs = parse(r#"wireguard peer=warp endpoint="10.0.0.1:51820",tor"#).unwrap();
    assert_eq!(kinds(&specs), vec!["wireguard", "tor"]);
    match &specs[0] {
        ExpandedHop::Hop(h) => match &h.config {
            qcore_core::config::HopConfig::Wireguard(c) => {
                assert_eq!(c.endpoint.as_deref(), Some("10.0.0.1:51820"))
            }
            _ => panic!("expected wireguard"),
        },
        ExpandedHop::Preset(_) => panic!("expected hop"),
    }
}

#[test]
fn unknown_key_names_field() {
    let err = parse("mock bogus=1").expect_err("unknown key");
    assert!(err.contains("bogus"), "names field: {err}");
}

#[test]
fn unknown_name_rejected() {
    let err = parse("frobnicate").expect_err("unknown transport");
    assert!(err.contains("frobnicate"), "names token: {err}");
}

#[test]
fn preset_with_options_rejected() {
    let err = parse("gool family=ipv4").expect_err("preset takes no options");
    assert!(err.contains("gool"), "names preset: {err}");
}

#[test]
fn unquoted_equals_rejected() {
    // mock has no `=`-valued keys, so probe via wireguard endpoint.
    let err = parse("wireguard endpoint=10.0.0.1:51820=x").expect_err("unquoted =");
    assert!(err.contains("quoted"), "must be quoted: {err}");
}

#[test]
fn trailing_comma_rejected() {
    assert!(parse("mock,").is_err());
}
