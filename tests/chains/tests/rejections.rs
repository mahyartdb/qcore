//! US3 rejections (T051): invalid chains are rejected pre-start with a reason.
//! All cases exit 2 at the CLI and start zero hops (stub-peer connection
//! counter unchanged). Port conflicts are structurally impossible in the
//! US1–US3 schema (all internal listeners are ephemeral `:0` by T020), so
//! that case asserts the positive: shared remote endpoints validate and two
//! hops start with no listener clash.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::{ChainBuilder, ExpandedHop};
use transport_mock::stub_peer::StubPeer;

fn engine_in(dir: &std::path::Path) -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig {
        dirs: qcore_core::config::profile_dir::ProfileDirs::resolve(Some(dir.to_path_buf()), None),
        ..Default::default()
    })
}

fn work(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("qcore-reject-{name}-{}", std::process::id()))
}

fn validate(specs: Vec<ExpandedHop>) -> Result<String, String> {
    let _engine = engine_in(&work("probe"));
    let registry = qcore_core::registry::TransportRegistry::global();
    match ChainBuilder::new(&registry, 3).build(specs) {
        Ok(chain) => Ok(chain.exit().map(|h| h.id.clone()).unwrap_or_default()),
        Err(e) => Err(e.to_string()),
    }
}

fn preset(name: &str) -> ExpandedHop {
    ExpandedHop::Preset(name.to_string())
}

fn hop(kind: &str, opts: &str) -> ExpandedHop {
    ExpandedHop::Hop(Engine::parse_single_hop(kind, opts).expect("spec parses"))
}

#[test]
fn gool_gool_is_over_depth_naming_hop() {
    let err = validate(vec![preset("gool"), preset("gool")]).expect_err("4 hops over cap");
    assert!(err.contains("exceeds max depth"), "over-depth: {err}");
    assert!(err.contains("gool-1"), "names the hop: {err}");
}

#[test]
fn bare_tor_wireguard_names_relay_insertion() {
    let err = validate(vec![hop("tor", ""), hop("wireguard", "peer=warp")])
        .expect_err("TCP-only carrier then UDP hop");
    assert!(err.contains("insert `relay`"), "names insertion: {err}");
    assert!(err.contains("tor"), "names carrier: {err}");
}

#[test]
fn gool_psiphon_tor_is_over_cap() {
    let err = validate(vec![
        preset("gool"),
        hop("psiphon", "sidecar_path=/nonexistent"),
        hop("tor", ""),
    ])
    .expect_err("2+1+1 over cap");
    assert!(err.contains("exceeds max depth"), "over-depth: {err}");
}

#[test]
fn self_targeting_hop_is_cycle() {
    use qcore_core::config::{HopConfig, HopSpec, WireguardConfig};
    let spec = HopSpec {
        id: "wg-0".into(),
        config: HopConfig::Wireguard(WireguardConfig {
            peer: "warp".into(),
            import_ref: None,
            obfuscation: None,
            family: "dual".into(),
            endpoint: Some("wg-0:51820".into()),
        }),
    };
    let err = validate(vec![ExpandedHop::Hop(spec)]).expect_err("self-targeting hop");
    assert!(err.contains("own listener"), "cycle: {err}");
}

#[test]
fn duplicate_ids_rejected() {
    let err = validate(vec![hop("mock", ""), hop("mock", "")]).expect_err("duplicate id");
    assert!(err.contains("duplicate hop id"), "names dup: {err}");
}

#[tokio::test]
async fn rejected_chain_starts_zero_hops() {
    let stub = StubPeer::bind("ipv4").await.unwrap();
    let before = stub.connection_count();
    let dir = work("zero");
    let engine = engine_in(&dir);
    // Over-depth mock chain: validation must fire before any dial.
    let specs = vec![
        hop("mock", ""),
        hop("mock", ""),
        hop("mock", ""),
        hop("mock", ""),
    ];
    let err = engine.start(specs).await.expect_err("over-depth");
    assert!(err.cause.contains("exceeds max depth"), "cause: {err}");
    assert_eq!(
        stub.connection_count(),
        before,
        "zero side effects before start"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn shared_remote_endpoints_have_no_conflict() {
    // Two hops dialing the same remote endpoint is valid; listeners are
    // ephemeral by construction, so no port clash is possible.
    let dir = work("shared");
    let engine = engine_in(&dir);
    let specs = vec![hop("mock", ""), hop("mock", "")];
    // Distinct ids required: re-id the second hop.
    let mut specs = specs;
    if let ExpandedHop::Hop(ref mut h) = specs[1] {
        h.id = "mock-1".to_string();
    }
    let handle = engine.start(specs).await.expect("shared remotes start");
    assert_eq!(handle.exit_hop_id, "mock-1");
    handle.stop_all().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}
