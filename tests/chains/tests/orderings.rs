//! US3 orderings (T050): named compositions establish in declared order with
//! the last hop as exit. Offline-capable chains (mock, relay) run live with
//! egress through the declared exit; compositions needing the network assert
//! expansion + exit + preflight here and establish nightly.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::{ChainBuilder, ExpandedHop};
use std::time::Duration;
use transport_mock::stub_peer::StubPeer;

fn engine_in(dir: &std::path::Path) -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig {
        dirs: qcore_core::config::profile_dir::ProfileDirs::resolve(Some(dir.to_path_buf()), None),
        ..Default::default()
    })
}

fn work(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("qcore-order-{name}-{}", std::process::id()))
}

fn hop_id(kind: &str, opts: &str, id: &str) -> ExpandedHop {
    let mut spec = Engine::parse_single_hop(kind, opts).expect("spec parses");
    spec.id = id.to_string();
    ExpandedHop::Hop(spec)
}

fn preset(name: &str) -> ExpandedHop {
    ExpandedHop::Preset(name.to_string())
}

fn kinds_of(specs: &[ExpandedHop]) -> Vec<String> {
    let _ = qcore_transports::linked_kinds();
    let registry = qcore_core::registry::TransportRegistry::global();
    let chain = ChainBuilder::new(&registry, 5)
        .build(specs.to_vec())
        .unwrap();
    chain
        .hops
        .iter()
        .map(|h| h.config.kind().to_string())
        .collect()
}

#[test]
fn preset_shapes_and_exits() {
    assert_eq!(kinds_of(&[preset("gool")]), vec!["wireguard", "wireguard"]);
    assert_eq!(kinds_of(&[preset("mim")]), vec!["masque", "masque"]);
    assert_eq!(
        kinds_of(&[preset("tor-warp")]),
        vec!["tor", "relay", "wireguard"]
    );
}

#[test]
fn named_compositions_are_valid_with_last_hop_exit() {
    let _e = engine_in(&work("probe"));
    let registry = qcore_core::registry::TransportRegistry::global();
    // (composition, expected exit id): single-hop and all-same-kind valid.
    let cases: Vec<(Vec<ExpandedHop>, &str)> = vec![
        (vec![preset("tor-warp")], "warp-0"),
        (vec![preset("gool")], "gool-1"),
        (vec![preset("mim")], "mim-1"),
        (
            vec![
                hop_id("wireguard", "peer=warp", "warp-0"),
                hop_id("tor", "", "tor-0"),
            ],
            "tor-0",
        ),
        (
            vec![
                hop_id("wireguard", "peer=warp", "warp-0"),
                hop_id("psiphon", "sidecar_path=/nonexistent", "psi-0"),
            ],
            "psi-0",
        ),
        (
            vec![
                hop_id("psiphon", "sidecar_path=/nonexistent", "psi-0"),
                hop_id("wireguard", "peer=warp", "warp-0"),
            ],
            "warp-0",
        ),
        (
            vec![
                hop_id("tor", "", "tor-0"),
                hop_id("relay", "", "relay-0"),
                hop_id("wireguard", "peer=warp", "warp-0"),
            ],
            "warp-0",
        ),
    ];
    for (specs, exit) in cases {
        let chain = ChainBuilder::new(&registry, 3)
            .build(specs)
            .expect("named composition validates");
        assert_eq!(chain.exit().unwrap().id, exit, "exit is the last hop");
    }
}

async fn live_egress(specs: Vec<ExpandedHop>, exit: &str, tag: &str, udp: bool) {
    let dir = work(tag);
    let engine = engine_in(&dir);
    let stub = StubPeer::bind("dual").await.unwrap();
    // The relay frames over a carrier TCP connection, so a relay-carried
    // flow dials a TCP echo target; plain flows dial UDP echo.
    let dst = if udp {
        stub.udp_addrs[0]
    } else {
        stub.tcp_addr(false).unwrap()
    };
    let handle = engine.start(specs).await.expect("chain establishes");
    assert_eq!(handle.exit_hop_id, exit, "exit is the last hop");
    let flow = handle.dialer().dial_udp(dst).await.expect("exit egress");
    flow.send_to(b"chain-e2e", dst).await.expect("send");
    let mut buf = [0u8; 32];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), flow.recv_from(&mut buf))
        .await
        .expect("echo arrives")
        .expect("recv");
    assert_eq!(&buf[..n], b"chain-e2e");
    assert_eq!(from, dst);
    handle.stop_all().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn mock_mock_establishes_with_exit_egress() {
    live_egress(
        vec![hop_id("mock", "", "mock-0"), hop_id("mock", "", "mock-1")],
        "mock-1",
        "mm",
        true,
    )
    .await;
}

#[tokio::test]
async fn mock_relay_mock_establishes_with_exit_egress() {
    live_egress(
        vec![
            hop_id("mock", "", "mock-0"),
            hop_id("relay", "", "relay-0"),
            hop_id("mock", "", "mock-1"),
        ],
        "mock-1",
        "mrm",
        false,
    )
    .await;
}
