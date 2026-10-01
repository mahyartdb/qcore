//! US1 acceptance (T038): single-family availability. A v4-only stub and a
//! v6-only stub each connect on the available family with the family
//! reported; the session does not fail (spec SC-001/SC-002).

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::ExpandedHop;
use std::time::Duration;
use transport_mock::stub_peer::StubPeer;

fn engine_in(dir: &std::path::Path) -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig {
        dirs: qcore_core::config::profile_dir::ProfileDirs::resolve(Some(dir.to_path_buf()), None),
        ..Default::default()
    })
}

async fn roundtrip_on(family: &str, stub_mode: &str) {
    let work = std::env::temp_dir().join(format!("qcore-single-{family}-{}", std::process::id()));
    let engine = engine_in(&work);
    let stub = StubPeer::bind(stub_mode).await.unwrap();
    let dst = stub.udp_addrs[0];

    let spec =
        Engine::parse_single_hop("mock", &format!("family={family}")).expect("mock spec parses");
    let handle = engine
        .start(vec![ExpandedHop::Hop(spec)])
        .await
        .expect("session establishes on the available family");

    // Healthy tunnel through the exit hop to the stub echo.
    let flow = handle
        .dialer()
        .dial_udp(dst)
        .await
        .expect("dial_udp through session");
    flow.send_to(b"ping-1", dst).await.expect("send_to");
    let mut buf = [0u8; 32];
    // One retry: a loopback echo under parallel CI load can miss the first
    // 5 s window without the tunnel being at fault.
    let mut attempt = 0;
    let (n, from) = loop {
        match tokio::time::timeout(Duration::from_secs(5), flow.recv_from(&mut buf)).await {
            Ok(Ok(v)) => break v,
            Ok(Err(e)) => panic!("recv_from: {e}"),
            Err(_) if attempt == 0 => {
                attempt += 1;
                flow.send_to(b"ping-1", dst).await.expect("send_to");
                continue;
            }
            Err(_) => panic!("echo arrives"),
        }
    };
    assert_eq!(&buf[..n], b"ping-1");
    assert_eq!(from, dst);

    // Reported family matches the available family.
    let hops = handle.hop_reports();
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].family, family);

    handle.stop_all().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&work);
}

#[tokio::test]
async fn v4_only_stub_connects_on_ipv4() {
    roundtrip_on("ipv4", "ipv4").await;
}

#[tokio::test]
async fn v6_only_stub_connects_on_ipv6() {
    roundtrip_on("ipv6", "ipv6").await;
}
