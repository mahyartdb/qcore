//! US3 relay acceptance (T7 story 20): the UDP-over-TCP framing adapter
//! establishes standalone over loopback, carries traffic both ways, and fails
//! closed naming transport + cause when unreachable. Offline only.

use qcore_transport_api::{HopConfig, HopFactory};
use std::net::SocketAddr;
use std::time::Duration;
use tests_conformance::testutil::closed_port;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn carrier() -> std::sync::Arc<dyn qcore_transport_api::Dialer> {
    qcore_core::session::net::root_dialer(
        qcore_core::session::net::FamilyPolicy::default(),
        Duration::from_secs(5),
    )
}

fn relay_cfg() -> HopConfig {
    let mut cfg = HopConfig::new("relay");
    cfg.fields.insert("hop_id".into(), "relay-test-0".into());
    cfg
}

/// Raw TCP echo responder: relay frames UDP as `[len: u32 BE][payload]` over
/// one carrier TCP connection, so a byte echo reflects frames verbatim.
async fn tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo binds loopback");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

#[test]
fn relay_descriptor_is_framing_adapter() {
    let _ = qcore_transports::linked_kinds();
    let d = transport_relay::plugin_descriptor();
    assert_eq!(d.kind, "relay");
    // Adapter shape: consumes a TCP carrier, offers UDP egress framed over
    // it (validator exempts relay-shaped hops from the UDP-carrier rule).
    assert!(d.capabilities.accepts_tcp_carrier);
    assert!(!d.capabilities.accepts_udp_carrier);
    assert!(d.capabilities.dials_tcp);
    assert!(d.capabilities.dials_udp);
    assert!(!d.needs_sidecar);
    assert!(qcore_transports::linked_kinds().contains(&"relay"));
}

#[tokio::test]
async fn relay_tcp_passthrough_carries_traffic() {
    let _ = qcore_transports::linked_kinds();
    let echo = tcp_echo().await;
    let hop = transport_relay::RelayFactory
        .build(relay_cfg(), carrier())
        .await
        .expect("relay builds over a direct carrier");
    assert_eq!(hop.health(), qcore_transport_api::HopHealth::Healthy);
    let mut stream = hop.dialer().dial_tcp(echo).await.expect("dial_tcp");
    stream.write_all(b"ping-relay").await.expect("write");
    let mut back = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("echo arrives")
        .expect("read");
    assert_eq!(&back, b"ping-relay");
    hop.stop().await.expect("clean stop");
}

#[tokio::test]
async fn relay_framed_udp_round_trips() {
    let _ = qcore_transports::linked_kinds();
    let echo = tcp_echo().await;
    let hop = transport_relay::RelayFactory
        .build(relay_cfg(), carrier())
        .await
        .expect("relay builds over a direct carrier");
    let flow = hop.dialer().dial_udp(echo).await.expect("dial_udp");
    flow.send_to(b"hello-relay", echo).await.expect("send_to");
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), flow.recv_from(&mut buf))
        .await
        .expect("echo arrives")
        .expect("recv_from");
    assert_eq!(&buf[..n], b"hello-relay");
    assert_eq!(from, echo);
    hop.stop().await.expect("clean stop");
}

#[tokio::test]
async fn unreachable_relay_names_transport_and_cause() {
    let _ = qcore_transports::linked_kinds();
    let dead = closed_port();
    let hop = transport_relay::RelayFactory
        .build(relay_cfg(), carrier())
        .await
        .expect("relay builds without dialing");
    let err = match hop.dialer().dial_udp(dead).await {
        Ok(_) => panic!("closed port must fail"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("relay"), "names transport: {msg}");
    assert!(
        msg.contains(&dead.to_string()) || msg.contains("unreachable transport"),
        "actionable cause: {msg}"
    );
    hop.stop().await.expect("clean stop");
}
