//! US1 acceptance: wireguard peer=warp connects standalone over IPv4 and
//! IPv6 against a real boringtun responder, carries traffic, stops cleanly.
//! Unreachable transport reports its name + actionable cause.

use qcore_core::session::net::{root_dialer, FamilyPolicy};
use qcore_transport_api::{HopConfig, HopFactory};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport_wireguard::test_support::{generate_keypair, WgResponder};

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn roundtrip(ip: IpAddr) {
    let _ = qcore_transports::linked_kinds();
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = WgResponder::spawn(ip, s_sk, c_pk).await.unwrap();

    let mut cfg = HopConfig::new("wireguard");
    cfg.fields.insert("hop_id".into(), "wg-test-0".into());
    cfg.fields.insert("peer".into(), "warp".into());
    cfg.fields
        .insert("endpoint".into(), responder.addr.to_string());
    cfg.fields.insert("private_key".into(), hex(&c_sk));
    cfg.fields.insert("peer_public_key".into(), hex(&s_pk));

    let carrier = root_dialer(FamilyPolicy::default(), Duration::from_secs(5));
    let hop = transport_wireguard::WireguardFactory
        .build(cfg, carrier)
        .await
        .expect("wireguard handshake over loopback");
    assert_eq!(
        hop.health(),
        qcore_transport_api::HopHealth::Healthy,
        "tunnel healthy"
    );

    // UDP egress through the tunnel.
    let flow = hop
        .dialer()
        .dial_udp(responder.addr)
        .await
        .expect("dial_udp");
    flow.send_to(b"hello-wg", responder.addr)
        .await
        .expect("send_to");
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), flow.recv_from(&mut buf))
        .await
        .expect("echo arrives")
        .expect("recv_from");
    assert_eq!(&buf[..n], b"hello-wg");
    assert_eq!(from, responder.addr);

    // TCP egress through the tunnel.
    let mut stream = hop
        .dialer()
        .dial_tcp(responder.addr)
        .await
        .expect("dial_tcp");
    stream.write_all(b"ping-tcp").await.expect("write");
    let mut back = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("echo arrives")
        .expect("read");
    assert_eq!(&back, b"ping-tcp");

    hop.stop().await.expect("clean stop");
}

#[tokio::test]
async fn wireguard_ipv4() {
    roundtrip(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn wireguard_ipv6() {
    roundtrip(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn unreachable_wireguard_names_transport_and_cause() {
    let _ = qcore_transports::linked_kinds();
    let (c_sk, _c_pk) = generate_keypair();
    let (_s_sk, s_pk) = generate_keypair();
    let mut cfg = HopConfig::new("wireguard");
    cfg.fields.insert("hop_id".into(), "wg-dead-0".into());
    cfg.fields.insert("peer".into(), "warp".into());
    cfg.fields.insert("endpoint".into(), "127.0.0.1:1".into());
    cfg.fields.insert("private_key".into(), hex(&c_sk));
    cfg.fields.insert("peer_public_key".into(), hex(&s_pk));
    let carrier = root_dialer(FamilyPolicy::default(), Duration::from_secs(5));
    let err = match transport_wireguard::WireguardFactory
        .build(cfg, carrier)
        .await
    {
        Ok(_) => panic!("closed port must fail"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("wireguard"), "names transport: {msg}");
    assert!(
        msg.contains("127.0.0.1:1") || msg.contains("timed out"),
        "actionable cause: {msg}"
    );
}
