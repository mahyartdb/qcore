//! US1 acceptance: masque alpn=h3 and alpn=h2 each connect standalone over
//! IPv4 and IPv6 against loopback responders, carry traffic, stop cleanly.

use qcore_transport_api::{Dialer, HopConfig, HopFactory};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport_masque::test_support::{H2Responder, QuinnResponder};

fn cert() -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (key.cert.der().to_vec(), key.signing_key.serialize_der())
}

fn cfg_for(alpn: &str, endpoint: std::net::SocketAddr) -> HopConfig {
    let mut cfg = HopConfig::new("masque");
    cfg.fields
        .insert("hop_id".into(), format!("masque-{alpn}-0"));
    cfg.fields.insert("alpn".into(), alpn.into());
    cfg.fields.insert("endpoint".into(), endpoint.to_string());
    cfg.fields
        .insert("insecure_skip_verify".into(), "true".into());
    cfg
}

fn root_carrier() -> std::sync::Arc<dyn Dialer> {
    qcore_core::session::net::root_dialer(
        qcore_core::session::net::FamilyPolicy::default(),
        Duration::from_secs(5),
    )
}

async fn roundtrip_h3(ip: IpAddr) {
    let _ = qcore_transports::linked_kinds();
    let (cert_der, key_der) = cert();
    let responder = QuinnResponder::spawn(ip, cert_der, key_der).await.unwrap();
    let hop = transport_masque::MasqueFactory
        .build(cfg_for("h3", responder.addr), root_carrier())
        .await
        .expect("masque h3 QUIC handshake over loopback");
    assert_eq!(hop.health(), qcore_transport_api::HopHealth::Healthy);

    let flow = hop
        .dialer()
        .dial_udp(responder.addr)
        .await
        .expect("dial_udp");
    flow.send_to(b"hello-h3", responder.addr)
        .await
        .expect("send_to");
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), flow.recv_from(&mut buf))
        .await
        .expect("datagram echo arrives")
        .expect("recv_from");
    assert_eq!(&buf[..n], b"hello-h3");
    assert_eq!(from, responder.addr);

    let mut stream = hop
        .dialer()
        .dial_tcp(responder.addr)
        .await
        .expect("dial_tcp");
    stream.write_all(b"ping-h3").await.expect("write");
    let mut back = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("stream echo arrives")
        .expect("read");
    assert_eq!(&back, b"ping-h3");

    hop.stop().await.expect("clean stop");
}

async fn roundtrip_h2(ip: IpAddr) {
    let _ = qcore_transports::linked_kinds();
    let responder = H2Responder::spawn(ip).await.unwrap();
    let hop = transport_masque::MasqueFactory
        .build(cfg_for("h2", responder.addr), root_carrier())
        .await
        .expect("masque h2 handshake over loopback");
    assert_eq!(hop.health(), qcore_transport_api::HopHealth::Healthy);

    let flow = hop
        .dialer()
        .dial_udp(responder.addr)
        .await
        .expect("dial_udp");
    flow.send_to(b"hello-h2", responder.addr)
        .await
        .expect("send_to");
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), flow.recv_from(&mut buf))
        .await
        .expect("datagram echo arrives")
        .expect("recv_from");
    assert_eq!(&buf[..n], b"hello-h2");
    assert_eq!(from, responder.addr);

    let mut stream = hop
        .dialer()
        .dial_tcp(responder.addr)
        .await
        .expect("dial_tcp");
    stream.write_all(b"ping-h2").await.expect("write");
    let mut back = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("stream echo arrives")
        .expect("read");
    assert_eq!(&back, b"ping-h2");

    hop.stop().await.expect("clean stop");
}

#[tokio::test]
async fn masque_h3_ipv4() {
    roundtrip_h3(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn masque_h3_ipv6() {
    roundtrip_h3(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn masque_h2_ipv4() {
    roundtrip_h2(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn masque_h2_ipv6() {
    roundtrip_h2(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
}

#[tokio::test]
async fn unreachable_masque_names_transport_and_cause() {
    let _ = qcore_transports::linked_kinds();
    let hop = transport_masque::MasqueFactory
        .build(
            cfg_for("h3", "127.0.0.1:1".parse().unwrap()),
            root_carrier(),
        )
        .await;
    let err = match hop {
        Ok(_) => panic!("closed port must fail"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("masque"), "names transport: {msg}");
}
