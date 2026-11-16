//! AmneziaWG loopback peer (test double): a vendored-boringtun responder
//! carrying the same `awg_*` transforms as the hop under test — S1..S4
//! prefixes, H1..H4 message types, optional random handshake trailers, header
//! protection when keyed.
//!
//! `transport_wireguard::test_support::WgResponder` stays a stock WireGuard
//! peer on purpose; proving AWG application against it would let a no-op
//! transform pass. Handshake proof only: tunnel data is dropped, because the
//! conformance assertions are establishment plus reporting.

use boringtun::noise::{Tunn, TunnResult};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use transport_wireguard::awg::AwgParams;

/// A boringtun responder bound to loopback with AWG transforms installed.
pub struct AwgResponder {
    pub addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl AwgResponder {
    /// Spawn a responder for `private_key` accepting `peer_public_key`.
    pub async fn spawn(
        bind_ip: IpAddr,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        params: AwgParams,
    ) -> std::io::Result<Self> {
        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
        let addr = udp.local_addr()?;
        let mut tunnel = Tunn::new(
            boringtun::x25519::StaticSecret::from(private_key),
            boringtun::x25519::PublicKey::from(peer_public_key),
            None,
            None,
            0,
            None,
        );
        tunnel
            .set_awg_params(Some(params.to_wire()))
            .map_err(|e| std::io::Error::other(format!("AWG params rejected: {e:?}")))?;
        let tunnel = Arc::new(Mutex::new(tunnel));
        let task = tokio::spawn(async move {
            // Reused buffers, allocated once per responder (same shape as the
            // stock responder; the patched `decapsulate` edits the datagram in
            // place while undoing header protection).
            let mut buf = vec![0u8; 65535];
            let mut plain = vec![0u8; 65535];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                let action = {
                    let mut tunnel = tunnel.lock().unwrap();
                    match tunnel.decapsulate(Some(src.ip()), &mut buf[..n], &mut plain) {
                        TunnResult::WriteToNetwork(reply) => Some(reply.to_vec()),
                        // Tunnel payloads (keepalive/data) and junk are not
                        // part of the handshake proof.
                        _ => None,
                    }
                };
                if let Some(bytes) = action {
                    udp.send_to(&bytes, src).await.ok();
                }
            }
        });
        Ok(AwgResponder { addr, _task: task })
    }
}
