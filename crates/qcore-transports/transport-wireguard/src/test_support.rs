//! Loopback test responder: a real boringtun peer over UDP that speaks the
//! tunnel-channel framing (echoes DATA on the same stream id/seq, echoes
//! DGRAMs, accepts OPENs). Used by the dual-stack conformance suite (US1).

use boringtun::noise::{Tunn, TunnResult};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Generate a fresh keypair via the OS RNG. Returns (secret, public).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("rng");
    let secret = boringtun::x25519::StaticSecret::from(sk);
    let public = boringtun::x25519::PublicKey::from(&secret);
    (*secret.as_bytes(), *public.as_bytes())
}

/// A boringtun responder bound to loopback.
pub struct WgResponder {
    pub addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl WgResponder {
    /// Spawn a responder for `private_key` accepting `peer_public_key`.
    pub async fn spawn(
        bind_ip: IpAddr,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
    ) -> std::io::Result<Self> {
        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
        let addr = udp.local_addr()?;
        let tunnel = Arc::new(Mutex::new(Tunn::new(
            boringtun::x25519::StaticSecret::from(private_key),
            boringtun::x25519::PublicKey::from(peer_public_key),
            None,
            None,
            0,
            None,
        )));
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                if std::env::var("QCORE_WG_TRACE").is_ok() {
                    eprintln!("[wg-resp] recv {n}B head={:02x?}", &buf[..n.min(12)]);
                }
                let mut plain = vec![0u8; 65535];
                let action = {
                    let mut tunnel = tunnel.lock().unwrap();
                    match tunnel.decapsulate(Some(src.ip()), &buf[..n], &mut plain) {
                        TunnResult::WriteToTunnelV4(data, _)
                        | TunnResult::WriteToTunnelV6(data, _) => {
                            if std::env::var("QCORE_WG_TRACE").is_ok() {
                                eprintln!("[wg-resp] decrypted {}B", data.len());
                            }
                            let reply = echo_frame(data);
                            // Re-encrypt the echo through the same tunnel.
                            let mut enc = vec![0u8; 65535];
                            match tunnel.encapsulate(&reply, &mut enc) {
                                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                                _ => None,
                            }
                        }
                        TunnResult::WriteToNetwork(reply) => {
                            if std::env::var("QCORE_WG_TRACE").is_ok() {
                                eprintln!("[wg-resp] reply {}B", reply.len());
                            }
                            Some(reply.to_vec())
                        }
                        TunnResult::Done => {
                            if std::env::var("QCORE_WG_TRACE").is_ok() {
                                eprintln!("[wg-resp] done");
                            }
                            None
                        }
                        TunnResult::Err(e) => {
                            if std::env::var("QCORE_WG_TRACE").is_ok() {
                                eprintln!("[wg-resp] decap err: {e:?}");
                            }
                            None
                        }
                    }
                };
                if let Some(bytes) = action {
                    udp.send_to(&bytes, src).await.ok();
                }
            }
        });
        Ok(WgResponder { addr, _task: task })
    }
}

/// Echo channel-packet payloads back verbatim (whole IPv4 envelope, so
/// stream ids/seqs survive). OPEN/FIN are accepted with empty reply;
/// non-channel traffic echoes empty.
fn echo_frame(data: &[u8]) -> Vec<u8> {
    match crate::stream::unwrap_ip(data) {
        Some(inner) if !inner.is_empty() => match inner[0] {
            0x01 | 0x03 => Vec::new(),
            0x02 | 0x04 => data.to_vec(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}
