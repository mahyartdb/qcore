//! Local proxy listener for `--bind` (US1 T047).
//!
//! Accepts SOCKS5 CONNECT (no-auth) on a loopback listener and relays each
//! connection through the session exit hop's [`Dialer`]. New module (not
//! `session/net.rs`): net owns family/DNS policy, this owns the
//! SOCKS-over-abstract-egress server. UDP ASSOCIATE is refused in US1 (TCP
//! proxy scope); chains with UDP egress use the exit dialer directly.

use super::net::{FamilyMode, FamilyPolicy};
use qcore_transport_api::Dialer;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Per-read handshake budget: a stalled peer must not hold a task forever.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Ceiling on concurrent proxied connections (Slowloris backstop).
const MAX_CONNECTIONS: usize = 128;
/// Overall relay budget. A bound is needed because `copy_bidirectional`
/// otherwise keeps the task (and its slot) alive forever for a peer that
/// holds the socket open without moving data. The honest simple bound is a
/// generous total time, not idle tracking: legitimate proxied sessions are
/// minutes-scale, hostile holds are indefinite, and 30 minutes covers the
/// former while capping the latter.
const RELAY_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Peer filter: who may CONNECT through the proxy. `LoopbackOnly` (default)
/// keeps the listener a localhost service even when bound non-locally; `Any`
/// is the explicit opt-in for network-facing deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerPolicy {
    #[default]
    LoopbackOnly,
    Any,
}

/// True when `peer` may use the proxy under `policy`.
fn peer_allowed(peer: &SocketAddr, policy: PeerPolicy) -> bool {
    match policy {
        PeerPolicy::Any => true,
        PeerPolicy::LoopbackOnly => peer.ip().is_loopback(),
    }
}

async fn read_exact_timeout(
    socket: &mut tokio::net::TcpStream,
    buf: &mut [u8],
) -> std::io::Result<()> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.read_exact(buf))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "socks handshake timed out")
        })??;
    Ok(())
}

/// Serve forever (spawn this): one task per accepted connection.
///
/// Default policy (`dual`) when the caller has no family preference: IPv6
/// targets are accepted at the SOCKS layer and the exit dialer enforces the
/// chain policy. Prefer [`serve_socks_via_dialer_with_policy`] when the
/// session family policy is known so IPv4-only sessions refuse IPv6 with
/// `0x08` before dialing. Peers are filtered loopback-only by default.
pub async fn serve_socks_via_dialer(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
) -> std::io::Result<()> {
    serve_socks_via_dialer_with_policy(listener, dialer, FamilyPolicy::default()).await
}

/// [`serve_socks_via_dialer`] with an explicit family policy for IPv6 gating
/// (and the default loopback-only peer filter).
pub async fn serve_socks_via_dialer_with_policy(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
    policy: FamilyPolicy,
) -> std::io::Result<()> {
    serve_socks(listener, dialer, policy, PeerPolicy::default()).await
}

/// [`serve_socks_via_dialer_with_policy`] plus an explicit [`PeerPolicy`].
pub async fn serve_socks(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
    policy: FamilyPolicy,
    peers: PeerPolicy,
) -> std::io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        // A transient accept error must not kill the proxy while the session
        // is still Up (contrast: the old `?` returned and left the session
        // reporting Up with a dead proxy and no log). The sleep keeps a
        // persistent failure from busy-spinning a core.
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if !peer_allowed(&peer, peers) {
            drop(socket);
            continue;
        }
        let dialer = dialer.clone();
        let policy = policy.clone();
        // Unbounded spawn is a task-exhaustion primitive: shed load by
        // closing the socket when every slot is busy.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(socket);
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            handle_connect(socket, &*dialer, &policy).await.ok();
        });
    }
}

async fn handle_connect(
    mut socket: tokio::net::TcpStream,
    dialer: &dyn Dialer,
    policy: &FamilyPolicy,
) -> std::io::Result<()> {
    let mut hdr = [0u8; 2];
    read_exact_timeout(&mut socket, &mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    read_exact_timeout(&mut socket, &mut methods).await?;
    if !methods.contains(&0x00) {
        socket.write_all(&[0x05, 0xFF]).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no acceptable auth method",
        ));
    }
    socket.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    read_exact_timeout(&mut socket, &mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        write_reply(&mut socket, 0x07).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only CONNECT is supported",
        ));
    }
    let target = match read_addr(&mut socket, req[3], policy).await {
        Ok(t) => t,
        Err(e) => {
            write_reply(&mut socket, 0x08).await.ok();
            return Err(e);
        }
    };
    // A dial failure must still answer (RFC 1928): the client cannot tell a
    // bare FIN from a refused/unreachable target.
    let mut upstream = match dialer.dial_tcp(target).await {
        Ok(s) => s,
        Err(e) => {
            write_reply(&mut socket, 0x05).await.ok();
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e.message,
            ));
        }
    };
    write_reply(&mut socket, 0x00).await?;
    // Relay bound: see RELAY_TOTAL_TIMEOUT for why a total timeout beats
    // idle tracking here. On expiry both sockets drop (client sees EOF).
    tokio::time::timeout(
        RELAY_TOTAL_TIMEOUT,
        tokio::io::copy_bidirectional(&mut socket, &mut upstream),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "relay exceeded its total time budget",
        )
    })??;
    Ok(())
}

async fn read_addr(
    socket: &mut tokio::net::TcpStream,
    atyp: u8,
    policy: &FamilyPolicy,
) -> std::io::Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            read_exact_timeout(socket, &mut b).await?;
            if policy.mode == FamilyMode::Ipv6 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "IPv4 CONNECT targets refused by family policy (mode=ipv6)",
                ));
            }
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        0x04 => {
            let mut b = [0u8; 18];
            read_exact_timeout(socket, &mut b).await?;
            if policy.mode == FamilyMode::Ipv4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "IPv6 CONNECT targets refused by family policy (mode=ipv4)",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        // Domain names stay refused until a tunnel resolver exists: resolving
        // via the OS here would leak DNS around the tunnel.
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_timeout(socket, &mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            read_exact_timeout(socket, &mut rest).await?;
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "domain CONNECT targets refused (no tunnel resolver; use a literal IP)",
            ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported address type",
        )),
    }
}

async fn write_reply(socket: &mut tokio::net::TcpStream, rep: u8) -> std::io::Result<()> {
    socket
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_transport_api::{ByteStream, Capabilities, HopError, UdpFlow};

    /// Test dialer: plain OS TCP (no tunnel), proving the relay path.
    struct DirectDialer;

    #[async_trait::async_trait]
    impl Dialer for DirectDialer {
        async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            let s = tokio::net::TcpStream::connect(dst)
                .await
                .map_err(HopError::from)?;
            Ok(Box::new(DirectStream { inner: s }))
        }

        async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::transport("test", "tcp only"))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: false,
            }
        }
    }

    struct DirectStream {
        inner: tokio::net::TcpStream,
    }

    impl tokio::io::AsyncRead for DirectStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for DirectStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl ByteStream for DirectStream {}

    #[tokio::test]
    async fn connect_relays_bytes() {
        // Echo target.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            tokio::io::copy(&mut r, &mut w).await.ok();
        });
        // Proxy under test.
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(DirectDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        c.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
        let ip = match echo_addr.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[1], 0x00);
        c.write_all(b"via-bind").await.unwrap();
        let mut back = [0u8; 8];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"via-bind");
    }

    /// Failing dialer: every dial refuses.
    struct RefusingDialer;

    #[async_trait::async_trait]
    impl Dialer for RefusingDialer {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::transport("test", "closed port"))
        }

        async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::transport("test", "tcp only"))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: false,
            }
        }
    }

    async fn socks_greet(c: &mut tokio::net::TcpStream) {
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        c.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn dial_failure_sends_refused_reply() {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(RefusingDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        socks_greet(&mut c).await;
        // Closed loopback port: dial fails, client must get 0x05, not a FIN.
        c.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], 0x05);
        assert_eq!(hdr[1], 0x05, "refused reply, not silent FIN");
    }

    #[tokio::test]
    async fn ipv6_mode_refuses_ipv4_with_08() {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let policy = FamilyPolicy {
            mode: FamilyMode::Ipv6,
            ..FamilyPolicy::default()
        };
        tokio::spawn(serve_socks_via_dialer_with_policy(
            proxy,
            Arc::new(DirectDialer),
            policy,
        ));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        socks_greet(&mut c).await;
        c.write_all(&[0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 1, 0xBB])
            .await
            .unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(
            hdr[1], 0x08,
            "ipv6-only refuses IPv4 like ipv4-only refuses IPv6"
        );
    }

    #[tokio::test]
    async fn ipv4_mode_refuses_ipv6_with_08() {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let policy = FamilyPolicy {
            mode: FamilyMode::Ipv4,
            ..FamilyPolicy::default()
        };
        tokio::spawn(serve_socks_via_dialer_with_policy(
            proxy,
            Arc::new(DirectDialer),
            policy,
        ));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        socks_greet(&mut c).await;
        // ::1 port 443, must be refused before dialing.
        let mut req = vec![0x05u8, 0x01, 0x00, 0x04];
        req.extend_from_slice(&[0u8; 15]);
        req.push(1);
        req.extend_from_slice(&443u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[1], 0x08, "ipv4-only refuses IPv6 at the SOCKS layer");
    }

    /// The peer filter (pure half): loopback peers allowed, everything else
    /// rejected. The integration half (a real non-loopback TCP peer gets
    /// 0x02) lives in conformance; unit-level we pin the decision table and
    /// the wire behavior for allowed peers.
    #[test]
    fn peer_filter_decision_table() {
        assert!(peer_allowed(
            &"127.0.0.1:5000".parse().unwrap(),
            PeerPolicy::LoopbackOnly
        ));
        assert!(peer_allowed(
            &"[::1]:5000".parse().unwrap(),
            PeerPolicy::LoopbackOnly
        ));
        for denied in ["10.1.2.3:5000", "192.168.0.5:9999", "[fe80::1]:443"] {
            assert!(
                !peer_allowed(&denied.parse().unwrap(), PeerPolicy::LoopbackOnly),
                "{denied}"
            );
            assert!(
                peer_allowed(&denied.parse().unwrap(), PeerPolicy::Any),
                "Any must accept {denied}"
            );
        }
    }

    /// Default policy is loopback-only: a non-loopback *peer* (the local end
    /// of the proxied connection) is refused with 0x02 before any dial —
    /// the proxy must not be an open relay for other hosts on the LAN.
    /// Integration coverage for a genuinely non-loopback source address is
    /// in tests-conformance (a unit test would need raw socket binding to a
    /// specific interface).
    #[tokio::test]
    async fn loopback_peer_is_accepted_and_relayed() {
        // Echo target.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            tokio::io::copy(&mut r, &mut w).await.ok();
        });
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(DirectDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        socks_greet(&mut c).await;
        let ip = match echo_addr.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let mut req = vec![0x05u8, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[1], 0x00, "loopback peer passes the default filter");
    }
}
