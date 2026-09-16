//! Deterministic loopback stub peer (constitution Dual-Stack Harness).
//!
//! TCP + UDP echo with a connection counter. `preflight` must leave the
//! counter unchanged (SC-002d). Modes: ipv4, ipv6, dual.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Bound stub peer.
pub struct StubPeer {
    pub tcp_addrs: Vec<SocketAddr>,
    pub udp_addrs: Vec<SocketAddr>,
    connections: Arc<AtomicU64>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl StubPeer {
    /// Bind loopback TCP+UDP echo servers for the given family mode.
    pub async fn bind(mode: &str) -> std::io::Result<Self> {
        let mut tcp_addrs = Vec::new();
        let mut udp_addrs = Vec::new();
        let mut tasks = Vec::new();
        let connections = Arc::new(AtomicU64::new(0));

        let bind_ip: Vec<IpAddr> = match mode {
            "ipv4" => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "ipv6" => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            _ => vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        };

        for ip in bind_ip {
            let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0)).await?;
            tcp_addrs.push(listener.local_addr()?);
            let counter = connections.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let (mut r, mut w) = socket.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            }));

            let udp = tokio::net::UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
            udp_addrs.push(udp.local_addr()?);
            let counter = connections.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                        break;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = udp.send_to(&buf[..n], peer).await;
                }
            }));
        }

        Ok(StubPeer {
            tcp_addrs,
            udp_addrs,
            connections,
            _tasks: tasks,
        })
    }

    /// Total accepted TCP connections + received UDP datagrams.
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn tcp_addr(&self, ipv6: bool) -> Option<SocketAddr> {
        self.tcp_addrs.iter().find(|a| a.is_ipv6() == ipv6).copied()
    }
}
