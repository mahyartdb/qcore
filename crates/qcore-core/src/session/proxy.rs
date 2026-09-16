//! Local proxy listener for `--bind` (US1 T047).
//!
//! Accepts SOCKS5 CONNECT (no-auth) on a loopback listener and relays each
//! connection through the session exit hop's [`Dialer`]. New module (not
//! `session/net.rs`): net owns family/DNS policy, this owns the
//! SOCKS-over-abstract-egress server. UDP ASSOCIATE is refused in US1 (TCP
//! proxy scope); chains with UDP egress use the exit dialer directly.

use qcore_transport_api::Dialer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serve forever (spawn this): one task per accepted connection.
pub async fn serve_socks_via_dialer(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
) -> std::io::Result<()> {
    loop {
        let (socket, _) = listener.accept().await?;
        let dialer = dialer.clone();
        tokio::spawn(async move {
            handle_connect(socket, &*dialer).await.ok();
        });
    }
}

async fn handle_connect(
    mut socket: tokio::net::TcpStream,
    dialer: &dyn Dialer,
) -> std::io::Result<()> {
    let mut hdr = [0u8; 2];
    socket.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        socket.write_all(&[0x05, 0xFF]).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no acceptable auth method",
        ));
    }
    socket.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    socket.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        write_reply(&mut socket, 0x07).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only CONNECT is supported",
        ));
    }
    let target = read_addr(&mut socket, req[3]).await?;
    let mut upstream = dialer
        .dial_tcp(target)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.message))?;
    write_reply(&mut socket, 0x00).await?;
    tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
    Ok(())
}

async fn read_addr(socket: &mut tokio::net::TcpStream, atyp: u8) -> std::io::Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            socket.read_exact(&mut b).await?;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize + 2];
            socket.read_exact(&mut host).await?;
            let port = u16::from_be_bytes([host[len[0] as usize], host[len[0] as usize + 1]]);
            let name = String::from_utf8_lossy(&host[..len[0] as usize]).into_owned();
            let mut addrs = tokio::net::lookup_host((name.as_str(), port)).await?;
            addrs.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "dns resolved nothing")
            })
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "IPv6 CONNECT targets are refused in US1",
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
}
