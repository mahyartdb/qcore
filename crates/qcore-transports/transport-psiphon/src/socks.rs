//! Minimal SOCKS5 client + server (RFC 1928, CONNECT + UDP ASSOCIATE).
//!
//! Used by the Psiphon hop (client), the fake sidecar and the CLI `--bind`
//! listener (server). No-auth only; authentication is the sidecar's job.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SOCKS5 server: accepts CONNECT, relays to the requested upstream.
pub struct Socks5Server {
    listener: tokio::net::TcpListener,
}

impl Socks5Server {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Socks5Server {
            listener: tokio::net::TcpListener::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve forever (spawn this).
    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (socket, _) = self.listener.accept().await?;
            tokio::spawn(async move {
                handle_client(socket).await.ok();
            });
        }
    }
}

async fn handle_client(mut socket: tokio::net::TcpStream) -> std::io::Result<()> {
    // Handshake: VER, NMETHODS, METHODS(no-auth 0x00 required).
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

    // Request: VER CMD RSV ATYP ADDR PORT.
    let mut req = [0u8; 4];
    socket.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad request version",
        ));
    }
    let target = read_addr(&mut socket, req[3]).await?;
    match req[1] {
        0x01 => {
            // CONNECT: relay.
            let mut upstream = tokio::net::TcpStream::connect(target).await?;
            let bind = upstream.local_addr()?;
            write_reply(&mut socket, 0x00, bind).await?;
            tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
            Ok(())
        }
        0x03 => {
            // UDP ASSOCIATE: relay between the associating client (first
            // sender) and the destinations it addresses.
            let relay = tokio::net::UdpSocket::bind(SocketAddr::new(target.ip(), 0)).await?;
            let mut relay_addr = relay.local_addr()?;
            // Bound to 0.0.0.0 (client asked ASSOCIATE to 0.0.0.0:0): the
            // reported address must be reachable, so map unspecified to
            // loopback. Without this the client sends to 0.0.0.0 and the
            // flow hangs until timeout.
            if relay_addr.ip().is_unspecified() {
                let port = relay_addr.port();
                let loopback = if relay_addr.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                };
                relay_addr = SocketAddr::new(loopback, port);
            }
            write_reply(&mut socket, 0x00, relay_addr).await?;
            let mut buf = vec![0u8; 65535];
            let mut client: Option<SocketAddr> = None;
            loop {
                let Ok((n, peer)) = relay.recv_from(&mut buf).await else {
                    break;
                };
                if client.is_none() {
                    // First datagram defines the associating client: the
                    // stub only replies after we forward, so the first
                    // sender is always the client.
                    client = Some(peer);
                }
                if Some(peer) == client {
                    // Client -> destination: SOCKS header + payload.
                    // RFC 1928 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT.
                    if n < 10 || buf[2] != 0x00 {
                        continue; // short or fragmented: not supported
                    }
                    // Client -> destination: strip header, forward payload.
                    let Some((dst, header_len)) = parse_udp_addr(&buf[4..], buf[3]) else {
                        continue;
                    };
                    relay.send_to(&buf[4 + header_len..n], dst).await.ok();
                } else {
                    // Destination -> client: raw payload, wrap unconditionally
                    // (no length gate: short echoes are the common case).
                    // Destination -> client: wrap in SOCKS header, relay back.
                    let Some(client_addr) = client else { continue };
                    let mut reply = vec![0u8, 0x00, 0x00];
                    match peer {
                        SocketAddr::V4(v4) => {
                            reply.push(0x01);
                            reply.extend_from_slice(&v4.ip().octets());
                            reply.extend_from_slice(&v4.port().to_be_bytes());
                        }
                        SocketAddr::V6(v6) => {
                            reply.push(0x04);
                            reply.extend_from_slice(&v6.ip().octets());
                            reply.extend_from_slice(&v6.port().to_be_bytes());
                        }
                    }
                    reply.extend_from_slice(&buf[..n]);
                    relay.send_to(&reply, client_addr).await.ok();
                }
            }
            Ok(())
        }
        _ => {
            write_reply(
                &mut socket,
                0x07,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported command",
            ))
        }
    }
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
        0x04 => {
            let mut b = [0u8; 18];
            socket.read_exact(&mut b).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize + 2];
            socket.read_exact(&mut host).await?;
            let port = u16::from_be_bytes([host[len[0] as usize], host[len[0] as usize + 1]]);
            let name = String::from_utf8_lossy(&host[..len[0] as usize]).into_owned();
            // Resolve via the OS (loopback tests use IPs or localhost).
            let mut addrs = tokio::net::lookup_host((name.as_str(), port))
                .await?
                .collect::<Vec<_>>();
            addrs.pop().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "dns resolved nothing")
            })
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad atyp",
        )),
    }
}

fn parse_udp_addr(buf: &[u8], atyp: u8) -> Option<(SocketAddr, usize)> {
    match atyp {
        0x01 if buf.len() >= 6 => {
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 6))
        }
        0x04 if buf.len() >= 18 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Some((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port), 18))
        }
        _ => None,
    }
}

async fn write_reply(
    socket: &mut tokio::net::TcpStream,
    rep: u8,
    bind: SocketAddr,
) -> std::io::Result<()> {
    let mut out = vec![0x05, rep, 0x00];
    match bind {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    socket.write_all(&out).await
}

/// CONNECT through `proxy` to `dst`. Returns the relayed stream.
pub async fn socks_connect(
    proxy: SocketAddr,
    dst: SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    let mut socket = tokio::net::TcpStream::connect(proxy).await?;
    socket.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    socket.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socks5 handshake rejected",
        ));
    }
    let mut req = vec![0x05, 0x01, 0x00];
    match dst {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    socket.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    socket.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("socks5 connect refused: {:#x}", hdr[1]),
        ));
    }
    // Consume bound address.
    let _ = read_addr(&mut socket, hdr[3]).await?;
    Ok(socket)
}

/// UDP ASSOCIATE through `proxy`. Returns the relay address; datagrams use
/// the SOCKS UDP header, relayed by the server.
pub async fn socks_udp_associate(
    proxy: SocketAddr,
) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    let mut socket = tokio::net::TcpStream::connect(proxy).await?;
    socket.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    socket.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socks5 handshake rejected",
        ));
    }
    // cmd ASSOCIATE to 0.0.0.0:0 (server picks relay).
    socket
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut hdr = [0u8; 4];
    socket.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "socks5 associate refused",
        ));
    }
    let relay = read_addr(&mut socket, hdr[3]).await?;
    Ok((socket, relay))
}

/// Encode one SOCKS UDP datagram for `dst` (RFC 1928: RSV FRAG ATYP ...).
pub fn encode_udp_datagram(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, 0x00, 0x00];
    match dst {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Decode a SOCKS UDP datagram into (dst, payload).
pub fn decode_udp_datagram(buf: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    if buf.len() < 10 || buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
        return None; // bad RSV or fragmented (unsupported)
    }
    let (dst, header_len) = parse_udp_addr(&buf[4..], buf[3])?;
    Some((dst, buf[4 + header_len..].to_vec()))
}
