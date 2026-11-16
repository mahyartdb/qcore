//! Local proxy listeners for `--bind` (US1 T047).
//!
//! Two listeners share the dial path (the session exit hop's [`Dialer`]),
//! the peer filter, the family policy and the tunnel-resolver wiring:
//!
//! - SOCKS5 (RFC 1928, no-auth): CONNECT and UDP ASSOCIATE. The UDP relay
//!   binds a local datagram socket, answers with BND.ADDR/BND.PORT, and
//!   ferries datagrams between the client and per-destination [`UdpFlow`]s
//!   dialed through the exit hop; FRAG != 0 datagrams are dropped (the
//!   association survives — 0x07 is reserved for request rejection).
//! - HTTP/1.1 CONNECT tunneling (RFC 7231 §4.3.6) via [`serve_http_proxy`].
//!   CONNECT only — other methods answer `405` with `Connection: close`
//!   (plain-HTTP proxying is out of scope).
//!
//! ATYP=domain targets (CONNECT requests and UDP datagrams both) resolve
//! through the session-scoped [`TunnelResolver`] (tunnel-routed DNS — the
//! domain name never reaches the OS resolver); a hostname-capable exit
//! ([`Dialer::dial_host`], e.g. tor resolving remote-side) dials the name
//! directly instead. Without either, domain targets refuse fail-closed.
//!
//! Peer filtering happens at accept time, before any protocol bytes: a
//! rejected peer is closed without a reply (no SOCKS reply is possible
//! before the greeting) and diagnosed on stderr.
//!
//! The CLI serves SOCKS (`--bind`) and HTTP CONNECT (`--http-proxy`) with
//! a second listener through the same dial path.

use super::net::{FamilyMode, FamilyPolicy};
use super::resolver::{ResolverError, TunnelResolver};
use qcore_transport_api::{unspecified_bind, ByteStream, Dialer, HopErrorKind, UdpFlow};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::OwnedSemaphorePermit;

/// Per-read handshake budget: a stalled peer must not hold a task forever.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Ceiling on concurrent proxied connections per listener (Slowloris
/// backstop).
const MAX_CONNECTIONS: usize = 128;
/// Relay idle bound: an association that moves no bytes in either direction
/// for this long is dropped (both sockets close; the peer sees EOF). This
/// replaces the old 30-minute TOTAL cap, which hard-killed long-lived
/// browser connections (WebSockets/SSE) that legally idle for minutes
/// between messages: browsers keep live connections moving (data or their
/// own keepalives), while a genuinely dead peer holds nothing after 15
/// quiet minutes.
const RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// Relay hard backstop: even a continuously active relay is dropped after
/// this long, so a peer trickling bytes forever cannot hold its slot (and
/// its [`MAX_CONNECTIONS`] permit) indefinitely. Generous by design — the
/// idle bound above is the real resource bound; this is the failsafe.
const RELAY_TOTAL_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
/// Watchdog sampling cadence for the relay idle bound: expiry is detected
/// at most one cadence late. 30 s is negligible against
/// [`RELAY_IDLE_TIMEOUT`] and cheap against thousands of relays.
const RELAY_WATCHDOG_POLL: std::time::Duration = std::time::Duration::from_secs(30);
/// Ceiling on concurrent UDP ASSOCIATE relays: a separate, smaller budget
/// next to [`MAX_CONNECTIONS`] — each association holds a TCP control slot
/// plus a relay socket plus per-destination flows.
const MAX_UDP_ASSOCIATIONS: usize = 16;
/// UDP association idle bound: an association that moves no datagram for
/// this long is torn down (relay socket closed, flows dropped). Shorter
/// than the TCP relay idle bound: datagram traffic is chatty by nature.
const UDP_ASSOCIATION_IDLE: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// Datagram receive buffer: the IPv4 datagram ceiling (65535). A UDP
/// payload can never exceed 65507 (16-bit UDP length field), so no
/// datagram is ever truncated into this buffer and the effective payload
/// cap is the IP limit minus the SOCKS header — the "65535 - header" bound.
const UDP_DATAGRAM_BUF: usize = 65535;
/// Distinct destinations per association (one dialed flow each). At the
/// cap further destinations are dropped, never evicted — evicting a flow
/// would silently break a live return path.
const UDP_MAX_FLOWS: usize = 32;
/// Bounded queue between per-destination forwarders and the relay loop:
/// backpressure, not unbounded buffering, when the client reads slowly.
const UDP_RELAY_QUEUE: usize = 64;
/// Request-head cap for the HTTP CONNECT listener: a peer streaming a head
/// without terminating it is dropped, never buffered unboundedly.
const HTTP_HEAD_LIMIT: usize = 8 * 1024;
/// Budget for the hostname-capable dial path ([`Dialer::dial_host`]):
/// matches the transports' own dial budget (tor dials with 15 s).
const DIAL_HOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

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

/// True when `addr`'s family is refused by the policy (the same gating the
/// SOCKS/HTTP CONNECT paths apply before dialing, applied to per-datagram
/// UDP destinations).
fn family_refused(addr: &SocketAddr, policy: &FamilyPolicy) -> bool {
    matches!(
        (policy.mode, addr.is_ipv4()),
        (FamilyMode::Ipv4, false) | (FamilyMode::Ipv6, true)
    )
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
    serve_socks_via_dialer_with_services(listener, dialer, policy, PeerPolicy::default(), None)
        .await
}

/// [`serve_socks_via_dialer_with_policy`] plus an explicit [`PeerPolicy`].
pub async fn serve_socks(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
    policy: FamilyPolicy,
    peers: PeerPolicy,
) -> std::io::Result<()> {
    serve_socks_via_dialer_with_services(listener, dialer, policy, peers, None).await
}

/// The full serve path: dialer + family policy + peer filter + optional
/// [`TunnelResolver`]. `resolver = None` keeps the fail-closed refusal for
/// ATYP=domain targets (no OS fallback — the domain name must not leak
/// around the tunnel); the engine wires a resolver when the exit hop has
/// UDP egress.
pub async fn serve_socks_via_dialer_with_services(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
    policy: FamilyPolicy,
    peers: PeerPolicy,
    resolver: Option<Arc<TunnelResolver>>,
) -> std::io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let udp_slots = Arc::new(tokio::sync::Semaphore::new(MAX_UDP_ASSOCIATIONS));
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
            // Accept-time rejection precedes any SOCKS bytes, so no RFC 1928
            // reply is possible (the peer has not even greeted). The
            // diagnostic keeps the drop observable instead of silent.
            eprintln!("qcore: proxy dropped non-permitted peer {peer} (policy={peers:?})");
            drop(socket);
            continue;
        }
        let dialer = dialer.clone();
        let policy = policy.clone();
        let resolver = resolver.clone();
        let udp_slots = udp_slots.clone();
        // Unbounded spawn is a task-exhaustion primitive: shed load by
        // closing the socket when every slot is busy.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(socket);
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            handle_connect(socket, &*dialer, &policy, resolver.as_deref(), &udp_slots)
                .await
                .ok();
        });
    }
}

/// Serve forever (spawn this): HTTP/1.1 CONNECT tunneling (RFC 7231 §4.3.6)
/// over the same dial path as the SOCKS listener — same [`PeerPolicy`]
/// filter, family policy and tunnel-resolver wiring.
///
/// CONNECT only: every other method is answered `405` with
/// `Connection: close` (plain-HTTP proxying is out of scope). Status
/// mapping: 400 malformed request line or authority; 403 family-policy
/// refusal; 501 domain target with no tunnel resolver wired; 502 dial or
/// resolution failure; 431 oversized request head.
///
/// CLI note: the CLI currently serves SOCKS only (`serve_socks*`); this
/// function is ready for a `--http-proxy`-style flag to bind a second
/// listener next to the SOCKS one (wiring owned by the CLI).
pub async fn serve_http_proxy(
    listener: tokio::net::TcpListener,
    dialer: Arc<dyn Dialer>,
    policy: FamilyPolicy,
    peers: PeerPolicy,
    resolver: Option<Arc<TunnelResolver>>,
) -> std::io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if !peer_allowed(&peer, peers) {
            // Same accept-time semantics as the SOCKS listener: the drop
            // precedes any HTTP bytes, so no status line is possible.
            eprintln!("qcore: http proxy dropped non-permitted peer {peer} (policy={peers:?})");
            drop(socket);
            continue;
        }
        let dialer = dialer.clone();
        let policy = policy.clone();
        let resolver = resolver.clone();
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(socket);
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            handle_http_connect(socket, &*dialer, &policy, resolver.as_deref())
                .await
                .ok();
        });
    }
}

async fn handle_connect(
    socket: tokio::net::TcpStream,
    dialer: &dyn Dialer,
    policy: &FamilyPolicy,
    resolver: Option<&TunnelResolver>,
    udp_slots: &Arc<tokio::sync::Semaphore>,
) -> std::io::Result<()> {
    let mut socket = socket;
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
    if req[0] != 0x05 {
        write_reply(&mut socket, 0x07).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    match req[1] {
        0x01 => handle_tcp_connect(socket, dialer, policy, resolver, req[3]).await,
        0x03 => {
            // The ASSOCIATE request's address is the client's expected
            // send-from endpoint (usually 0.0.0.0:0), not a routing target —
            // it is consumed for the protocol shape and discarded; the
            // dual default disables family gating that must not apply here
            // (real per-datagram destinations are gated in the relay).
            let _expected_client =
                match read_addr(&mut socket, req[3], &FamilyPolicy::default()).await {
                    Ok(addr) => addr,
                    Err(e) => {
                        write_reply(&mut socket, reply_for(&e)).await.ok();
                        return Err(e);
                    }
                };
            let peer = socket.peer_addr()?;
            // A separate, smaller budget: associations hold their control
            // slot plus a relay socket plus per-destination flows.
            let Ok(permit) = udp_slots.clone().try_acquire_owned() else {
                write_reply(&mut socket, 0x01).await.ok();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "too many concurrent UDP associations",
                ));
            };
            handle_udp_associate(socket, dialer, policy, resolver, peer, permit).await
        }
        _ => {
            write_reply(&mut socket, 0x07).await?;
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command not supported",
            ))
        }
    }
}

async fn handle_tcp_connect(
    mut socket: tokio::net::TcpStream,
    dialer: &dyn Dialer,
    policy: &FamilyPolicy,
    resolver: Option<&TunnelResolver>,
    atyp: u8,
) -> std::io::Result<()> {
    let target = match read_addr(&mut socket, atyp, policy).await {
        Ok(t) => t,
        Err(e) => {
            write_reply(&mut socket, reply_for(&e)).await.ok();
            return Err(e);
        }
    };
    // A domain target is resolved through the tunnel resolver — never the
    // OS resolver (the domain name must not leak around the tunnel). No
    // resolver wired (the exit hop has no UDP egress, or none was built) or
    // the resolution itself failing both refuse before any dial; the reply
    // code distinguishes capability (0x08) from resolution failure (0x01).
    // A hostname-capable exit (e.g. tor resolves remote-side) dials the
    // name directly: the defaulted `dial_host`'s Validation Err is the
    // capability signal (no kind matching); only without that capability
    // does the resolver fallback apply.
    let target = match target {
        SocksTarget::Ip(addr) => addr,
        SocksTarget::Domain(host, port) => {
            match dialer.dial_host(&host, port, DIAL_HOST_TIMEOUT).await {
                Ok(upstream) => {
                    write_reply(&mut socket, 0x00).await?;
                    return relay_with_idle_bounds(
                        socket,
                        upstream,
                        RELAY_IDLE_TIMEOUT,
                        RELAY_TOTAL_BACKSTOP,
                        RELAY_WATCHDOG_POLL,
                    )
                    .await;
                }
                // Capability signal (default method) or target-shape
                // refusal: fall through to tunnel-DNS resolution below.
                Err(e) if e.kind == HopErrorKind::Validation => {}
                Err(e) => {
                    write_reply(&mut socket, 0x05).await.ok();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        e.message,
                    ));
                }
            }
            let Some(resolver) = resolver else {
                write_reply(&mut socket, 0x08).await.ok();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "domain CONNECT targets refused (no tunnel resolver wired; use a literal IP)",
                ));
            };
            match resolver.resolve(&host, policy).await {
                Ok(ip) => SocketAddr::new(ip, port),
                Err(e) => {
                    let rep = reply_for_resolver(&e);
                    write_reply(&mut socket, rep).await.ok();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("domain target `{host}` did not resolve: {e}"),
                    ));
                }
            }
        }
    };
    // A dial failure must still answer (RFC 1928): the client cannot tell a
    // bare FIN from a refused/unreachable target.
    let upstream = match dialer.dial_tcp(target).await {
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
    // Relay bound: see RELAY_IDLE_TIMEOUT / RELAY_TOTAL_BACKSTOP. On expiry
    // both sockets drop (client sees EOF).
    relay_with_idle_bounds(
        socket,
        upstream,
        RELAY_IDLE_TIMEOUT,
        RELAY_TOTAL_BACKSTOP,
        RELAY_WATCHDOG_POLL,
    )
    .await
}

/// RFC 1928 UDP ASSOCIATE: reply with a local relay endpoint, then ferry
/// datagrams between the client and the exit hop's [`UdpFlow`] egress.
///
/// Shape (lifted from transport-psiphon/socks.rs, read-only reference): the
/// associating client is pinned to the control connection's peer IP —
/// datagrams from that IP (any port) relay; other sources are dropped. Each
/// distinct destination gets one `dial_udp` flow (bounded by
/// [`UDP_MAX_FLOWS`]; at the cap further destinations are dropped, never
/// evicted — evicting would silently break a live return path). FRAG != 0
/// datagrams are dropped (fragmentation is not supported; the association
/// survives — 0x07 is a request rejection, so it fires only when the
/// ASSOCIATE request itself is invalid). Domain ATYPs resolve through the
/// tunnel resolver — without one they drop fail-closed (no OS fallback,
/// same policy as CONNECT); UDP has no per-datagram error channel, so
/// undeliverable datagrams are dropped silently.
///
/// The association ends when the control connection closes (RFC 1928 §6) or
/// after [`UDP_ASSOCIATION_IDLE`] without datagram movement.
async fn handle_udp_associate(
    mut socket: tokio::net::TcpStream,
    dialer: &dyn Dialer,
    policy: &FamilyPolicy,
    resolver: Option<&TunnelResolver>,
    peer: SocketAddr,
    _permit: OwnedSemaphorePermit,
) -> std::io::Result<()> {
    if !dialer.capabilities().dials_udp {
        write_reply(&mut socket, 0x07).await.ok();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP ASSOCIATE refused: exit hop has no UDP egress",
        ));
    }
    // Relay socket: unspecified bind in the client's address family; the
    // reported BND.ADDR maps an unspecified IP to loopback so the client
    // can actually send to it (an unspecified address is not routable for
    // the peer).
    let bind = unspecified_bind(&peer);
    let relay = match tokio::net::UdpSocket::bind(bind).await {
        Ok(r) => r,
        Err(e) => {
            write_reply(&mut socket, 0x01).await.ok();
            return Err(e);
        }
    };
    let mut relay_addr = relay.local_addr()?;
    if relay_addr.ip().is_unspecified() {
        let port = relay_addr.port();
        let loopback = if relay_addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        relay_addr = SocketAddr::new(loopback, port);
    }
    write_reply_with_bind(&mut socket, 0x00, relay_addr).await?;

    let (reply_tx, mut reply_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(UDP_RELAY_QUEUE);
    let mut flows: HashMap<SocketAddr, Arc<dyn UdpFlow>> = HashMap::new();
    // Client pin (S2.6): the TCP control connection's peer IP is the
    // associating client's identity — datagrams are accepted only from that
    // IP (any port: NAT reprices ports mid-association). First-datagram-wins
    // would let a LAN host racing the real client become the client with
    // free egress under PeerPolicy::Any. Under LoopbackOnly the control peer
    // is loopback, so behavior is unchanged there.
    let client_ip = peer.ip();
    // Latest accepted datagram's source (its IP is the pin-checked one):
    // the return path for encapsulated replies, repriced along with NAT.
    let mut client_addr: Option<SocketAddr> = None;
    let mut buf = vec![0u8; UDP_DATAGRAM_BUF];
    let mut ctl = [0u8; 1];
    let idle_sleep = tokio::time::sleep(UDP_ASSOCIATION_IDLE);
    tokio::pin!(idle_sleep);
    loop {
        tokio::select! {
            _ = &mut idle_sleep => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "UDP association idle past its inactivity bound",
                ));
            }
            // Control connection closed: the association ends (RFC 1928 §6).
            // Unexpected bytes are ignored — clients do not speak here.
            read = socket.read(&mut ctl) => {
                match read {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
            datagram = relay.recv_from(&mut buf) => {
                let (n, from) = datagram?;
                if from.ip() != client_ip {
                    continue;
                }
                client_addr = Some(from);
                idle_sleep.as_mut().reset(
                    tokio::time::Instant::now() + UDP_ASSOCIATION_IDLE,
                );
                match parse_udp_datagram(&buf[..n]) {
                    None => continue, // malformed: drop, never guess
                    Some(UdpDatagram::Fragmented) => {
                        // FRAG != 0: fragmentation is not supported. RFC 1928
                        // frames 0x07 as a request rejection, so killing the
                        // association here would over-punish one unsupported
                        // datagram: drop it like the malformed case and
                        // answer 0x07 only when the ASSOCIATE request itself
                        // is invalid.
                        continue;
                    }
                    Some(UdpDatagram::To { dst, payload_at }) => {
                        let Some(dst_addr) =
                            resolve_udp_dst(dst, policy, resolver).await
                        else {
                            continue;
                        };
                        if !flows.contains_key(&dst_addr) {
                            if flows.len() >= UDP_MAX_FLOWS {
                                continue; // at the flow cap: drop, never evict
                            }
                            let Ok(flow) = dialer.dial_udp(dst_addr).await else {
                                continue;
                            };
                            let flow: Arc<dyn UdpFlow> = Arc::from(flow);
                            flows.insert(dst_addr, flow.clone());
                            spawn_udp_forwarder(flow, dst_addr, reply_tx.clone());
                        }
                        let flow = flows.get(&dst_addr).expect("inserted or checked above");
                        let _ = flow.send_to(&buf[payload_at..n], dst_addr).await;
                    }
                }
            }
            reply = reply_rx.recv() => {
                let Some((src, payload)) = reply else {
                    // Unreachable while the loop holds the sender half; if it
                    // ever happened, no reply could arrive again.
                    return Ok(());
                };
                idle_sleep.as_mut().reset(
                    tokio::time::Instant::now() + UDP_ASSOCIATION_IDLE,
                );
                let Some(client) = client_addr else {
                    continue; // replies before the first client datagram have nowhere to go
                };
                let mut out = Vec::with_capacity(22 + payload.len());
                out.extend_from_slice(&[0x00, 0x00, 0x00]);
                match src {
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
                out.extend_from_slice(&payload);
                let _ = relay.send_to(&out, client).await;
            }
        }
    }
}

/// One forwarder per dialed destination: tunnels datagrams back to the
/// relay loop through `reply_tx`. Ends on its own when the association
/// ends (the reply channel closes) or the flow errors.
fn spawn_udp_forwarder(
    flow: Arc<dyn UdpFlow>,
    dst: SocketAddr,
    reply_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_DATAGRAM_BUF];
        loop {
            match flow.recv_from(&mut buf).await {
                Ok((n, _from)) => {
                    // The flow is dialed to `dst` (connected-flow semantics):
                    // replies are attributed to that destination, which is
                    // the address the client's datagram named.
                    if reply_tx.send((dst, buf[..n].to_vec())).await.is_err() {
                        return; // association ended
                    }
                }
                Err(_) => return, // flow gone
            }
        }
    });
}

/// Resolve one UDP datagram destination: literal IPs pass the family gate;
/// domains resolve through the tunnel resolver (single-stack modes query
/// only their family, so the answer always fits the mode). `None` = drop
/// the datagram (no resolver wired, resolution failed, or family refusal).
async fn resolve_udp_dst(
    dst: SocksTarget,
    policy: &FamilyPolicy,
    resolver: Option<&TunnelResolver>,
) -> Option<SocketAddr> {
    match dst {
        SocksTarget::Ip(addr) => {
            if family_refused(&addr, policy) {
                return None;
            }
            Some(addr)
        }
        SocksTarget::Domain(host, port) => {
            let resolver = resolver?;
            let ip = resolver.resolve(&host, policy).await.ok()?;
            Some(SocketAddr::new(ip, port))
        }
    }
}

/// One client datagram's parsed shape.
enum UdpDatagram {
    /// Client → destination; the payload starts at `payload_at`.
    To { dst: SocksTarget, payload_at: usize },
    /// FRAG != 0: fragmentation is not supported (RFC 1928), refused.
    Fragmented,
}

/// Parse the RFC 1928 UDP request header (RSV FRAG ATYP DST.ADDR DST.PORT
/// payload) out of one client datagram. `None` = malformed, drop.
fn parse_udp_datagram(buf: &[u8]) -> Option<UdpDatagram> {
    if buf.len() < 4 {
        return None;
    }
    if buf[0] != 0x00 || buf[1] != 0x00 {
        return None; // RSV must be zero
    }
    if buf[2] != 0x00 {
        return Some(UdpDatagram::Fragmented);
    }
    let (dst, header_len) = parse_addr_bytes(&buf[4..], buf[3])?;
    Some(UdpDatagram::To {
        dst,
        payload_at: 4 + header_len,
    })
}

/// Parse an in-memory SOCKS address block (ATYP already split off): IP
/// literals and domain names, plus the trailing port. Returns the target
/// and the number of bytes the address block consumed (the UDP datagram
/// form; `read_addr` is its timeout-reading socket sibling).
fn parse_addr_bytes(buf: &[u8], atyp: u8) -> Option<(SocksTarget, usize)> {
    match atyp {
        0x01 if buf.len() >= 6 => {
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Some((SocksTarget::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 6))
        }
        0x04 if buf.len() >= 18 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Some((
                SocksTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)),
                18,
            ))
        }
        0x03 if !buf.is_empty() => {
            let host_len = buf[0] as usize;
            if buf.len() < host_len + 3 {
                // len byte + name + 2-byte port
                return None;
            }
            let host = std::str::from_utf8(&buf[1..1 + host_len]).ok()?;
            if host.is_empty() {
                return None;
            }
            let port = u16::from_be_bytes([buf[1 + host_len], buf[2 + host_len]]);
            Some((SocksTarget::Domain(host.to_string(), port), host_len + 3))
        }
        _ => None,
    }
}

async fn handle_http_connect(
    mut socket: tokio::net::TcpStream,
    dialer: &dyn Dialer,
    policy: &FamilyPolicy,
    resolver: Option<&TunnelResolver>,
) -> std::io::Result<()> {
    let head = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        read_request_head(&mut socket, HTTP_HEAD_LIMIT),
    )
    .await
    {
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "http request head timed out",
            ));
        }
        Ok(Err(HeadError::Eof)) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the request head completed",
            ));
        }
        Ok(Err(HeadError::TooLarge)) => {
            write_http_reply(&mut socket, 431, "Request Header Fields Too Large", "")
                .await
                .ok();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "http request head exceeds the size cap",
            ));
        }
        Ok(Err(HeadError::Io(e))) => return Err(e),
        Ok(Ok(head)) => head,
    };
    let Some((method, target, version)) = parse_request_line(&head) else {
        write_http_reply(&mut socket, 400, "Bad Request", "")
            .await
            .ok();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed http request line",
        ));
    };
    if method != "CONNECT" {
        write_http_reply(&mut socket, 405, "Method Not Allowed", "Allow: CONNECT\r\n")
            .await
            .ok();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("only CONNECT is supported, got {method}"),
        ));
    }
    if !version.starts_with("HTTP/1.") {
        write_http_reply(&mut socket, 400, "Bad Request", "")
            .await
            .ok();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported http version `{version}`"),
        ));
    }
    let Some(authority) = parse_authority(target) else {
        write_http_reply(&mut socket, 400, "Bad Request", "")
            .await
            .ok();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed CONNECT authority `{target}`"),
        ));
    };
    let target_addr = match authority {
        SocksTarget::Ip(addr) => {
            if family_refused(&addr, policy) {
                write_http_reply(&mut socket, 403, "Forbidden", "")
                    .await
                    .ok();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{addr} refused by family policy (mode={:?})", policy.mode),
                ));
            }
            addr
        }
        SocksTarget::Domain(host, port) => {
            // Same fail-closed DNS policy as SOCKS: the domain name must not
            // leak around the tunnel via the OS resolver. A hostname-capable
            // exit (dial_host, e.g. tor) dials the name directly; the
            // Validation Err is the capability signal and falls through to
            // the tunnel resolver.
            match dialer.dial_host(&host, port, DIAL_HOST_TIMEOUT).await {
                Ok(upstream) => {
                    socket
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    return relay_with_idle_bounds(
                        socket,
                        upstream,
                        RELAY_IDLE_TIMEOUT,
                        RELAY_TOTAL_BACKSTOP,
                        RELAY_WATCHDOG_POLL,
                    )
                    .await;
                }
                Err(e) if e.kind == HopErrorKind::Validation => {}
                Err(e) => {
                    write_http_reply(&mut socket, 502, "Bad Gateway", "")
                        .await
                        .ok();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        e.message,
                    ));
                }
            }
            let Some(resolver) = resolver else {
                write_http_reply(&mut socket, 501, "Not Implemented", "")
                    .await
                    .ok();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "domain CONNECT targets refused (no tunnel resolver wired; use a literal IP)",
                ));
            };
            match resolver.resolve(&host, policy).await {
                Ok(ip) => SocketAddr::new(ip, port),
                Err(e) => {
                    write_http_reply(&mut socket, 502, "Bad Gateway", "")
                        .await
                        .ok();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("domain target `{host}` did not resolve: {e}"),
                    ));
                }
            }
        }
    };
    let upstream = match dialer.dial_tcp(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            write_http_reply(&mut socket, 502, "Bad Gateway", "")
                .await
                .ok();
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e.message,
            ));
        }
    };
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    relay_with_idle_bounds(
        socket,
        upstream,
        RELAY_IDLE_TIMEOUT,
        RELAY_TOTAL_BACKSTOP,
        RELAY_WATCHDOG_POLL,
    )
    .await
}

/// Why a request head could not be read.
enum HeadError {
    /// The head exceeded the caller's cap without terminating.
    TooLarge,
    /// The connection closed before the head completed.
    Eof,
    Io(std::io::Error),
}

/// Read one request head (through its terminating blank line, CRLF per
/// RFC 7230). `cap` bounds the head: a peer streaming without terminating
/// is dropped, never buffered unboundedly (detected at most one chunk past
/// the cap).
async fn read_request_head(
    socket: &mut tokio::net::TcpStream,
    cap: usize,
) -> Result<Vec<u8>, HeadError> {
    let mut head = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        if let Some(pos) = find_subslice(&head, b"\r\n\r\n") {
            // Keep the terminator: the request line's own CRLF is part of
            // the head `parse_request_line` splits on.
            head.truncate(pos + 4);
            return Ok(head);
        }
        if head.len() > cap {
            return Err(HeadError::TooLarge);
        }
        let n = socket.read(&mut chunk).await.map_err(HeadError::Io)?;
        if n == 0 {
            return Err(HeadError::Eof);
        }
        head.extend_from_slice(&chunk[..n]);
    }
}

/// Split the request line into (method, target, version). Strictly three
/// space-separated tokens; anything else fails closed.
fn parse_request_line(head: &[u8]) -> Option<(&str, &str, &str)> {
    let line_end = head.iter().position(|&b| b == b'\n')?;
    let mut line = &head[..line_end];
    if line.ends_with(b"\r") {
        line = &line[..line.len() - 1];
    }
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || method.is_empty() || target.is_empty() || version.is_empty() {
        return None;
    }
    Some((method, target, version))
}

/// Parse a CONNECT target: authority-form `host:port` (RFC 7230 §5.3.3) or
/// tolerated absolute-form `scheme://authority[/path]` (§5.3.2, http/https
/// schemes only — anything else fails closed).
fn parse_authority(target: &str) -> Option<SocksTarget> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"));
    let authority = match rest {
        Some(r) => &r[..r.find('/').unwrap_or(r.len())],
        None => target,
    };
    split_host_port(authority)
}

/// Split `host:port` into a target. Bracketed IPv6 literals are handled;
/// an unbracketed host containing `:` is malformed (ambiguous with a
/// colon-split port), as are empty hosts, port 0, and domain characters
/// that cannot appear in a DNS name (the resolver would encode anything —
/// refuse those here instead).
fn split_host_port(authority: &str) -> Option<SocksTarget> {
    let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port_str = rest[close + 1..].strip_prefix(':')?;
        if host.parse::<Ipv6Addr>().is_err() {
            return None;
        }
        (host, port_str)
    } else {
        let (host, port_str) = authority.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port_str)
    };
    if host.is_empty() {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocksTarget::Ip(SocketAddr::new(ip, port)));
    }
    if host.len() > 253 || host.contains(['@', '/', '?', '#', ' ', '\t']) {
        return None;
    }
    Some(SocksTarget::Domain(host.to_string(), port))
}

/// Write an HTTP error reply; every reply carries `Connection: close` (the
/// connection is closed right after).
async fn write_http_reply(
    socket: &mut tokio::net::TcpStream,
    code: u16,
    reason: &str,
    extra_headers: &str,
) -> std::io::Result<()> {
    let msg = format!(
        "HTTP/1.1 {code} {reason}\r\n{extra_headers}Connection: close\r\nContent-Length: 0\r\n\r\n"
    );
    socket.write_all(msg.as_bytes()).await
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A parsed SOCKS/HTTP CONNECT target: literal IP or a domain name to
/// resolve.
enum SocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// SOCKS reply for a target-read failure. Protocol/shape problems answer
/// 0x08 (TTL/ACL-equivalent refusal, matching the family-policy refusals);
/// only an out-of-range port is a hard client error (0x01).
fn reply_for(e: &std::io::Error) -> u8 {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        0x01
    } else {
        0x08
    }
}

/// SOCKS reply for a resolver failure. 0x08 marks capability problems (the
/// transport cannot carry the DNS datagram); every name-level failure
/// (NXDOMAIN, ServFail, timeout, malformed answer) is a general failure
/// (0x01) — the response message distinguishes them in logs.
fn reply_for_resolver(e: &ResolverError) -> u8 {
    match e {
        ResolverError::NoUdpEgress(_) => 0x08,
        _ => 0x01,
    }
}

async fn read_addr(
    socket: &mut tokio::net::TcpStream,
    atyp: u8,
    policy: &FamilyPolicy,
) -> std::io::Result<SocksTarget> {
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
            Ok(SocksTarget::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                u16::from_be_bytes([b[4], b[5]]),
            )))
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
            Ok(SocksTarget::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes([b[16], b[17]]),
            )))
        }
        // ATYP=domain: consumed here, resolved later through the tunnel
        // resolver (see `handle_tcp_connect`) — never via the OS resolver,
        // which would leak DNS around the tunnel on censored networks.
        // Family policy defers to resolution: a v4/v6-only session filters
        // the resolved address by dialing with the session policy applied
        // inside `TunnelResolver::resolve` (single-stack modes query only
        // their family, so the answer always fits the mode).
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_timeout(socket, &mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            read_exact_timeout(socket, &mut rest).await?;
            let host_len = len[0] as usize;
            let host = match String::from_utf8(rest[..host_len].to_vec()) {
                Ok(h) => h,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "domain target is not valid UTF-8 (RFC 1928 requires a name)",
                    ))
                }
            };
            if host.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "domain target is empty",
                ));
            }
            let port = u16::from_be_bytes([rest[host_len], rest[host_len + 1]]);
            Ok(SocksTarget::Domain(host, port))
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

/// SOCKS reply with a real BND.ADDR/BND.PORT (the UDP ASSOCIATE relay
/// endpoint; RFC 1928 §6).
async fn write_reply_with_bind(
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

/// Session relay byte aggregate: `tx` = client → exit, `rx` = exit →
/// client; live-incremented by [`CountingStream`] on the client side
/// (each byte counted once, Relaxed like the watchdog counter).
#[derive(Debug, Default)]
pub struct RelayCounters {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
}

/// The process's current aggregate: `Engine::start` attaches one per
/// session (one session per process — the CLI session lock); `None` =
/// no serving session (relays count into a detached sink).
static CURRENT_RELAY_COUNTERS: std::sync::RwLock<Option<Arc<RelayCounters>>> =
    std::sync::RwLock::new(None);

/// Attach a fresh aggregate as the current one (once per `Engine::start`).
/// The engine files the returned Arc under the session id; the relay path
/// reaches the same Arc through the process-global above.
pub fn attach_relay_counters() -> Arc<RelayCounters> {
    let counters = Arc::new(RelayCounters::default());
    *CURRENT_RELAY_COUNTERS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(counters.clone());
    counters
}

/// Current aggregate for the relay path; a detached sink when unattached
/// (the bytes are counted, never misattributed to a session).
fn current_relay_counters() -> Arc<RelayCounters> {
    CURRENT_RELAY_COUNTERS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_default()
}

/// Current relay byte totals for the report path (`rx`, `tx`): the
/// process-wide aggregate — the CLI serves exactly one session per process
/// (session lock), so this IS the session's counters.
pub fn relay_byte_totals() -> (u64, u64) {
    let c = current_relay_counters();
    (c.rx.load(Ordering::Relaxed), c.tx.load(Ordering::Relaxed))
}

/// Wraps a stream and counts every byte moved through it — the input for
/// the relay watchdog's idle bound (activity detection only, so Relaxed
/// ordering suffices: the counter only ever needs "did it change").
struct CountingStream<S> {
    inner: S,
    moved: Arc<AtomicU64>,
    /// Session aggregate (client side only): tx on read (client → exit),
    /// rx on write (exit → client). The upstream side counts into a
    /// detached sink so each byte is counted exactly once.
    counters: Arc<RelayCounters>,
}

impl<S> CountingStream<S> {
    fn new(inner: S, moved: Arc<AtomicU64>, counters: Arc<RelayCounters>) -> Self {
        CountingStream {
            inner,
            moved,
            counters,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(()))) {
            self.moved
                .fetch_add(buf.filled().len() as u64, Ordering::Relaxed);
            self.counters
                .tx
                .fetch_add(buf.filled().len() as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            self.moved.fetch_add(*n as u64, Ordering::Relaxed);
            self.counters.rx.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
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

/// Relay an established association until either side closes, the relay
/// goes idle past `idle`, or `total` elapses (hard backstop).
///
/// The copy runs in its own task behind [`CountingStream`] wrappers; this
/// task is the watchdog: it samples the bytes-moved counter every `poll`
/// and drops the relay (abort the copy → both sockets close → the peer sees
/// EOF) when no byte moved for `idle`, or unconditionally at `total`.
/// Non-racy by construction: the counter is atomic and monotonic; the
/// watchdog only asks "did it change since the last sample".
async fn relay_with_idle_bounds(
    client: tokio::net::TcpStream,
    upstream: Box<dyn ByteStream>,
    idle: std::time::Duration,
    total: std::time::Duration,
    poll: std::time::Duration,
) -> std::io::Result<()> {
    let moved = Arc::new(AtomicU64::new(0));
    let counters = current_relay_counters();
    let mut copy = {
        let moved = moved.clone();
        tokio::spawn(async move {
            let mut client = CountingStream::new(client, moved.clone(), counters);
            let mut upstream =
                CountingStream::new(upstream, moved, Arc::new(RelayCounters::default()));
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
        })
    };
    let started = tokio::time::Instant::now();
    let mut last_seen = 0u64;
    let mut last_progress = started;
    loop {
        tokio::select! {
            copy_result = &mut copy => {
                match copy_result {
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(join) => {
                        return Err(std::io::Error::other(format!(
                            "relay copy task failed: {join}"
                        )));
                    }
                }
            }
            _ = tokio::time::sleep(poll) => {
                let now = tokio::time::Instant::now();
                let seen = moved.load(Ordering::Relaxed);
                if seen != last_seen {
                    last_seen = seen;
                    last_progress = now;
                }
                if now.duration_since(started) >= total {
                    copy.abort();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "relay exceeded its total time backstop",
                    ));
                }
                if now.duration_since(last_progress) >= idle {
                    copy.abort();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "relay idle past its inactivity bound",
                    ));
                }
            }
        }
    }
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

    /// Test dialer with hostname support: records every host it is asked
    /// to dial (the assertion target), then serves plain OS TCP.
    struct HostCapableDialer {
        hosts: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Dialer for HostCapableDialer {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::transport("test", "hosts only"))
        }

        async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::transport("test", "tcp only"))
        }

        async fn dial_host(
            &self,
            host: &str,
            port: u16,
            _timeout: std::time::Duration,
        ) -> Result<Box<dyn ByteStream>, HopError> {
            self.hosts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!("{host}:{port}"));
            // One-shot echo: a fresh listener per dial, served inline by a
            // spawned task the dialed stream drives to EOF (no shared
            // listener to race across dials).
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(HopError::from)?;
            let addr = echo.local_addr().map_err(HopError::from)?;
            tokio::spawn(async move {
                if let Ok((mut s, _)) = echo.accept().await {
                    let (mut r, mut w) = s.split();
                    tokio::io::copy(&mut r, &mut w).await.ok();
                }
            });
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(HopError::from)?;
            Ok(Box::new(DirectStream { inner: stream }))
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

    // --- relay byte counters (S3.1) ----------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_counters_advance_after_a_round_trip() {
        // Attach an aggregate (Engine::start's role) so the serve path
        // increments THIS session's counters.
        let counters = attach_relay_counters();
        assert_eq!(counters.tx.load(Ordering::Relaxed), 0);

        // Echo target + proxy under test.
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
        assert_eq!(hdr[1], 0x00);
        c.write_all(b"counted").await.unwrap();
        let mut back = [0u8; 7];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"counted");
        // Counters advance live (before the relay even closes): the client
        // stream's poll_read counts tx (client → exit), poll_write rx.
        let (rx, tx) = relay_byte_totals();
        assert!(tx >= 7, "client → exit bytes counted (tx={tx})");
        assert!(rx >= 7, "exit → client bytes counted (rx={rx})");
        let _ = c.shutdown().await;
        let _ = counters;
    }

    // --- hostname-capable exits (S3.2) --------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn domain_connect_reaches_dial_host_unmodified_without_a_resolver() {
        let dialer = Arc::new(HostCapableDialer {
            hosts: std::sync::Mutex::new(Vec::new()),
        });
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        // No resolver wired: the dial_host capability alone must serve.
        tokio::spawn(serve_socks_via_dialer_with_services(
            proxy,
            dialer.clone() as Arc<dyn Dialer>,
            FamilyPolicy::default(),
            PeerPolicy::default(),
            None,
        ));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let hdr = socks_request_domain(&mut c, "example.test", 443).await;
        assert_eq!(hdr[1], 0x00, "hostname-capable exit serves domain CONNECT");
        // The host reached dial_host EXACTLY as the client sent it.
        let dialed = dialer
            .hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            dialed,
            vec!["example.test:443".to_string()],
            "the host passed through unmodified (no resolution, no rewriting)"
        );
        // And the tunnel is live end-to-end.
        c.write_all(b"via-host").await.unwrap();
        let mut back = [0u8; 8];
        tokio::time::timeout(std::time::Duration::from_secs(2), c.read_exact(&mut back))
            .await
            .expect("echo within deadline")
            .expect("read");
        assert_eq!(&back, b"via-host");
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
    /// rejected. Rejection happens at accept time, before any SOCKS bytes,
    /// so a refused peer is closed without a reply (no RFC 1928 reply is
    /// possible before the greeting); the drop is diagnosed on stderr.
    /// A real non-loopback source address cannot be produced in a unit test
    /// (it would need raw socket binding to a specific interface).
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
    /// of the proxied connection) is refused before any dial — the proxy
    /// must not be an open relay for other hosts on the LAN.
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

    // --- ATYP=domain through the tunnel resolver ---------------------------

    /// UDP flow over an OS socket for the proxy tests (same shape as
    /// `net::SocketUdpFlow`; inlined so the test owns no production paths).
    struct ProxyUdpFlow {
        inner: tokio::net::UdpSocket,
    }

    #[async_trait::async_trait]
    impl UdpFlow for ProxyUdpFlow {
        async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
            self.inner
                .send_to(buf, dst)
                .await
                .map(|_| ())
                .map_err(HopError::from)
        }

        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
            self.inner.recv_from(buf).await.map_err(HopError::from)
        }

        fn local_addr(&self) -> Result<SocketAddr, HopError> {
            self.inner.local_addr().map_err(HopError::from)
        }
    }

    /// Minimal fake DNS server (canned A answers) + test dialer shared with
    /// `resolver.rs` tests; here it proves the PROXY half: the domain name
    /// from the SOCKS request is resolved through the tunnel and the dial
    /// lands on the RESOLVED address.
    struct ProxyDialer;

    #[async_trait::async_trait]
    impl Dialer for ProxyDialer {
        async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            let s = tokio::net::TcpStream::connect(dst)
                .await
                .map_err(HopError::from)?;
            Ok(Box::new(DirectStream { inner: s }))
        }

        async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            let bind = qcore_transport_api::unspecified_bind(&dst);
            let socket = tokio::net::UdpSocket::bind(bind)
                .await
                .map_err(HopError::from)?;
            socket.connect(dst).await.map_err(HopError::from)?;
            Ok(Box::new(ProxyUdpFlow { inner: socket }))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: true,
            }
        }
    }

    /// Echo server bound to a SPECIFIC loopback address the fake DNS names,
    /// so the assertion "the proxy dialed the RESOLVED addr" is meaningful
    /// (the request itself carries only a name).
    async fn echo_on(ip: IpAddr) -> SocketAddr {
        let l = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            tokio::io::copy(&mut r, &mut w).await.ok();
        });
        addr
    }

    /// One canned-A fake DNS server (same wire shape the resolver tests use,
    /// inlined here to keep the proxy test self-contained).
    async fn fake_dns(name: &str, answer: IpAddr) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let name = name.to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                if n < 17 {
                    continue;
                }
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let mut q = &buf[12..n];
                let mut labels = Vec::new();
                while let Some(&len) = q.first() {
                    if len == 0 {
                        break;
                    }
                    let Some(label) = q.get(1..1 + len as usize) else {
                        break;
                    };
                    labels.push(String::from_utf8_lossy(label).into_owned());
                    q = &q[1 + len as usize..];
                }
                if labels.join(".") != name {
                    continue;
                }
                let mut r = Vec::new();
                r.extend_from_slice(&id.to_be_bytes());
                r.push(0x80); // QR=1
                r.push(0x00); // rcode 0, no TC
                r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
                r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
                r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                for label in name.split('.') {
                    r.push(label.len() as u8);
                    r.extend_from_slice(label.as_bytes());
                }
                r.push(0);
                r.extend_from_slice(&[0x00, 0x01]); // QTYPE A
                r.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
                r.extend_from_slice(&[0xC0, 0x0C]); // owner pointer
                r.extend_from_slice(&[0x00, 0x01]); // TYPE A
                r.extend_from_slice(&[0x00, 0x01]); // CLASS IN
                r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
                r.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
                if let IpAddr::V4(v4) = answer {
                    r.extend_from_slice(&v4.octets());
                }
                let _ = socket.send_to(&r, from).await;
            }
        });
        addr
    }

    async fn socks_request_domain(
        c: &mut tokio::net::TcpStream,
        host: &str,
        port: u16,
    ) -> [u8; 10] {
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [0x05, 0x00]);
        let mut req = vec![0x05u8, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        hdr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn domain_target_resolves_through_tunnel_and_dials_resolved_addr() {
        // The resolved address must be an address the REQUEST never carries:
        // 127.0.0.2 (loopback, but distinct from the default 127.0.0.1 the
        // SOCKS test traffic uses elsewhere).
        let target_ip = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
        let echo_addr = echo_on(target_ip).await;
        let dns = fake_dns("example.internal", target_ip).await;
        let resolver = Arc::new(TunnelResolver::with_server(Arc::new(ProxyDialer), dns));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer_with_services(
            proxy,
            Arc::new(ProxyDialer),
            FamilyPolicy::default(),
            PeerPolicy::default(),
            Some(resolver),
        ));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let hdr = socks_request_domain(&mut c, "example.internal", echo_addr.port()).await;
        assert_eq!(hdr[1], 0x00, "domain CONNECT succeeds via tunnel DNS");
        // The relay is live end-to-end: bytes traverse proxy → resolved addr.
        c.write_all(b"resolved").await.unwrap();
        let mut back = [0u8; 8];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"resolved");
        assert_eq!(
            echo_addr.ip(),
            target_ip,
            "the echo that answered sits on the RESOLVED address"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn domain_target_without_resolver_refuses_08() {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(ProxyDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let hdr = socks_request_domain(&mut c, "no-resolver.test", 443).await;
        assert_eq!(
            hdr[1], 0x08,
            "no tunnel resolver wired: fail-closed 0x08, never OS resolution"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn domain_target_unresolvable_refuses_01() {
        // Resolver wired but the name answers NXDOMAIN: general failure.
        let dns = fake_dns("known.test", IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let resolver = Arc::new(TunnelResolver::with_server(Arc::new(ProxyDialer), dns));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer_with_services(
            proxy,
            Arc::new(ProxyDialer),
            FamilyPolicy::default(),
            PeerPolicy::default(),
            Some(resolver),
        ));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let hdr = socks_request_domain(&mut c, "unknown.test", 443).await;
        assert_eq!(hdr[1], 0x01, "NXDOMAIN maps to general failure 0x01");
    }

    // --- UDP ASSOCIATE (RFC 1928) ------------------------------------------

    /// Encode one SOCKS UDP datagram for `dst` (RFC 1928 §7:
    /// RSV FRAG ATYP DST.ADDR DST.PORT payload).
    fn udp_datagram(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
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

    /// Decode one encapsulated reply into (source, payload).
    fn parse_udp_reply(buf: &[u8]) -> Option<(SocketAddr, &[u8])> {
        if buf.len() < 10 || buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
            return None;
        }
        match buf[3] {
            0x01 if buf.len() >= 10 => {
                let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                Some((SocketAddr::new(IpAddr::V4(ip), port), &buf[10..]))
            }
            0x04 if buf.len() >= 22 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[4..20]);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                Some((
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port),
                    &buf[22..],
                ))
            }
            _ => None,
        }
    }

    /// UDP echo server bound to a specific address (the domain-ATYP test
    /// names 127.0.0.2 so the resolved-addr assertion is meaningful).
    async fn udp_echo_on(ip: IpAddr) -> SocketAddr {
        let s = tokio::net::UdpSocket::bind(SocketAddr::new(ip, 0))
            .await
            .unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = s.recv_from(&mut buf).await else {
                    break;
                };
                let _ = s.send_to(&buf[..n], from).await;
            }
        });
        addr
    }

    /// Greet + UDP ASSOCIATE; asserts the success reply shape and returns
    /// the relay endpoint (BND.ADDR/BND.PORT).
    async fn socks_associate(c: &mut tokio::net::TcpStream) -> SocketAddr {
        socks_greet(c).await;
        c.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00, "associate accepted");
        assert_eq!(reply[2], 0x00, "RSV");
        assert_eq!(reply[3], 0x01, "BND.ADDR is an IPv4 literal");
        let ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
        let port = u16::from_be_bytes([reply[8], reply[9]]);
        assert_ne!(port, 0, "BND.PORT carries the relay port");
        SocketAddr::new(IpAddr::V4(ip), port)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_associate_relays_client_datagrams_through_exit_flows() {
        let echo = udp_echo_on(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(ProxyDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let relay = socks_associate(&mut c).await;

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = b"udp-echo-roundtrip";
        udp.send_to(&udp_datagram(&echo, payload), relay)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv_from(&mut buf))
                .await
                .expect("echo reply within deadline")
                .expect("recv");
        let (src, got) = parse_udp_reply(&buf[..n]).expect("encapsulated reply");
        assert_eq!(got, &payload[..], "payload round-trips through the flow");
        assert_eq!(
            src, echo,
            "reply header names the destination the client addressed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fragmented_udp_datagram_is_dropped_and_the_association_survives() {
        let echo = udp_echo_on(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(ProxyDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let relay = socks_associate(&mut c).await;

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut frag = udp_datagram(&"127.0.0.1:9".parse().unwrap(), b"x");
        frag[2] = 1; // FRAG = 1
        udp.send_to(&frag, relay).await.unwrap();

        // FRAG != 0 drops the datagram (like the malformed case) — no
        // control-connection reply, association still live: a normal
        // datagram after the fragmented one round-trips through the echo.
        udp.send_to(&udp_datagram(&echo, b"after-frag"), relay)
            .await
            .unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv_from(&mut buf))
                .await
                .expect("echo reply within deadline")
                .expect("recv");
        let (_src, got) = parse_udp_reply(&buf[..n]).expect("encapsulated reply");
        assert_eq!(
            got, b"after-frag",
            "association survived the fragmented datagram"
        );
    }

    /// A foreign-IP sender (datagrams whose source IP differs from the TCP
    /// control peer's IP) is dropped and the association stays pinned to the
    /// real client: 127.0.0.2 races the control peer 127.0.0.1, its datagram
    /// never pins nor flows, and the real client's datagram still round-trips.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn datagrams_from_a_foreign_ip_are_dropped() {
        let echo = udp_echo_on(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(ProxyDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let relay = socks_associate(&mut c).await;

        // The "LAN racer": same loopback range but a different IP than the
        // control connection's peer (127.0.0.1).
        let racer = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        racer
            .send_to(&udp_datagram(&echo, b"race-pin"), relay)
            .await
            .unwrap();

        // The real client (control peer's IP) still relays.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&udp_datagram(&echo, b"real-client"), relay)
            .await
            .unwrap();

        // Only the real client's echo must arrive — the racer's datagram is
        // dropped, so exactly one payload ever comes back through the relay.
        let mut buf = vec![0u8; 2048];
        let (n, _from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv_from(&mut buf))
                .await
                .expect("echo reply within deadline")
                .expect("recv");
        let (_src, got) = parse_udp_reply(&buf[..n]).expect("encapsulated reply");
        assert_eq!(got, b"real-client", "the real client's datagram flows");
        // The racer gets no reply: its datagram was dropped before any flow.
        let mut racer_buf = vec![0u8; 2048];
        let race_reply = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            racer.recv_from(&mut racer_buf),
        )
        .await;
        assert!(
            race_reply.is_err(),
            "foreign-IP datagram must be dropped, not answered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_associate_without_udp_egress_refuses_07() {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer(proxy, Arc::new(DirectDialer)));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        socks_greet(&mut c).await;
        c.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut hdr = [0u8; 10];
        c.read_exact(&mut hdr).await.unwrap();
        assert_eq!(
            hdr[1], 0x07,
            "exit hop without UDP egress: command not supported"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_domain_datagram_resolves_through_tunnel_then_dials() {
        // The resolved address is an address the REQUEST never carries.
        let target_ip = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
        let echo = udp_echo_on(target_ip).await;
        let dns = fake_dns("udp.internal", target_ip).await;
        let resolver = Arc::new(TunnelResolver::with_server(Arc::new(ProxyDialer), dns));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_socks_via_dialer_with_services(
            proxy,
            Arc::new(ProxyDialer),
            FamilyPolicy::default(),
            PeerPolicy::default(),
            Some(resolver),
        ));

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let relay = socks_associate(&mut c).await;

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut dgram = vec![0u8, 0x00, 0x00, 0x03, "udp.internal".len() as u8];
        dgram.extend_from_slice(b"udp.internal");
        dgram.extend_from_slice(&echo.port().to_be_bytes());
        dgram.extend_from_slice(b"resolved-udp");
        udp.send_to(&dgram, relay).await.unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv_from(&mut buf))
                .await
                .expect("echo reply within deadline")
                .expect("recv");
        let (src, got) = parse_udp_reply(&buf[..n]).expect("encapsulated reply");
        assert_eq!(got, b"resolved-udp", "payload round-trips");
        assert_eq!(
            src.ip(),
            target_ip,
            "the flow dialed the RESOLVED address (the request carried only a name)"
        );
        assert_eq!(src.port(), echo.port());
    }

    // --- relay idle bounds (idle replaces the old 30-min total cap) -------

    /// Wire a relay through a hub listener: the returned stream is the raw
    /// client end, the far end is a TCP echo reachable via the test dialer.
    async fn spawn_relay(
        idle: std::time::Duration,
        total: std::time::Duration,
        poll: std::time::Duration,
    ) -> tokio::net::TcpStream {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    tokio::io::copy(&mut r, &mut w).await.ok();
                });
            }
        });
        let hub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub_addr = hub.local_addr().unwrap();
        let accepted = tokio::spawn(async move { hub.accept().await.unwrap().0 });
        let raw = tokio::net::TcpStream::connect(hub_addr).await.unwrap();
        let relay_client = accepted.await.unwrap();
        let upstream = DirectDialer.dial_tcp(echo_addr).await.expect("echo dial");
        tokio::spawn(relay_with_idle_bounds(
            relay_client,
            upstream,
            idle,
            total,
            poll,
        ));
        raw
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_relay_drops_at_the_idle_deadline() {
        let mut raw = spawn_relay(
            std::time::Duration::from_millis(200),
            std::time::Duration::from_secs(30),
            std::time::Duration::from_millis(25),
        )
        .await;
        // Nothing is ever written: the relay must reach EOF at the idle
        // bound, not hang for the (much longer) total backstop.
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), raw.read(&mut byte))
            .await
            .expect("EOF within deadline")
            .expect("read");
        assert_eq!(n, 0, "idle relay drops with EOF at the idle bound");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn active_relay_survives_past_the_idle_deadline() {
        let raw = spawn_relay(
            std::time::Duration::from_millis(300),
            std::time::Duration::from_secs(30),
            std::time::Duration::from_millis(30),
        )
        .await;
        let (mut rh, mut wh) = tokio::io::split(raw);
        // 15 writes 40 ms apart (600 ms total) — twice the idle bound. The
        // analog of "a browser WebSocket survives past the old 30-min mark".
        let writer = tokio::spawn(async move {
            for i in 0..15u32 {
                wh.write_all(&[b'a' + i as u8]).await.expect("write");
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
        });
        for i in 0..15u32 {
            let mut back = [0u8; 1];
            tokio::time::timeout(std::time::Duration::from_secs(2), rh.read_exact(&mut back))
                .await
                .expect("echo within deadline")
                .expect("read");
            assert_eq!(
                back[0],
                b'a' + i as u8,
                "echo {i} arrived through a live relay"
            );
        }
        writer.await.expect("writer");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_hard_total_backstop_drops_even_an_active_relay() {
        let raw = spawn_relay(
            std::time::Duration::from_secs(60), // idle never fires
            std::time::Duration::from_millis(400),
            std::time::Duration::from_millis(25),
        )
        .await;
        let (mut rh, mut wh) = tokio::io::split(raw);
        // The writer outlives the 400 ms backstop: an EOF before it stops
        // proves the total bound fired, not an idle drop.
        let writer = tokio::spawn(async move {
            let mut written = 0usize;
            while written < 200 {
                match wh.write_all(b"x").await {
                    Ok(()) => written += 1,
                    Err(_) => break, // relay dropped: nothing left to prove
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            written
        });
        let eof = tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            let mut byte = [0u8; 1];
            loop {
                // EOF or a reset both prove the relay dropped: aborting the
                // copy closes the sockets immediately, and on Windows a
                // socket dropped with pending data surfaces as ConnectionReset.
                // The window is generous (3 s vs a 400 ms backstop) because
                // under parallel test load the relay's poll loop can be
                // scheduled late; the written<200 check below keeps the
                // proof honest even in that window (a clean writer-side
                // close would also produce EOF — but only after all 200
                // writes, which the assertion rejects).
                match rh.read(&mut byte).await {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return,
                    Err(e) => panic!("unexpected read error: {e}"),
                }
            }
        })
        .await;
        assert!(
            eof.is_ok(),
            "relay hit the hard total backstop while the writer was still active"
        );
        let written = writer.await.expect("writer");
        assert!(
            written < 200,
            "EOF must come from the relay dropping under an active writer \
             (backstop), not from the writer finishing cleanly"
        );
    }

    // --- HTTP CONNECT listener ---------------------------------------------

    /// Read one HTTP reply (through its blank line) with a per-read deadline.
    async fn http_read_reply(c: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            if find_subslice(&buf, b"\r\n\r\n").is_some() {
                break;
            }
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), c.read(&mut chunk))
                .await
                .expect("reply within deadline")
                .expect("read");
            assert!(n > 0, "connection closed before a reply");
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn spawn_http(
        dialer: Arc<dyn Dialer>,
        peers: PeerPolicy,
        resolver: Option<Arc<TunnelResolver>>,
    ) -> SocketAddr {
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_http_proxy(
            proxy,
            dialer,
            FamilyPolicy::default(),
            peers,
            resolver,
        ));
        addr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_connect_tunnels_to_the_dial_path() {
        let echo_addr = echo_on(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let proxy_addr = spawn_http(Arc::new(DirectDialer), PeerPolicy::default(), None).await;

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo_addr.port()).as_bytes())
            .await
            .unwrap();
        let reply = http_read_reply(&mut c).await;
        assert!(
            reply.starts_with("HTTP/1.1 200"),
            "CONNECT accepted: {reply}"
        );
        c.write_all(b"via-http-connect").await.unwrap();
        let mut back = [0u8; 16];
        tokio::time::timeout(std::time::Duration::from_secs(2), c.read_exact(&mut back))
            .await
            .expect("echo within deadline")
            .expect("read");
        assert_eq!(&back, b"via-http-connect", "tunnel bytes flow both ways");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_domain_authority_resolves_through_tunnel_then_dials() {
        let target_ip = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
        let echo_addr = echo_on(target_ip).await;
        let dns = fake_dns("http.internal", target_ip).await;
        let resolver = Arc::new(TunnelResolver::with_server(Arc::new(ProxyDialer), dns));
        let proxy_addr =
            spawn_http(Arc::new(ProxyDialer), PeerPolicy::default(), Some(resolver)).await;

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(
            format!(
                "CONNECT http.internal:{} HTTP/1.1\r\n\r\n",
                echo_addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let reply = http_read_reply(&mut c).await;
        assert!(
            reply.starts_with("HTTP/1.1 200"),
            "domain authority accepted via tunnel DNS: {reply}"
        );
        c.write_all(b"resolved-http").await.unwrap();
        let mut back = [0u8; 13];
        tokio::time::timeout(std::time::Duration::from_secs(2), c.read_exact(&mut back))
            .await
            .expect("echo within deadline")
            .expect("read");
        assert_eq!(&back, b"resolved-http");
        assert_eq!(
            echo_addr.ip(),
            target_ip,
            "the echo that answered sits on the RESOLVED address"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_get_is_answered_405_and_the_connection_closes() {
        let proxy_addr = spawn_http(Arc::new(DirectDialer), PeerPolicy::default(), None).await;

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
            .await
            .unwrap();
        let reply = http_read_reply(&mut c).await;
        assert!(reply.starts_with("HTTP/1.1 405"), "GET refused: {reply}");
        assert!(
            reply.contains("Connection: close"),
            "405 carries Connection: close: {reply}"
        );
        // And the connection actually closes after the reply.
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), c.read(&mut byte))
            .await
            .expect("close within deadline")
            .expect("read");
        assert_eq!(n, 0, "connection closed after 405");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_malformed_authority_is_400() {
        let proxy_addr = spawn_http(Arc::new(DirectDialer), PeerPolicy::default(), None).await;

        let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        // CONNECT requires an explicit port; a bare host fails closed.
        c.write_all(b"CONNECT no-port-here HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let reply = http_read_reply(&mut c).await;
        assert!(
            reply.starts_with("HTTP/1.1 400"),
            "malformed authority refused: {reply}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_listener_shares_the_socks_peer_filter() {
        // Loopback peers serve under both policies — the filter is the same
        // `peer_allowed` decision the SOCKS listener applies.
        for policy in [PeerPolicy::LoopbackOnly, PeerPolicy::Any] {
            let echo_addr = echo_on(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
            let proxy_addr = spawn_http(Arc::new(DirectDialer), policy, None).await;
            let mut c = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            c.write_all(
                format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo_addr.port()).as_bytes(),
            )
            .await
            .unwrap();
            let reply = http_read_reply(&mut c).await;
            assert!(
                reply.starts_with("HTTP/1.1 200"),
                "loopback peer serves under {policy:?}: {reply}"
            );
        }
    }
}
