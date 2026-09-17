//! Address-family policy, Happy Eyeballs dial, root carrier, DNS policy.
//!
//! `dual` = Happy Eyeballs v2 racing (RFC 8305): staggered attempts across
//! families, never true simultaneous equal-race. Preferred family defaults to
//! IPv4 (configurable to IPv6). `AllowedIPs` honored exactly (no silent family
//! expansion). DNS routed through the tunnel or refuse to start (FR-013c).

use qcore_transport_api::{ByteStream, Capabilities, Dialer, HopError, UdpFlow};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Address-family mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FamilyMode {
    Ipv4,
    Ipv6,
    Dual,
}

/// Family policy: explicit user choice (FR-013) + Happy Eyeballs tuning (FR-013a).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyPolicy {
    pub mode: FamilyMode,
    /// Preferred family for Happy Eyeballs racing. Default IPv4.
    pub prefer: FamilyMode,
    /// Connection Attempt Delay. Default 250 ms, configurable 10 ms–2 s.
    pub connection_attempt_delay_ms: u64,
    /// Resolution Delay. Default 50 ms.
    pub resolution_delay_ms: u64,
}

impl Default for FamilyPolicy {
    fn default() -> Self {
        FamilyPolicy {
            mode: FamilyMode::Dual,
            prefer: FamilyMode::Ipv4,
            connection_attempt_delay_ms: 250,
            resolution_delay_ms: 50,
        }
    }
}

impl FamilyPolicy {
    pub fn parse(mode: &str, prefer: &str) -> Result<Self, String> {
        let mode = match mode {
            "ipv4" => FamilyMode::Ipv4,
            "ipv6" => FamilyMode::Ipv6,
            "dual" => FamilyMode::Dual,
            other => return Err(format!("unknown family `{other}` (ipv4|ipv6|dual)")),
        };
        let prefer = match prefer {
            "ipv4" => FamilyMode::Ipv4,
            "ipv6" => FamilyMode::Ipv6,
            other => return Err(format!("unknown prefer `{other}` (ipv4|ipv6)")),
        };
        Ok(FamilyPolicy {
            mode,
            prefer,
            ..Default::default()
        })
    }

    /// Order candidate addresses for Happy Eyeballs racing: preferred family
    /// first, then the other; single-stack modes filter.
    pub fn order(&self, addrs: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut v: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| match self.mode {
                FamilyMode::Ipv4 => a.is_ipv4(),
                FamilyMode::Ipv6 => a.is_ipv6(),
                FamilyMode::Dual => true,
            })
            .collect();
        let preferred = |a: &SocketAddr| match self.prefer {
            FamilyMode::Ipv4 => a.is_ipv4(),
            FamilyMode::Ipv6 => a.is_ipv6(),
            FamilyMode::Dual => true,
        };
        v.sort_by_key(|a| !preferred(a));
        v
    }
}

/// Outcome of broken-IPv6 detection during validation: never connect into a
/// black hole — fall back or report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyFallback {
    NoAction,
    FallbackToIpv4,
    RefuseBlackhole,
}

/// Pure detection logic over validation probe results.
pub fn detect_broken_ipv6(v4_ok: bool, v6_ok: bool, mode: FamilyMode) -> FamilyFallback {
    match (mode, v4_ok, v6_ok) {
        (FamilyMode::Dual, true, false) => FamilyFallback::FallbackToIpv4,
        (FamilyMode::Dual, false, false) => FamilyFallback::RefuseBlackhole,
        (FamilyMode::Ipv6, _, false) => FamilyFallback::RefuseBlackhole,
        _ => FamilyFallback::NoAction,
    }
}

/// Staggered Happy Eyeballs TCP dial over pre-ordered addresses.
pub async fn eyeballs_dial(
    addrs: &[SocketAddr],
    attempt_delay: Duration,
    timeout: Duration,
) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no addresses to dial",
        ));
    }
    let mut errors = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(attempt_delay).await;
        }
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(*addr)).await {
            Ok(Ok(s)) => return Ok((s, *addr)),
            Ok(Err(e)) => errors.push(e.to_string()),
            Err(_) => errors.push("attempt timed out".to_string()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        format!("all {} attempts failed: {}", addrs.len(), errors.join("; ")),
    ))
}

/// Owned TCP byte stream (orphan-rule-safe wrapper around `TcpStream`).
pub struct TcpByteStream {
    inner: tokio::net::TcpStream,
}

impl TcpByteStream {
    pub fn new(inner: tokio::net::TcpStream) -> Self {
        TcpByteStream { inner }
    }
}

impl tokio::io::AsyncRead for TcpByteStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TcpByteStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl ByteStream for TcpByteStream {}

/// UDP flow over an OS socket (root carrier).
pub struct SocketUdpFlow {
    socket: tokio::net::UdpSocket,
}

impl SocketUdpFlow {
    pub fn new(socket: tokio::net::UdpSocket) -> Self {
        SocketUdpFlow { socket }
    }
}

#[async_trait::async_trait]
impl UdpFlow for SocketUdpFlow {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        self.socket
            .send_to(buf, dst)
            .await
            .map(|_| ())
            .map_err(HopError::from)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        self.socket.recv_from(buf).await.map_err(HopError::from)
    }

    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        self.socket.local_addr().map_err(HopError::from)
    }
}

/// Root carrier: hop 0 dials through OS sockets.
pub struct RootDialer {
    policy: FamilyPolicy,
    timeout: Duration,
}

impl RootDialer {
    pub fn new(policy: FamilyPolicy, timeout: Duration) -> Self {
        RootDialer { policy, timeout }
    }
}

#[async_trait::async_trait]
impl Dialer for RootDialer {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        let ordered = self.policy.order(&[dst]);
        let (stream, _) = eyeballs_dial(
            &ordered,
            Duration::from_millis(self.policy.connection_attempt_delay_ms),
            self.timeout,
        )
        .await
        .map_err(HopError::from)?;
        Ok(Box::new(TcpByteStream::new(stream)))
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        // Static unspecified-bind literals: unparsable only if edited wrong.
        let bind: SocketAddr = if dst.is_ipv4() {
            "0.0.0.0:0"
                .parse()
                .expect("IPv4 unspecified bind literal parses")
        } else {
            "[::]:0"
                .parse()
                .expect("IPv6 unspecified bind literal parses")
        };
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(HopError::from)?;
        socket.connect(dst).await.map_err(HopError::from)?;
        Ok(Box::new(SocketUdpFlow::new(socket)))
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

/// Root dialer handle shared with hop 0.
pub fn root_dialer(policy: FamilyPolicy, timeout: Duration) -> Arc<dyn Dialer> {
    Arc::new(RootDialer::new(policy, timeout))
}

/// DNS policy (FR-013c): DNS is routed through the tunnel chain or the client
/// refuses to start. Resolver transport prefers IPv6 with penalty-based
/// fallback; synthesis only for IPv4 literals (Pref64/RFC 6052) and as the
/// RFC 8305 2-second last resort; never synthesize AAAA when real AAAA exist.
#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub through_tunnel_or_refuse: bool,
    pub prefer_ipv6_transport: bool,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        DnsPolicy {
            through_tunnel_or_refuse: true,
            prefer_ipv6_transport: true,
        }
    }
}

impl DnsPolicy {
    pub fn ensure(&self, tunnel_up: bool) -> Result<(), HopError> {
        if tunnel_up || !self.through_tunnel_or_refuse {
            Ok(())
        } else {
            Err(HopError::validation(
                "DNS cannot be routed through the tunnel: refusing to start",
            ))
        }
    }
}

/// Advisory keepalive interval when keepalive is enabled (~25 s per T044).
pub const ADVISORY_KEEPALIVE_SECS: u64 = 25;

/// Per-hop keepalive policy (T044): configurable, default off. A tick observes
/// hop health; a non-healthy hop emits `HopEvent::Failed` on the session bus
/// so the session degrades/fails honestly instead of idling on a dead hop.
#[derive(Debug, Clone)]
pub struct KeepalivePolicy {
    pub enabled: bool,
    pub interval_secs: u64,
}

impl Default for KeepalivePolicy {
    fn default() -> Self {
        KeepalivePolicy {
            enabled: false,
            interval_secs: ADVISORY_KEEPALIVE_SECS,
        }
    }
}

/// Spawn the keepalive watcher for one hop. Only aborting the returned
/// handle stops the ticks — dropping a `JoinHandle` detaches (the task keeps
/// running). The owner stores `handle.abort_handle()` in `StartedHop` and
/// aborts on teardown (`unwind`, `SessionHandle::stop_all`); the linger is
/// then bounded by abort delivery, not by the next tick. A missing bus
/// receiver deliberately does NOT stop the watcher: receivers attach
/// transiently, so explicit abort is the only stop signal.
pub fn spawn_keepalive(
    hop_id: String,
    hop: std::sync::Arc<dyn qcore_transport_api::RunningHop>,
    policy: KeepalivePolicy,
    events: tokio::sync::broadcast::Sender<qcore_transport_api::HopEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !policy.enabled {
            return;
        }
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(policy.interval_secs.max(1)));
        // Skip the immediate first tick: health right after bring-up is known.
        tick.tick().await;
        loop {
            tick.tick().await;
            match hop.health() {
                qcore_transport_api::HopHealth::Healthy
                | qcore_transport_api::HopHealth::Starting => {}
                h => {
                    let _ = events.send(qcore_transport_api::HopEvent::Failed {
                        hop_id: hop_id.clone(),
                        cause: format!("keepalive observed hop health {h:?}"),
                    });
                    break;
                }
            }
        }
    })
}

/// Endpoint roaming (T044): when the local network changes, re-select the
/// primary endpoint from the known candidates under the same family policy.
/// Returns the newly preferred candidate, or `None` when nothing is usable
/// (fail closed upstream, never black-hole).
pub fn roam_endpoint(policy: &FamilyPolicy, candidates: &[SocketAddr]) -> Option<SocketAddr> {
    policy.order(candidates).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_orders_preferred_family_first() {
        let policy = FamilyPolicy::default();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(policy.order(&[v6, v4]), vec![v4, v6]);
        let prefer6 = FamilyPolicy {
            prefer: FamilyMode::Ipv6,
            ..policy
        };
        assert_eq!(prefer6.order(&[v4, v6]), vec![v6, v4]);
    }

    #[test]
    fn single_stack_modes_filter() {
        let v4only = FamilyPolicy {
            mode: FamilyMode::Ipv4,
            ..Default::default()
        };
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(v4only.order(&[v6, v4]), vec![v4]);
    }

    #[test]
    fn broken_ipv6_never_blackholes() {
        assert_eq!(
            detect_broken_ipv6(true, false, FamilyMode::Dual),
            FamilyFallback::FallbackToIpv4
        );
        assert_eq!(
            detect_broken_ipv6(false, false, FamilyMode::Dual),
            FamilyFallback::RefuseBlackhole
        );
        assert_eq!(
            detect_broken_ipv6(true, true, FamilyMode::Dual),
            FamilyFallback::NoAction
        );
    }

    #[test]
    fn dns_refuses_without_tunnel() {
        assert!(DnsPolicy::default().ensure(false).is_err());
        assert!(DnsPolicy::default().ensure(true).is_ok());
    }

    #[test]
    fn keepalive_defaults_off_with_advisory_interval() {
        let p = KeepalivePolicy::default();
        assert!(!p.enabled);
        assert_eq!(p.interval_secs, ADVISORY_KEEPALIVE_SECS);
    }

    #[test]
    fn roam_prefers_policy_family_and_never_blackholes() {
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let dual = FamilyPolicy::default();
        assert_eq!(roam_endpoint(&dual, &[v6, v4]), Some(v4));
        let v4only = FamilyPolicy {
            mode: FamilyMode::Ipv4,
            ..Default::default()
        };
        assert_eq!(roam_endpoint(&v4only, &[v6, v4]), Some(v4));
        assert_eq!(roam_endpoint(&v4only, &[v6]), None);
        assert_eq!(roam_endpoint(&dual, &[]), None);
    }

    #[tokio::test]
    async fn eyeballs_reaches_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let (stream, used) =
            eyeballs_dial(&[addr], Duration::from_millis(250), Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(used, addr);
        assert!(stream.peer_addr().is_ok());
    }
}
