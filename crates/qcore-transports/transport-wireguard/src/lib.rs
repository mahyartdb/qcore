//! WireGuard transport over `boringtun` (T039).
//!
//! Real WireGuard handshake + transport encryption (Noise IK), keepalive,
//! roaming, MTU derivation. Serves WARP, imported and AmneziaWG modes
//! ([`modes`]); AmneziaWG obfuscation decorates this same data plane (US5).
//!
//! Egress model: hops expose tunnel transport-data *channels* to the peer
//! endpoint, framed by [`stream`] (streams for TCP, datagrams for UDP).
//! Against a qcore peer (or the loopback test responder) the framing carries
//! inner destinations; host IP routing via a TUN device is platform
//! integration outside the core. Health reflects handshake state.

pub mod awg;
pub mod modes;
pub mod stream;
pub mod test_support;

use boringtun::noise::{Tunn, TunnResult};
use qcore_transport_api::{
    unspecified_bind, ByteStream, Capabilities, Dialer, HopConfig, HopError, HopErrorKind,
    HopEvent, HopHealth, ObfuscationFamily, RunningHop, TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::stream::FrameSender;

/// Per-hop ordered egress cap (#12 queue decision: bounded-block with
/// backpressure). The egress FIFO is replay-order-sensitive, so a full queue
/// parks senders (async `send` awaits space; `poll_write` parks its waker)
/// instead of dropping. 1024 packets ≈ 1.4 MB at full MTU — bounded memory
/// per hop, deep enough to absorb pump scheduling jitter. #10 measured the
/// status quo this replaces: 100k × 1400 B queued with zero backpressure
/// (~140 MB growth).
pub const EGRESS_QUEUE_CAP: usize = 1024;

/// One queued uplink packet: destination + encrypted bytes.
pub type EgressItem = (SocketAddr, Vec<u8>);

thread_local! {
    /// Reused 64K boringtun scratch (#15 perf batch). `vec![0u8; 65535]`
    /// zeroing measured ~1.5 µs/alloc here (11.6 µs in #10) — the dominant
    /// per-packet cost next to ~100–300 ns framing. One buffer per worker
    /// thread; `seal` copies the packet out before returning, so reuse is
    /// race-free. Grows once, never shrinks.
    static SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` against the thread-local 64K scratch (boringtun writes its output
/// into the buffer; the returned packet slice is copied out by the caller
/// before the next use).
fn with_scratch<R>(f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    SCRATCH.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < 65535 {
            buf.resize(65535, 0);
        }
        f(&mut buf)
    })
}

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "wireguard",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[ObfuscationFamily::Noize, ObfuscationFamily::Awg],
    config_schema: "wireguard/v1",
    needs_sidecar: false,
};

pub struct WireguardFactory;
static FACTORY: WireguardFactory = WireguardFactory;

qcore_transport_api::register_plugin!(&FACTORY);

/// Linkage anchor (see `qcore_transports::linked_kinds`).
pub fn plugin_descriptor() -> &'static TransportDescriptor {
    &DESCRIPTOR
}

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for WireguardFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let hop_id = cfg.get("hop_id").unwrap_or("wireguard-0").to_string();
        // Hostnames resolve here (async) so standard `.conf` endpoints work:
        // the sync `modes::resolve` below then always sees an IP literal.
        let mut cfg = cfg;
        if let Some(ep) = cfg.get("endpoint") {
            if ep.parse::<SocketAddr>().is_err() {
                let family = cfg.get("family").unwrap_or("dual").to_string();
                let resolved = modes::resolve_endpoint(&ep, &family)
                    .await
                    .map_err(|e| HopError::new(HopErrorKind::Config, Some(hop_id.clone()), e))?;
                cfg.fields
                    .insert("endpoint".to_string(), resolved.to_string());
            }
        }
        let params = modes::resolve(&cfg)
            .map_err(|e| HopError::new(HopErrorKind::Config, Some(hop_id.clone()), e))?;
        WireguardHop::bring_up(hop_id, params, carrier).await
    }
}

/// Resolved peer parameters.
#[derive(Debug, Clone)]
pub struct WgParams {
    pub peer_endpoint: SocketAddr,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Persistent keepalive seconds. Default off (FR-013d).
    pub keepalive: Option<u16>,
    /// AmneziaWG params when `peer=awg` (decorator lands in US5 T071).
    pub awg: Option<awg::AwgParams>,
    /// Noize params when an obfuscation profile is active (US5 T070).
    pub noize: Option<qcore_transport_api::obfuscate::NoizeParams>,
}

/// A running WireGuard hop: boringtun tunnel + UDP pump task.
pub struct WireguardHop {
    hop_id: String,
    inner: Arc<HopInner>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    _pump: tokio::task::JoinHandle<()>,
}

struct HopInner {
    tunnel: Mutex<Tunn>,
    udp: Arc<dyn PacketSock>,
    peer: std::sync::RwLock<SocketAddr>,
    streams: Arc<stream::StreamTable>,
    /// Ordered egress queue: FIFO send order is load-bearing — concurrent
    /// `send_to` spawns let keepalives overtake DATA and trip the peer's
    /// replay protection. Only the pump task transmits. Bounded
    /// ([`EGRESS_QUEUE_CAP`]): full means backpressure, never growth.
    tx: tokio::sync::mpsc::Sender<EgressItem>,
}

/// Packet uplink for the boringtun pump (US3 T058 nesting): an OS UDP socket
/// when the carrier is direct, a carrier flow when nested. Both expose the
/// same send/recv shape, so the pump is uplink-agnostic.
#[async_trait::async_trait]
trait PacketSock: Send + Sync {
    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> std::io::Result<()>;
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

struct OsSock {
    socket: Arc<tokio::net::UdpSocket>,
}

#[async_trait::async_trait]
impl PacketSock for OsSock {
    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> std::io::Result<()> {
        self.socket.send_to(bytes, peer).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

struct FlowSock {
    flow: Box<dyn UdpFlow>,
}

#[async_trait::async_trait]
impl PacketSock for FlowSock {
    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> std::io::Result<()> {
        self.flow
            .send_to(bytes, peer)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.message))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.flow
            .recv_from(buf)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.message))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.flow
            .local_addr()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotConnected, e.message))
    }
}

/// Pre-handshake junk train over the uplink (best-effort; failures ignored).
/// Defense-in-depth caps: count and sizes are already validated at parse,
/// directly constructed params are clamped here too.
async fn send_junk(
    udp: &Arc<dyn PacketSock>,
    peer: SocketAddr,
    count: usize,
    min: usize,
    max: usize,
) {
    use qcore_transport_api::obfuscate::{MAX_JUNK_COUNT, MAX_JUNK_SIZE};
    let count = count.min(MAX_JUNK_COUNT as usize);
    let min = min.clamp(1, MAX_JUNK_SIZE);
    let max = max.max(min).min(MAX_JUNK_SIZE);
    if count == 0 || max == 0 {
        return;
    }
    let mut rng = qcore_transport_api::obfuscate::XorShift64::new(
        qcore_transport_api::obfuscate::XorShift64::seed(),
    );
    for _ in 0..count {
        let packet = qcore_transport_api::obfuscate::junk_packet(&mut rng, min, max);
        udp.send_to(&packet, peer).await.ok();
    }
}

impl WireguardHop {
    async fn bring_up(
        hop_id: String,
        params: WgParams,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let local_private = boringtun::x25519::StaticSecret::from(params.private_key);
        let peer_public = boringtun::x25519::PublicKey::from(params.peer_public_key);
        let tunnel = Tunn::new(
            local_private,
            peer_public,
            params.preshared_key,
            params.keepalive,
            0,
            None,
        );
        // Nested uplink (T058): an encapsulated carrier drives boringtun over
        // a carrier flow; a direct carrier keeps the OS UDP socket. Against a
        // framing-unaware far end the nested handshake fails closed below.
        let direct = carrier.nested_mtu().is_none();
        let udp: Arc<dyn PacketSock> = if !direct {
            let flow = carrier.dial_udp(params.peer_endpoint).await.map_err(|e| {
                HopError::transport(
                    hop_id.clone(),
                    format!("nested uplink via carrier: {}", e.message),
                )
            })?;
            Arc::new(FlowSock { flow })
        } else {
            let bind: SocketAddr = unspecified_bind(&params.peer_endpoint);
            Arc::new(OsSock {
                socket: Arc::new(
                    tokio::net::UdpSocket::bind(bind)
                        .await
                        .map_err(HopError::from)?,
                ),
            })
        };
        // Obfuscation junk trains (US5 T070/T071): pre-handshake random-size
        // datagrams on DIRECT uplinks only (responders drop them, the
        // handshake proceeds). Nested uplinks skip junk — noise inside the
        // outer tunnel is pointless.
        if direct {
            if let Some(n) = &params.noize {
                send_junk(
                    &udp,
                    params.peer_endpoint,
                    n.junk_before as usize,
                    n.junk_min,
                    n.junk_max,
                )
                .await;
            }
            if let Some(a) = &params.awg {
                for packet in awg::junk_train(a) {
                    udp.send_to(&packet, params.peer_endpoint).await.ok();
                }
            }
        }
        let (events, _) = tokio::sync::broadcast::channel(16);
        let (tx, tx_rx) = tokio::sync::mpsc::channel(EGRESS_QUEUE_CAP);
        let streams = Arc::new(stream::StreamTable::new());
        streams.observe(hop_id.clone(), events.clone());
        let inner = Arc::new(HopInner {
            tunnel: Mutex::new(tunnel),
            udp,
            peer: std::sync::RwLock::new(params.peer_endpoint),
            streams,
            tx,
        });

        // Initiate the handshake immediately (lock released before await).
        // Scratch is thread-local-reused, not allocated per call (#15).
        let init: Option<Vec<u8>> = {
            let mut tunnel = inner.tunnel.lock().unwrap();
            with_scratch(|dst| match tunnel.encapsulate(&[], dst) {
                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                _ => None,
            })
        };
        if let Some(packet) = init {
            inner.udp.send_to(&packet, params.peer_endpoint).await.ok();
        }

        let pump_inner = inner.clone();
        let pump_events = events.clone();
        let pump_id = hop_id.clone();
        let pump = tokio::spawn(async move {
            pump_loop(pump_inner, tx_rx, pump_events, pump_id).await;
        });

        // Wait for handshake completion (engine wraps with its own timeout).
        // One reused scratch buffer for the retry loop, not one 64K alloc
        // per tick. The loop polls every 20 ms but retransmits at most every
        // RETRANSMIT_INTERVAL: the old code slept 200 ms per iteration,
        // flooring loopback handshakes at ~200 ms (measured 208 ms,
        // i5-12400 loopback, release); the retransmit cadence — the only
        // network-visible behavior — is unchanged.
        const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(200);
        let mut retry_dst = vec![0u8; 65535];
        // Backdated so the first iteration retransmits immediately, exactly
        // like the old loop (which sent before its first 200 ms sleep).
        let mut last_tx = std::time::Instant::now()
            .checked_sub(RETRANSMIT_INTERVAL)
            .unwrap_or_else(std::time::Instant::now);
        let ok = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                {
                    let tunnel = inner.tunnel.lock().unwrap();
                    if tunnel.time_since_last_handshake().is_some() {
                        break;
                    }
                }
                // Retransmit initiation while unestablished (lock released
                // before await so the pump can make progress).
                if last_tx.elapsed() >= RETRANSMIT_INTERVAL {
                    let retry: Option<Vec<u8>> = {
                        let mut tunnel = inner.tunnel.lock().unwrap();
                        match tunnel.encapsulate(&[], &mut retry_dst) {
                            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                            _ => None,
                        }
                    };
                    if let Some(packet) = retry {
                        let peer = *inner.peer.read().unwrap();
                        inner.udp.send_to(&packet, peer).await.ok();
                    }
                    last_tx = std::time::Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok();
        if !ok {
            pump.abort();
            return Err(HopError::transport(
                hop_id,
                format!(
                    "wireguard handshake to {} timed out (unreachable transport)",
                    params.peer_endpoint
                ),
            ));
        }

        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(WireguardHop {
            hop_id,
            inner,
            events,
            _pump: pump,
        }))
    }
}

/// Encrypt one channel frame into a queued uplink packet (sync half of the
/// egress path: IP-wrap + boringtun encapsulate under the tunnel lock, which
/// is released before any queue await). The 64K boringtun scratch is
/// thread-local-reused; only the sized packet copy allocates (#15).
fn seal(inner: &HopInner, frame: Vec<u8>) -> Result<EgressItem, HopError> {
    // Frames ride the tunnel as IPv4/253 payloads (see stream::wrap_ip).
    let packet = stream::wrap_ip(&frame);
    with_scratch(|dst| {
        let mut tunnel = inner.tunnel.lock().unwrap();
        match tunnel.encapsulate(&packet, dst) {
            TunnResult::WriteToNetwork(packet) => {
                let peer = *inner.peer.read().unwrap();
                Ok((peer, packet.to_vec()))
            }
            TunnResult::Done => Err(HopError::transport(
                "wireguard",
                "encapsulate produced nothing to send",
            )),
            TunnResult::Err(e) => Err(HopError::transport(
                "wireguard",
                format!("encapsulate: {e:?}"),
            )),
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Err(
                HopError::transport("wireguard", "encapsulate returned tunnel data"),
            ),
        }
    })
}

/// Bounded-egress frame sender shared by flows and streams. Queued (not
/// spawned) so the pump transmits FIFO — see `HopInner::tx`.
struct EgressTx {
    hop_id: String,
    inner: Arc<HopInner>,
}

#[async_trait::async_trait]
impl FrameSender for EgressTx {
    /// Encrypt then await queue space (backpressure, never growth).
    async fn send_frame(&self, frame: Vec<u8>) -> Result<(), HopError> {
        let item = seal(&self.inner, frame)?;
        self.inner
            .tx
            .send(item)
            .await
            .map_err(|_| HopError::transport(self.hop_id.clone(), "egress queue closed"))?;
        Ok(())
    }

    /// Encrypt then queue without waiting: full maps to retryable
    /// [`HopError::overloaded`], closed to a terminal transport error.
    fn try_send_frame(&self, frame: Vec<u8>) -> Result<(), HopError> {
        let item = seal(&self.inner, frame)?;
        self.inner.tx.try_send(item).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                HopError::overloaded(self.hop_id.clone(), "egress queue full")
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                HopError::transport(self.hop_id.clone(), "egress queue closed")
            }
        })?;
        Ok(())
    }

    fn congestion_waiter(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        let tx = self.inner.tx.clone();
        Box::pin(async move {
            let _ = tx.reserve().await;
        })
    }
}

async fn pump_loop(
    inner: Arc<HopInner>,
    mut tx_rx: tokio::sync::mpsc::Receiver<EgressItem>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    hop_id: String,
) {
    // Reused 64K buffers, allocated once per pump task — never per packet
    // (#15 perf batch: per-packet 64K zeroing was the top hotspot in #10).
    // `buf`/`plain`/`tick_dst` are each consumed synchronously before the
    // next iteration, so reuse is race-free on this single task.
    let mut buf = vec![0u8; 65535];
    let mut plain = vec![0u8; 65535];
    let mut tick_dst = vec![0u8; 65535];
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Keepalive / handshake retransmit driver. Enqueued (never
                // sent directly) so ALL transmissions share one FIFO order —
                // direct sends let keepalives overtake DATA and trip the
                // peer's replay protection.
                let queued: Option<EgressItem> = {
                    let mut tunnel = inner.tunnel.lock().unwrap();
                    match tunnel.encapsulate(&[], &mut tick_dst) {
                        TunnResult::WriteToNetwork(packet) => {
                            Some((*inner.peer.read().unwrap(), packet.to_vec()))
                        }
                        _ => None,
                    }
                };
                if let Some(item) = queued {
                    // Best-effort: a full queue already holds 1024 newer
                    // packets' worth of backpressure; the next 100 ms tick
                    // retransmits. Never blocks the pump on its own queue.
                    let _ = inner.tx.try_send(item);
                }
            }
            queued = tx_rx.recv() => {
                let Some((peer, bytes)) = queued else { break };
                inner.udp.send_to(&bytes, peer).await.ok();
            }
            recvd = inner.udp.recv_from(&mut buf) => {
                let Ok((n, src)) = recvd else { break };
                let mut tunnel = inner.tunnel.lock().unwrap();
                match tunnel.decapsulate(Some(src.ip()), &buf[..n], &mut plain) {
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        drop(tunnel);
                        // Roaming: a valid packet from a new source moves the peer.
                        *inner.peer.write().unwrap() = src;
                        // Single copy on ingress: the frame is copied out of the
                        // reused decrypt buffer once, then handed to dispatch
                        // by value — `Bytes::from` reuses that allocation and
                        // slices the header by refcount (was two copies).
                        // Non-channel packets (a TUN integration would route
                        // these) are skipped, never dispatched.
                        let Some(inner_frame) = stream::unwrap_ip(data) else {
                            continue;
                        };
                        let inner_frame = inner_frame.to_vec();
                        if std::env::var("QCORE_WG_TRACE").is_ok() {
                            eprintln!("[wg-pump] tunnel-data {}B type={:02x}", data.len(), data.first().copied().unwrap_or(0));
                        }
                        if let Err(e) = stream::dispatch(&inner.streams, inner_frame) {
                            let _ = events.send(HopEvent::Failed { hop_id: hop_id.clone(), cause: e });
                        }
                    }
                    TunnResult::WriteToNetwork(reply) => {
                        let bytes = reply.to_vec();
                        drop(tunnel);
                        // Same FIFO queue: handshake replies stay ordered
                        // relative to data (replay protection). Best-effort
                        // on a full queue — the peer retransmits.
                        let _ = inner.tx.try_send((src, bytes));
                    }
                    TunnResult::Done => {}
                    TunnResult::Err(_) => {}
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl RunningHop for WireguardHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(WgDialer {
            hop_id: self.hop_id.clone(),
            inner: self.inner.clone(),
        })
    }

    fn health(&self) -> HopHealth {
        let tunnel = self.inner.tunnel.lock().unwrap();
        if tunnel.is_expired() {
            HopHealth::Failed
        } else if tunnel.time_since_last_handshake().is_some() {
            HopHealth::Healthy
        } else {
            HopHealth::Starting
        }
    }

    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.events.subscribe()
    }

    async fn stop(&self) -> Result<(), HopError> {
        self._pump.abort();
        let _ = self.events.send(HopEvent::Stopped {
            hop_id: self.hop_id.clone(),
        });
        Ok(())
    }
}

struct WgDialer {
    hop_id: String,
    inner: Arc<HopInner>,
}

#[async_trait::async_trait]
impl Dialer for WgDialer {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        let send: stream::SendFrame = Arc::new(EgressTx {
            hop_id: self.hop_id.clone(),
            inner: self.inner.clone(),
        });
        let stream = stream::open_stream(&self.inner.streams, dst, send)
            .await
            .map_err(|e| HopError::transport(self.hop_id.clone(), e))?;
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        Ok(Box::new(WgUdpFlow {
            hop_id: self.hop_id.clone(),
            inner: self.inner.clone(),
            send: Arc::new(EgressTx {
                hop_id: self.hop_id.clone(),
                inner: self.inner.clone(),
            }),
            dst,
            prefix: stream::dgram_prefix(&dst),
            rx: tokio::sync::Mutex::new(self.inner.streams.subscribe_dgrams()),
        }))
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    /// Exit egress rides the WireGuard tunnel (inner addressing).
    fn nested_mtu(&self) -> Option<u16> {
        Some(1420)
    }
}

struct WgUdpFlow {
    hop_id: String,
    inner: Arc<HopInner>,
    send: stream::SendFrame,
    dst: SocketAddr,
    /// Pre-encoded datagram header (flow is dst-bound; see
    /// [`stream::dgram_prefix`]).
    prefix: Vec<u8>,
    rx: tokio::sync::Mutex<tokio::sync::broadcast::Receiver<(Vec<u8>, SocketAddr)>>,
}

#[async_trait::async_trait]
impl UdpFlow for WgUdpFlow {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        if dst != self.dst {
            return Err(HopError::transport(
                self.hop_id.clone(),
                "wireguard flow is bound to its dial destination",
            ));
        }
        // Bound before framing: the `as u16` IP-length header in `wrap_ip`
        // wraps past 65535 and the peer would receive a truncated lie.
        if self.prefix.len().saturating_add(buf.len()) > 65535 {
            return Err(HopError::transport(
                self.hop_id.clone(),
                format!(
                    "datagram {} exceeds 65535",
                    self.prefix.len().saturating_add(buf.len())
                ),
            ));
        }
        let frame = stream::encode_dgram_prefixed(&self.prefix, buf);
        // Async send awaits queue space: datagram senders get backpressure,
        // never unbounded growth (#12).
        self.send.send_frame(frame).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok((data, from)) if from == self.dst => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, from));
                }
                Ok(_) => continue,
                // Lagged is receiver-side loss on the bounded dgram fan-out,
                // not a dead channel: count it (surfaced as `Congested`) and
                // keep waiting. Only `Closed` ends the flow. (#12)
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    self.inner.streams.record_dgram_drops(n);
                    continue;
                }
                Err(_) => {
                    return Err(HopError::transport(
                        self.hop_id.clone(),
                        "datagram channel closed",
                    ))
                }
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        self.inner.udp.local_addr().map_err(HopError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefusingCarrier;

    #[async_trait::async_trait]
    impl Dialer for RefusingCarrier {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::transport("test-carrier", "refused"))
        }

        async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::transport("test-carrier", "no uplink"))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: true,
            }
        }

        fn nested_mtu(&self) -> Option<u16> {
            Some(1400)
        }
    }

    fn params() -> WgParams {
        WgParams {
            peer_endpoint: "127.0.0.1:1".parse().unwrap(),
            private_key: [7u8; 32],
            peer_public_key: [9u8; 32],
            preshared_key: None,
            keepalive: None,
            awg: None,
            noize: None,
        }
    }

    struct StubSock;

    #[async_trait::async_trait]
    impl PacketSock for StubSock {
        async fn send_to(&self, _bytes: &[u8], _peer: SocketAddr) -> std::io::Result<()> {
            Ok(())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    /// Test-only hop interior: a real boringtun tunnel with a completed
    /// offline handshake (so data encapsulation yields packets) over a stub
    /// uplink. `cap` sizes the egress queue.
    fn test_inner(cap: usize) -> (Arc<HopInner>, tokio::sync::mpsc::Receiver<EgressItem>) {
        let sk_a = boringtun::x25519::StaticSecret::from([7u8; 32]);
        let pk_a = boringtun::x25519::PublicKey::from(&sk_a);
        let sk_b = boringtun::x25519::StaticSecret::from([9u8; 32]);
        let pk_b = boringtun::x25519::PublicKey::from(&sk_b);
        let mut a = Tunn::new(sk_a, pk_b, None, None, 0, None);
        let mut b = Tunn::new(sk_b, pk_a, None, None, 0, None);
        let mut buf = vec![0u8; 65535];
        let init = match a.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("handshake init"),
        };
        let resp = match b.decapsulate(None, &init, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("handshake response"),
        };
        if let TunnResult::Err(e) = a.decapsulate(None, &resp, &mut buf) {
            panic!("initiator completes: {e:?}")
        }
        assert!(
            a.time_since_last_handshake().is_some(),
            "initiator established offline"
        );
        let (tx, rx) = tokio::sync::mpsc::channel(cap);
        let inner = Arc::new(HopInner {
            tunnel: Mutex::new(a),
            udp: Arc::new(StubSock),
            peer: std::sync::RwLock::new("127.0.0.1:1".parse().unwrap()),
            streams: Arc::new(stream::StreamTable::new()),
            tx,
        });
        (inner, rx)
    }

    fn egress_tx(inner: &Arc<HopInner>) -> EgressTx {
        EgressTx {
            hop_id: "wg-test-0".into(),
            inner: inner.clone(),
        }
    }

    /// Failing-first (#12 handoff): a full egress queue yields retryable
    /// backpressure — never unbounded growth. Pre-fix this failed: the queue
    /// was unbounded, so `try_send` never signaled full.
    #[tokio::test]
    async fn full_egress_yields_backpressure_not_growth() {
        let (inner, rx) = test_inner(EGRESS_QUEUE_CAP);
        let tx = egress_tx(&inner);
        let _rx = rx; // held: nobody drains, so the queue must fill, not grow
        let mut backpressure = 0u32;
        for i in 0..(EGRESS_QUEUE_CAP + 50) {
            let frame = vec![0x02, (i & 0xFF) as u8];
            match tx.try_send_frame(frame) {
                Ok(()) => {}
                Err(e) if e.is_backpressure() => backpressure += 1,
                Err(e) => panic!("terminal error, not backpressure: {e}"),
            }
        }
        assert_eq!(backpressure, 50, "overflow parks, never grows");
        assert_eq!(inner.tx.max_capacity(), EGRESS_QUEUE_CAP);
        assert_eq!(inner.tx.capacity(), 0, "queue is at its bound");
    }

    /// The async half of backpressure: `send_frame` awaits space instead of
    /// failing, and completes once the pump drains one packet.
    #[tokio::test]
    async fn async_send_awaits_space_then_completes() {
        let (inner, mut rx) = test_inner(EGRESS_QUEUE_CAP);
        let tx = egress_tx(&inner);
        for i in 0..EGRESS_QUEUE_CAP {
            tx.try_send_frame(vec![0x02, (i & 0xFF) as u8])
                .expect("fills to the bound");
        }
        let waiter = tokio::spawn({
            let tx = egress_tx(&inner);
            async move { tx.send_frame(vec![0x02, 0xAA]).await }
        });
        // Still parked while full (past a scheduler pass, with no drain
        // happening).
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "send_frame parks on a full queue");
        rx.recv().await.expect("pump drains one");
        waiter
            .await
            .expect("waiter joins")
            .expect("send_frame completes after drain");
    }

    /// Failing-first (#12): `Lagged` on the bounded dgram fan-out is counted
    /// (surfaced as `Congested`) and skipped — the flow keeps working.
    /// Pre-fix this failed: any lag returned "datagram channel closed".
    #[tokio::test]
    async fn dgram_lag_counts_congested_and_keeps_flow() {
        let (inner, _rx) = test_inner(EGRESS_QUEUE_CAP);
        let (events, _bus) = tokio::sync::broadcast::channel(4096);
        inner.streams.observe("wg-test-0".to_string(), events);
        let dst_b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let dst_a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let flow = WgUdpFlow {
            hop_id: "wg-test-0".into(),
            inner: inner.clone(),
            send: Arc::new(egress_tx(&inner)),
            dst: dst_b,
            prefix: stream::dgram_prefix(&dst_b),
            rx: tokio::sync::Mutex::new(inner.streams.subscribe_dgrams()),
        };
        // Overflow the 256-cap fan-out with non-matching datagrams, then
        // deliver one matching datagram inside the surviving window.
        for _ in 0..300 {
            stream::dispatch(&inner.streams, stream::encode_dgram(&dst_a, b"noise"))
                .expect("dispatches");
        }
        stream::dispatch(&inner.streams, stream::encode_dgram(&dst_b, b"hi")).expect("dispatches");
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), flow.recv_from(&mut buf))
            .await
            .expect("recv arrives")
            .expect("lag is skipped, not fatal");
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(from, dst_b);
        assert!(
            inner.streams.dgram_drops() > 0,
            "lag is counted into the congested total"
        );
    }

    #[tokio::test]
    async fn nested_carrier_failure_is_fail_closed_and_named() {
        let err =
            match WireguardHop::bring_up("wg-nested-0".into(), params(), Arc::new(RefusingCarrier))
                .await
            {
                Ok(_) => panic!("nested uplink failure must fail closed"),
                Err(e) => e,
            };
        assert!(
            err.message.contains("nested uplink via carrier"),
            "names path: {err}"
        );
        assert_eq!(
            err.hop_id.as_deref(),
            Some("wg-nested-0"),
            "names hop: {err}"
        );
    }
}
