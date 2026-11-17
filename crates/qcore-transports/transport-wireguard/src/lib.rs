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
//!
//! `--all-features` caveat: the workspace gate unifies boringtun's optional
//! `mock-instant` feature into this crate's dependency graph, which replaces
//! boringtun's clock with a mock that only advances explicitly. Timing tests
//! advance that mock *and* sleep real time so both feature sets pass; a plain
//! `cargo test -p qcore-transport-wireguard` (default features) exercises only
//! the real-clock path, so a change can pass one and fail the other.
//! `MockClock` state is thread-local, so timing tests are pinned to
//! `flavor = "current_thread"`: the advance and the wait must share a thread.

pub mod awg;
pub mod modes;
pub mod stream;
pub mod test_support;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use qcore_transport_api::{
    unspecified_bind, ByteStream, Capabilities, Dialer, HopConfig, HopError, HopErrorKind,
    HopEvent, HopHealth, ObfuscationFamily, RunningHop, TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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

/// Largest channel-frame length the datagram gate accepts: `wrap_ip` writes
/// the IPv4 total length as `u16` including its 20-byte header, so a frame
/// past 65535 - 20 wraps to a bogus tiny length and is dropped by the peer.
/// A 65515-byte frame wraps exactly to 65535.
pub const MAX_DGRAM_FRAME: usize = 65515;

/// One queued uplink packet: destination + encrypted bytes.
pub type EgressItem = (SocketAddr, Vec<u8>);

/// How long the pump may stay parked on one `send_to` before the hop is
/// declared failed (finding 6: a wedged carrier send must not silently stall
/// the whole pump — recv stops, health stays green, timers freeze). 5 s: far
/// above any legitimate loopback/LAN carrier latency, far below the
/// WireGuard session-expiry window, so a false positive costs a clean
/// failure rather than a silent blackhole.
const PUMP_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// `QCORE_WG_TRACE` resolved once (finding 5: the hot path previously ran
/// `std::env::var` per inbound packet). Read on first use; never re-read.
fn wg_trace_enabled() -> bool {
    static TRACE: OnceLock<bool> = OnceLock::new();
    *TRACE.get_or_init(|| std::env::var("QCORE_WG_TRACE").is_ok())
}

/// Cumulative boringtun protocol-error count (finding 1b observability):
/// tick errors (`update_timers`) and inbound decapsulate errors are counted
/// here, never swallowed silently. `ConnectionExpired` additionally fails
/// the hop.
static PUMP_TICK_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Total boringtun protocol errors across all hops (diagnostics).
pub fn pump_tick_errors() -> u64 {
    PUMP_TICK_ERRORS.load(Ordering::Relaxed)
}

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
                let resolved = modes::resolve_endpoint(ep, &family)
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
    /// AmneziaWG params when `peer=awg` (applied by the vendored boringtun
    /// transform module; `QCORE_PATCHES.md`).
    pub awg: Option<awg::AwgParams>,
    /// Noize params when an obfuscation profile is active (US5 T070).
    pub noize: Option<qcore_transport_api::obfuscate::NoizeParams>,
}

/// A running WireGuard hop: boringtun tunnel + UDP pump task.
pub struct WireguardHop {
    hop_id: String,
    inner: Arc<HopInner>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    pump: PumpGuard,
}

/// Keeps the pump task alive for the hop's lifetime and aborts it on drop.
/// `bring_up` holds this guard across the handshake wait so a dropped
/// build-future (engine timeout race) aborts the pump immediately instead
/// of leaving a detached task retransmitting handshakes forever.
struct PumpGuard {
    abort: tokio::task::AbortHandle,
}

impl PumpGuard {
    /// Defuse the abort-on-drop: hand pump ownership to the hop.
    fn forget(self) {
        std::mem::forget(self);
    }
}

impl Drop for PumpGuard {
    fn drop(&mut self) {
        self.abort.abort();
    }
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
        let mut tunnel = Tunn::new(
            local_private,
            peer_public,
            params.preshared_key,
            params.keepalive,
            0,
            None,
        );
        // AmneziaWG transforms live inside the vendored boringtun handshake
        // plane; the transport only hands over validated params.
        if let Some(a) = &params.awg {
            tunnel.set_awg_params(Some(a.to_wire())).map_err(|e| {
                HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id.clone()),
                    format!("AmneziaWG parameters rejected: {e:?}"),
                )
            })?;
        }
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
                for packet in awg::handshake_preamble(a) {
                    udp.send_to(&packet, params.peer_endpoint).await.ok();
                }
            }
        }
        let (events, _) = tokio::sync::broadcast::channel(16);
        let (tx, tx_rx) = tokio::sync::mpsc::channel(EGRESS_QUEUE_CAP);
        // This hop always initiates the WireGuard handshake, so it allocates
        // odd stream ids (finding 3 invariant; responder space is even).
        let streams = Arc::new(stream::StreamTable::new_with_side(
            stream::StreamSide::Initiator,
        ));
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
        // The handshake is now `InitSent`; from here the pump's
        // `update_timers` tick owns retransmission (boringtun REKEY_TIMEOUT
        // = 5 s + jitter). The pre-fix retry loop kept calling
        // `encapsulate(&[])`, which returns `Done` while `is_in_progress()` —
        // it could never retransmit (finding 1a).

        let pump_inner = Arc::downgrade(&inner);
        let pump_events = events.clone();
        let pump_id = hop_id.clone();
        let pump = tokio::spawn(async move {
            pump_loop(pump_inner, tx_rx, pump_events, pump_id).await;
        });
        // Cancellation safety (transport-api HopFactory contract): the
        // engine races `build` with a timeout and drops the future. This
        // guard aborts the pump when bring-up is dropped mid-handshake;
        // on success it is forgotten into the hop so the pump survives
        // normally (the Weak below makes a residual iteration exit too).
        let pump_guard = PumpGuard {
            abort: pump.abort_handle(),
        };

        // Wait for handshake completion (engine wraps with its own timeout).
        // Poll-only: retransmission is boringtun's job now (pump
        // `update_timers` tick, REKEY_TIMEOUT = 5 s + jitter). The old loop
        // "retried" by calling `encapsulate(&[])` every 200 ms — which
        // returns `Done` while the handshake is `InitSent`, so it never
        // actually retransmitted (finding 1a); forcing a retransmit here
        // instead (via `format_handshake_initiation(force_resend)`) would
        // also reset `time_sent` per attempt and race the pump's rekey
        // driver. 15 s exceeds boringtun's REKEY_ATTEMPT_TIME (90 s is not
        // reached; the engine's own dial timeout fires first) — this local
        // timeout is just the fail-closed backstop.
        let ok = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let established = {
                    let tunnel = inner.tunnel.lock().unwrap();
                    tunnel.time_since_last_handshake().is_some()
                };
                if established {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok();
        if !ok {
            drop(pump_guard);
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
        pump_guard.forget();
        Ok(Arc::new(WireguardHop {
            hop_id,
            inner,
            events,
            pump: PumpGuard {
                abort: pump.abort_handle(),
            },
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

/// One WireGuard timer tick against `inner`'s tunnel (finding 1): drives
/// `Tunn::update_timers` — boringtun's single entry point for handshake
/// retransmission (REKEY_TIMEOUT = 5 s + jitter), rekey
/// (REKEY_AFTER_TIME = 120 s), reactive keepalive (10 s after the last
/// inbound packet), persistent keepalive (per policy, default off —
/// FR-013d) and expiry. The pre-fix tick called `encapsulate(&[])`
/// instead, which (a) never retransmits while the handshake is `InitSent`
/// (returns `Done`), (b) never rekeys — sessions silently blackholed
/// after ~2-3 min against a real peer — and (c) emitted an empty
/// keepalive every 100 ms with an established session (10 Hz), violating
/// keepalive-default-off. The returned packet is enqueued by the caller
/// (never sent directly) so ALL transmissions share one FIFO order —
/// direct sends let keepalives overtake DATA and trip the peer's replay
/// protection.
fn pump_tick(inner: &HopInner, tick_dst: &mut [u8]) -> Result<Option<EgressItem>, WireGuardError> {
    let mut tunnel = inner.tunnel.lock().unwrap();
    match tunnel.update_timers(tick_dst) {
        TunnResult::WriteToNetwork(packet) => {
            Ok(Some((*inner.peer.read().unwrap(), packet.to_vec())))
        }
        // `update_timers` never decrypts inbound traffic, so tunnel-data
        // results are unreachable — matched defensively anyway.
        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Ok(None),
        TunnResult::Done => Ok(None),
        TunnResult::Err(e) => Err(e),
    }
}

/// Pump tick-error branch (finding 1b): count every tick error honestly
/// (never swallowed), and map the terminal `ConnectionExpired` to the
/// `HopEvent::Failed` the pump emits before stopping — the session can no
/// longer carry traffic (keys zeroed), so fail the hop loudly instead of
/// leaving health green over a blackholed tunnel. Returns `Some(Failed)`
/// for a terminal error (the pump sends it and breaks); transient errors
/// return `None` and the next tick retries (expiry still lands here within
/// REJECT_AFTER_TIME). Shared by the pump select-arm and the tests, so
/// deleting the mapping fails the tests.
fn on_tick_error(err: WireGuardError, hop_id: &str) -> Option<HopEvent> {
    PUMP_TICK_ERRORS.fetch_add(1, Ordering::Relaxed);
    if matches!(err, WireGuardError::ConnectionExpired) {
        return Some(HopEvent::Failed {
            hop_id: hop_id.to_string(),
            cause: format!("wireguard session expired: {err:?}"),
        });
    }
    None
}

async fn pump_loop(
    inner: std::sync::Weak<HopInner>,
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
        // Upgrade per iteration: an expired Weak means the hop (and any
        // surviving guard) is gone — exit instead of ticking forever. This
        // is the second cancellation net under the bring-up abort guard.
        let Some(inner) = inner.upgrade() else {
            break;
        };
        tokio::select! {
            _ = tick.tick() => {
                // WireGuard timer driver (finding 1): see [`pump_tick`].
                match pump_tick(&inner, &mut tick_dst) {
                    Ok(Some(item)) => {
                        // Best-effort: a full queue already holds 1024 newer
                        // packets' worth of backpressure; the next 100 ms
                        // tick retransmits. Never blocks the pump on its own
                        // queue.
                        let _ = inner.tx.try_send(item);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // Honest error accounting (finding 1b): count every
                        // tick error; `ConnectionExpired` is terminal — the
                        // session can no longer carry traffic (keys zeroed),
                        // so fail the hop loudly instead of leaving health
                        // green over a blackholed tunnel. Transient tick
                        // errors retry on the next tick.
                        if let Some(failed) = on_tick_error(e, &hop_id) {
                            let _ = events.send(failed);
                            break;
                        }
                    }
                }
            }
            queued = tx_rx.recv() => {
                let Some((peer, bytes)) = queued else { break };
                // Bounded transmit (finding 6): a wedged nested-carrier
                // `send_to` previously parked this whole select loop — recv
                // stopped, timers froze, health stayed green. A send that
                // exceeds [`PUMP_SEND_TIMEOUT`] is a dead carrier: fail the
                // hop and stop cleanly rather than hang.
                match tokio::time::timeout(PUMP_SEND_TIMEOUT, inner.udp.send_to(&bytes, peer)).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        // Windows: ICMP feedback surfaces on UDP sends as
                        // ConnectionReset — routine transient, like the recv
                        // path above. The packet is lost; WireGuard's
                        // retransmit/keepalive timers recover.
                    }
                    Ok(Err(e)) => {
                        // Terminal send failure: report like every other
                        // failure path instead of dropping packets forever
                        // with health green.
                        let _ = events.send(HopEvent::Failed {
                            hop_id: hop_id.clone(),
                            cause: format!("uplink send failed: {e}"),
                        });
                        break;
                    }
                    Err(_) => {
                        let _ = events.send(HopEvent::Failed {
                            hop_id: hop_id.clone(),
                            cause: format!(
                                "uplink send wedged >{PUMP_SEND_TIMEOUT:?}; pump stopped"
                            ),
                        });
                        break;
                    }
                }
            }
            recvd = inner.udp.recv_from(&mut buf) => {
                match recvd {
                    Ok((n, src)) => {
                        handle_inbound(&inner, &events, &hop_id, src, &mut buf[..n], &mut plain);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        // Windows: an ICMP port-unreachable lands on the
                        // unconnected socket as ConnectionReset — a routine
                        // transient, never a pump exit.
                        continue;
                    }
                    Err(e) => {
                        // Terminal recv failure: report like every other
                        // failure path instead of exiting silently with
                        // health green and streams parked forever.
                        let cause = format!("uplink recv failed: {e}");
                        let _ = events.send(HopEvent::Failed {
                            hop_id: hop_id.clone(),
                            cause,
                        });
                        break;
                    }
                }
            }
        }
    }
}

/// Decapsulate and dispatch one inbound packet (matched in the pump select).
#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    inner: &Arc<HopInner>,
    events: &tokio::sync::broadcast::Sender<HopEvent>,
    hop_id: &str,
    src: SocketAddr,
    // Mutable: AmneziaWG undoes header protection in place before parsing.
    packet: &mut [u8],
    plain: &mut [u8],
) {
    let mut tunnel = inner.tunnel.lock().unwrap();
    match tunnel.decapsulate(Some(src.ip()), packet, plain) {
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
                return;
            };
            let inner_frame = inner_frame.to_vec();
            if wg_trace_enabled() {
                eprintln!(
                    "[wg-pump] tunnel-data {}B type={:02x}",
                    data.len(),
                    data.first().copied().unwrap_or(0)
                );
            }
            if let Err(e) = stream::dispatch(&inner.streams, inner_frame) {
                let _ = events.send(HopEvent::Failed {
                    hop_id: hop_id.to_string(),
                    cause: e,
                });
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
        TunnResult::Err(e) => {
            // Counted, not swallowed (finding 1b): decapsulate errors are
            // per-packet (bad MAC, replay, no session — routine on the
            // internet), so unlike a tick error they are not terminal;
            // expiry also surfaces here per-packet and via the tick's
            // terminal ConnectionExpired handling.
            PUMP_TICK_ERRORS.fetch_add(1, Ordering::Relaxed);
            if wg_trace_enabled() {
                eprintln!("[wg-pump] decap err: {e:?}");
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
        self.pump.abort.abort();
        // Clear the stream table: dropping the entries closes the per-lane
        // channels, so parked readers see EOF/error instead of parking
        // forever with writes already failing `Closed`.
        self.inner.streams.clear();
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
        // Bound before framing: `wrap_ip` writes the IPv4 total length as
        // `u16` including its 20-byte header, so a frame past 65515 wraps
        // to a bogus tiny length and the peer drops a truncated lie.
        if self.prefix.len().saturating_add(buf.len()) > MAX_DGRAM_FRAME {
            return Err(HopError::transport(
                self.hop_id.clone(),
                format!(
                    "datagram {} exceeds {MAX_DGRAM_FRAME}",
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
        let mut init = match a.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("handshake init"),
        };
        let mut resp = match b.decapsulate(None, &mut init, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            _ => panic!("handshake response"),
        };
        if let TunnResult::Err(e) = a.decapsulate(None, &mut resp, &mut buf) {
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
            // The offline-completed handshake makes the test hop the
            // initiator (same as the real bring-up): odd id space.
            streams: Arc::new(stream::StreamTable::new_with_side(
                stream::StreamSide::Initiator,
            )),
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

    /// A `PumpGuard` over a real pump task (weak-held inner so the pump can
    /// exit on drop). Unused directly today (the two pump tests drive
    /// `pump_loop` via their own handles for finer control) but kept for
    /// parity with the guard shape used in `bring_up`.
    #[allow(dead_code)]
    fn spawn_pump(
        inner: &Arc<HopInner>,
        rx: tokio::sync::mpsc::Receiver<EgressItem>,
        events: tokio::sync::broadcast::Sender<HopEvent>,
    ) -> PumpGuard {
        let weak = Arc::downgrade(inner);
        let id = "wg-pump-test".to_string();
        let handle = tokio::spawn(async move {
            pump_loop(weak, rx, events, id).await;
        });
        PumpGuard {
            abort: handle.abort_handle(),
        }
    }

    /// Finding 1a regression: `encapsulate(&[])` returns `Done` while the
    /// handshake is `InitSent`, so the pre-fix pump tick (and bring-up
    /// "retry" loop) NEVER retransmitted the handshake initiation — against
    /// a lossy/slow path the hop sat silent until the 15 s timeout. The
    /// post-fix tick drives `update_timers`, which retransmits after
    /// boringtun's REKEY_TIMEOUT (5 s + jitter ≤ 333 ms). Asserts a
    /// retransmitted initiation arrives at the uplink within 6 s of the
    /// first send. Pre-fix this failed: no packet ever left after the
    /// initial initiation.
    #[tokio::test(flavor = "current_thread")]
    async fn pump_tick_retransmits_unanswered_handshake() {
        use crate::test_support::generate_keypair;
        let (c_sk, _c_pk) = generate_keypair();
        let (_s_sk, s_pk) = generate_keypair();
        // A fresh (unestablished) tunnel — no offline handshake completion.
        let tunnel = Tunn::new(
            boringtun::x25519::StaticSecret::from(c_sk),
            boringtun::x25519::PublicKey::from(s_pk),
            None,
            None,
            0,
            None,
        );
        let (tx, _rx) = tokio::sync::mpsc::channel(EGRESS_QUEUE_CAP);
        let inner = Arc::new(HopInner {
            tunnel: Mutex::new(tunnel),
            udp: Arc::new(StubSock),
            peer: std::sync::RwLock::new("127.0.0.1:1".parse().unwrap()),
            streams: Arc::new(stream::StreamTable::new()),
            tx,
        });
        // Initial initiation, exactly like bring-up.
        let init: Option<Vec<u8>> = {
            let mut t = inner.tunnel.lock().unwrap();
            with_scratch(|dst| match t.encapsulate(&[], dst) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            })
        };
        assert!(init.is_some(), "fresh tunnel initiates");
        assert!(
            init.as_ref().is_some_and(|p| p.len() == 148),
            "handshake init is 148 B"
        );
        // Pre-REKEY_TIMEOUT the tick must stay silent (no 10 Hz spray).
        let mut tick_dst = vec![0u8; 65535];
        assert!(
            pump_tick(&inner, &mut tick_dst).expect("tick ok").is_none(),
            "no retransmit before REKEY_TIMEOUT"
        );
        // Past REKEY_TIMEOUT (5 s) + jitter headroom, the tick retransmits.
        // boringtun's optional `mock-instant` feature — unified ON when the
        // workspace gate builds with `--all-features` — replaces its clock
        // with a mock that only advances explicitly, so a real sleep alone
        // never crosses the REKEY_TIMEOUT boundary in that build. The mock
        // clock is thread-local, hence `flavor = "current_thread"` above: the
        // advance below and the tick must run on the thread that owns it. A
        // dependent crate cannot cfg on boringtun's features, so do both
        // unconditionally: advance the mock clock (no-op for boringtun's real
        // clock) and sleep real time (the real-clock path needs 5 s + ≤333 ms
        // jitter + load headroom; the mock path finishes on the first tick
        // after advance).
        mock_instant::MockClock::advance(Duration::from_millis(6200));
        tokio::time::sleep(Duration::from_millis(6200)).await;
        let retried = pump_tick(&inner, &mut tick_dst)
            .expect("tick ok after REKEY_TIMEOUT")
            .expect("handshake retransmitted");
        assert_eq!(retried.1.len(), 148, "retransmit is a fresh initiation");
    }

    /// Finding 1b: `TunnResult::Err` is counted (observable via
    /// [`pump_tick_errors`]) and a terminal `ConnectionExpired` from the
    /// tick fails the pump loudly. Boringtun's real expiry lives at
    /// REJECT_AFTER_TIME*3 = 540 s (no mock clock in the default-feature
    /// build), so the
    /// test pins the two observable halves of the contract:
    ///
    /// 1. Counting — an inbound decapsulate error increments the shared
    ///    counter (pre-fix `TunnResult::Err` was swallowed uncounted).
    /// 2. Terminal mapping — the pump's own `on_tick_error` branch maps
    ///    `ConnectionExpired` to `HopEvent::Failed`. The test calls the
    ///    production fn (the same code the pump select-arm runs) and
    ///    asserts the RETURNED event, so deleting the real mapping breaks
    ///    this test (no more in-test re-implementation of the branch).
    #[tokio::test]
    async fn tick_error_counted_and_expired_fails_pump() {
        // Half 1 — counting through the real handle_inbound path.
        let before = pump_tick_errors();
        let (inner, _rx) = test_inner(64);
        let mut garbage = [0xFFu8; 64];
        let mut plain = vec![0u8; 65535];
        {
            let mut t = inner.tunnel.lock().unwrap();
            assert!(matches!(
                t.decapsulate(Some("127.0.0.1".parse().unwrap()), &mut garbage, &mut plain),
                TunnResult::Err(_)
            ));
        }
        let (events, _ev) = tokio::sync::broadcast::channel(16);
        handle_inbound(
            &inner,
            &events,
            "wg-pump-test",
            "127.0.0.1:1".parse().unwrap(),
            &mut garbage,
            &mut plain,
        );
        assert!(
            pump_tick_errors() > before,
            "decapsulate error is counted, not swallowed"
        );

        // Half 2 — the terminal mapping, through the pump's own branch:
        // `on_tick_error` counts the error and returns the Failed event the
        // pump emits. Assert the returned event, not a hand-rolled copy.
        let expired_err = WireGuardError::ConnectionExpired;
        let got = on_tick_error(expired_err, "wg-pump-test")
            .expect("terminal ConnectionExpired maps to Failed");
        let HopEvent::Failed { hop_id, cause } = got else {
            panic!("on_tick_error returned a non-Failed event")
        };
        assert_eq!(hop_id, "wg-pump-test");
        assert!(cause.contains("expired"), "{cause}");
        // The count moved by exactly one more (the branch's own bump, not a
        // test-side fetch_add on the process-global other tests read).
        assert!(
            pump_tick_errors() > before,
            "on_tick_error counts the tick error itself"
        );

        // Transient tick errors are counted but not terminal.
        let before_transient = pump_tick_errors();
        assert!(
            on_tick_error(WireGuardError::InvalidMac, "wg-pump-test").is_none(),
            "transient tick error does not fail the pump"
        );
        assert!(
            pump_tick_errors() > before_transient,
            "transient tick error is still counted"
        );
    }

    /// Finding 6: a wedged nested-carrier `send_to` previously parked the
    /// pump's whole select loop (recv stopped, timers froze, health stayed
    /// green). The pump now bounds every transmit at [`PUMP_SEND_TIMEOUT`];
    /// a wedged send must emit `HopEvent::Failed` and stop the pump
    /// cleanly.
    #[tokio::test]
    async fn wedged_send_fails_pump_within_timeout() {
        struct WedgedSock;
        #[async_trait::async_trait]
        impl PacketSock for WedgedSock {
            async fn send_to(&self, _bytes: &[u8], _peer: SocketAddr) -> std::io::Result<()> {
                std::future::pending().await
            }
            async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
                std::future::pending().await
            }
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                Ok("127.0.0.1:0".parse().unwrap())
            }
        }
        let (inner, rx) = test_inner(64);
        // Swap in the wedged uplink.
        let wedged = Arc::new(HopInner {
            tunnel: Mutex::new({
                // Rebuild the tunnel (test_inner's is behind the Arc move).
                let sk_a = boringtun::x25519::StaticSecret::from([7u8; 32]);
                let pk_a = boringtun::x25519::PublicKey::from(&sk_a);
                let sk_b = boringtun::x25519::StaticSecret::from([9u8; 32]);
                let pk_b = boringtun::x25519::PublicKey::from(&sk_b);
                let mut a = Tunn::new(sk_a, pk_b, None, None, 0, None);
                let mut b = Tunn::new(sk_b, pk_a, None, None, 0, None);
                let mut buf = vec![0u8; 65535];
                let mut init = match a.encapsulate(&[], &mut buf) {
                    TunnResult::WriteToNetwork(p) => p.to_vec(),
                    _ => panic!("handshake init"),
                };
                let mut resp = match b.decapsulate(None, &mut init, &mut buf) {
                    TunnResult::WriteToNetwork(p) => p.to_vec(),
                    _ => panic!("handshake response"),
                };
                let _ = a.decapsulate(None, &mut resp, &mut buf);
                a
            }),
            udp: Arc::new(WedgedSock),
            peer: std::sync::RwLock::new("127.0.0.1:1".parse().unwrap()),
            streams: Arc::new(stream::StreamTable::new()),
            tx: inner.tx.clone(),
        });
        let (events, mut ev_rx) = tokio::sync::broadcast::channel(16);
        let weak = Arc::downgrade(&wedged);
        let handle = tokio::spawn(async move {
            pump_loop(weak, rx, events, "wg-wedge-0".to_string()).await;
        });
        // Queue one packet: the pump's send branch parks on the wedged
        // socket until the timeout fires.
        wedged
            .tx
            .send(("127.0.0.1:1".parse().unwrap(), vec![0u8; 16]))
            .await
            .expect("queued");
        let failed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match ev_rx.recv().await {
                    Ok(HopEvent::Failed { hop_id, cause }) => break (hop_id, cause),
                    Ok(_) => continue,
                    Err(_) => panic!("event bus closed before Failed"),
                }
            }
        })
        .await
        .expect("Failed within PUMP_SEND_TIMEOUT + slack");
        assert_eq!(failed.0, "wg-wedge-0");
        assert!(
            failed.1.contains("wedged"),
            "names the wedge: {:?}",
            failed.1
        );
        // Pump stopped cleanly (not hung, not aborted).
        let done = tokio::time::timeout(Duration::from_millis(500), handle).await;
        assert!(done.is_ok(), "pump exits after the wedge failure");
    }
}
