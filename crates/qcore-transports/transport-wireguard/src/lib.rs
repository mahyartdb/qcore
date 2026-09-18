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
    /// replay protection. Only the pump task transmits.
    tx: tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
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
async fn send_junk(
    udp: &Arc<dyn PacketSock>,
    peer: SocketAddr,
    count: usize,
    min: usize,
    max: usize,
) {
    if count == 0 || max == 0 {
        return;
    }
    let mut rng = qcore_transport_api::obfuscate::XorShift64::new(
        qcore_transport_api::obfuscate::XorShift64::seed(),
    );
    for _ in 0..count.min(16) {
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
        let (tx, tx_rx) = tokio::sync::mpsc::unbounded_channel();
        let inner = Arc::new(HopInner {
            tunnel: Mutex::new(tunnel),
            udp,
            peer: std::sync::RwLock::new(params.peer_endpoint),
            streams: Arc::new(stream::StreamTable::new()),
            tx,
        });

        // Initiate the handshake immediately (lock released before await).
        let init: Option<Vec<u8>> = {
            let mut tunnel = inner.tunnel.lock().unwrap();
            let mut dst = vec![0u8; 65535];
            match tunnel.encapsulate(&[], &mut dst) {
                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                _ => None,
            }
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
                let retry: Option<Vec<u8>> = {
                    let mut tunnel = inner.tunnel.lock().unwrap();
                    let mut dst = vec![0u8; 65535];
                    match tunnel.encapsulate(&[], &mut dst) {
                        TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                        _ => None,
                    }
                };
                if let Some(packet) = retry {
                    let peer = *inner.peer.read().unwrap();
                    inner.udp.send_to(&packet, peer).await.ok();
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
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

/// Encrypt-and-queue helper shared by flows and streams. Queued (not
/// spawned) so the pump transmits FIFO — see `HopInner::tx`.
fn wg_send(inner: &HopInner, plaintext: &[u8]) -> Result<(), HopError> {
    // Frames ride the tunnel as IPv4/253 payloads (see stream::wrap_ip).
    let packet = stream::wrap_ip(plaintext);
    let mut tunnel = inner.tunnel.lock().unwrap();
    let mut dst = vec![0u8; 65535];
    match tunnel.encapsulate(&packet, &mut dst) {
        TunnResult::WriteToNetwork(packet) => {
            let peer = *inner.peer.read().unwrap();
            inner
                .tx
                .send((peer, packet.to_vec()))
                .map_err(|_| HopError::transport("wireguard", "egress queue closed"))?;
            Ok(())
        }
        TunnResult::Done => Ok(()),
        TunnResult::Err(e) => Err(HopError::transport(
            "wireguard",
            format!("encapsulate: {e:?}"),
        )),
        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => Err(
            HopError::transport("wireguard", "encapsulate returned tunnel data"),
        ),
    }
}

async fn pump_loop(
    inner: Arc<HopInner>,
    mut tx_rx: tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    hop_id: String,
) {
    let mut buf = vec![0u8; 65535];
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Keepalive / handshake retransmit driver. Enqueued (never
                // sent directly) so ALL transmissions share one FIFO order —
                // direct sends let keepalives overtake DATA and trip the
                // peer's replay protection.
                let queued: Option<(SocketAddr, Vec<u8>)> = {
                    let mut tunnel = inner.tunnel.lock().unwrap();
                    let mut dst = vec![0u8; 65535];
                    match tunnel.encapsulate(&[], &mut dst) {
                        TunnResult::WriteToNetwork(packet) => {
                            Some((*inner.peer.read().unwrap(), packet.to_vec()))
                        }
                        _ => None,
                    }
                };
                if let Some((peer, bytes)) = queued {
                    inner.tx.send((peer, bytes)).ok();
                }
            }
            queued = tx_rx.recv() => {
                let Some((peer, bytes)) = queued else { break };
                inner.udp.send_to(&bytes, peer).await.ok();
            }
            recvd = inner.udp.recv_from(&mut buf) => {
                let Ok((n, src)) = recvd else { break };
                let mut plain = vec![0u8; 65535];
                let mut tunnel = inner.tunnel.lock().unwrap();
                match tunnel.decapsulate(Some(src.ip()), &buf[..n], &mut plain) {
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        drop(tunnel);
                        // Roaming: a valid packet from a new source moves the peer.
                        *inner.peer.write().unwrap() = src;
                        let frame = data.to_vec();
                        // Strip the IPv4 envelope; non-channel IP packets
                        // belong to a future TUN integration, not dispatch.
                        let Some(inner_frame) = stream::unwrap_ip(&frame) else {
                            continue;
                        };
                        let inner_frame = inner_frame.to_vec();
                        if std::env::var("QCORE_WG_TRACE").is_ok() {
                            eprintln!("[wg-pump] tunnel-data {}B type={:02x}", frame.len(), frame.first().copied().unwrap_or(0));
                        }
                        if let Err(e) = stream::dispatch(&inner.streams, &inner_frame) {
                            let _ = events.send(HopEvent::Failed { hop_id: hop_id.clone(), cause: e });
                        }
                    }
                    TunnResult::WriteToNetwork(reply) => {
                        let bytes = reply.to_vec();
                        drop(tunnel);
                        // Same FIFO queue: handshake replies stay ordered
                        // relative to data (replay protection).
                        inner.tx.send((src, bytes)).ok();
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
        let inner = self.inner.clone();
        let send: stream::SendFrame = Arc::new(move |frame: &[u8]| wg_send(&inner, frame));
        let stream = stream::open_stream(&self.inner.streams, dst, send)
            .await
            .map_err(|e| HopError::transport(self.hop_id.clone(), e))?;
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        Ok(Box::new(WgUdpFlow {
            hop_id: self.hop_id.clone(),
            inner: self.inner.clone(),
            dst,
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
    dst: SocketAddr,
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
        let frame = stream::encode_dgram(&self.dst, buf);
        wg_send(&self.inner, &frame)
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
