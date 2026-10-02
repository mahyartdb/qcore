//! Psiphon/Cfon sidecar hop (T042, research R6).
//!
//! A Psiphon client process exposing a local SOCKS proxy, wired into the
//! chain like any other hop. Borrowed integration shape from
//! Oblivion/warp-plus. No Psiphon code is linked into the Rust core; the
//! bounded [`supervisor`] spawns it, secrets reach it via stdin (never argv).

pub mod socks;
pub mod supervisor;

use qcore_transport_api::{
    unspecified_bind, ByteStream, Capabilities, Dialer, HopConfig, HopError, HopErrorKind,
    HopEvent, HopHealth, RunningHop, TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "psiphon",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "psiphon/v1",
    needs_sidecar: true,
};

pub struct PsiphonFactory;
static FACTORY: PsiphonFactory = PsiphonFactory;

qcore_transport_api::register_plugin!(&FACTORY);

/// Linkage anchor (see `qcore_transports::linked_kinds`).
pub fn plugin_descriptor() -> &'static TransportDescriptor {
    &DESCRIPTOR
}

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for PsiphonFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        _carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let hop_id = cfg.get("hop_id").unwrap_or("psiphon-0").to_string();
        let exe = cfg.get("sidecar_path").ok_or_else(|| {
            HopError::new(
                HopErrorKind::Config,
                Some(hop_id.clone()),
                "psiphon hop requires sidecar_path=<explicit executable path>",
            )
        })?;
        let mut scfg = supervisor::SidecarConfig::new(PathBuf::from(exe));
        if let Some(args) = cfg.get("sidecar_args") {
            // Comma-separated passthrough (test doubles take flags like
            // `--die-after-ms=100`; production sidecars take their ports and
            // options here). Secrets never ride args (stdin only, FR-001b).
            scfg.args = args
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Some(secs) = cfg.get("ready_timeout_secs") {
            scfg.ready_timeout = Duration::from_secs(secs.parse().map_err(|_| {
                HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id.clone()),
                    "bad ready_timeout_secs",
                )
            })?);
        }
        if let Some(secret) = cfg.get("sidecar_secret") {
            scfg.secret = Some(supervisor::SidecarSecret {
                payload: secret.as_bytes().to_vec(),
            });
        }
        let supervisor = supervisor::SidecarSupervisor::new(scfg);
        let running = supervisor
            .spawn()
            .await
            .map_err(|e| HopError::new(HopErrorKind::Sidecar, Some(hop_id.clone()), e))?;
        let socks = running.socks_addr();
        let (events, _) = tokio::sync::broadcast::channel(16);
        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(PsiphonHop {
            shared: Arc::new(PsiphonShared {
                hop_id,
                supervisor,
                running: tokio::sync::Mutex::new(running),
                // Revived sidecars rebind: test doubles bind :0 per process
                // (new address each revival, propagated on every dial);
                // production sidecars take a stable port from config.
                socks: std::sync::RwLock::new(socks),
                events,
                alive: std::sync::atomic::AtomicBool::new(true),
            }),
        }))
    }
}

/// Shared hop state: the dialer holds it too, so every dial revives an
/// exited sidecar within the restart budget and observes the fresh SOCKS
/// address. Revival must live on the dial path: a frozen address with a
/// stale `Healthy` would serve dead listeners.
struct PsiphonShared {
    hop_id: String,
    supervisor: supervisor::SidecarSupervisor,
    running: tokio::sync::Mutex<supervisor::RunningSidecar>,
    socks: std::sync::RwLock<SocketAddr>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    alive: std::sync::atomic::AtomicBool,
}

impl PsiphonShared {
    /// Revive-if-needed within budget, returning the live SOCKS address.
    /// Exhaustion fails closed (marks not-alive, emits `Failed`, names the
    /// bound) instead of dialing a dead listener.
    async fn ensure_live(&self) -> Result<SocketAddr, HopError> {
        // A stopped hop stays stopped: dial-after-stop must fail, never
        // silently resurrect a torn-down sidecar.
        if !self.alive.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(HopError::transport(
                self.hop_id.clone(),
                "psiphon hop is stopped",
            ));
        }
        let mut running = self.running.lock().await;
        if let Err(e) = self.supervisor.ensure_running(&mut running).await {
            self.alive.store(false, std::sync::atomic::Ordering::SeqCst);
            let _ = self.events.send(HopEvent::Failed {
                hop_id: self.hop_id.clone(),
                cause: e.clone(),
            });
            return Err(HopError::transport(self.hop_id.clone(), e));
        }
        let addr = running.socks_addr();
        *self.socks.write().unwrap() = addr;
        Ok(addr)
    }
}

pub struct PsiphonHop {
    shared: Arc<PsiphonShared>,
}

struct PsiphonDialer {
    shared: Arc<PsiphonShared>,
}

#[async_trait::async_trait]
impl Dialer for PsiphonDialer {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        let socks = self.shared.ensure_live().await?;
        let stream = socks::socks_connect(socks, dst).await.map_err(|e| {
            HopError::new(
                HopErrorKind::Transport,
                Some(self.shared.hop_id.clone()),
                format!("psiphon socks connect to {dst}: {e}"),
            )
        })?;
        Ok(Box::new(TcpByteStream { inner: stream }))
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        let socks = self.shared.ensure_live().await?;
        let (_control, relay) = socks::socks_udp_associate(socks).await.map_err(|e| {
            HopError::new(
                HopErrorKind::Transport,
                Some(self.shared.hop_id.clone()),
                format!("psiphon socks associate: {e}"),
            )
        })?;
        // Hold the TCP control connection open for the flow's lifetime.
        let socket = tokio::net::UdpSocket::bind(unspecified_bind(&dst))
            .await
            .map_err(HopError::from)?;
        Ok(Box::new(PsiphonUdpFlow {
            hop_id: self.shared.hop_id.clone(),
            _control,
            socket,
            relay,
            dst,
        }))
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    /// Streams ride the sidecar SOCKS proxy (TCP), never OS-direct.
    fn nested_mtu(&self) -> Option<u16> {
        Some(1460)
    }
}

struct TcpByteStream {
    inner: tokio::net::TcpStream,
}

impl tokio::io::AsyncRead for TcpByteStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TcpByteStream {
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

impl ByteStream for TcpByteStream {}

struct PsiphonUdpFlow {
    hop_id: String,
    _control: tokio::net::TcpStream,
    socket: tokio::net::UdpSocket,
    relay: SocketAddr,
    dst: SocketAddr,
}

#[async_trait::async_trait]
impl UdpFlow for PsiphonUdpFlow {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        if dst != self.dst {
            return Err(HopError::transport(
                self.hop_id.clone(),
                "psiphon flow is bound to its dial destination",
            ));
        }
        let frame = socks::encode_udp_datagram(&dst, buf);
        self.socket
            .send_to(&frame, self.relay)
            .await
            .map(|_| ())
            .map_err(HopError::from)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        let mut tmp = vec![0u8; 65535];
        loop {
            let (n, _) = self
                .socket
                .recv_from(&mut tmp)
                .await
                .map_err(HopError::from)?;
            let Some((from, payload)) = socks::decode_udp_datagram(&tmp[..n]) else {
                continue;
            };
            if from != self.dst {
                continue;
            }
            let k = payload.len().min(buf.len());
            buf[..k].copy_from_slice(&payload[..k]);
            return Ok((k, from));
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        self.socket.local_addr().map_err(HopError::from)
    }
}

#[async_trait::async_trait]
impl RunningHop for PsiphonHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(PsiphonDialer {
            shared: self.shared.clone(),
        })
    }

    fn health(&self) -> HopHealth {
        // Live check when uncontended; last-known flag while a dial holds
        // the lock (a dial in flight implies recent liveness anyway). Never
        // a stale-forever green: the flag clears on stop and on exhausted
        // revival, and any live check observes the real child.
        match self.shared.running.try_lock() {
            Ok(mut r) => {
                if r.is_running() {
                    HopHealth::Healthy
                } else {
                    HopHealth::Stopped
                }
            }
            Err(_) => {
                if self.shared.alive.load(std::sync::atomic::Ordering::SeqCst) {
                    HopHealth::Healthy
                } else {
                    HopHealth::Stopped
                }
            }
        }
    }

    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.shared.events.subscribe()
    }

    async fn stop(&self) -> Result<(), HopError> {
        self.shared
            .alive
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.shared.running.lock().await.shutdown().await;
        let _ = self.shared.events.send(HopEvent::Stopped {
            hop_id: self.shared.hop_id.clone(),
        });
        Ok(())
    }
}

impl PsiphonHop {
    /// Live SOCKS address for tests and diagnostics.
    pub async fn socks_addr(&self) -> SocketAddr {
        *self.shared.socks.read().unwrap()
    }
}
