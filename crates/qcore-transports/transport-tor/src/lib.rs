//! Tor transport via `arti-client` (T041, research R5).
//!
//! TCP-only hop (`dials_udp=false`): a UDP-carrier hop after Tor is rejected
//! at validation unless the `relay` adapter is present. Before/after placement
//! both work: as a carrier Tor dials through the previous hop's SOCKS... in
//! v1 the carrier dialer is reserved for future Tor-upstream proxy config;
//! reverse placement (next hop dials through Tor) works via this hop's
//! SOCKS-capable egress today.

use arti_client::TorClient;
use qcore_transport_api::{
    ByteStream, Capabilities, Dialer, HopConfig, HopError, HopErrorKind, HopEvent, HopHealth,
    RunningHop, TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "tor",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: false,
    },
    obfuscation_families: &[],
    config_schema: "tor/v1",
    needs_sidecar: false,
};

pub struct TorFactory;
static FACTORY: TorFactory = TorFactory;

qcore_transport_api::register_plugin!(&FACTORY);

/// Linkage anchor (see `qcore_transports::linked_kinds`).
pub fn plugin_descriptor() -> &'static TransportDescriptor {
    &DESCRIPTOR
}

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for TorFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        _carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let hop_id = cfg.get("hop_id").unwrap_or("tor-0").to_string();
        // Arti uses rustls internally; install the process-wide default
        // provider (ring) before bootstrap, or bootstrap panics. Shared with
        // the masque hop's `ensure_provider`; second install is a no-op Err.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let bootstrap_secs: u64 = cfg
            .get("bootstrap_timeout_secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(120);
        let client = tokio::time::timeout(
            Duration::from_secs(bootstrap_secs),
            TorClient::builder().create_bootstrapped(),
        )
        .await
        .map_err(|_| {
            HopError::transport(
                hop_id.clone(),
                format!("tor bootstrap timed out after {bootstrap_secs}s (unreachable transport)"),
            )
        })
        .and_then(|r| {
            r.map_err(|e| HopError::transport(hop_id.clone(), format!("tor bootstrap: {e}")))
        })?;
        let (events, _) = tokio::sync::broadcast::channel(16);
        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(TorHop {
            hop_id,
            client,
            events,
        }))
    }
}

pub struct TorHop {
    hop_id: String,
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
}

struct TorDialer {
    hop_id: String,
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
}

/// Owned Tor stream (orphan-rule-safe wrapper).
pub struct TorStream {
    inner: arti_client::DataStream,
}

impl tokio::io::AsyncRead for TorStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TorStream {
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

impl ByteStream for TorStream {}

#[async_trait::async_trait]
impl Dialer for TorDialer {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        let stream = self
            .client
            .connect((dst.ip().to_string(), dst.port()))
            .await
            .map_err(|e| {
                HopError::new(
                    HopErrorKind::Transport,
                    Some(self.hop_id.clone()),
                    format!("tor connect to {dst}: {e}"),
                )
            })?;
        Ok(Box::new(TorStream { inner: stream }))
    }

    async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        Err(HopError::new(
            HopErrorKind::Transport,
            Some(self.hop_id.clone()),
            "tor is TCP-only; a UDP hop after tor needs a relay hop after tor",
        ))
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    /// Streams ride Tor circuits (cell payload ~498 B), never OS-direct.
    fn nested_mtu(&self) -> Option<u16> {
        Some(498)
    }
}

#[async_trait::async_trait]
impl RunningHop for TorHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(TorDialer {
            hop_id: self.hop_id.clone(),
            client: self.client.clone(),
        })
    }

    fn health(&self) -> HopHealth {
        // build() only returns after successful bootstrap.
        HopHealth::Healthy
    }

    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.events.subscribe()
    }

    async fn stop(&self) -> Result<(), HopError> {
        let _ = self.events.send(HopEvent::Stopped {
            hop_id: self.hop_id.clone(),
        });
        Ok(())
    }
}
