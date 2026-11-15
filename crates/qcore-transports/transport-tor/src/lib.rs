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
use std::sync::atomic::{AtomicBool, Ordering};
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
        let bootstrap_secs: u64 = match parse_bootstrap_secs(cfg.get("bootstrap_timeout_secs")) {
            Ok(v) => v,
            Err(e) => {
                return Err(HopError::new(HopErrorKind::Config, Some(hop_id.clone()), e));
            }
        };
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
            stopped: Arc::new(AtomicBool::new(false)),
        }))
    }
}

/// Strict bootstrap budget parse: absent → 120 s default; anything else must
/// be an integer in 1..=3600 (a silent 120 s default on typos, a 0 s instant
/// timeout, or a 300-year hang are all worse than an error).
fn parse_bootstrap_secs(v: Option<&str>) -> Result<u64, String> {
    let Some(s) = v else { return Ok(120) };
    let n: u64 = s
        .parse()
        .map_err(|_| "bad bootstrap_timeout_secs (want 1..=3600)".to_string())?;
    if !(1..=3600).contains(&n) {
        return Err(format!("bad bootstrap_timeout_secs `{n}` (want 1..=3600)"));
    }
    Ok(n)
}

pub struct TorHop {
    hop_id: String,
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    /// Stopped-stays-stopped (psiphon invariant): post-stop dials fail
    /// instead of silently serving through the still-bootstrapped client.
    /// Shared with every dialer handed out by `dialer()` — the engine holds
    /// carriers across stop(), so a snapshot at dialer-creation time would
    /// let pre-existing dialers keep dialing after stop; the same Arc makes
    /// the flag live for them too.
    stopped: Arc<AtomicBool>,
}

struct TorDialer {
    hop_id: String,
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    stopped: Arc<AtomicBool>,
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
        if self.stopped.load(Ordering::SeqCst) {
            return Err(HopError::new(
                HopErrorKind::Transport,
                Some(self.hop_id.clone()),
                "tor hop is stopped",
            ));
        }
        // `ip().to_string()` drops the IPv6 scope id; rather than dial the
        // wrong interface, fail closed: Tor exits cannot route link-local
        // destinations anyway, so a scoped address is always a caller bug.
        if let SocketAddr::V6(v6) = dst {
            if v6.scope_id() != 0 {
                return Err(HopError::new(
                    HopErrorKind::Validation,
                    Some(self.hop_id.clone()),
                    format!("tor cannot dial scoped IPv6 `{dst}` (no zone over Tor)"),
                ));
            }
        }
        let stream = tokio::time::timeout(
            Duration::from_secs(15),
            self.client.connect((dst.ip().to_string(), dst.port())),
        )
        .await
        .map_err(|_| {
            HopError::new(
                HopErrorKind::Transport,
                Some(self.hop_id.clone()),
                format!("tor connect to {dst} timed out (unreachable transport)"),
            )
        })?
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
        if self.stopped.load(Ordering::SeqCst) {
            return Err(HopError::new(
                HopErrorKind::Transport,
                Some(self.hop_id.clone()),
                "tor hop is stopped",
            ));
        }
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
            // Share the live flag, never a snapshot: dials through a carrier
            // held from bring-up must observe stop() too.
            stopped: Arc::clone(&self.stopped),
        })
    }

    fn health(&self) -> HopHealth {
        if self.stopped.load(Ordering::SeqCst) {
            HopHealth::Stopped
        } else {
            // build() only returns after successful bootstrap.
            HopHealth::Healthy
        }
    }

    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.events.subscribe()
    }

    async fn stop(&self) -> Result<(), HopError> {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.events.send(HopEvent::Stopped {
            hop_id: self.hop_id.clone(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_budget_parses_strictly() {
        assert_eq!(parse_bootstrap_secs(None).unwrap(), 120);
        assert_eq!(parse_bootstrap_secs(Some("45")).unwrap(), 45);
        assert!(parse_bootstrap_secs(Some("abc")).is_err());
        assert!(parse_bootstrap_secs(Some("0")).is_err());
        assert!(parse_bootstrap_secs(Some("9999999999")).is_err());
    }

    /// Stopped-stays-stopped through a pre-existing dialer: the dialer taken
    /// BEFORE stop() shares the hop's flag, so dialing through it after
    /// stop() fails with the stopped error instead of being served by the
    /// still-bootstrapped client (the engine holds carriers across stop()).
    #[tokio::test]
    async fn dialer_taken_before_stop_fails_after_stop() {
        // Unique state/cache dirs (same pattern as tests/conformance/testutil):
        // the default config points at the user's real arti state, which
        // parallel runs and sqlite locks must never touch.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("qcore-tor-stop-{}-{n}", std::process::id()));
        let state = base.join("state");
        let cache = base.join("cache");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::create_dir_all(&cache).expect("cache dir");
        let config = arti_client::config::TorClientConfigBuilder::from_directories(&state, &cache)
            .build()
            .expect("tor client config");
        // Same provider requirement the factory satisfies before bootstrap.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = TorClient::builder()
            .config(config)
            .bootstrap_behavior(arti_client::BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .expect("unbootstrapped tor client (no network in tests)");
        let hop = TorHop {
            hop_id: "tor-stop-0".to_string(),
            client,
            events: {
                let (tx, _) = tokio::sync::broadcast::channel(16);
                tx
            },
            stopped: Arc::new(AtomicBool::new(false)),
        };

        // Take the dialer while the hop is running.
        let dialer = hop.dialer();
        assert_eq!(hop.health(), HopHealth::Healthy);
        let dst: SocketAddr = "127.0.0.1:80".parse().expect("static literal");
        // Pre-stop: the dial itself may fail (unbootstrapped client), but it
        // must NOT fail with the stopped error.
        if let Err(e) = dialer.dial_tcp(dst).await {
            assert!(
                !e.message.contains("stopped"),
                "pre-stop dial must not be gated by the stopped flag: {e}"
            );
        }

        hop.stop().await.expect("clean stop");
        assert_eq!(hop.health(), HopHealth::Stopped);

        // Post-stop: dialing through the SAME dialer (a carrier the engine
        // held from bring-up) must fail with the stopped error.
        let err = match dialer.dial_tcp(dst).await {
            Ok(_) => panic!("dial through pre-existing dialer must fail after stop"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Transport);
        assert_eq!(err.hop_id.as_deref(), Some("tor-stop-0"));
        assert!(
            err.message.contains("stopped"),
            "names the stopped reason: {err}"
        );

        // New dialers from the stopped hop see the flag too.
        let err = match hop.dialer().dial_udp(dst).await {
            Ok(_) => panic!("dial_udp on stopped hop must fail"),
            Err(e) => e,
        };
        assert!(err.message.contains("stopped"), "stopped reason: {err}");
    }
}
