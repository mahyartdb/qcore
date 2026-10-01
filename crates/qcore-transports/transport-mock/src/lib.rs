//! Mock transport: conformance double (test only).
//!
//! Pass-through dialer to OS sockets so chains can run against the loopback
//! stub peer deterministically. Never shipped as a user transport.

pub mod stub_peer;

use qcore_transport_api::{
    ByteStream, Capabilities, Dialer, HopConfig, HopError, HopEvent, HopHealth, ObfuscationFamily,
    RunningHop, TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::sync::Arc;

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "mock",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[ObfuscationFamily::Noize],
    config_schema: "mock/v1",
    needs_sidecar: false,
};

pub struct MockFactory;
static FACTORY: MockFactory = MockFactory;

qcore_transport_api::register_plugin!(&FACTORY);

/// Linkage anchor: referencing this from the final binary forces the linker
/// to keep this crate's objects, so the `register_plugin!` submission above
/// reaches the inventory registry (static archives only link used objects).
pub fn plugin_descriptor() -> &'static TransportDescriptor {
    &DESCRIPTOR
}

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for MockFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        // Strict like real factories: the grammar gates fields, but
        // embedder-built configs bypass it — garbage must fail here, not
        // silently ride a test double into a false-green chain.
        if let Some(k) = cfg
            .fields
            .keys()
            .find(|k| k.as_str() != "hop_id" && k.as_str() != "family")
        {
            return Err(HopError::new(
                qcore_transport_api::HopErrorKind::Config,
                Some(cfg.get("hop_id").unwrap_or("mock-0").to_string()),
                format!("unknown mock field `{k}`"),
            ));
        }
        let hop_id = cfg.get("hop_id").unwrap_or("mock-0").to_string();
        let (tx, _) = tokio::sync::broadcast::channel(16);
        let _ = tx.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(MockHop {
            hop_id,
            dialer: Arc::new(MockDialer { carrier }),
            events: tx,
        }))
    }
}

struct MockDialer {
    carrier: Arc<dyn Dialer>,
}

#[async_trait::async_trait]
impl Dialer for MockDialer {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        self.carrier.dial_tcp(dst).await
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        self.carrier.dial_udp(dst).await
    }

    fn capabilities(&self) -> Capabilities {
        // Runtime truth, not the static descriptor: mock delegates to its
        // carrier, so UDP capability follows the carrier (a tor carrier is
        // TCP-only even though the mock descriptor advertises UDP — the
        // static descriptor is for registry listing; dial decisions see this).
        let c = self.carrier.capabilities();
        Capabilities {
            dials_tcp: c.dials_tcp,
            dials_udp: c.dials_udp,
            ..DESCRIPTOR.capabilities
        }
    }

    /// Transparent pass-through: nesting is the carrier's property.
    fn nested_mtu(&self) -> Option<u16> {
        self.carrier.nested_mtu()
    }
}

struct MockHop {
    hop_id: String,
    dialer: Arc<MockDialer>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
}

#[async_trait::async_trait]
impl RunningHop for MockHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.clone()
    }

    fn health(&self) -> HopHealth {
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
