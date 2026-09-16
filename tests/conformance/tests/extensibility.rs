//! Throwaway-transport extensibility proof (T093, SC-002c).
//!
//! A brand-new transport defined entirely in this file — one descriptor, one
//! factory, one dialer, one hop, registered with a single
//! `register_plugin!` — passes the generated conformance path (parse,
//! preflight, start, exit reporting, chaining) with zero edits to the
//! engine, chain validator, CLI, or schemas.

use qcore_core::api::{Engine, EngineConfig};
use qcore_transport_api::{
    Capabilities, Dialer, HopConfig, HopError, HopEvent, HopHealth, RunningHop, TransportDescriptor,
};
use std::net::SocketAddr;
use std::sync::Arc;

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "throwaway",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "throwaway/v1",
    needs_sidecar: false,
};

struct ThrowawayFactory;
static FACTORY: ThrowawayFactory = ThrowawayFactory;

qcore_transport_api::register_plugin!(&FACTORY);

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for ThrowawayFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let hop_id = cfg.get("hop_id").unwrap_or("throwaway-0").to_string();
        let (tx, _) = tokio::sync::broadcast::channel(16);
        let _ = tx.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(ThrowawayHop {
            hop_id,
            dialer: Arc::new(ThrowawayDialer { carrier }),
            events: tx,
        }))
    }
}

struct ThrowawayDialer {
    carrier: Arc<dyn Dialer>,
}

#[async_trait::async_trait]
impl Dialer for ThrowawayDialer {
    async fn dial_tcp(
        &self,
        dst: SocketAddr,
    ) -> Result<Box<dyn qcore_transport_api::ByteStream>, HopError> {
        self.carrier.dial_tcp(dst).await
    }

    async fn dial_udp(
        &self,
        dst: SocketAddr,
    ) -> Result<Box<dyn qcore_transport_api::UdpFlow>, HopError> {
        self.carrier.dial_udp(dst).await
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    fn nested_mtu(&self) -> Option<u16> {
        self.carrier.nested_mtu()
    }
}

struct ThrowawayHop {
    hop_id: String,
    dialer: Arc<ThrowawayDialer>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
}

#[async_trait::async_trait]
impl RunningHop for ThrowawayHop {
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

fn engine() -> Engine {
    // Link mock for the carrier side; the throwaway plugin registers itself
    // from this binary via `register_plugin!` (same-crate inventory).
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig::default())
}

#[test]
fn throwaway_kind_is_registry_visible() {
    let e = engine();
    assert!(
        e.registry().get("throwaway").is_some(),
        "register_plugin! must surface the new kind with no engine edits"
    );
}

#[test]
fn throwaway_parses_and_preflights() {
    let e = engine();
    let specs = e
        .parse_chain("throwaway")
        .expect("grammar is registry-driven");
    match e.preflight(specs) {
        qcore_core::api::engine::Preflight::Ok { depth } => assert_eq!(depth, 1),
        qcore_core::api::engine::Preflight::Rejected(err) => {
            panic!("throwaway preflight rejected: {err}")
        }
    }
}

#[tokio::test]
async fn throwaway_chains_with_builtin_transports() {
    let e = engine();
    // Declared order respected, last hop is exit — through a mixed chain the
    // validator and lifecycle never knew about at compile time.
    let specs = e.parse_chain("mock,throwaway").expect("mixed chain parses");
    let handle = e.start(specs).await.expect("mixed chain starts");
    // Auto-ids count chain positions (mock-0, throwaway-1); the exit is the
    // declared last hop.
    assert_eq!(handle.exit_hop_id, "throwaway-1");
    let kinds: Vec<String> = handle
        .hop_reports()
        .iter()
        .map(|r| r.kind.clone())
        .collect();
    assert_eq!(kinds, vec!["mock".to_string(), "throwaway".to_string()]);
    handle.stop_all().await.expect("clean stop");
}
