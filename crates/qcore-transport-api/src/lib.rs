//! Public transport plugin boundary (plan: The Transport Interface).
//!
//! A transport is a plugin behind three traits plus static descriptor data.
//! The engine reads descriptors from its transport registry and never
//! matches on a transport kind. Depends on tokio + async-trait only, so
//! transport crates never pull in the engine.

pub mod error;
pub mod obfuscate;

pub use error::{FailureLayer, FailureReport, HopError, HopErrorKind, HopEvent, HopHealth};
pub use inventory;

use std::net::SocketAddr;
use std::sync::Arc;

/// Carrier/egress capability, known WITHOUT building an instance (FR-006a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub accepts_tcp_carrier: bool,
    pub accepts_udp_carrier: bool,
    pub dials_tcp: bool,
    pub dials_udp: bool,
}

/// Obfuscation family. Source of truth for profile compatibility (FR-021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationFamily {
    Noize,
    Awg,
}

/// Static descriptor: registry key is a string, not an enum.
#[derive(Debug)]
pub struct TransportDescriptor {
    /// Registry key, not an enum.
    pub kind: &'static str,
    pub capabilities: Capabilities,
    /// Compatibility source of truth for obfuscation profiles.
    pub obfuscation_families: &'static [ObfuscationFamily],
    /// Typed config identity.
    pub config_schema: &'static str,
    /// Only `psiphon`.
    pub needs_sidecar: bool,
}

/// Abstract async byte stream: what hop n+1 receives. An inner hop may return a
/// `smoltcp`-backed stream with no OS socket.
pub trait ByteStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Abstract async datagram flow (UDP associate equivalent).
#[async_trait::async_trait]
pub trait UdpFlow: Send + Sync {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError>;
    fn local_addr(&self) -> Result<SocketAddr, HopError>;
}

/// The egress handed to the next hop.
#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError>;
    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError>;
    fn capabilities(&self) -> Capabilities;
    /// Encapsulated uplink MTU when this dialer's traffic rides inside a
    /// tunnel (nesting, US3 T058); `None` for direct OS egress. Defaulted so
    /// adding the report never breaks an implementor. Transports that need a
    /// packet/stream socket consult this on their carrier to decide between
    /// OS sockets (direct) and carrier flows/streams (nested).
    fn nested_mtu(&self) -> Option<u16> {
        None
    }
}

/// A built hop: handle, health, event stream, stop.
#[async_trait::async_trait]
pub trait RunningHop: Send + Sync {
    fn descriptor(&self) -> &'static TransportDescriptor;
    fn dialer(&self) -> Arc<dyn Dialer>;
    fn health(&self) -> HopHealth;
    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent>;
    async fn stop(&self) -> Result<(), HopError>;
}

/// The plugin boundary: builds a hop with a carrier dialer.
#[async_trait::async_trait]
pub trait HopFactory: Send + Sync {
    fn descriptor(&self) -> &'static TransportDescriptor;
    async fn build(
        &self,
        cfg: HopConfig,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError>;
}

/// Typed hop configuration, deserialized by the engine (see
/// `qcore-core::config::HopConfig`). Kept here so factories name the type
/// without depending on the engine.
#[derive(Debug, Clone)]
pub struct HopConfig {
    pub kind: String,
    pub fields: std::collections::BTreeMap<String, String>,
}

impl HopConfig {
    pub fn new(kind: impl Into<String>) -> Self {
        HopConfig {
            kind: kind.into(),
            fields: Default::default(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }
}

/// Inventory entry. Transport crates register exactly one of these:
/// ```ignore
/// struct MyFactory;
/// static FACTORY: MyFactory = MyFactory;
/// qcore_transport_api::register_plugin!(&FACTORY);
/// ```
pub struct PluginEntry(pub &'static dyn HopFactory);

inventory::collect!(PluginEntry);

/// Self-register a factory into the transport registry.
#[macro_export]
macro_rules! register_plugin {
    ($e:expr) => {
        $crate::inventory::submit! {
            $crate::PluginEntry($e)
        }
    };
}
