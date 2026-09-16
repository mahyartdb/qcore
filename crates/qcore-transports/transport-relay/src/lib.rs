//! UDP-over-TCP framing adapter (US3 T052).
//!
//! First-class registered transport: a hop that dials UDP can sit behind a
//! TCP-only carrier with the relay between (validator names the insertion).
//! TCP dials pass through untouched. UDP dials open one TCP connection per
//! flow through the carrier and frame datagrams on the wire as
//! `relay/v1`: `[len: u32 BE][payload]`, max 65535 payload bytes. The far end
//! MUST unframe `relay/v1` (a raw echo responder round-trips by accident of
//! echo, which is what the loopback gate exercises).

use qcore_transport_api::{
    ByteStream, Capabilities, Dialer, HopConfig, HopError, HopEvent, HopHealth, RunningHop,
    TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "relay",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: false,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[],
    config_schema: "relay/v1",
    needs_sidecar: false,
};

pub struct RelayFactory;
static FACTORY: RelayFactory = RelayFactory;

qcore_transport_api::register_plugin!(&FACTORY);

/// Linkage anchor (see `qcore_transports::linked_kinds`).
pub fn plugin_descriptor() -> &'static TransportDescriptor {
    &DESCRIPTOR
}

/// Max framed payload per datagram.
pub const MAX_DATAGRAM: usize = 65535;

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for RelayFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let hop_id = cfg.get("hop_id").unwrap_or("relay-0").to_string();
        let (events, _) = tokio::sync::broadcast::channel(16);
        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(RelayHop {
            hop_id,
            carrier,
            events,
        }))
    }
}

struct RelayHop {
    hop_id: String,
    carrier: Arc<dyn Dialer>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
}

struct RelayDialer {
    hop_id: String,
    carrier: Arc<dyn Dialer>,
}

#[async_trait::async_trait]
impl Dialer for RelayDialer {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        // Transparent: TCP needs no framing.
        self.carrier.dial_tcp(dst).await
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        let stream = self.carrier.dial_tcp(dst).await.map_err(|e| {
            HopError::transport(
                self.hop_id.clone(),
                format!("relay tcp carrier to {dst}: {}", e.message),
            )
        })?;
        Ok(Box::new(RelayFlow {
            hop_id: self.hop_id.clone(),
            stream: tokio::sync::Mutex::new(stream),
            dst,
            local: None,
        }))
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    /// UDP always rides framed over the carrier (never OS-direct).
    fn nested_mtu(&self) -> Option<u16> {
        Some(1400)
    }
}

/// One framed flow: datagrams multiplexed in order over a single carrier TCP
/// connection, bound to the dial destination like every other UdpFlow.
struct RelayFlow {
    hop_id: String,
    stream: tokio::sync::Mutex<Box<dyn ByteStream>>,
    dst: SocketAddr,
    local: Option<SocketAddr>,
}

#[async_trait::async_trait]
impl UdpFlow for RelayFlow {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        if dst != self.dst {
            return Err(HopError::transport(
                self.hop_id.clone(),
                "relay flow is bound to its dial destination",
            ));
        }
        if buf.len() > MAX_DATAGRAM {
            return Err(HopError::transport(
                self.hop_id.clone(),
                format!("datagram {} exceeds {MAX_DATAGRAM}", buf.len()),
            ));
        }
        let mut frame = (buf.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(buf);
        let mut stream = self.stream.lock().await;
        stream
            .write_all(&frame)
            .await
            .map_err(|e| HopError::transport(self.hop_id.clone(), format!("relay send: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| HopError::transport(self.hop_id.clone(), format!("relay send: {e}")))?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        let mut stream = self.stream.lock().await;
        let mut len = [0u8; 4];
        stream
            .read_exact(&mut len)
            .await
            .map_err(|e| HopError::transport(self.hop_id.clone(), format!("relay recv: {e}")))?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_DATAGRAM {
            return Err(HopError::transport(
                self.hop_id.clone(),
                format!("peer framed {len} exceeding {MAX_DATAGRAM}"),
            ));
        }
        let mut payload = vec![0u8; len];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| HopError::transport(self.hop_id.clone(), format!("relay recv: {e}")))?;
        let k = len.min(buf.len());
        buf[..k].copy_from_slice(&payload[..k]);
        Ok((k, self.dst))
    }

    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        self.local.ok_or_else(|| {
            HopError::transport(self.hop_id.clone(), "relay flow has no packet socket")
        })
    }
}

#[async_trait::async_trait]
impl RunningHop for RelayHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(RelayDialer {
            hop_id: self.hop_id.clone(),
            carrier: self.carrier.clone(),
        })
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
