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
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.carrier.dial_tcp(dst),
        )
        .await
        .map_err(|_| {
            HopError::transport(
                self.hop_id.clone(),
                format!("relay tcp carrier to {dst} timed out (unreachable transport)"),
            )
        })?
        .map_err(|e| {
            HopError::transport(
                self.hop_id.clone(),
                format!("relay tcp carrier to {dst}: {}", e.message),
            )
        })?;
        // Split the stream: recv_from owns the read half, send_to the write
        // half. Sharing one Mutex meant recv_from held it across
        // `read_exact`, parking every send_to until inbound data arrived —
        // a self-deadlock on quiet flows. `tokio::io::split` guards each
        // poll with an internal std Mutex held only for the duration of one
        // poll (never across an await), so concurrent send+recv is safe.
        let (read, write) = tokio::io::split(stream);
        Ok(Box::new(RelayFlow {
            hop_id: self.hop_id.clone(),
            read: tokio::sync::Mutex::new(read),
            write: tokio::sync::Mutex::new(write),
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
/// The carrier stream is split once at dial time: `write` is owned by
/// `send_to`, `read` by `recv_from`, so a quiet inbound side can never park
/// outbound sends.
struct RelayFlow {
    hop_id: String,
    read: tokio::sync::Mutex<tokio::io::ReadHalf<Box<dyn ByteStream>>>,
    write: tokio::sync::Mutex<tokio::io::WriteHalf<Box<dyn ByteStream>>>,
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
        let mut stream = self.write.lock().await;
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
        // Steady-state payload reads are unbounded: a healthy idle flow
        // waits for the next datagram past 15 s of silence (dial_udp owns
        // the bounded reachability check, like every sibling transport).
        let mut stream = self.read.lock().await;
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
        let k = len.min(buf.len());
        if len <= buf.len() {
            // Fast path: frame directly into the caller's buffer — no
            // temporary allocation and no second copy per datagram.
            stream.read_exact(&mut buf[..len]).await.map_err(|e| {
                HopError::transport(self.hop_id.clone(), format!("relay recv: {e}"))
            })?;
        } else {
            // Truncation path (caller buffer smaller than the datagram):
            // stage then copy the prefix.
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await.map_err(|e| {
                HopError::transport(self.hop_id.clone(), format!("relay recv: {e}"))
            })?;
            buf[..k].copy_from_slice(&payload[..k]);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_transport_api::{Dialer, HopFactory};
    use std::sync::Arc as StdArc;
    use tokio::io::AsyncReadExt;

    /// Test carrier stream: in-process duplex implementing the api surface.
    struct TestStream(tokio::io::DuplexStream);

    impl tokio::io::AsyncRead for TestStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for TestStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl ByteStream for TestStream {}

    /// A carrier that dials into an in-process duplex pair: the "far end" is
    /// a raw tokio duplex stream the test owns, so a quiet flow (the test
    /// never writes inbound on the far end) exercises send_to alone.
    struct DuplexCarrier {
        far_ready: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
    }

    #[async_trait::async_trait]
    impl Dialer for DuplexCarrier {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            let (near, far) = tokio::io::duplex(64 * 1024);
            let _ = self.far_ready.send(far);
            Ok(Box::new(TestStream(near)))
        }

        async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            let stream = self.dial_tcp(dst).await?;
            let (read, write) = tokio::io::split(stream);
            Ok(Box::new(RelayFlow {
                hop_id: "relay-quiet-0".to_string(),
                read: tokio::sync::Mutex::new(read),
                write: tokio::sync::Mutex::new(write),
                dst,
                local: None,
            }))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: false,
                dials_tcp: true,
                dials_udp: true,
            }
        }
    }

    /// A quiet flow (nothing ever sent inbound) must still accept outbound
    /// sends: with the old single-Mutex stream, `send_to` parked forever
    /// behind a concurrent `recv_from` blocked in `read_exact`. One task
    /// parks in recv_from while the main task sends; the send must complete
    /// and arrive at the far end framed as relay/v1.
    #[tokio::test]
    async fn quiet_flow_sends_outbound_without_deadlock() {
        let dst: SocketAddr = "127.0.0.1:443".parse().expect("static literal");
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();
        let hop = RelayFactory
            .build(
                {
                    let mut cfg = HopConfig::new("relay");
                    cfg.fields.insert("hop_id".into(), "relay-quiet-0".into());
                    cfg
                },
                StdArc::new(DuplexCarrier {
                    far_ready: ready_tx,
                }),
            )
            .await
            .expect("relay build");

        // The flow the engine would hold; recv_from is called through an Arc
        // clone of the dialer's flow. dial_udp returns one boxed flow — wrap
        // it in an Arc so both halves of the test can reach it concurrently.
        let flow: StdArc<dyn UdpFlow> =
            StdArc::from(hop.dialer().dial_udp(dst).await.expect("dial_udp"));
        let mut far = ready_rx.recv().await.expect("far end of the flow");

        // One task parks in recv_from forever (quiet flow — nothing inbound).
        let recv_flow = StdArc::clone(&flow);
        let recv_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let _ = recv_flow.recv_from(&mut buf).await;
        });
        // Give the recv task a moment to actually park in read_exact.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let payload = b"quiet-send";
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            flow.send_to(payload, dst),
        )
        .await
        .expect("send_to must not deadlock behind a parked recv_from")
        .expect("send_to succeeds");

        // The far end sees the framed datagram: [len u32 BE][payload].
        let mut frame = vec![0u8; 4 + payload.len()];
        far.read_exact(&mut frame)
            .await
            .expect("far end reads the frame");
        assert_eq!(&frame[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&frame[4..], payload);

        // A second send right after also passes (the write half stays live).
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            flow.send_to(payload, dst),
        )
        .await
        .expect("second send_to also completes")
        .expect("second send_to succeeds");

        recv_task.abort();
    }
}
