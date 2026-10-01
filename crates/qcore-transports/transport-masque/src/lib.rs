//! MASQUE transport over a single QUIC provider (T040, research R4 outcome).
//!
//! - `alpn=h3`: real QUIC (quinn + rustls/ring) with ALPN `h3`; TCP egress
//!   rides native QUIC bidirectional streams, UDP egress rides QUIC DATAGRAM
//!   frames with a dst-prefix.
//! - `alpn=h2`: HTTP/2 over TCP (h2 crate, prior knowledge); egress rides
//!   per-dial POST streams, datagrams length-prefixed on a dedicated stream.
//!
//! Loopback-verified against [`test_support`] responders (real QUIC/TLS and
//! HTTP/2 framing). Full MASQUE CONNECT-UDP proxy interop against third-party
//! edges is a later milestone; the transport boundary isolates the provider.

pub mod obfuscate;
pub mod test_support;

use bytes::Bytes;
use qcore_transport_api::{
    unspecified_bind, ByteStream, Capabilities, Dialer, HopConfig, HopError, HopErrorKind,
    HopEvent, HopHealth, ObfuscationFamily, RunningHop, TransportDescriptor, UdpFlow,
};
use std::net::SocketAddr;
use std::sync::Arc;

static DESCRIPTOR: TransportDescriptor = TransportDescriptor {
    kind: "masque",
    capabilities: Capabilities {
        accepts_tcp_carrier: true,
        accepts_udp_carrier: true,
        dials_tcp: true,
        dials_udp: true,
    },
    obfuscation_families: &[ObfuscationFamily::Noize],
    config_schema: "masque/v1",
    needs_sidecar: false,
};

pub struct MasqueFactory;
static FACTORY: MasqueFactory = MasqueFactory;

qcore_transport_api::register_plugin!(&FACTORY);

/// Linkage anchor (see `qcore_transports::linked_kinds`).
pub fn plugin_descriptor() -> &'static TransportDescriptor {
    &DESCRIPTOR
}

#[async_trait::async_trait]
impl qcore_transport_api::HopFactory for MasqueFactory {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    async fn build(
        &self,
        cfg: HopConfig,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let hop_id = cfg.get("hop_id").unwrap_or("masque-0").to_string();
        let alpn = cfg.get("alpn").unwrap_or("h3");
        let endpoint: SocketAddr = cfg
            .get("endpoint")
            .ok_or_else(|| {
                HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id.clone()),
                    "masque hop requires endpoint=<ip:port>",
                )
            })?
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id.clone()),
                    format!("bad endpoint: {e}"),
                )
            })?;
        let insecure = cfg.get("insecure_skip_verify") == Some("true");
        let fragment = obfuscate::fragment_size(&cfg);
        match alpn {
            "h3" => MasqueHop::bring_up_h3(hop_id, endpoint, insecure, carrier).await,
            "h2" => MasqueHop::bring_up_h2(hop_id, endpoint, carrier, fragment).await,
            other => Err(HopError::new(
                HopErrorKind::Config,
                Some(hop_id),
                format!("unknown masque alpn `{other}` (h3|h2)"),
            )),
        }
    }
}

enum Conn {
    H3(quinn::Connection),
    H2(H2Conn),
}

struct H2Conn {
    nested: bool,
    fragment: Option<usize>,
    /// Bring-up connection driver: aborted on `stop()` (a detached task
    /// would hold the bring-up TCP+H2 connection open past teardown).
    driver: tokio::task::AbortHandle,
}

/// A running MASQUE hop.
pub struct MasqueHop {
    hop_id: String,
    endpoint: SocketAddr,
    local: SocketAddr,
    conn: Conn,
    /// Uplink carrier: per-dial H2 egress rides it when nested (T058).
    carrier: Arc<dyn Dialer>,
    events: tokio::sync::broadcast::Sender<HopEvent>,
}

impl MasqueHop {
    async fn bring_up_h3(
        hop_id: String,
        endpoint: SocketAddr,
        insecure: bool,
        carrier: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let mut endpoint_builder = quinn::Endpoint::client(unspecified_bind(&endpoint))
            .map_err(|e| HopError::transport(hop_id.clone(), format!("quinn bind: {e}")))?;
        endpoint_builder.set_default_client_config(client_config(insecure)?);
        let local = endpoint_builder
            .local_addr()
            .map_err(|e| HopError::transport(hop_id.clone(), format!("quinn local: {e}")))?;
        let connecting = endpoint_builder
            .connect(endpoint, "localhost")
            .map_err(|e| {
                HopError::transport(hop_id.clone(), format!("masque QUIC connect: {e}"))
            })?;
        let conn = tokio::time::timeout(std::time::Duration::from_secs(15), connecting)
            .await
            .map_err(|_| {
                HopError::transport(
                    hop_id.clone(),
                    format!("masque QUIC connect to {endpoint} timed out (unreachable transport)"),
                )
            })?
            .map_err(|e| HopError::transport(hop_id.clone(), format!("masque handshake: {e}")))?;
        // Keep the endpoint alive with the connection.
        std::mem::forget(endpoint_builder);
        let (events, _) = tokio::sync::broadcast::channel(16);
        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(MasqueHop {
            hop_id,
            endpoint,
            local,
            conn: Conn::H3(conn),
            // H3 is OS-direct QUIC in US3 (T058); the carrier is kept so the
            // dialer shape stays uniform.
            carrier,
            events,
        }))
    }

    async fn bring_up_h2(
        hop_id: String,
        endpoint: SocketAddr,
        carrier: Arc<dyn Dialer>,
        fragment: Option<usize>,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        // Nested uplink (T058): an encapsulated carrier drives H2 over a
        // carrier TCP stream; a direct carrier keeps the OS TCP socket.
        // Against a framing-unaware far end the nested handshake fails closed.
        let nested = carrier.nested_mtu().is_some();
        // The bring-up sender is dropped: per-dial H2 egress opens a fresh
        // connection (see H2DialerRef); the driver task keeps the conn alive.
        let (_, task, local) = if nested {
            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                carrier.dial_tcp(endpoint),
            )
            .await
            .map_err(|_| {
                HopError::transport(
                    hop_id.clone(),
                    format!("nested uplink via carrier: masque H2 connect to {endpoint} timed out"),
                )
            })?
            .map_err(|e| {
                HopError::transport(
                    hop_id.clone(),
                    format!("nested uplink via carrier: {}", e.message),
                )
            })?;
            let (sender, conn) = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                h2::client::handshake(stream),
            )
            .await
            .map_err(|_| {
                HopError::transport(
                    hop_id.clone(),
                    format!(
                        "nested uplink via carrier: masque H2 handshake to {endpoint} timed out"
                    ),
                )
            })?
            .map_err(|e| {
                HopError::transport(hop_id.clone(), format!("masque H2 handshake: {e}"))
            })?;
            let task = tokio::spawn(async move {
                let mut conn = conn;
                let _ = (&mut conn).await;
            });
            let local: SocketAddr = unspecified_bind(&endpoint);
            (sender, task, local)
        } else {
            let tcp = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                tokio::net::TcpStream::connect(endpoint),
            )
            .await
            .map_err(|_| {
                HopError::transport(
                    hop_id.clone(),
                    format!("masque H2 connect to {endpoint} timed out (unreachable transport)"),
                )
            })?
            .map_err(|e| HopError::transport(hop_id.clone(), format!("masque H2 TCP: {e}")))?;
            let local = tcp
                .local_addr()
                .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 local: {e}")))?;
            let (sender, conn) = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                h2::client::handshake(tcp),
            )
            .await
            .map_err(|_| {
                HopError::transport(
                    hop_id.clone(),
                    format!("masque H2 handshake to {endpoint} timed out (unreachable transport)"),
                )
            })?
            .map_err(|e| {
                HopError::transport(hop_id.clone(), format!("masque H2 handshake: {e}"))
            })?;
            let task = tokio::spawn(async move {
                let mut conn = conn;
                let _ = (&mut conn).await;
            });
            (sender, task, local)
        };
        let (events, _) = tokio::sync::broadcast::channel(16);
        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        let task = task.abort_handle();
        Ok(Arc::new(MasqueHop {
            hop_id,
            endpoint,
            local,
            conn: Conn::H2(H2Conn {
                nested,
                fragment,
                driver: task,
            }),
            carrier,
            events,
        }))
    }
}

/// Install the process-wide rustls crypto provider once (ring via quinn's
/// `rustls-ring` feature). Required before any ClientConfig/ServerConfig
/// builder use.
pub(crate) fn ensure_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn client_config(insecure: bool) -> Result<quinn::ClientConfig, HopError> {
    ensure_provider();
    let mut roots = rustls::RootCertStore::empty();
    if !insecure {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            return Err(HopError::transport(
                "masque",
                format!("native certs: {:?}", loaded.errors),
            ));
        }
        roots.add_parsable_certificates(loaded.certs);
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    if insecure {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(test_support::NoVerifier));
    }
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| HopError::transport("masque", format!("quic crypto: {e}")))?,
    )))
}

#[async_trait::async_trait]
impl RunningHop for MasqueHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        match &self.conn {
            Conn::H3(conn) => Arc::new(H3Dialer {
                hop_id: self.hop_id.clone(),
                conn: conn.clone(),
                local: self.local,
            }),
            Conn::H2(c) => Arc::new(H2DialerRef {
                hop_id: self.hop_id.clone(),
                endpoint: self.endpoint,
                local: self.local,
                nested: c.nested,
                fragment: c.fragment,
                carrier: self.carrier.clone(),
            }),
        }
    }

    fn health(&self) -> HopHealth {
        match &self.conn {
            Conn::H3(conn) => {
                if conn.close_reason().is_some() {
                    HopHealth::Failed
                } else {
                    HopHealth::Healthy
                }
            }
            Conn::H2(_) => HopHealth::Healthy,
        }
    }

    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.events.subscribe()
    }

    async fn stop(&self) -> Result<(), HopError> {
        match &self.conn {
            Conn::H3(conn) => conn.close(0u32.into(), b"stop"),
            // Reap the bring-up driver: without this the H2 connection it
            // holds stays open past teardown.
            Conn::H2(c) => c.driver.abort(),
        }
        let _ = self.events.send(HopEvent::Stopped {
            hop_id: self.hop_id.clone(),
        });
        Ok(())
    }
}

/// H2 dialer needs the live sender; the hop owns it, so the dialer borrows
/// through a channel. Simplified: H2 dials open a fresh TCP+H2 connection per
/// dial (correct, slightly heavier; multiplexing milestone later).
struct H2DialerRef {
    hop_id: String,
    endpoint: SocketAddr,
    local: SocketAddr,
    nested: bool,
    fragment: Option<usize>,
    carrier: Arc<dyn Dialer>,
}

struct H3Dialer {
    hop_id: String,
    conn: quinn::Connection,
    local: SocketAddr,
}

#[async_trait::async_trait]
impl Dialer for H3Dialer {
    async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        let (send, recv) =
            tokio::time::timeout(std::time::Duration::from_secs(15), self.conn.open_bi())
                .await
                .map_err(|_| {
                    HopError::transport(
                        self.hop_id.clone(),
                        "masque QUIC open stream timed out (unreachable transport)".to_string(),
                    )
                })?
                .map_err(|e| {
                    HopError::transport(self.hop_id.clone(), format!("open stream: {e}"))
                })?;
        Ok(Box::new(QuicStream { send, recv }))
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        // The flow is bound to `dst` (send_to rejects anything else), so
        // the length-prefixed destination header is encoded once here —
        // not formatted per datagram on the hot path.
        let dst_s = dst.to_string();
        let mut prefix = Vec::with_capacity(1 + dst_s.len());
        prefix.push(dst_s.len() as u8);
        prefix.extend_from_slice(dst_s.as_bytes());
        Ok(Box::new(QuicDgrams {
            hop_id: self.hop_id.clone(),
            conn: self.conn.clone(),
            dst,
            prefix,
            local: self.local,
        }))
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    /// H3 egress is OS-direct QUIC in US3 (never rides the carrier).
    fn nested_mtu(&self) -> Option<u16> {
        None
    }
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl tokio::io::AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.send).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

impl ByteStream for QuicStream {}

struct QuicDgrams {
    hop_id: String,
    conn: quinn::Connection,
    dst: SocketAddr,
    /// Pre-encoded `[len u8][dst]` datagram header (flow is dst-bound).
    prefix: Vec<u8>,
    local: SocketAddr,
}

#[async_trait::async_trait]
impl UdpFlow for QuicDgrams {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        if dst != self.dst {
            return Err(HopError::transport(
                self.hop_id.clone(),
                "masque datagram flow is bound to its dial destination",
            ));
        }
        check_datagram_len(&self.hop_id, buf.len())?;
        let mut frame = Vec::with_capacity(self.prefix.len() + buf.len());
        frame.extend_from_slice(&self.prefix);
        frame.extend_from_slice(buf);
        self.conn
            .send_datagram(Bytes::from(frame))
            .map_err(|e| HopError::transport(self.hop_id.clone(), format!("datagram: {e}")))?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        loop {
            let dg =
                self.conn.read_datagram().await.map_err(|e| {
                    HopError::transport(self.hop_id.clone(), format!("datagram: {e}"))
                })?;
            if dg.is_empty() {
                continue;
            }
            let len = dg[0] as usize;
            if dg.len() < 1 + len {
                continue;
            }
            let dst: SocketAddr = std::str::from_utf8(&dg[1..1 + len])
                .map_err(|e| HopError::transport(self.hop_id.clone(), e.to_string()))?
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    HopError::transport(self.hop_id.clone(), e.to_string())
                })?;
            if dst != self.dst {
                continue;
            }
            let n = dg.len() - 1 - len;
            let n = n.min(buf.len());
            buf[..n].copy_from_slice(&dg[1 + len..1 + len + n]);
            return Ok((n, dst));
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        Ok(self.local)
    }
}

#[async_trait::async_trait]
impl Dialer for H2DialerRef {
    async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        h2_dial_tcp(
            self.hop_id.clone(),
            self.endpoint,
            self.local,
            dst,
            &self.carrier,
            self.nested,
            self.fragment,
        )
        .await
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        h2_dial_udp(
            self.hop_id.clone(),
            self.endpoint,
            self.local,
            dst,
            &self.carrier,
            self.nested,
        )
        .await
    }

    fn capabilities(&self) -> Capabilities {
        DESCRIPTOR.capabilities
    }

    /// Nested H2 egress rides the carrier TCP stream; direct H2 is OS-direct.
    fn nested_mtu(&self) -> Option<u16> {
        if self.nested {
            Some(1460)
        } else {
            None
        }
    }
}

async fn h2_connect(
    hop_id: &str,
    endpoint: SocketAddr,
    carrier: &Arc<dyn Dialer>,
    nested: bool,
) -> Result<
    (
        h2::client::SendRequest<Bytes>,
        SocketAddr,
        tokio::task::AbortHandle,
    ),
    HopError,
> {
    if nested {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            carrier.dial_tcp(endpoint),
        )
        .await
        .map_err(|_| {
            HopError::transport(
                hop_id,
                format!("nested uplink via carrier: masque H2 dial to {endpoint} timed out"),
            )
        })?
        .map_err(|e| {
            HopError::transport(hop_id, format!("nested uplink via carrier: {}", e.message))
        })?;
        let (sender, conn) = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            h2::client::handshake(stream),
        )
        .await
        .map_err(|_| {
            HopError::transport(
                hop_id,
                format!("nested uplink via carrier: masque H2 handshake to {endpoint} timed out"),
            )
        })?
        .map_err(|e| HopError::transport(hop_id, format!("h2 handshake: {e}")))?;
        // The driver owns the TCP+H2 connection: bind its lifetime to the
        // returned abort handle so cancellation or stream drop reaps it
        // instead of leaking a detached task holding the socket.
        let driver = tokio::spawn(async move {
            let mut conn = conn;
            let _ = (&mut conn).await;
        })
        .abort_handle();
        let local: SocketAddr = unspecified_bind(&endpoint);
        return Ok((sender, local, driver));
    }
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::net::TcpStream::connect(endpoint),
    )
    .await
    .map_err(|_| {
        HopError::transport(
            hop_id,
            format!("masque H2 dial to {endpoint} timed out (unreachable transport)"),
        )
    })?
    .map_err(|e| HopError::transport(hop_id, format!("h2 tcp: {e}")))?;
    let local = tcp
        .local_addr()
        .map_err(|e| HopError::transport(hop_id, format!("h2 local: {e}")))?;
    let (sender, conn) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        h2::client::handshake(tcp),
    )
    .await
    .map_err(|_| {
        HopError::transport(
            hop_id,
            format!("masque H2 handshake to {endpoint} timed out (unreachable transport)"),
        )
    })?
    .map_err(|e| HopError::transport(hop_id, format!("h2 handshake: {e}")))?;
    // Same lifetime binding as the nested path above.
    let driver = tokio::spawn(async move {
        let mut conn = conn;
        let _ = (&mut conn).await;
    })
    .abort_handle();
    Ok((sender, local, driver))
}

async fn h2_dial_tcp(
    hop_id: String,
    endpoint: SocketAddr,
    _local: SocketAddr,
    dst: SocketAddr,
    carrier: &Arc<dyn Dialer>,
    nested: bool,
    fragment: Option<usize>,
) -> Result<Box<dyn ByteStream>, HopError> {
    let (mut sender, _, driver) = h2_connect(&hop_id, endpoint, carrier, nested).await?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://{dst}/stream"))
        .body(())
        .map_err(|e| HopError::transport(hop_id.clone(), e.to_string()))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 request: {e}")))?;
    let recv = tokio::time::timeout(std::time::Duration::from_secs(15), response)
        .await
        .map_err(|_| {
            HopError::transport(
                hop_id.clone(),
                format!("masque H2 response from {dst} timed out (unreachable transport)"),
            )
        })?
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 response: {e}")))?
        .into_body();
    // Drain headers/body start: server echoes request body chunks.
    Ok(Box::new(H2Stream {
        send,
        recv,
        fragment,
        pending: Vec::new(),
        driver,
    }))
}

struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    fragment: Option<usize>,
    /// Buffered tail when one H2 DATA frame exceeds the caller's read buffer.
    pending: Vec<u8>,
    /// Per-dial connection driver: aborting on drop reaps the TCP+H2
    /// connection when the stream goes away (a cancelled dial or a dropped
    /// stream must not leave a detached task holding the socket).
    driver: tokio::task::AbortHandle,
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl tokio::io::AsyncRead for H2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        // Serve a buffered tail first; the remainder stays for the next read.
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                let _ = self.recv.flow_control().release_capacity(data.len());
                if n < data.len() {
                    self.pending.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => {
                if buf.filled().is_empty() {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for H2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        // Honor H2 flow-control windows: park on `Pending`/zero capacity so
        // a stalled peer applies backpressure instead of unbounded buffering
        // (or a misreported `BrokenPipe` that tears down a healthy stream).
        // Closed/reset streams still fail fast below.
        match self.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2 stream closed",
            ))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            Poll::Ready(Some(Ok(0))) => Poll::Pending,
            Poll::Ready(Some(Ok(_))) => {
                // Noize fragmentation (US5 T070): chunk writes at the profile size.
                let n = obfuscate::chunk_for_send(buf.len().min(16384), self.fragment);
                match self
                    .send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    ))),
                }
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

impl ByteStream for H2Stream {}

async fn h2_dial_udp(
    hop_id: String,
    endpoint: SocketAddr,
    local: SocketAddr,
    dst: SocketAddr,
    carrier: &Arc<dyn Dialer>,
    nested: bool,
) -> Result<Box<dyn UdpFlow>, HopError> {
    let (mut sender, _, driver) = h2_connect(&hop_id, endpoint, carrier, nested).await?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://{dst}/datagrams"))
        .body(())
        .map_err(|e| HopError::transport(hop_id.clone(), e.to_string()))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 request: {e}")))?;
    let recv = tokio::time::timeout(std::time::Duration::from_secs(15), response)
        .await
        .map_err(|_| {
            HopError::transport(
                hop_id.clone(),
                format!("masque H2 response from {dst} timed out (unreachable transport)"),
            )
        })?
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 response: {e}")))?
        .into_body();
    Ok(Box::new(H2Dgrams {
        hop_id,
        send: tokio::sync::Mutex::new(send),
        recv: tokio::sync::Mutex::new(recv),
        pending: tokio::sync::Mutex::new(Vec::new()),
        dst,
        local,
        driver,
    }))
}

struct H2Dgrams {
    hop_id: String,
    send: tokio::sync::Mutex<h2::SendStream<Bytes>>,
    recv: tokio::sync::Mutex<h2::RecvStream>,
    pending: tokio::sync::Mutex<Vec<u8>>,
    dst: SocketAddr,
    local: SocketAddr,
    /// Per-dial connection driver (same lifetime binding as `H2Stream`).
    driver: tokio::task::AbortHandle,
}

impl Drop for H2Dgrams {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Max framed payload per H2 datagram (bounded framing checked before allocating).
const MAX_H2_DATAGRAM: usize = 65535;

/// Cap on buffered-but-unframed H2 datagram bytes: one max-size frame plus
/// its 4-byte length prefix. Anything beyond that is a hostile or broken
/// peer trickling bytes forever; fail closed instead of growing `pending`.
const MAX_H2_PENDING: usize = MAX_H2_DATAGRAM + 4;

/// Fail-fast datagram size gate shared by the H3 (QUIC DATAGRAM) and H2
/// (length-prefixed DATA) UDP paths. Runs before any frame allocation or
/// transport call, so an oversized caller buffer is rejected without
/// allocating or depending on QUIC/H2 peer behavior.
fn check_datagram_len(hop_id: &str, len: usize) -> Result<(), HopError> {
    if len > MAX_H2_DATAGRAM {
        return Err(HopError::transport(
            hop_id,
            format!("datagram {len} exceeds {MAX_H2_DATAGRAM}"),
        ));
    }
    Ok(())
}

/// Bounded append for the H2 datagram reassembly buffer: refuses to grow
/// `pending` past [`MAX_H2_PENDING`] instead of extending without limit.
fn push_pending(pending: &mut Vec<u8>, data: &[u8], hop_id: &str) -> Result<(), HopError> {
    if pending.len().saturating_add(data.len()) > MAX_H2_PENDING {
        return Err(HopError::transport(
            hop_id,
            format!(
                "datagram buffer {} exceeds {MAX_H2_PENDING}",
                pending.len() + data.len()
            ),
        ));
    }
    pending.extend_from_slice(data);
    Ok(())
}

#[async_trait::async_trait]
impl UdpFlow for H2Dgrams {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> Result<(), HopError> {
        if dst != self.dst {
            return Err(HopError::transport(
                self.hop_id.clone(),
                "masque datagram flow is bound to its dial destination",
            ));
        }
        check_datagram_len(&self.hop_id, buf.len())?;
        let mut frame = Vec::with_capacity(4 + buf.len());
        frame.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        frame.extend_from_slice(buf);
        self.send
            .lock()
            .await
            .send_data(Bytes::from(frame), false)
            .map_err(|e| HopError::transport(self.hop_id.clone(), e.to_string()))?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), HopError> {
        loop {
            {
                let mut pending = self.pending.lock().await;
                if pending.len() >= 4 {
                    // Guarded by the length check above: exactly 4 bytes.
                    let len =
                        u32::from_be_bytes(pending[..4].try_into().expect("len prefix is 4 bytes"))
                            as usize;
                    // Bounded framing checked before allocating (networking).
                    if len > MAX_H2_DATAGRAM {
                        return Err(HopError::transport(
                            self.hop_id.clone(),
                            format!("peer framed {len} exceeding {MAX_H2_DATAGRAM}"),
                        ));
                    }
                    if pending.len() >= 4 + len {
                        let data: Vec<u8> = pending.drain(..4 + len).skip(4).collect();
                        let n = len.min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        return Ok((n, self.dst));
                    }
                }
            }
            let chunk = {
                let mut recv = self.recv.lock().await;
                recv.data()
                    .await
                    .transpose()
                    .map_err(|e| HopError::transport(self.hop_id.clone(), e.to_string()))?
            };
            match chunk {
                Some(data) => {
                    let n = data.len();
                    {
                        let mut pending = self.pending.lock().await;
                        push_pending(&mut pending, &data, &self.hop_id)?;
                    }
                    let mut recv = self.recv.lock().await;
                    let _ = recv.flow_control().release_capacity(n);
                }
                None => {
                    return Err(HopError::transport(
                        self.hop_id.clone(),
                        "datagram stream closed",
                    ))
                }
            }
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, HopError> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_transport_api::HopFactory;

    struct RefusingCarrier;

    #[async_trait::async_trait]
    impl Dialer for RefusingCarrier {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::transport("test-carrier", "no uplink"))
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

    #[tokio::test]
    async fn nested_carrier_failure_is_fail_closed_and_named() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-nested-0".into());
        cfg.fields.insert("endpoint".into(), "127.0.0.1:1".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("nested uplink failure must fail closed"),
            Err(e) => e,
        };
        assert!(
            err.message.contains("nested uplink via carrier"),
            "names path: {err}"
        );
        assert_eq!(
            err.hop_id.as_deref(),
            Some("masque-nested-0"),
            "names hop: {err}"
        );
        assert_eq!(err.kind, HopErrorKind::Transport);
    }

    #[test]
    fn datagram_size_gate_rejects_oversize_before_alloc() {
        // Shared H3/H2 gate: a 200k caller buffer must Err without allocating
        // a frame or touching QUIC/H2 (QuicDgrams::send_to calls this first).
        let err = check_datagram_len("masque-h3-0", 200_000).expect_err("200k must be rejected");
        assert!(
            err.message.contains("datagram 200000 exceeds 65535"),
            "H2-shaped cap message: {err}"
        );
        assert!(check_datagram_len("masque-h3-0", MAX_H2_DATAGRAM).is_ok());
        assert!(check_datagram_len("masque-h3-0", MAX_H2_DATAGRAM + 1).is_err());
    }

    #[test]
    fn h2_pending_trickle_stays_bounded() {
        // Endless 1-byte chunks must never grow pending past MAX_H2_PENDING.
        let mut pending = Vec::new();
        let mut rejected_at = None;
        for i in 0..200_000 {
            if let Err(e) = push_pending(&mut pending, &[0x55], "masque-h2-0") {
                rejected_at = Some((i, e));
                break;
            }
            assert!(pending.len() <= MAX_H2_PENDING, "bounded at chunk {i}");
        }
        let (count, err) = rejected_at.expect("trickle must trip the ceiling");
        assert_eq!(pending.len(), MAX_H2_PENDING);
        assert_eq!(count, MAX_H2_PENDING);
        assert!(
            err.message.contains("exceeds"),
            "fail-closed message: {err}"
        );
    }

    /// Real h2 stream pair (client send/recv + server peer) backing an
    /// H2Dgrams flow, so send/recv caps are exercised without mocks.
    async fn h2_pair(hop_id: &str, dst: SocketAddr) -> (H2Dgrams, h2::SendStream<Bytes>) {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let client_handshake = tokio::spawn(async move {
            let (sender, conn) = h2::client::handshake(client_io)
                .await
                .expect("client handshake");
            tokio::spawn(async move {
                let mut conn = conn;
                let _ = (&mut conn).await;
            });
            sender
        });
        let mut server = h2::server::handshake(server_io)
            .await
            .expect("server handshake");
        let mut sender = client_handshake.await.expect("client task");
        let request = http::Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/datagrams")
            .body(())
            .unwrap();
        let (resp_fut, client_send) = sender.send_request(request, false).expect("send_request");
        let (req, mut respond) = server
            .accept()
            .await
            .expect("accept Some")
            .expect("accept Ok");
        drop(req.into_body());
        let response = http::Response::builder().status(200).body(()).unwrap();
        let server_send = respond
            .send_response(response, false)
            .expect("send_response");
        tokio::spawn(async move {
            let mut server = server;
            while let Some(accepted) = server.accept().await {
                let _ = accepted;
            }
        });
        let client_recv = resp_fut.await.expect("response").into_body();
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let flow = H2Dgrams {
            hop_id: hop_id.to_string(),
            send: tokio::sync::Mutex::new(client_send),
            recv: tokio::sync::Mutex::new(client_recv),
            pending: tokio::sync::Mutex::new(Vec::new()),
            dst,
            local,
            // Test-owned driver: aborted with the flow on drop (same
            // lifetime binding as production dials).
            driver: tokio::spawn(std::future::pending::<()>()).abort_handle(),
        };
        (flow, server_send)
    }

    #[tokio::test]
    async fn h2_send_to_rejects_oversize() {
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (flow, _server) = h2_pair("masque-h2-0", dst).await;
        let big = vec![0u8; 200_000];
        let err = flow
            .send_to(&big, dst)
            .await
            .expect_err("200k datagram must be rejected");
        assert!(
            err.message.contains("exceeds 65535"),
            "same shape as relay cap: {err}"
        );
    }

    #[tokio::test]
    async fn h2_recv_rejects_pending_overflow() {
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (flow, mut server_send) = h2_pair("masque-h2-0", dst).await;
        // Chunk 1: one complete 10-byte datagram + 60_000 bytes of filler
        // that open a second frame declaring len 65535 (valid, incomplete).
        let mut first = Vec::with_capacity(14 + 60_000);
        first.extend_from_slice(&10u32.to_be_bytes());
        first.extend_from_slice(&[0xAB; 10]);
        first.extend_from_slice(&65535u32.to_be_bytes());
        first.resize(14 + 60_000, 0xCD);
        server_send
            .send_data(Bytes::from(first), false)
            .expect("feed chunk 1");
        let mut buf = vec![0u8; 70_000];
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(5), flow.recv_from(&mut buf))
                .await
                .expect("recv arrives")
                .expect("first frame ok");
        assert_eq!(from, dst);
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], &[0xAB; 10]);
        // Chunk 2 pushes the incomplete second frame past MAX_H2_DATAGRAM+4.
        server_send
            .send_data(Bytes::from(vec![0xEF; 8192]), false)
            .expect("feed chunk 2");
        let err = tokio::time::timeout(std::time::Duration::from_secs(5), flow.recv_from(&mut buf))
            .await
            .expect("recv resolves")
            .expect_err("pending overflow must fail closed");
        assert!(err.message.contains("exceeds"), "bounded pending: {err}");
    }
}
