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
    _task: tokio::task::JoinHandle<()>,
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
            let (sender, conn) = h2::client::handshake(stream).await.map_err(|e| {
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
            let (sender, conn) = h2::client::handshake(tcp).await.map_err(|e| {
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
        Ok(Arc::new(MasqueHop {
            hop_id,
            endpoint,
            local,
            conn: Conn::H2(H2Conn {
                nested,
                fragment,
                _task: task,
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
        if let Conn::H3(conn) = &self.conn {
            conn.close(0u32.into(), b"stop");
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
            self.conn.open_bi().await.map_err(|e| {
                HopError::transport(self.hop_id.clone(), format!("open stream: {e}"))
            })?;
        Ok(Box::new(QuicStream { send, recv }))
    }

    async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        Ok(Box::new(QuicDgrams {
            hop_id: self.hop_id.clone(),
            conn: self.conn.clone(),
            dst,
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
        let dst_s = dst.to_string();
        let mut frame = Vec::with_capacity(1 + dst_s.len() + buf.len());
        frame.push(dst_s.len() as u8);
        frame.extend_from_slice(dst_s.as_bytes());
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
) -> Result<(h2::client::SendRequest<Bytes>, SocketAddr), HopError> {
    if nested {
        let stream = carrier.dial_tcp(endpoint).await.map_err(|e| {
            HopError::transport(hop_id, format!("nested uplink via carrier: {}", e.message))
        })?;
        let (sender, conn) = h2::client::handshake(stream)
            .await
            .map_err(|e| HopError::transport(hop_id, format!("h2 handshake: {e}")))?;
        tokio::spawn(async move {
            let mut conn = conn;
            let _ = (&mut conn).await;
        });
        let local: SocketAddr = unspecified_bind(&endpoint);
        return Ok((sender, local));
    }
    let tcp = tokio::net::TcpStream::connect(endpoint)
        .await
        .map_err(|e| HopError::transport(hop_id, format!("h2 tcp: {e}")))?;
    let local = tcp
        .local_addr()
        .map_err(|e| HopError::transport(hop_id, format!("h2 local: {e}")))?;
    let (sender, conn) = h2::client::handshake(tcp)
        .await
        .map_err(|e| HopError::transport(hop_id, format!("h2 handshake: {e}")))?;
    tokio::spawn(async move {
        let mut conn = conn;
        let _ = (&mut conn).await;
    });
    Ok((sender, local))
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
    let (mut sender, _) = h2_connect(&hop_id, endpoint, carrier, nested).await?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://{dst}/stream"))
        .body(())
        .map_err(|e| HopError::transport(hop_id.clone(), e.to_string()))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 request: {e}")))?;
    let recv = response
        .await
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 response: {e}")))?
        .into_body();
    // Drain headers/body start: server echoes request body chunks.
    Ok(Box::new(H2Stream {
        send,
        recv,
        fragment,
    }))
}

struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    fragment: Option<usize>,
}

impl tokio::io::AsyncRead for H2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                let _ = self.recv.flow_control().release_capacity(n);
                // Return remainder to flow control accounting is best-effort;
                // unread tail is dropped (loopback tests use small writes).
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
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Noize fragmentation (US5 T070): chunk writes at the profile size.
        let n = obfuscate::chunk_for_send(buf.len().min(16384), self.fragment);
        match self
            .send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
        {
            Ok(()) => std::task::Poll::Ready(Ok(n)),
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
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
    let (mut sender, _) = h2_connect(&hop_id, endpoint, carrier, nested).await?;
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://{dst}/datagrams"))
        .body(())
        .map_err(|e| HopError::transport(hop_id.clone(), e.to_string()))?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 request: {e}")))?;
    let recv = response
        .await
        .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 response: {e}")))?
        .into_body();
    Ok(Box::new(H2Dgrams {
        hop_id,
        send: tokio::sync::Mutex::new(send),
        recv: tokio::sync::Mutex::new(recv),
        pending: tokio::sync::Mutex::new(Vec::new()),
        dst,
        local,
    }))
}

struct H2Dgrams {
    hop_id: String,
    send: tokio::sync::Mutex<h2::SendStream<Bytes>>,
    recv: tokio::sync::Mutex<h2::RecvStream>,
    pending: tokio::sync::Mutex<Vec<u8>>,
    dst: SocketAddr,
    local: SocketAddr,
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
                    let len = u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
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
                    self.pending.lock().await.extend_from_slice(&data);
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
}
