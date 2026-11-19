//! MASQUE transport over a single QUIC provider (T040, research R4 outcome).
//!
//! - `alpn=h3`: real QUIC (quinn + rustls/ring) with ALPN `h3`; TCP egress
//!   rides native QUIC bidirectional streams, UDP egress rides QUIC DATAGRAM
//!   frames with a dst-prefix. The client connection sends QUIC keep-alives
//!   every 15 s so NATed idle paths do not die under green health.
//! - `alpn=h2`: HTTP/2 over TCP (h2 crate, prior knowledge); egress rides
//!   per-dial POST streams, datagrams length-prefixed on a dedicated stream.
//!   H2 sends are flow-window-bounded (`reserve_capacity` then
//!   `poll_capacity`) so a fast writer cannot buffer unboundedly inside h2.
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
        // `build` is async, so hostnames resolve here (same policy as
        // transport-wireguard's `resolve_endpoint`): IP literals parse
        // synchronously, names go through `lookup_host` with a timeout, and
        // every failure is a Config error naming the field — never a chain
        // that cannot run.
        let endpoints = resolve_endpoint(hop_id.clone(), cfg.get("endpoint")).await?;
        let insecure = cfg.get("insecure_skip_verify") == Some("true");
        let fragment = obfuscate::fragment_size(&cfg)?;
        // Try each resolved address in order; the first successful bring-up
        // wins. Dual-stack names (`localhost` → `::1` + `127.0.0.1`) are
        // platform-ordered, so one address must not be picked upfront — that
        // silently broke IPv4-only peers on linux (the CI dry-run failure).
        let mut last: Option<HopError> = None;
        for endpoint in endpoints {
            let result = match alpn {
                "h3" => {
                    MasqueHop::bring_up_h3(hop_id.clone(), endpoint, insecure, carrier.clone())
                        .await
                }
                "h2" => {
                    MasqueHop::bring_up_h2(hop_id.clone(), endpoint, carrier.clone(), fragment)
                        .await
                }
                other => {
                    return Err(HopError::new(
                        HopErrorKind::Config,
                        Some(hop_id),
                        format!("unknown masque alpn `{other}` (h3|h2)"),
                    ));
                }
            };
            match result {
                Ok(hop) => return Ok(hop),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            HopError::new(
                HopErrorKind::Config,
                Some(hop_id),
                "endpoint resolved to no addresses".to_string(),
            )
        }))
    }
}

/// Timeout for the DNS resolution of a hostname `endpoint` (fails closed).
const ENDPOINT_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Resolve `endpoint=<ip:port|host:port>` into every address the name has
/// (a literal is a one-element list). Callers try the addresses in order —
/// "localhost" resolves to both `::1` and `127.0.0.1` and which one comes
/// first is platform-ordered, so a single-address pick silently breaks
/// dual-stack peers (the linux CI failure). Fails closed with a Config
/// error naming the field, like `transport-wireguard::modes::resolve_endpoint`.
async fn resolve_endpoint(hop_id: String, raw: Option<&str>) -> Result<Vec<SocketAddr>, HopError> {
    let config_err = |msg: String| HopError::new(HopErrorKind::Config, Some(hop_id.clone()), msg);
    let Some(s) = raw else {
        return Err(config_err(
            "masque hop requires endpoint=<ip:port>".to_string(),
        ));
    };
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    // Bracketed v6 that failed to parse above is malformed, not a name.
    if s.starts_with('[') {
        return Err(config_err(format!(
            "bad endpoint: `{s}` is not `[ipv6]:port`"
        )));
    }
    // Unbracketed multi-colon input is ambiguous: do not guess.
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| config_err(format!("bad endpoint: `{s}` is not host:port")))?;
    if host.is_empty() || host.contains(':') {
        return Err(config_err(format!("bad endpoint: `{s}` is not host:port")));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| config_err(format!("bad endpoint: port `{port_str}` is not numeric")))?;
    if port == 0 {
        return Err(config_err(
            "bad endpoint: port `0` is not connectable".to_string(),
        ));
    }
    let lookup = tokio::time::timeout(
        ENDPOINT_RESOLVE_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| config_err(format!("bad endpoint: resolve `{host}` timed out")))?;
    let resolved: Vec<SocketAddr> = lookup
        .map_err(|e| config_err(format!("bad endpoint: resolve `{host}`: {e}")))?
        .collect();
    if resolved.is_empty() {
        return Err(config_err(format!("bad endpoint: no address for `{host}`")));
    }
    Ok(resolved)
}

enum Conn {
    H3 {
        /// Client connection riding this endpoint.
        conn: quinn::Connection,
        /// QUIC endpoint (owns the bound UDP socket + endpoint driver task).
        /// Quinn semantics (vendored quinn-0.11.12): the driver task spawned
        /// by `Endpoint::client` exits only once every `Endpoint` handle is
        /// dropped AND every connection has drained, so the endpoint must be
        /// owned here — forgetting it leaks the driver and socket forever.
        endpoint: quinn::Endpoint,
    },
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
        // The endpoint is owned by the hop: dropping it is what lets the
        // endpoint driver exit and releases the UDP socket at stop().
        let (events, _) = tokio::sync::broadcast::channel(16);
        let _ = events.send(HopEvent::Started {
            hop_id: hop_id.clone(),
        });
        Ok(Arc::new(MasqueHop {
            hop_id,
            endpoint,
            local,
            conn: Conn::H3 {
                conn,
                endpoint: endpoint_builder,
            },
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

/// QUIC keep-alive interval: an ack-eliciting ping every 15 s keeps idle
/// connections alive through NAT rebinding / idle timeouts that would
/// otherwise kill them while health still reports green.
const QUIC_KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

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
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| HopError::transport("masque", format!("quic crypto: {e}")))?,
    ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[async_trait::async_trait]
impl RunningHop for MasqueHop {
    fn descriptor(&self) -> &'static TransportDescriptor {
        &DESCRIPTOR
    }

    fn dialer(&self) -> Arc<dyn Dialer> {
        match &self.conn {
            Conn::H3 { conn, .. } => Arc::new(H3Dialer {
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
            Conn::H3 { conn, .. } => {
                if conn.close_reason().is_some() {
                    HopHealth::Failed
                } else {
                    HopHealth::Healthy
                }
            }
            Conn::H2(_) => HopHealth::Healthy,
            // H2 has no liveness signal to poll (no PING task in v1): the
            // value below is a build-succeeded/never-stopped signal, NOT a
            // probe of the TCP+H2 connection, which can die silently behind
            // green health. Known limitation, documented here until an idle
            // PING task (bounded by the connection handle) lands.
        }
    }

    fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.events.subscribe()
    }

    async fn stop(&self) -> Result<(), HopError> {
        match &self.conn {
            Conn::H3 { conn, endpoint } => {
                // Close the connection, then the endpoint: quinn's
                // `Endpoint::close` immediately ceases accepting/sending new
                // connections and signals every connection to close, so the
                // driver task exits as soon as the connection drains — and
                // dropping this hop's handle (the only one left, the old
                // builder handle never escapes) drops the socket state with
                // it. Sending the close frame is the driver's job while it
                // still runs, so the order matters: close first, drop after.
                conn.close(0u32.into(), b"stop");
                endpoint.close(0u32.into(), b"stop");
                // Dropping happens implicitly when this `MasqueHop` (and the
                // dialers cloned from it) go away; nothing is forgotten.
            }
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

/// Parse one dst-prefixed datagram frame: `[len u8][dst][payload]`.
/// Returns `None` for anything malformed or addressed elsewhere — callers
/// skip-and-count those instead of failing the flow. `Ok` always carries the
/// flow's own `dst` (send_to rejects anything else, so a frame for another
/// destination is malformed for this flow).
fn parse_dst_prefixed(dg: &[u8], flow_dst: SocketAddr) -> Option<(SocketAddr, &[u8])> {
    let (&len, rest) = dg.split_first()?;
    let len = len as usize;
    let payload = rest.get(len..)?;
    let dst_s = std::str::from_utf8(&rest[..len]).ok()?;
    let dst: SocketAddr = dst_s.parse().ok()?;
    (dst == flow_dst).then_some((dst, payload))
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
        // Debug-counted skip of malformed datagrams: one junk datagram must
        // not kill the whole flow. Fail-closed stays for framing that gates
        // the whole stream (connection errors below).
        let mut malformed: u64 = 0;
        loop {
            let dg =
                self.conn.read_datagram().await.map_err(|e| {
                    HopError::transport(self.hop_id.clone(), format!("datagram: {e}"))
                })?;
            let frame = match parse_dst_prefixed(&dg, self.dst) {
                Some(dst) => dst,
                None => {
                    malformed = malformed.wrapping_add(1);
                    #[cfg(debug_assertions)]
                    if malformed % 128 == 1 {
                        eprintln!("qcore-masque: skipped {malformed} malformed datagram(s)");
                    }
                    continue;
                }
            };
            let (dst, payload) = frame;
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
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
        // Window-bounded send: reserve capacity for the chunk, then await
        // `poll_capacity` before handing data to h2. Without this pairing a
        // writer faster than the network buffers unboundedly inside h2
        // (`send_data` without reserved capacity implicitly requests capacity
        // and buffers the frame while waiting for the window — h2's own docs
        // call this buffering unbounded).
        //
        // The pairing is `reserve_capacity` FIRST, `poll_capacity` second:
        // capacity is only assigned in response to a reservation, so polling
        // without reserving hangs forever (a prior revision did exactly this
        // and deadlocked the H2 conformance suite — keep that lesson).
        //
        // Chunks stay ≤16384 so one write can never exceed a max DATA frame.
        let n = obfuscate::chunk_for_send(buf.len().min(16384), self.fragment);
        // Reserve the full chunk, then poll: `poll_capacity` returns the
        // total assigned capacity (≥1, >0 guaranteed by h2) which bounds what
        // we may hand to `send_data` here.
        self.send.reserve_capacity(n);
        let assigned = match self.send.poll_capacity(cx) {
            std::task::Poll::Ready(Some(Ok(c))) => c,
            std::task::Poll::Ready(Some(Err(e))) => {
                self.send.reserve_capacity(0);
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                )));
            }
            // `None`: the stream is no longer streaming (closed/reset).
            std::task::Poll::Ready(None) => {
                self.send.reserve_capacity(0);
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "h2 send capacity closed",
                )));
            }
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };
        // Never exceed the assigned capacity: h2 decrements the reservation
        // as data is sent, so a send larger than `assigned` would over-buffer.
        let n = n.min(assigned);
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

    /// Direct carrier (no nesting): H2 bring-up dials the OS socket path.
    struct DirectCarrier;

    #[async_trait::async_trait]
    impl Dialer for DirectCarrier {
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

    // --- Fix 6: one malformed datagram must not kill the flow ---

    #[test]
    fn malformed_dst_prefixed_frames_parse_to_none() {
        let dst: SocketAddr = "127.0.0.1:53".parse().expect("static literal");
        let other: SocketAddr = "127.0.0.1:54".parse().expect("static literal");
        let frame = |dst_s: &str, payload: &[u8]| {
            let mut v = vec![dst_s.len() as u8];
            v.extend_from_slice(dst_s.as_bytes());
            v.extend_from_slice(payload);
            v
        };
        // Good frame parses to (dst, payload).
        let good = frame("127.0.0.1:53", b"ping");
        assert_eq!(
            parse_dst_prefixed(&good, dst),
            Some((dst, b"ping".as_slice()))
        );
        // Empty datagram: nothing to parse.
        assert_eq!(parse_dst_prefixed(&[], dst), None);
        // Length prefix declares more bytes than present (truncated).
        let mut truncated = frame("127.0.0.1:53", b"ping");
        truncated[0] = 64;
        assert_eq!(parse_dst_prefixed(&truncated, dst), None);
        // Destination is not UTF-8.
        let not_utf8 = vec![
            12u8, 0xFF, 0xFE, 0x31, 0x32, 0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x31, 0x00,
        ];
        assert_eq!(parse_dst_prefixed(&not_utf8, dst), None);
        // Destination does not parse as a SocketAddr.
        let bad_addr = frame("not-an-address", b"ping");
        assert_eq!(parse_dst_prefixed(&bad_addr, dst), None);
        // Valid frame addressed to a different destination: malformed for
        // this flow (send_to rejects foreign dsts, so recv must not accept).
        let foreign = frame("127.0.0.1:54", b"ping");
        assert_eq!(parse_dst_prefixed(&foreign, dst), None);
        // But the same frame IS valid for a flow bound to that destination.
        assert_eq!(
            parse_dst_prefixed(&foreign, other),
            Some((other, b"ping".as_slice()))
        );
    }

    // --- Fix 3: hostname endpoints resolve at build, fail closed ---

    #[tokio::test]
    async fn hostname_endpoint_resolves_through_loopback() {
        // `localhost:PORT` must resolve via lookup_host and complete the h2
        // handshake against the loopback responder.
        let responder = test_support::H2Responder::spawn("127.0.0.1".parse().unwrap())
            .await
            .expect("h2 responder");
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-host-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert(
            "endpoint".into(),
            format!("localhost:{}", responder.addr.port()),
        );
        let hop = MasqueFactory
            .build(cfg, Arc::new(DirectCarrier))
            .await
            .expect("hostname endpoint resolves and connects");
        assert_eq!(hop.health(), HopHealth::Healthy);
        hop.stop().await.expect("clean stop");
    }

    #[tokio::test]
    async fn bogus_hostname_fails_closed_as_config_error() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-host-1".into());
        cfg.fields
            .insert("endpoint".into(), "bogus.invalid.example:443".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("unresolvable hostname must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config, "Config, not panic: {err}");
        assert_eq!(
            err.hop_id.as_deref(),
            Some("masque-host-1"),
            "names hop: {err}"
        );
        assert!(
            err.message.contains("endpoint") && err.message.contains("bogus.invalid.example"),
            "names the field and host: {err}"
        );
    }

    #[tokio::test]
    async fn missing_endpoint_and_bad_port_fail_closed() {
        // Absent field.
        let err = match MasqueFactory
            .build(HopConfig::new("masque"), Arc::new(RefusingCarrier))
            .await
        {
            Ok(_) => panic!("missing endpoint must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(err.message.contains("endpoint"), "names field: {err}");
        // Non-numeric port on a hostname.
        let mut cfg = HopConfig::new("masque");
        cfg.fields
            .insert("endpoint".into(), "proxy.example.com:nope".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("non-numeric port must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(
            err.message.contains("port") && err.message.contains("nope"),
            "names the bad port: {err}"
        );
    }

    // --- Fix 4: h2 writes are flow-window bounded (reserve THEN poll) ---

    /// An H2Stream paired with a real h2 server peer whose window the test
    /// controls: the server never releases inbound capacity, so a bounded
    /// writer must stop making progress instead of buffering forever.
    /// Returns the stream and the server connection (the test owns the
    /// server task's abort handle to reap it with the test).
    async fn h2_stream_pair() -> (H2Stream, tokio::task::AbortHandle) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_task = tokio::spawn(async move {
            let (sender, conn) = h2::client::handshake(client_io)
                .await
                .expect("client handshake");
            tokio::spawn(async move {
                let mut conn = conn;
                let _ = (&mut conn).await;
            });
            sender
        });
        let mut server = h2::server::Builder::new()
            .initial_window_size(1) // 1-byte stream window: slow peer by construction
            .handshake::<_, Bytes>(server_io)
            .await
            .expect("server handshake");
        let mut sender = client_task.await.expect("client task");
        let request = http::Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/stream")
            .body(())
            .unwrap();
        let (resp_fut, send) = sender.send_request(request, false).expect("send_request");
        let (req, mut respond) = server
            .accept()
            .await
            .expect("accept Some")
            .expect("accept Ok");
        let response = http::Response::builder().status(200).body(()).unwrap();
        let _server_send = respond
            .send_response(response, false)
            .expect("send_response");
        let body = req.into_body();
        let driver = tokio::spawn(async move {
            let mut server = server;
            // The slow peer: hold the request body and never poll it. Dropping
            // it would auto-release the recv capacity (h2 sends a
            // WINDOW_UPDATE on drop) and unblock the client's sends.
            let _held_body = body;
            while let Some(accepted) = server.accept().await {
                let _ = accepted;
            }
        });
        // The driver must run before awaiting the response, or the queued
        // 200 HEADERS never reach the client and this await hangs forever.
        let client_recv = resp_fut.await.expect("response").into_body();
        let stream = H2Stream {
            send,
            recv: client_recv,
            fragment: None,
            pending: Vec::new(),
            driver: driver.abort_handle(),
        };
        (stream, driver.abort_handle())
    }

    #[tokio::test]
    async fn h2_write_is_window_bounded_not_unbounded() {
        use tokio::io::AsyncWriteExt;
        let (mut stream, _server_driver) =
            tokio::time::timeout(std::time::Duration::from_secs(5), h2_stream_pair())
                .await
                .expect("pair built");
        // The server's stream window starts at 1 byte and it never releases
        // capacity. The first write must complete bounded by the assigned
        // capacity, NOT with the full 4096 buffered into h2.
        let big = vec![0x42u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.write(&big))
            .await
            .expect("first write resolves against the 1-byte window")
            .expect("first write is capacity-capped");
        assert!(
            n <= 1,
            "write must be bounded by the server's 1-byte window (sent {n})"
        );
        // Without the server releasing capacity, a second write must stay
        // pending: the pairing reserves then polls, so outstanding bytes are
        // bounded — an unbounded implementation would buffer all 4096 here.
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.write(&big)).await;
        assert!(
            second.is_err(),
            "write past exhausted window must await capacity, not buffer"
        );
    }

    // --- Fix 1: stop() must release the QUIC endpoint + UDP socket ---

    #[tokio::test]
    async fn stop_releases_the_bound_udp_port() {
        let (cert_der, key_der) = {
            let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("self-signed cert");
            (key.cert.der().to_vec(), key.signing_key.serialize_der())
        };
        let responder =
            test_support::QuinnResponder::spawn("127.0.0.1".parse().unwrap(), cert_der, key_der)
                .await
                .expect("quinn responder");
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-h3-own-0".into());
        cfg.fields.insert("alpn".into(), "h3".into());
        cfg.fields
            .insert("endpoint".into(), responder.addr.to_string());
        cfg.fields
            .insert("insecure_skip_verify".into(), "true".into());
        let hop = MasqueFactory
            .build(cfg, Arc::new(DirectCarrier))
            .await
            .expect("masque h3 establishes over loopback");

        // Discover the hop's actual local UDP port: dial a flow whose
        // `local_addr` is the client endpoint's bind address.
        let local = {
            let flow = hop
                .dialer()
                .dial_udp(responder.addr)
                .await
                .expect("dial_udp");
            flow.local_addr().expect("local addr")
        };
        assert_ne!(local.port(), 0, "endpoint bound an ephemeral port");

        hop.stop().await.expect("clean stop");
        // Drop every handle that keeps the quinn socket's Arc alive: the hop
        // (owning the endpoint) and the dialers' connection clones. The
        // `Arc::new(MasqueHop)` goes away with the local `hop` binding here.
        drop(hop);

        // The leak proof: a NEW bind on the same port must succeed once the
        // endpoint driver exits. Rebinds race the driver's drain, so poll
        // with a deadline instead of assuming a fixed delay.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let rebind = loop {
            match tokio::net::UdpSocket::bind(local).await {
                Ok(sock) => break Ok(sock),
                Err(e) if tokio::time::Instant::now() >= deadline => {
                    break Err(e);
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        match rebind {
            Ok(sock) => {
                let got = sock.local_addr().expect("rebind local addr");
                assert_eq!(got.port(), local.port(), "same port re-bound");
            }
            Err(e) => panic!(
                "stop() must release the UDP socket; rebind {} failed: {e}",
                local
            ),
        }
    }
}
