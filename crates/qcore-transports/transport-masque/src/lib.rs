//! MASQUE transport over a single QUIC provider (T040, research R4 outcome).
//!
//! - `alpn=h3`: real QUIC (quinn + rustls/ring) with ALPN `h3`; TCP egress
//!   rides native QUIC bidirectional streams, UDP egress rides QUIC DATAGRAM
//!   frames with a dst-prefix. The client connection sends QUIC keep-alives
//!   every 15 s so NATed idle paths do not die under green health.
//! - `alpn=h2`: HTTP/2 over TCP (h2 crate, prior knowledge); egress rides
//!   per-dial POST streams, datagrams length-prefixed on a dedicated stream.
//!   H2 sends (streams and datagrams alike) are flow-window-bounded
//!   (`reserve_capacity` then `poll_capacity`) so a fast writer cannot
//!   buffer unboundedly inside h2.
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
        let alpn = match cfg.get("alpn").unwrap_or("h3") {
            "h3" => Alpn::H3,
            "h2" => Alpn::H2,
            other => {
                return Err(HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id),
                    format!("unknown masque alpn `{other}` (h3|h2)"),
                ));
            }
        };
        let family = Family::parse(cfg.get("family").unwrap_or("dual"), &hop_id)?;
        // The H2 arm is plain TCP with no TLS layer: `server_name` and a
        // `insecure_skip_verify=true` are h3-only knobs, and honoring them on
        // h2 would validate then silently drop a security-affecting flag.
        // Reject before the resolve: a statically impossible config must not
        // pay for (or depend on) a DNS lookup. `false` is a documented no-op
        // on h2 — there is no verification to skip.
        if alpn == Alpn::H2 {
            if cfg.get("server_name").is_some() {
                return Err(HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id),
                    "`server_name` requires alpn=h3 (alpn=h2 has no TLS layer)".to_string(),
                ));
            }
            if cfg.get("insecure_skip_verify") == Some("true") {
                return Err(HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id),
                    "`insecure_skip_verify=true` requires alpn=h3 (alpn=h2 has no TLS layer)"
                        .to_string(),
                ));
            }
        }
        // `build` is async, so hostnames resolve here (same policy as
        // transport-wireguard's `resolve_endpoint`): IP literals parse
        // synchronously, names go through `lookup_host` with a timeout, and
        // every failure is a Config error naming the field — never a chain
        // that cannot run.
        let endpoint = resolve_endpoint(&hop_id, cfg.get("endpoint"), family).await?;
        let server_name = resolve_server_name(&hop_id, cfg.get("server_name"), &endpoint.host)?;
        // Strict at the transport boundary too: the factory compares against
        // the canonical spelling, so anything else must fail closed naming the
        // field instead of silently reading as "not true".
        let insecure = match cfg.get("insecure_skip_verify") {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                return Err(HopError::new(
                    HopErrorKind::Config,
                    Some(hop_id),
                    format!("bad `insecure_skip_verify` `{other}` (true|false)"),
                ));
            }
        };
        let fragment = obfuscate::fragment_size(&cfg)?;
        // Try each resolved address in order; the first successful bring-up
        // wins. Dual-stack names (`localhost` → `::1` + `127.0.0.1`) are
        // platform-ordered, so one address must not be picked upfront — that
        // silently broke IPv4-only peers on linux (the CI dry-run failure).
        // One overall [`BUILD_BUDGET`] deadline caps the whole loop: a
        // per-address floor may exceed the total for a long address list, and
        // without the cap the engine's connection budget cancels mid-attempt,
        // losing the aggregated cause.
        let overall_deadline = tokio::time::Instant::now() + BUILD_BUDGET;
        let budget = attempt_budget(BUILD_BUDGET, endpoint.addrs.len());
        try_endpoints(
            &hop_id,
            alpn.as_str(),
            endpoint.addrs,
            overall_deadline,
            budget,
            |addr, deadline| {
                let hop_id = hop_id.clone();
                let carrier = carrier.clone();
                let server_name = server_name.clone();
                async move {
                    match alpn {
                        Alpn::H3 => {
                            MasqueHop::bring_up_h3(
                                hop_id,
                                addr,
                                &server_name,
                                insecure,
                                carrier,
                                deadline,
                            )
                            .await
                        }
                        Alpn::H2 => {
                            MasqueHop::bring_up_h2(hop_id, addr, carrier, fragment, deadline).await
                        }
                    }
                }
            },
        )
        .await
    }
}

/// Try each resolved address in order until one brings up a hop. The loop
/// shares one [`BUILD_BUDGET`] deadline: an attempt gets
/// `min(its share, time remaining)`, and once the overall budget is spent the
/// remaining addresses are not attempted (letting the engine cancel mid-way
/// would lose the aggregate). Every attempted address's failure is kept in
/// the returned error.
async fn try_endpoints<F, Fut>(
    hop_id: &str,
    alpn: &'static str,
    addrs: Vec<SocketAddr>,
    overall_deadline: tokio::time::Instant,
    budget: std::time::Duration,
    mut attempt: F,
) -> Result<Arc<dyn RunningHop>, HopError>
where
    F: FnMut(SocketAddr, tokio::time::Instant) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<dyn RunningHop>, HopError>>,
{
    let total = addrs.len();
    let mut failures: Vec<String> = Vec::new();
    let mut attempted = 0usize;
    for addr in addrs {
        let Some(deadline) =
            attempt_deadline(tokio::time::Instant::now(), budget, overall_deadline)
        else {
            break;
        };
        attempted += 1;
        match attempt(addr, deadline).await {
            Ok(hop) => return Ok(hop),
            Err(e) => failures.push(format!("{addr}: {}", e.message)),
        }
    }
    let detail = if attempted == total {
        format!("every resolved endpoint ({})", failures.join("; "))
    } else {
        format!(
            "{attempted} of {total} resolved endpoints before the build budget expired ({}); the rest were not attempted",
            failures.join("; ")
        )
    };
    Err(HopError::new(
        HopErrorKind::Transport,
        Some(hop_id.to_string()),
        format!("masque {alpn} bring-up failed on {detail}"),
    ))
}

/// Per-attempt deadline: the attempt's share of the build window, capped by
/// the overall deadline. `None` means the overall budget is spent — stop
/// trying addresses instead of letting the engine cancel mid-attempt.
fn attempt_deadline(
    now: tokio::time::Instant,
    budget: std::time::Duration,
    overall: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    if now >= overall {
        None
    } else {
        Some((now + budget).min(overall))
    }
}

/// QUIC/TCP bring-up protocol, resolved from the `alpn` field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Alpn {
    H3,
    H2,
}

impl Alpn {
    fn as_str(self) -> &'static str {
        match self {
            Alpn::H3 => "h3",
            Alpn::H2 => "h2",
        }
    }
}

/// Total bring-up budget for one hop build, divided across the resolved
/// endpoint addresses (the engine's 30 s connection budget is the outer
/// bound).
const BUILD_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Floor for one endpoint attempt's share of [`BUILD_BUDGET`]: a dual-stack
/// name must still leave a blackholed address enough time to be told apart
/// from a slow handshake.
const MIN_ATTEMPT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Divide `total` across `endpoints` attempts, floor-bounded by
/// [`MIN_ATTEMPT_BUDGET`] (a min-bound may exceed `total` for very long
/// address lists, which is the documented trade: never give an attempt an
/// unusably short window).
fn attempt_budget(total: std::time::Duration, endpoints: usize) -> std::time::Duration {
    let n = u32::try_from(endpoints.max(1)).unwrap_or(u32::MAX);
    (total / n).max(MIN_ATTEMPT_BUDGET)
}

/// Endpoint address family policy (`family=dual|ipv4|ipv6`). The core parse
/// gate rejects unknown values too; this is the transport boundary, so it
/// fails closed naming the field instead of silently treating a typo as
/// `dual`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Dual,
    Ipv4,
    Ipv6,
}

impl Family {
    fn parse(raw: &str, hop_id: &str) -> Result<Self, HopError> {
        match raw {
            "dual" => Ok(Family::Dual),
            "ipv4" => Ok(Family::Ipv4),
            "ipv6" => Ok(Family::Ipv6),
            other => Err(HopError::new(
                HopErrorKind::Config,
                Some(hop_id.to_string()),
                format!("unknown `family` value `{other}` (dual|ipv4|ipv6)"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Family::Dual => "dual",
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }

    fn accepts(self, addr: &SocketAddr) -> bool {
        match self {
            Family::Dual => true,
            Family::Ipv4 => addr.is_ipv4(),
            Family::Ipv6 => addr.is_ipv6(),
        }
    }
}

/// Timeout for the DNS resolution of a hostname `endpoint` (fails closed).
const ENDPOINT_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A resolved `endpoint`: every address to try, plus the host as written
/// (the default TLS server name for `alpn=h3` — a hostname endpoint must not
/// present an IP as SNI, and an IP literal must present the IP, never the
/// hardcoded `localhost` the pre-fix code sent against every real server).
#[derive(Debug)]
struct ResolvedEndpoint {
    addrs: Vec<SocketAddr>,
    host: String,
}

/// Resolve `endpoint=<ip:port|host:port>` into every address the name has
/// (a literal is a one-element list). Callers try the addresses in order —
/// "localhost" resolves to both `::1` and `127.0.0.1` and which one comes
/// first is platform-ordered, so a single-address pick silently breaks
/// dual-stack peers (the linux CI failure). `family` filters resolved
/// addresses like `transport-wireguard::modes::resolve_endpoint`; a filter
/// that leaves nothing fails closed naming the field. Fails closed with a
/// Config error naming the field.
async fn resolve_endpoint(
    hop_id: &str,
    raw: Option<&str>,
    family: Family,
) -> Result<ResolvedEndpoint, HopError> {
    let config_err =
        |msg: String| HopError::new(HopErrorKind::Config, Some(hop_id.to_string()), msg);
    let Some(s) = raw else {
        return Err(config_err(
            "masque hop requires endpoint=<ip:port>".to_string(),
        ));
    };
    if let Ok(addr) = s.parse::<SocketAddr>() {
        // The hostname arm has always rejected port 0; the literal arm
        // accepted it (finding 4). One gate for both.
        if addr.port() == 0 {
            return Err(config_err(
                "bad endpoint: port `0` is not connectable".to_string(),
            ));
        }
        // The literal arm returns before the resolver filter: an explicit
        // `family` that contradicts the literal must fail closed, not
        // silently connect over the stack the operator ruled out.
        if !family.accepts(&addr) {
            return Err(config_err(format!(
                "bad endpoint: no {} address for `{s}` (family={})",
                family.as_str(),
                family.as_str()
            )));
        }
        return Ok(ResolvedEndpoint {
            host: addr.ip().to_string(),
            addrs: vec![addr],
        });
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
    let mut addrs: Vec<SocketAddr> = lookup
        .map_err(|e| config_err(format!("bad endpoint: resolve `{host}`: {e}")))?
        .collect();
    addrs.retain(|a| family.accepts(a));
    if addrs.is_empty() {
        return Err(config_err(format!(
            "bad endpoint: no {} address for `{host}` (family={})",
            family.as_str(),
            family.as_str()
        )));
    }
    Ok(ResolvedEndpoint {
        addrs,
        host: host.to_string(),
    })
}

/// TLS server name for `alpn=h3`: the explicit `server_name` when set,
/// otherwise the endpoint host as written. Validated at the boundary so a
/// malformed name is a Config error naming the field, not a handshake
/// failure deep inside rustls.
fn resolve_server_name(
    hop_id: &str,
    explicit: Option<&str>,
    endpoint_host: &str,
) -> Result<String, HopError> {
    let Some(name) = explicit else {
        return Ok(endpoint_host.to_string());
    };
    rustls::pki_types::ServerName::try_from(name).map_err(|e| {
        HopError::new(
            HopErrorKind::Config,
            Some(hop_id.to_string()),
            format!("bad `server_name` `{name}`: {e}"),
        )
    })?;
    Ok(name.to_string())
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
        server_name: &str,
        insecure: bool,
        carrier: Arc<dyn Dialer>,
        deadline: tokio::time::Instant,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        let mut endpoint_builder = quinn::Endpoint::client(unspecified_bind(&endpoint))
            .map_err(|e| HopError::transport(hop_id.clone(), format!("quinn bind: {e}")))?;
        endpoint_builder.set_default_client_config(client_config(insecure)?);
        let local = endpoint_builder
            .local_addr()
            .map_err(|e| HopError::transport(hop_id.clone(), format!("quinn local: {e}")))?;
        let connecting = endpoint_builder
            .connect(endpoint, server_name)
            .map_err(|e| {
                HopError::transport(hop_id.clone(), format!("masque QUIC connect: {e}"))
            })?;
        let conn = tokio::time::timeout_at(deadline, connecting)
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
        deadline: tokio::time::Instant,
    ) -> Result<Arc<dyn RunningHop>, HopError> {
        // Nested uplink (T058): an encapsulated carrier drives H2 over a
        // carrier TCP stream; a direct carrier keeps the OS TCP socket.
        // Against a framing-unaware far end the nested handshake fails closed.
        let nested = carrier.nested_mtu().is_some();
        // The bring-up sender is dropped: per-dial H2 egress opens a fresh
        // connection (see H2DialerRef); the driver task keeps the conn alive.
        let (_, task, local) = if nested {
            let stream = tokio::time::timeout_at(deadline, carrier.dial_tcp(endpoint))
                .await
                .map_err(|_| {
                    HopError::transport(
                        hop_id.clone(),
                        format!(
                            "nested uplink via carrier: masque H2 connect to {endpoint} timed out"
                        ),
                    )
                })?
                .map_err(|e| {
                    HopError::transport(
                        hop_id.clone(),
                        format!("nested uplink via carrier: {}", e.message),
                    )
                })?;
            let (sender, conn) =
                tokio::time::timeout_at(deadline, h2::client::handshake(stream))
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
            let tcp = tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(endpoint))
                .await
                .map_err(|_| {
                    HopError::transport(
                        hop_id.clone(),
                        format!(
                            "masque H2 connect to {endpoint} timed out (unreachable transport)"
                        ),
                    )
                })?
                .map_err(|e| HopError::transport(hop_id.clone(), format!("masque H2 TCP: {e}")))?;
            let local = tcp
                .local_addr()
                .map_err(|e| HopError::transport(hop_id.clone(), format!("h2 local: {e}")))?;
            let (sender, conn) = tokio::time::timeout_at(deadline, h2::client::handshake(tcp))
                .await
                .map_err(|_| {
                    HopError::transport(
                        hop_id.clone(),
                        format!(
                            "masque H2 handshake to {endpoint} timed out (unreachable transport)"
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

/// Window-bounded H2 datagram send: reserve capacity for the next chunk,
/// await the assignment, then hand h2 no more than that assignment — the
/// same reserve→poll→send pairing as `H2Stream::poll_write`. `send_data`
/// without a reservation buffers the frame unboundedly inside h2 while the
/// window is closed (h2's own docs say so), so `send_to` returned `Ok` and
/// the WireGuard pump's wedge timeout never saw a wedged peer. A frame may
/// span several DATA frames — `recv_from` reassembles from the
/// length-prefixed byte stream — so each piece is capped by the assigned
/// window instead of the whole frame being buffered.
async fn send_frame_bounded(
    send: &mut h2::SendStream<Bytes>,
    frame: &[u8],
    hop_id: &str,
) -> Result<(), HopError> {
    /// Largest chunk per iteration: one h2 max DATA frame.
    const CHUNK: usize = 16384;
    let mut off = 0;
    while off < frame.len() {
        let want = (frame.len() - off).min(CHUNK);
        // Reserve FIRST: capacity is only assigned in response to a
        // reservation, so polling without reserving parks forever.
        send.reserve_capacity(want);
        let assigned = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                send.reserve_capacity(0);
                return Err(HopError::transport(hop_id, format!("datagram send: {e}")));
            }
            // `None`: the stream is no longer streaming (closed/reset).
            None => {
                send.reserve_capacity(0);
                return Err(HopError::transport(hop_id, "datagram stream closed"));
            }
        };
        // Never exceed the assignment: h2 decrements the reservation as data
        // is sent, so a larger send would over-buffer (the bug this fixes).
        let n = want.min(assigned);
        send.send_data(Bytes::copy_from_slice(&frame[off..off + n]), false)
            .map_err(|e| {
                send.reserve_capacity(0);
                HopError::transport(hop_id, format!("datagram send: {e}"))
            })?;
        off += n;
    }
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
        // `UdpFlow::send_to` is async, so the window wait is awaited here
        // rather than handed to h2's unbounded internal buffer.
        let mut send = self.send.lock().await;
        send_frame_bounded(&mut send, &frame, &self.hop_id).await
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

    /// Finding 4: the hostname arm always rejected port 0; the literal arm
    /// accepted it and only failed later inside connect. One gate now.
    #[tokio::test]
    async fn literal_endpoint_port_zero_fails_closed() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-p0-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert("endpoint".into(), "127.0.0.1:0".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("literal port 0 must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config, "Config, not connect: {err}");
        assert!(err.message.contains("endpoint"), "names field: {err}");
        assert!(err.message.contains("port `0`"), "names port: {err}");
    }

    // --- Finding 5: family is honoured at the transport boundary ---

    #[test]
    fn family_filter_selects_one_family() {
        let v4: SocketAddr = "127.0.0.1:443".parse().expect("static literal");
        let v6: SocketAddr = "[::1]:443".parse().expect("static literal");
        assert!(Family::Dual.accepts(&v4) && Family::Dual.accepts(&v6));
        assert!(Family::Ipv4.accepts(&v4) && !Family::Ipv4.accepts(&v6));
        assert!(Family::Ipv6.accepts(&v6) && !Family::Ipv6.accepts(&v4));
    }

    #[test]
    fn unknown_family_is_a_config_error_naming_the_field() {
        let err = Family::parse("v4", "masque-fam-0").expect_err("unknown family");
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(err.message.contains("family"), "names field: {err}");
        assert!(err.message.contains("v4"), "names value: {err}");
    }

    /// Family filtering applies to literals too: the literal arm returns
    /// before the resolver filter, so `family=ipv6` with an IPv4 literal used
    /// to connect over IPv4 anyway.
    #[tokio::test]
    async fn literal_endpoint_family_mismatch_fails_closed() {
        let err = resolve_endpoint("masque-fam-lit-0", Some("127.0.0.1:443"), Family::Ipv6)
            .await
            .expect_err("v4 literal under family=ipv6");
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(err.message.contains("family=ipv6"), "names value: {err}");
    }

    /// `family=ipv6` must filter the resolved IPv4 address out instead of
    /// silently falling back to it: the responder listens on 127.0.0.1 only,
    /// so pre-fix (family ignored) the build connected anyway.
    #[tokio::test]
    async fn family_ipv6_never_falls_back_to_the_ipv4_responder() {
        let responder =
            test_support::H2Responder::spawn("127.0.0.1".parse().expect("static literal"))
                .await
                .expect("h2 responder");
        let endpoint = format!("localhost:{}", responder.addr.port());

        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-v4-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert("endpoint".into(), endpoint.clone());
        cfg.fields.insert("family".into(), "ipv4".into());
        let hop = MasqueFactory
            .build(cfg, Arc::new(DirectCarrier))
            .await
            .expect("family=ipv4 keeps the ipv4 address");
        hop.stop().await.expect("clean stop");

        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-v6-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert("endpoint".into(), endpoint);
        cfg.fields.insert("family".into(), "ipv6".into());
        let err = match MasqueFactory.build(cfg, Arc::new(DirectCarrier)).await {
            Ok(_) => panic!("family=ipv6 must not reach the ipv4 responder"),
            Err(e) => e,
        };
        assert!(
            !err.message.contains("127.0.0.1"),
            "the filtered ipv4 address must never be attempted: {err}"
        );
    }

    // --- Finding 3: per-address budget + aggregated failures ---

    #[test]
    fn build_budget_is_divided_and_floor_bounded() {
        assert_eq!(attempt_budget(BUILD_BUDGET, 1), BUILD_BUDGET);
        assert_eq!(
            attempt_budget(BUILD_BUDGET, 2),
            std::time::Duration::from_secs(15)
        );
        // A name with many addresses may exceed the total (floor-bounded by
        // design), but one attempt never gets the whole build window.
        assert_eq!(attempt_budget(BUILD_BUDGET, 100), MIN_ATTEMPT_BUDGET);
        assert!(
            attempt_budget(BUILD_BUDGET, 2) < BUILD_BUDGET,
            "fallback addresses share the window"
        );
    }

    /// Every per-address failure must survive into the final error — pre-fix
    /// only the last attempt's message was reported, hiding the cause that
    /// mattered (usually the first, platform-ordered address).
    #[tokio::test]
    async fn endpoint_failures_are_aggregated_not_last_only() {
        let resolved = resolve_endpoint("masque-agg-0", Some("localhost:1"), Family::Dual)
            .await
            .expect("localhost resolves offline");
        assert!(!resolved.addrs.is_empty(), "localhost has an address");
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-agg-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert("endpoint".into(), "localhost:1".into());
        let build = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            MasqueFactory.build(cfg, Arc::new(DirectCarrier)),
        )
        .await
        .expect("closed loopback ports refuse fast");
        let err = match build {
            Ok(_) => panic!("nothing listens on localhost:1"),
            Err(e) => e,
        };
        assert!(
            err.message.contains("every resolved endpoint"),
            "aggregate marker: {err}"
        );
        for addr in &resolved.addrs {
            assert!(
                err.message.contains(&addr.to_string()),
                "keeps the failure for {addr}: {err}"
            );
        }
    }

    /// The per-address floor (5 s) exceeds the total budget for a long
    /// address list, so the loop needs one overall deadline: attempts stop
    /// once it is spent and the error aggregates only what was attempted.
    #[tokio::test]
    async fn build_budget_caps_the_whole_attempt_loop() {
        let addrs: Vec<SocketAddr> = (1..=8)
            .map(|i| {
                format!("127.0.0.1:{i}")
                    .parse()
                    .expect("static loopback literal")
            })
            .collect();
        let overall = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
        let started = tokio::time::Instant::now();
        let err = match try_endpoints(
            "masque-budget-0",
            "h2",
            addrs,
            overall,
            std::time::Duration::from_secs(5),
            |addr, deadline| async move {
                // Burn the whole attempt window, as a blackholed address does.
                tokio::time::sleep_until(deadline).await;
                Err(HopError::transport(
                    "masque-budget-0",
                    format!("blackholed {addr}"),
                ))
            },
        )
        .await
        {
            Ok(_) => panic!("nothing succeeds"),
            Err(e) => e,
        };
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "loop must stop at the overall deadline, took {:?}",
            started.elapsed()
        );
        assert!(
            err.message.contains("1 of 8 resolved endpoints"),
            "stops after the attempted address: {err}"
        );
        assert!(
            err.message.contains("127.0.0.1:1"),
            "aggregates the attempted address: {err}"
        );
        assert!(
            !err.message.contains("127.0.0.1:2"),
            "never claims an unattempted address: {err}"
        );
    }

    // --- Fix 4: h2 writes are flow-window bounded (reserve THEN poll) ---

    /// Real h2 pair whose server peer keeps a 1-byte stream window and never
    /// polls the request body, so it never releases inbound capacity. Returns
    /// the client send/recv halves plus the server driver's abort handle (the
    /// test owns it so the connection is reaped with the test).
    async fn h2_stalled_pair() -> (
        h2::SendStream<Bytes>,
        h2::RecvStream,
        tokio::task::AbortHandle,
    ) {
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
        (send, client_recv, driver.abort_handle())
    }

    async fn h2_stream_pair() -> (H2Stream, tokio::task::AbortHandle) {
        let (send, recv, driver) = h2_stalled_pair().await;
        (
            H2Stream {
                send,
                recv,
                fragment: None,
                pending: Vec::new(),
                driver: driver.clone(),
            },
            driver,
        )
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

    /// `H2Dgrams::send_to` must obey the same window bound as `H2Stream`:
    /// the datagram's whole length-prefixed frame pre-fix went into
    /// `send_data` with no reservation, so h2 buffered it unboundedly and
    /// `send_to` returned `Ok` on a peer that had granted one byte — the
    /// WireGuard pump's wedge guard only sees a `send_to` that actually
    /// waits. Post-fix the send stays parked until the window reopens.
    #[tokio::test]
    async fn h2_datagram_send_is_window_bounded_not_unbounded() {
        let dst: SocketAddr = "127.0.0.1:9".parse().expect("static literal");
        let (send, recv, driver) =
            tokio::time::timeout(std::time::Duration::from_secs(5), h2_stalled_pair())
                .await
                .expect("pair built");
        let local: SocketAddr = "127.0.0.1:0".parse().expect("static literal");
        let flow = H2Dgrams {
            hop_id: "masque-h2-dg-0".into(),
            send: tokio::sync::Mutex::new(send),
            recv: tokio::sync::Mutex::new(recv),
            pending: tokio::sync::Mutex::new(Vec::new()),
            dst,
            local,
            driver,
        };
        // 12-byte frame (4-byte length prefix + 8-byte payload) against the
        // server's 1-byte window.
        let sent = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            flow.send_to(b"12345678", dst),
        )
        .await;
        assert!(
            sent.is_err(),
            "send_to past a 1-byte window must await capacity, not buffer the frame"
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

    // --- Finding 7: the h3 TLS server name is the endpoint host / configured
    //     `server_name`, never the hardcoded `localhost` ---

    fn self_signed(subject: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::generate_simple_self_signed(vec![subject.to_string()])
            .expect("self-signed cert");
        (key.cert.der().to_vec(), key.signing_key.serialize_der())
    }

    /// The pre-fix connect hardcoded `localhost` as the TLS server name, so
    /// against a real server (whose certificate/SNI gate names its own host)
    /// verified TLS could not succeed. The explicit `server_name` wins; the
    /// default is the endpoint host, which for an IP literal means no SNI at
    /// all (RFC 6066) — never the old hardcoded `localhost`.
    #[tokio::test]
    async fn h3_server_name_reaches_the_wire() {
        let (cert_der, key_der) = self_signed("masque.test");
        let responder = test_support::QuinnResponder::spawn_requiring_sni(
            "127.0.0.1".parse().expect("static literal"),
            cert_der.clone(),
            key_der.clone(),
            "masque.test",
        )
        .await
        .expect("sni-gated responder");

        // Explicit override wins over the literal endpoint's IP.
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-sni-0".into());
        cfg.fields.insert("alpn".into(), "h3".into());
        cfg.fields
            .insert("endpoint".into(), responder.addr.to_string());
        cfg.fields
            .insert("insecure_skip_verify".into(), "true".into());
        cfg.fields
            .insert("server_name".into(), "masque.test".into());
        let hop = MasqueFactory
            .build(cfg, Arc::new(DirectCarrier))
            .await
            .expect("server_name reaches the peer as SNI");
        assert_eq!(hop.health(), HopHealth::Healthy);
        hop.stop().await.expect("clean stop");

        // Omitted: the endpoint host is the default server name. An IP
        // literal is a name too (`ServerName::IpAddress`), and rustls sends
        // no SNI for it — a gate that requires SNI to be absent is what tells
        // this apart from the old `localhost`.
        let no_sni = test_support::QuinnResponder::spawn_requiring_no_sni(
            "127.0.0.1".parse().expect("static literal"),
            cert_der,
            key_der,
        )
        .await
        .expect("no-sni-gated responder");
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-sni-1".into());
        cfg.fields.insert("alpn".into(), "h3".into());
        cfg.fields
            .insert("endpoint".into(), no_sni.addr.to_string());
        cfg.fields
            .insert("insecure_skip_verify".into(), "true".into());
        let hop = MasqueFactory
            .build(cfg, Arc::new(DirectCarrier))
            .await
            .expect("an IP endpoint default sends no SNI, not `localhost`");
        assert_eq!(hop.health(), HopHealth::Healthy);
        hop.stop().await.expect("clean stop");
    }

    #[tokio::test]
    async fn malformed_server_name_fails_closed_naming_the_field() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-sni-2".into());
        cfg.fields.insert("alpn".into(), "h3".into());
        cfg.fields.insert("endpoint".into(), "127.0.0.1:443".into());
        cfg.fields.insert("server_name".into(), "not a name".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("malformed server_name must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(err.message.contains("server_name"), "names field: {err}");
    }

    // --- h2 has no TLS layer: server_name / insecure_skip_verify are
    //     h3-only knobs and must fail closed on an h2 hop instead of
    //     validating then silently doing nothing ---

    #[tokio::test]
    async fn h2_hop_rejects_server_name_naming_field_and_alpn() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-h2-tls-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert("endpoint".into(), "127.0.0.1:443".into());
        cfg.fields
            .insert("server_name".into(), "masque.test".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("server_name on alpn=h2 must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(err.message.contains("server_name"), "names field: {err}");
        assert!(err.message.contains("alpn=h3"), "names remedy: {err}");
    }

    #[tokio::test]
    async fn h2_hop_rejects_insecure_skip_verify_naming_field_and_alpn() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-h2-tls-1".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields.insert("endpoint".into(), "127.0.0.1:443".into());
        cfg.fields
            .insert("insecure_skip_verify".into(), "true".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("insecure_skip_verify on alpn=h2 must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(
            err.message.contains("insecure_skip_verify"),
            "names field: {err}"
        );
        assert!(err.message.contains("alpn=h3"), "names remedy: {err}");
    }

    /// Only `true` is security-affecting on h2 (there is no TLS layer to
    /// skip); `false` is a documented no-op and must build, not fail parse.
    #[tokio::test]
    async fn h2_hop_allows_insecure_skip_verify_false_as_noop() {
        let responder =
            test_support::H2Responder::spawn("127.0.0.1".parse().expect("static literal"))
                .await
                .expect("h2 responder");
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-h2-tls-2".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields
            .insert("endpoint".into(), responder.addr.to_string());
        cfg.fields
            .insert("insecure_skip_verify".into(), "false".into());
        let hop = MasqueFactory
            .build(cfg, Arc::new(DirectCarrier))
            .await
            .expect("insecure_skip_verify=false is a no-op on h2");
        assert_eq!(hop.health(), HopHealth::Healthy);
        hop.stop().await.expect("clean stop");
    }

    /// The h2 TLS-knob rejection is statically decidable and must run before
    /// the endpoint resolve: pre-fix a bogus hostname paid the DNS lookup
    /// (up to the resolve timeout) before the Config error.
    #[tokio::test]
    async fn h2_rejects_tls_knobs_before_resolving_the_endpoint() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-order-0".into());
        cfg.fields.insert("alpn".into(), "h2".into());
        cfg.fields
            .insert("endpoint".into(), "bogus.invalid.example:443".into());
        cfg.fields
            .insert("server_name".into(), "masque.test".into());
        let err = match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            MasqueFactory.build(cfg, Arc::new(RefusingCarrier)),
        )
        .await
        .expect("rejected before the DNS resolve")
        {
            Ok(_) => panic!("server_name on alpn=h2 must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(err.message.contains("server_name"), "names field: {err}");
        assert!(
            !err.message.contains("endpoint"),
            "no resolve happened: {err}"
        );
    }

    #[tokio::test]
    async fn malformed_insecure_skip_verify_fails_closed_naming_the_field() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-sni-3".into());
        cfg.fields.insert("alpn".into(), "h3".into());
        cfg.fields.insert("endpoint".into(), "127.0.0.1:443".into());
        cfg.fields
            .insert("insecure_skip_verify".into(), "yes".into());
        let err = match MasqueFactory.build(cfg, Arc::new(RefusingCarrier)).await {
            Ok(_) => panic!("malformed insecure_skip_verify must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, HopErrorKind::Config);
        assert!(
            err.message.contains("insecure_skip_verify"),
            "names field: {err}"
        );
    }
}
