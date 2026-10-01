//! Single-hop bring-up in declared order (US1 T043).
//!
//! Hop 0 dials through the root carrier; each next hop dials through the
//! previous hop's dialer (carrier handoff). Multi-hop nesting/MTU lands in
//! T058; this module owns ordering, handoff, per-hop family reporting, and
//! fail-closed unwind (started hops are stopped reverse-order on failure, so
//! a failed start leaves zero partial state).

use crate::chain::Chain;
use crate::registry::TransportRegistry;
use crate::session::nest::{layer_mtu, PmtuProber};
use crate::session::net::{spawn_keepalive, KeepalivePolicy};
use qcore_transport_api::{
    Dialer, FailureLayer, FailureReport, HopErrorKind, HopEvent, RunningHop,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// One started hop plus the family in effect. `family` is resolved from the
/// hop's fixed endpoint when it has one, else the hop's configured family.
/// `via` names the incoming carrier ("root" or the carrier hop id);
/// `nested` is true when the carrier is encapsulated; `inner_mtu` is the
/// layered (PMTU-probed) MTU reported for this layer.
#[derive(Clone)]
pub struct StartedHop {
    pub hop_id: String,
    pub kind: String,
    pub family: String,
    pub endpoint: Option<String>,
    pub via: String,
    pub nested: bool,
    pub inner_mtu: u16,
    /// Active obfuscation profile name, if any (US5 T073 reporting).
    pub obfuscation: Option<String>,
    pub hop: Arc<dyn RunningHop>,
    /// Cumulative bus-lag drops observed by this hop's session forwarder
    /// (#12 observability hook): the per-hop event bus is bounded-drop, so a
    /// slow session consumer loses events as `Lagged(n)`. The forwarder
    /// counts them, re-emits the cumulative total as `HopEvent::Congested`,
    /// and shares the counter here so `hop_reports` surfaces it.
    pub congested_drops: Arc<std::sync::atomic::AtomicU64>,
    /// Keepalive watcher abort handle (`None` when keepalive is disabled).
    /// `AbortHandle` (not `JoinHandle`) so `StartedHop` stays `Clone`.
    /// Teardown (`unwind`, `SessionHandle::stop_all`) aborts before stopping
    /// the hop: dropping the handle would detach the task and leak it.
    /// Crate-internal (`pub(crate)`): teardown bookkeeping, not embedder
    /// API — future internal handles stay minor for the same reason.
    pub(crate) keepalive: Option<tokio::task::AbortHandle>,
    /// Per-hop event forwarder abort handle. Same ownership rule as keepalive:
    /// teardown aborts before stopping the hop, otherwise the forwarder blocks
    /// on `recv` forever holding the hop alive.
    pub(crate) forwarder: Option<tokio::task::AbortHandle>,
}

/// Per-hop material merged into factory configs at bring-up (in memory
/// only; chain > import > profile precedence, never persisted).
pub struct BringUpMaterials<'a> {
    /// US2 import material per hop id.
    pub imports: &'a std::collections::HashMap<String, crate::config::import::ImportMaterial>,
    /// US5 obfuscation applications per hop id.
    pub obfuscation:
        &'a std::collections::HashMap<String, crate::config::obfuscation::ObfApplication>,
    /// 002 identity material per hop id (stored identities + cached
    /// endpoints for warp/masque hops).
    pub identities:
        &'a std::collections::HashMap<String, crate::identity::inject::IdentityMaterial>,
}

/// Bring up every hop in declared order before `deadline`
/// (CONNECTION_TIMEOUT_SECONDS budget, enforced per hop and overall).
pub async fn bring_up(
    registry: &TransportRegistry,
    chain: &Chain,
    mut carrier: Arc<dyn Dialer>,
    events: &tokio::sync::broadcast::Sender<HopEvent>,
    keepalive: &KeepalivePolicy,
    deadline: Instant,
    materials: BringUpMaterials<'_>,
) -> Result<Vec<StartedHop>, FailureReport> {
    let mut started: Vec<StartedHop> = Vec::new();
    for (depth, spec) in chain.hops.iter().enumerate() {
        if Instant::now() >= deadline {
            unwind(&started).await;
            return Err(FailureReport::new(
                FailureLayer::Chain,
                spec.id.clone(),
                "hop bring-up exceeded the connection timeout budget before starting",
                "timeout",
            ));
        }
        let nested = carrier.nested_mtu().is_some();
        let via = if depth == 0 {
            "root".to_string()
        } else {
            started
                .last()
                .map(|s: &StartedHop| s.hop_id.clone())
                .unwrap_or_else(|| "root".to_string())
        };
        let mut prober = PmtuProber::new(layer_mtu(depth as u32));
        let kind = spec.config.kind();
        let Some(factory) = registry.factory(kind) else {
            unwind(&started).await;
            return Err(FailureReport::new(
                FailureLayer::Chain,
                spec.id.clone(),
                format!("transport `{kind}` is not registered"),
                "chain",
            ));
        };
        let mut fcfg = spec.config.to_factory_config();
        // Endpoint/family reporting reads this same snapshot: one
        // `to_factory_config` build per hop instead of four (the helpers
        // below each rebuilt it). Values are unchanged — the report
        // reflects authored config, not merged material.
        let endpoint = fcfg.get("endpoint").map(str::to_string);
        let family = match endpoint.as_deref().map(|ep| ep.parse::<SocketAddr>()) {
            Some(Ok(addr)) if addr.is_ipv4() => "ipv4".to_string(),
            Some(Ok(_)) => "ipv6".to_string(),
            _ => spec.config.family().to_string(),
        };
        fcfg.fields.insert("hop_id".into(), spec.id.clone());
        // US2: explicit chain values win; import material fills the rest.
        if let Some(material) = materials.imports.get(&spec.id) {
            for (k, v) in &material.fields {
                fcfg.fields.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        // 002: registered identity + cached endpoint material fills
        // whatever is still unset (endpoint/keys for warp hops, endpoint
        // for masque hops); chain and imports still win.
        if let Some(material) = materials.identities.get(&spec.id) {
            for (k, v) in &material.fields {
                fcfg.fields
                    .entry(k.clone())
                    .or_insert_with(|| v.as_str().to_string());
            }
        }
        // US5: profile params fill whatever is still unset; the active name
        // rides along for reporting.
        let active_obfuscation = materials.obfuscation.get(&spec.id).map(|a| {
            for (k, v) in &a.fields {
                fcfg.fields.entry(k.clone()).or_insert_with(|| v.clone());
            }
            a.profile.clone()
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        let hop = match tokio::time::timeout(remaining, factory.build(fcfg, carrier.clone())).await
        {
            Err(_) => {
                unwind(&started).await;
                return Err(FailureReport::new(
                    FailureLayer::Chain,
                    spec.id.clone(),
                    "hop bring-up exceeded the connection timeout budget",
                    "timeout",
                ));
            }
            Ok(Err(e)) => {
                unwind(&started).await;
                return Err(to_report(&spec.id, e, nested, &mut prober));
            }
            Ok(Ok(hop)) => {
                prober.report_success();
                hop
            }
        };
        // Fan hop events into the session bus (push, not poll). The per-hop
        // bus is bounded-drop (#12): a slow session consumer loses bursts as
        // `Lagged(n)`. Lag is counted per hop and re-emitted as `Congested`
        // carrying the cumulative total, so loss is observable even when the
        // session bus itself drops the re-emission. Only `Closed` ends the
        // forwarder.
        let mut rx = hop.events();
        let tx = events.clone();
        let forwarder_drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let forwarder_hop_id = spec.id.clone();
        let forwarder_abort = {
            let forwarder_drops = forwarder_drops.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(e) => {
                            if tx.send(e).is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            let total = forwarder_drops
                                .fetch_add(n, std::sync::atomic::Ordering::Relaxed)
                                + n;
                            let _ = tx.send(HopEvent::Congested {
                                hop_id: forwarder_hop_id.clone(),
                                dropped: total,
                            });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
            .abort_handle()
        };
        let keepalive_abort = if keepalive.enabled {
            Some(
                spawn_keepalive(
                    spec.id.clone(),
                    hop.clone(),
                    keepalive.clone(),
                    events.clone(),
                )
                .abort_handle(),
            )
        } else {
            None
        };
        let _ = events.send(HopEvent::EndpointSelected {
            hop_id: spec.id.clone(),
            endpoint: endpoint.clone().unwrap_or_else(|| family.clone()),
        });
        carrier = hop.dialer();
        started.push(StartedHop {
            hop_id: spec.id.clone(),
            kind: kind.to_string(),
            family,
            endpoint,
            via,
            nested,
            inner_mtu: prober.current_mtu(),
            obfuscation: active_obfuscation,
            hop,
            congested_drops: forwarder_drops,
            keepalive: keepalive_abort,
            forwarder: Some(forwarder_abort),
        });
    }
    Ok(started)
}

/// Stop started hops reverse-order, best effort (unwind path). Each hop's
/// keepalive watcher and event forwarder are aborted before its hop stops:
/// aborting is the only stop signal (a missing bus receiver must NOT kill the
/// watcher — receivers attach transiently), and dropping the handle would
/// detach.
async fn unwind(started: &[StartedHop]) {
    for s in started.iter().rev() {
        if let Some(keepalive) = &s.keepalive {
            keepalive.abort();
        }
        if let Some(forwarder) = &s.forwarder {
            forwarder.abort();
        }
        let _ = s.hop.stop().await;
    }
}

/// Map a factory build error to a layer + hop-naming report. Nested
/// timeout/IO failures decay the PMTU prober and the decay is reported.
fn to_report(
    hop_id: &str,
    e: qcore_transport_api::HopError,
    nested: bool,
    prober: &mut PmtuProber,
) -> FailureReport {
    let layer = match e.kind {
        HopErrorKind::Validation => FailureLayer::Validation,
        HopErrorKind::Sidecar => FailureLayer::Sidecar,
        HopErrorKind::Transport | HopErrorKind::Timeout | HopErrorKind::Io => {
            FailureLayer::Transport
        }
        HopErrorKind::Chain => FailureLayer::Chain,
        HopErrorKind::Scan => FailureLayer::Scan,
        HopErrorKind::Config | HopErrorKind::Shutdown => FailureLayer::Config,
    };
    let kind = format!("{:?}", e.kind).to_lowercase();
    let mut cause = e.message;
    if nested
        && matches!(
            e.kind,
            HopErrorKind::Timeout | HopErrorKind::Io | HopErrorKind::Transport
        )
    {
        if let Some(mtu) = prober.report_loss() {
            cause.push_str(&format!(" (path MTU probed down to {mtu})"));
        }
    }
    FailureReport::new(layer, hop_id, cause, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_transport_api::{
        ByteStream, Capabilities, HopError, HopHealth, TransportDescriptor, UdpFlow,
    };

    struct StubDialer;

    #[async_trait::async_trait]
    impl Dialer for StubDialer {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::validation("unused in keepalive test"))
        }
        async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::validation("unused in keepalive test"))
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: false,
                accepts_udp_carrier: false,
                dials_tcp: false,
                dials_udp: false,
            }
        }
    }

    static STUB_DESCRIPTOR: TransportDescriptor = TransportDescriptor {
        kind: "stub",
        capabilities: Capabilities {
            accepts_tcp_carrier: false,
            accepts_udp_carrier: false,
            dials_tcp: false,
            dials_udp: false,
        },
        obfuscation_families: &[],
        config_schema: "stub/v1",
        needs_sidecar: false,
    };

    /// Always-healthy hop: the keepalive watcher never exits on its own, so
    /// a finished watcher proves the owner aborted it (dropping the
    /// JoinHandle would detach and the task would linger).
    struct StubHop {
        events: tokio::sync::broadcast::Sender<HopEvent>,
    }

    #[async_trait::async_trait]
    impl RunningHop for StubHop {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &STUB_DESCRIPTOR
        }
        fn dialer(&self) -> Arc<dyn Dialer> {
            Arc::new(StubDialer)
        }
        fn health(&self) -> HopHealth {
            HopHealth::Healthy
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
            self.events.subscribe()
        }
        async fn stop(&self) -> Result<(), HopError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn unwind_aborts_keepalive_watchers() {
        let hop: Arc<dyn RunningHop> = Arc::new(StubHop {
            events: tokio::sync::broadcast::channel(16).0,
        });
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let handle = spawn_keepalive(
            "h0".into(),
            hop.clone(),
            KeepalivePolicy {
                enabled: true,
                interval_secs: 3600,
            },
            tx,
        );
        let abort = handle.abort_handle();
        let started = vec![StartedHop {
            hop_id: "h0".into(),
            kind: "stub".into(),
            family: "ipv4".into(),
            endpoint: None,
            via: "root".into(),
            nested: false,
            inner_mtu: 1500,
            obfuscation: None,
            hop,
            congested_drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            keepalive: Some(handle.abort_handle()),
            forwarder: None,
        }];
        assert!(!abort.is_finished());
        unwind(&started).await;
        // Abort delivery needs a scheduler pass; bound the wait instead of
        // sleeping (no wall-clock dependence).
        let mut finished = false;
        for _ in 0..100 {
            if abort.is_finished() {
                finished = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(finished, "keepalive watcher survived unwind");
    }
}
