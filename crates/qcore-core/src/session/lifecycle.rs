//! Single-hop bring-up in declared order (US1 T043).
//!
//! Hop 0 dials through the root carrier; each next hop dials through the
//! previous hop's dialer (carrier handoff). Multi-hop nesting/MTU lands in
//! T058; this module owns ordering, handoff, per-hop family reporting, and
//! fail-closed unwind (started hops are stopped reverse-order on failure, so
//! a failed start leaves zero partial state).

use crate::chain::Chain;
use crate::registry::TransportRegistry;
use crate::session::nest::layer_mtu;
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
/// layered MTU reported for this layer.
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
        let inner_mtu = layer_mtu(depth as u32);
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
                return Err(to_report(&spec.id, e));
            }
            Ok(Ok(hop)) => hop,
        };
        // Fan hop events into the session bus (push, not poll). The per-hop
        // bus is bounded-drop (#12): a slow session consumer loses bursts as
        // `Lagged(n)`. Lag is counted per hop and re-emitted as `Congested`
        // carrying the cumulative total, so loss is observable even when the
        // session bus itself drops the re-emission. Only `Closed` ends the
        // forwarder.
        let forwarder_drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let forwarder_hop_id = spec.id.clone();
        let forwarder_abort = spawn_forwarder(
            hop.events(),
            events.clone(),
            forwarder_hop_id,
            forwarder_drops.clone(),
        );
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
            inner_mtu,
            obfuscation: active_obfuscation,
            hop,
            congested_drops: forwarder_drops,
            keepalive: keepalive_abort,
            forwarder: Some(forwarder_abort),
        });
    }
    Ok(started)
}

/// Per-hop event forwarder: pumps one hop's bus into the session bus.
/// Survives zero session receivers (the engine subscribes transiently);
/// only the hop bus closing ends it. Returns the abort handle for teardown.
fn spawn_forwarder(
    mut rx: tokio::sync::broadcast::Receiver<HopEvent>,
    tx: tokio::sync::broadcast::Sender<HopEvent>,
    hop_id: String,
    drops: Arc<std::sync::atomic::AtomicU64>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(e) => {
                    let _ = tx.send(e);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let total = drops.fetch_add(n, std::sync::atomic::Ordering::Relaxed) + n;
                    let _ = tx.send(HopEvent::Congested {
                        hop_id: hop_id.clone(),
                        dropped: total,
                    });
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
    .abort_handle()
}

/// Stop started hops reverse-order, best effort (unwind path). Abort all
/// watchers first, yield so aborts land, then stop hops: aborting is the only
/// stop signal for watcher tasks, and stopping the socket immediately used
/// to race the watcher into emitting a spurious post-stop `Failed`.
async fn unwind(started: &[StartedHop]) {
    for s in started.iter() {
        if let Some(keepalive) = &s.keepalive {
            keepalive.abort();
        }
        if let Some(forwarder) = &s.forwarder {
            forwarder.abort();
        }
    }
    // One scheduler pass so abort delivery wins over the socket close below
    // (transport `health()` racing `stop()` on another task is still the
    // transport's own contract to honor).
    tokio::task::yield_now().await;
    for s in started.iter().rev() {
        let _ = s.hop.stop().await;
    }
}

impl Drop for StartedHop {
    /// Last-resort task hygiene: abort watchers so a handle dropped without
    /// `stop_all()` does not linger tasks holding the hop alive. Socket and
    /// sidecar teardown still needs `stop()` (`stop_all`); Drop cannot await
    /// it, so this only stops the bleeding (fd/task growth per forgotten
    /// session), not the session itself.
    fn drop(&mut self) {
        if let Some(keepalive) = &self.keepalive {
            keepalive.abort();
        }
        if let Some(forwarder) = &self.forwarder {
            forwarder.abort();
        }
    }
}

/// Map a factory build error to a layer + hop-naming report. The layered
/// MTU already accounts for nesting depth; failures do not report a probe
/// step-down (a fresh bring-up has no probe history to decay).
fn to_report(hop_id: &str, e: qcore_transport_api::HopError) -> FailureReport {
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
    FailureReport::new(layer, hop_id, e.message, kind)
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

    #[tokio::test]
    async fn forwarder_survives_zero_receivers() {
        // No session subscriber yet (engine drops the initial handle): the
        // first event must not kill the forwarder — a late subscriber still
        // gets later events.
        let (hop_tx, _) = tokio::sync::broadcast::channel::<HopEvent>(16);
        let (sess_tx, _) = tokio::sync::broadcast::channel::<HopEvent>(16);
        let drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let abort = spawn_forwarder(hop_tx.subscribe(), sess_tx.clone(), "h0".into(), drops);
        hop_tx
            .send(HopEvent::Started {
                hop_id: "h0".into(),
            })
            .expect("hop bus sends");
        // Let the forwarder observe the zero-receiver send.
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(!abort.is_finished(), "forwarder died on zero receivers");
        // Late subscriber still receives subsequent events.
        let mut late = sess_tx.subscribe();
        hop_tx
            .send(HopEvent::Started {
                hop_id: "h0".into(),
            })
            .expect("hop bus sends");
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), late.recv())
            .await
            .expect("late event arrives")
            .expect("recv ok");
        assert!(matches!(got, HopEvent::Started { .. }), "{got:?}");
        abort.abort();
    }

    #[tokio::test]
    async fn dropped_handle_aborts_watchers() {
        // A StartedHop dropped without stop_all() must not linger tasks.
        let hop: Arc<dyn RunningHop> = Arc::new(StubHop {
            events: tokio::sync::broadcast::channel(16).0,
        });
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (hop_tx, _) = tokio::sync::broadcast::channel::<HopEvent>(16);
        let started = StartedHop {
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
            keepalive: Some(
                spawn_keepalive(
                    "h0".into(),
                    Arc::new(StubHop {
                        events: hop_tx.clone(),
                    }),
                    KeepalivePolicy {
                        enabled: true,
                        interval_secs: 3600,
                    },
                    tx,
                )
                .abort_handle(),
            ),
            forwarder: Some(spawn_forwarder(
                hop_tx.subscribe(),
                tokio::sync::broadcast::channel(16).0,
                "h0".into(),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            )),
        };
        let (ka, fw) = (
            started.keepalive.clone().expect("ka"),
            started.forwarder.clone().expect("fw"),
        );
        drop(started);
        let mut finished = false;
        for _ in 0..100 {
            if ka.is_finished() && fw.is_finished() {
                finished = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(finished, "dropped handle left watcher tasks behind");
    }

    // --- bring_up fail-closed unwind (FR-027): zero partial state on any
    // --- failure. The module doc claims "started hops are stopped
    // --- reverse-order on failure"; these tests pin that on every fail
    // --- path. Bring-up is exercised through the real `bring_up` fn with
    // --- test-double factories registered like the registry.rs tests do
    // --- (`register_plugin!`; nextest runs each test in its own process, so
    // --- the process-global stop counter and registry snapshot are test-
    // --- local by construction).

    /// Shared stop counter (process-global; see the block doc).
    static REC_STOPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn rec_stops() -> u64 {
        REC_STOPS.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Hop that counts `stop()` calls into [`REC_STOPS`].
    struct RecordingHop {
        events: tokio::sync::broadcast::Sender<HopEvent>,
    }

    #[async_trait::async_trait]
    impl RunningHop for RecordingHop {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &REC_DESCRIPTOR
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
            REC_STOPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Registry descriptor + factory for a "rec" (recording) kind.
    struct RecFactory;

    static REC_DESCRIPTOR: TransportDescriptor = TransportDescriptor {
        kind: "rec",
        capabilities: Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "rec/v1",
        needs_sidecar: false,
    };

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for RecFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &REC_DESCRIPTOR
        }
        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn RunningHop>, HopError> {
            let (tx, _) = tokio::sync::broadcast::channel(16);
            Ok(Arc::new(RecordingHop { events: tx }))
        }
    }

    static REC_FACTORY: RecFactory = RecFactory;

    qcore_transport_api::register_plugin!(&REC_FACTORY);

    /// Factory whose build fails closed immediately (named error).
    struct FailingBuildFactory;

    static FAIL_BUILD_DESCRIPTOR: TransportDescriptor = TransportDescriptor {
        kind: "fail-build",
        capabilities: Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "fail-build/v1",
        needs_sidecar: false,
    };

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for FailingBuildFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &FAIL_BUILD_DESCRIPTOR
        }
        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn RunningHop>, HopError> {
            Err(HopError::transport("boom-1", "sidecar exploded at build"))
        }
    }

    static FAIL_BUILD_FACTORY: FailingBuildFactory = FailingBuildFactory;

    qcore_transport_api::register_plugin!(&FAIL_BUILD_FACTORY);

    /// Factory whose build never resolves (the timeout path races it).
    struct PendingBuildFactory;

    static PENDING_BUILD_DESCRIPTOR: TransportDescriptor = TransportDescriptor {
        kind: "pending-build",
        capabilities: Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "pending-build/v1",
        needs_sidecar: false,
    };

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for PendingBuildFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &PENDING_BUILD_DESCRIPTOR
        }
        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn RunningHop>, HopError> {
            std::future::pending().await
        }
    }

    static PENDING_BUILD_FACTORY: PendingBuildFactory = PendingBuildFactory;

    qcore_transport_api::register_plugin!(&PENDING_BUILD_FACTORY);

    /// Registry for the doubles: `TransportRegistry::global()` already
    /// carries every `register_plugin!` submission compiled into this test
    /// binary (the pattern registry.rs tests use). "ghost" is genuinely
    /// unregistered for the unregistered-kind path.
    fn test_registry() -> TransportRegistry {
        TransportRegistry::global()
    }

    fn spec(kind: &str, id: &str) -> crate::config::HopSpec {
        // Test-double kinds are not builtin typed configs: ride the opaque
        // plugin shape (`to_factory_config` passes kind + family through).
        crate::config::HopSpec {
            id: id.to_string(),
            config: crate::config::HopConfig::Plugin(crate::config::hop::PluginHopConfig {
                kind: kind.to_string(),
                family: "dual".to_string(),
                fields: Default::default(),
            }),
        }
    }

    fn materials() -> BringUpMaterials<'static> {
        // Empty material maps, leaked for the 'static borrow (test-only).
        BringUpMaterials {
            imports: Box::leak(Box::new(std::collections::HashMap::new())),
            obfuscation: Box::leak(Box::new(std::collections::HashMap::new())),
            identities: Box::leak(Box::new(std::collections::HashMap::new())),
        }
    }

    async fn run_bring_up(
        reg: &TransportRegistry,
        chain: &Chain,
    ) -> Result<Vec<StartedHop>, FailureReport> {
        let (events, _rx) = tokio::sync::broadcast::channel::<HopEvent>(64);
        bring_up(
            reg,
            chain,
            Arc::new(StubDialer),
            &events,
            &KeepalivePolicy::default(),
            Instant::now() + std::time::Duration::from_secs(5),
            materials(),
        )
        .await
    }

    fn chain_of(hops: Vec<crate::config::HopSpec>) -> Chain {
        Chain { hops, max_depth: 3 }
    }

    fn expect_fail(started: Result<Vec<StartedHop>, FailureReport>, why: &str) -> FailureReport {
        // `expect_err` needs Debug on the Ok payload; StartedHop is not
        // Debug (a running hop), so match explicitly.
        match started {
            Ok(_) => panic!("{why}"),
            Err(e) => e,
        }
    }

    /// (a) 2-hop chain, hop 1 build fails → start errs, hop 0 was stopped
    /// exactly once, and no StartedHop survives the error.
    #[tokio::test]
    async fn build_failure_stops_started_hops_and_leaves_no_partial_state() {
        let reg = test_registry();
        assert!(reg.factory("rec").is_some(), "rec double registered");
        let chain = chain_of(vec![spec("rec", "rec-0"), spec("fail-build", "boom-1")]);
        let err = expect_fail(
            run_bring_up(&reg, &chain).await,
            "build failure fails closed",
        );
        assert_eq!(err.hop_id, "boom-1", "error names the failing hop");
        assert_eq!(err.layer, FailureLayer::Transport);
        assert_eq!(err.kind, "transport");
        assert!(err.cause.contains("sidecar exploded"), "{err}");
        assert_eq!(
            rec_stops(),
            1,
            "started hop 0 received exactly one stop() during the unwind"
        );
    }

    /// (b) hop 1 build pending forever + 200 ms deadline → timeout error
    /// names the hop, and hop 0 is stopped (no partial state).
    #[tokio::test]
    async fn build_timeout_stops_started_hops_and_names_the_hop() {
        let reg = test_registry();
        let chain = chain_of(vec![spec("rec", "rec-0"), spec("pending-build", "slow-1")]);
        let (events, _rx) = tokio::sync::broadcast::channel::<HopEvent>(64);
        let err = expect_fail(
            bring_up(
                &reg,
                &chain,
                Arc::new(StubDialer),
                &events,
                &KeepalivePolicy::default(),
                Instant::now() + std::time::Duration::from_millis(200),
                materials(),
            )
            .await,
            "pending build times out",
        );
        assert_eq!(err.hop_id, "slow-1", "timeout names the pending hop");
        assert_eq!(err.layer, FailureLayer::Chain);
        assert_eq!(err.kind, "timeout");
        assert!(err.cause.contains("timeout"), "{err}");
        assert_eq!(
            rec_stops(),
            1,
            "started hop 0 stopped on the timeout unwind"
        );
    }

    /// (c) Unregistered kind mid-chain: fails closed naming hop + kind,
    /// started hops stopped. (Path :103 `registry.factory(kind) == None`.)
    #[tokio::test]
    async fn unregistered_kind_fails_closed_after_stopping_started_hops() {
        let reg = test_registry();
        assert!(
            reg.factory("ghost").is_none(),
            "ghost must stay unregistered"
        );
        let chain = chain_of(vec![spec("rec", "rec-0"), spec("ghost", "unknown-1")]);
        let err = expect_fail(
            run_bring_up(&reg, &chain).await,
            "unregistered kind fails closed",
        );
        assert_eq!(err.hop_id, "unknown-1");
        assert!(err.cause.contains("ghost"), "{err}");
        assert!(err.cause.contains("not registered"), "{err}");
        assert_eq!(
            rec_stops(),
            1,
            "started hop 0 stopped on the unknown-kind unwind"
        );
    }

    /// (d) Deadline pre-check (:83) — the deadline is already past when a
    /// hop's turn arrives: fail closed naming that hop, and any hop started
    /// before the expiry is stopped. With a far-past deadline nothing has
    /// started yet, so the unwind stops nothing; the inter-hop expiry shape
    /// (hop 0 alive when hop 1's pre-check fires) is the same unwind pinned
    /// by the build-timeout test above (same `unwind` call site).
    #[tokio::test]
    async fn expired_deadline_precheck_stops_started_hops() {
        let reg = test_registry();
        let chain = chain_of(vec![spec("rec", "rec-0")]);
        let (events, _rx) = tokio::sync::broadcast::channel::<HopEvent>(64);
        // Deadline one tick in the past: the pre-check fires before hop 0's
        // build starts.
        let err = expect_fail(
            bring_up(
                &reg,
                &chain,
                Arc::new(StubDialer),
                &events,
                &KeepalivePolicy::default(),
                Instant::now() - std::time::Duration::from_millis(1),
                materials(),
            )
            .await,
            "past deadline fails closed",
        );
        assert_eq!(err.hop_id, "rec-0", "the pre-check names the current hop");
        assert_eq!(err.kind, "timeout");
        assert!(err.cause.contains("timeout budget"), "{err}");
        assert_eq!(
            rec_stops(),
            0,
            "nothing had started when the pre-check fired"
        );
    }

    /// Happy-path guard for the doubles above: a 1-hop `rec` chain starts,
    /// health is Healthy, and explicit stop works — so a green unwind test
    /// means the unwind saw a *started* hop, not a broken double.
    #[tokio::test]
    async fn rec_double_starts_and_stops_cleanly() {
        let reg = test_registry();
        let chain = chain_of(vec![spec("rec", "rec-0")]);
        let started = run_bring_up(&reg, &chain).await.expect("rec chain starts");
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].hop_id, "rec-0");
        assert_eq!(started[0].hop.health(), HopHealth::Healthy);
        assert_eq!(rec_stops(), 0, "bring-up itself never stops a hop");
    }
}
