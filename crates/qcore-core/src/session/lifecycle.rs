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
}

/// Per-hop material merged into factory configs at bring-up (in memory
/// only; chain > import > profile precedence, never persisted).
pub struct BringUpMaterials<'a> {
    /// US2 import material per hop id.
    pub imports: &'a std::collections::HashMap<String, crate::config::import::ImportMaterial>,
    /// US5 obfuscation applications per hop id.
    pub obfuscation:
        &'a std::collections::HashMap<String, crate::config::obfuscation::ObfApplication>,
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
        fcfg.fields.insert("hop_id".into(), spec.id.clone());
        // US2: explicit chain values win; import material fills the rest.
        if let Some(material) = materials.imports.get(&spec.id) {
            for (k, v) in &material.fields {
                fcfg.fields.entry(k.clone()).or_insert_with(|| v.clone());
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
        // Fan hop events into the session bus (push, not poll).
        let mut rx = hop.events();
        let tx = events.clone();
        tokio::spawn(async move {
            while let Ok(e) = rx.recv().await {
                if tx.send(e).is_err() {
                    break;
                }
            }
        });
        if keepalive.enabled {
            spawn_keepalive(
                spec.id.clone(),
                hop.clone(),
                keepalive.clone(),
                events.clone(),
            );
        }
        let _ = events.send(HopEvent::EndpointSelected {
            hop_id: spec.id.clone(),
            endpoint: effective_endpoint(spec),
        });
        carrier = hop.dialer();
        started.push(StartedHop {
            hop_id: spec.id.clone(),
            kind: kind.to_string(),
            family: effective_family(spec),
            endpoint: endpoint_of(spec),
            via,
            nested,
            inner_mtu: prober.current_mtu(),
            obfuscation: active_obfuscation,
            hop,
        });
    }
    Ok(started)
}

/// Stop started hops reverse-order, best effort (unwind path).
async fn unwind(started: &[StartedHop]) {
    for s in started.iter().rev() {
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

/// Family in effect: endpoint-resolved when the hop has a fixed endpoint.
fn effective_family(spec: &crate::config::HopSpec) -> String {
    if let Some(ep) = endpoint_of(spec) {
        if let Ok(addr) = ep.parse::<SocketAddr>() {
            return if addr.is_ipv4() {
                "ipv4".to_string()
            } else {
                "ipv6".to_string()
            };
        }
    }
    spec.config.family().to_string()
}

fn endpoint_of(spec: &crate::config::HopSpec) -> Option<String> {
    spec.config
        .to_factory_config()
        .get("endpoint")
        .map(str::to_string)
}

fn effective_endpoint(spec: &crate::config::HopSpec) -> String {
    endpoint_of(spec).unwrap_or_else(|| spec.config.family().to_string())
}
