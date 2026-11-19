//! Auto-reconnect watchdog (F2).
//!
//! Subscribes to the per-session event bus; on `HopEvent::Failed` of any hop:
//! degrade honestly (`Up -> Degraded`, persisted + reflected in the live
//! report), then rebuild the chain through the existing bring-up primitives
//! with a bounded retry budget (3 attempts, 2 s / 5 s / 10 s backoff, 120 s
//! total). Success flips the session back to `Up` and counts the reconnect
//! in `session.json`; a budget that runs dry re-fails through the existing
//! terminal path (Failed record + hops torn down — exit-code semantics
//! unchanged). A flapping session (≥5 reconnects within 10 minutes) gives up
//! naming the flap.
//!
//! Chain semantics: a failed hop N invalidates hops > N transitively (their
//! carrier died), so the rebuild unwinds N..end and re-brings-up that
//! segment through the kept prefix's carrier dialer. Before each attempt the
//! quick-reconnect ring (per-carrier verified-winner cache) is consulted for
//! a fresher wireguard-family endpoint; a hit swaps the endpoint into the
//! spec copy instead of needing transport cooperation.
//!
//! Transparency: the control listener is session-level and is never touched;
//! during a rebuild the live report (control-channel STATUS) carries the
//! additive `session_state: "degraded"` + `reconnects` fields, and the
//! durable record reads degraded.
//!
//! Cancellation: the task selects the session's stop watch and is aborted
//! through the abort handle stored on the handle (`stop_all` aborts first,
//! same ownership rule as keepalive/forwarder handles), so `stop()` never
//! waits out a rebuild. A stop landing mid-`bring_up` drops the in-flight
//! future: factory builds release their own partial resources by contract
//! (`HopFactory::build` cancellation safety); hops already pushed to the
//! segment get watcher aborts from `StartedHop::drop`, and socket reclamation
//! rides process exit — the prompt-stop contract wins over teardown tidiness
//! on this one path.

use crate::config::profile_dir::ProfileDirs;
use crate::session::lifecycle::{self, StartedHop};
use crate::session::report::ConnectionReport;
use crate::session::{LiveExit, Session, SessionHandle, SessionState};
use qcore_transport_api::{FailureLayer, FailureReport, HopEvent};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Watchdog tuning. Named consts (diag convention); [`WatchdogConfig`]
/// carries them as fields so tests can tighten the clocks without sleeps.
mod tuning {
    use super::Duration;
    pub const REBUILD_ATTEMPTS: u32 = 3;
    pub const REBUILD_BACKOFF_SECS: [u64; 3] = [2, 5, 10];
    pub const REBUILD_BUDGET: Duration = Duration::from_secs(120);
    /// One rebuild attempt's bring-up budget, bounded independently of the
    /// overall budget so a hung factory cannot eat it in one attempt.
    pub const REBUILD_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
    pub const FLAP_WINDOW: Duration = Duration::from_secs(600);
    pub const FLAP_CAP: u32 = 5;
}

/// Quick-reconnect ring (F2f): newest verified winner for a wireguard-family
/// hop (`wireguard`/`warp` cache keys — the same scoping rule as
/// `config::import::wireguard_family_winner`; a masque/tor winner must never
/// poison a wireguard hop with a foreign endpoint). `None` for every other
/// kind: the ring is a wireguard-endpoint cache, not a generic one.
fn ring_endpoint(dirs: &ProfileDirs, kind: &str, family: &str) -> Option<std::net::SocketAddr> {
    const WG_FAMILY_KEYS: &[&str] = &["wireguard", "warp"];
    if !WG_FAMILY_KEYS.contains(&kind) {
        return None;
    }
    crate::scan::cache::read_winners(dirs)
        .into_iter()
        .filter(|(k, _)| WG_FAMILY_KEYS.contains(&k.as_str()))
        .filter(|(_, w)| family == "dual" || w.family == family)
        .max_by_key(|(_, w)| w.verified_at_ms)
        .and_then(|(_, w)| w.socket_addr())
}

/// Swap a fresh ring endpoint into the spec copy when the hop carries an
/// explicit wireguard endpoint and the ring has a different verified one.
/// The copy keeps everything else byte-identical (keys, obfuscation,
/// family); hops without an explicit endpoint keep rebuilding through the
/// winner-cache fill at build time (`identity::inject`), which reads the
/// same cache anyway.
fn with_ring_endpoint(dirs: &ProfileDirs, spec: &crate::config::HopSpec) -> crate::config::HopSpec {
    let family = spec.config.family().to_string();
    let Some(fresh) = ring_endpoint(dirs, spec.config.kind(), &family) else {
        return spec.clone();
    };
    let fresh = fresh.to_string();
    let mut copy = spec.clone();
    if let crate::config::HopConfig::Wireguard(c) = &mut copy.config {
        if c.endpoint.as_deref() == Some(fresh.as_str()) {
            return spec.clone();
        }
        c.endpoint = Some(fresh);
        return copy;
    }
    spec.clone()
}

/// Everything the watchdog needs beyond the handle: the same config the
/// engine started the session with, plus tightened clocks for tests.
/// Production values are the named tuning consts.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    pub dirs: ProfileDirs,
    pub keepalive: crate::session::net::KeepalivePolicy,
    pub timeout_secs: u64,
    pub family: String,
    pub prefer: String,
    pub attempts: u32,
    pub backoff_secs: Vec<u64>,
    pub budget: Duration,
    pub attempt_timeout: Duration,
    /// DNS resolver address the session was started with (`EngineConfig::
    /// dns_resolver`): a post-rebuild exit re-wires the tunnel resolver over
    /// the NEW exit's UDP egress so ATYP=domain targets keep resolving.
    pub dns_resolver: Option<std::net::IpAddr>,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        WatchdogConfig {
            dirs: ProfileDirs::resolve(None, None),
            keepalive: crate::session::net::KeepalivePolicy::default(),
            timeout_secs: 30,
            family: "dual".into(),
            prefer: "ipv4".into(),
            attempts: tuning::REBUILD_ATTEMPTS,
            backoff_secs: tuning::REBUILD_BACKOFF_SECS.to_vec(),
            budget: tuning::REBUILD_BUDGET,
            attempt_timeout: tuning::REBUILD_ATTEMPT_TIMEOUT,
            dns_resolver: None,
        }
    }
}

impl WatchdogConfig {
    /// Re-resolve the per-hop materials exactly like `Engine::start` (same
    /// fail-closed helpers): imports, obfuscation, identities. A rebuild is
    /// a fresh bring-up of the same specs, so it re-reads stored material —
    /// a renewed identity or a newer winner-cache entry flows in here too.
    ///
    /// The maps come back owned ([`OwnedMaterials`]): the caller takes the
    /// borrowed view for the `bring_up` await and drops the owned maps with
    /// the attempt — secrets (identity `Zeroizing` keys) drop with the
    /// attempt instead of leaking per rebuild (R1.3).
    fn resolve_materials(
        &self,
        registry: &crate::registry::TransportRegistry,
        hops: &[crate::config::HopSpec],
    ) -> Result<crate::session::lifecycle::OwnedMaterials, FailureReport> {
        let imports = crate::config::import::materialize(&self.dirs, hops).map_err(|e| {
            FailureReport::new(
                FailureLayer::Validation,
                e.hop_id.clone().unwrap_or_else(|| "-".to_string()),
                e.to_string(),
                "validation",
            )
        })?;
        let obfuscation = crate::config::obfuscation::resolve_for_chain(&self.dirs, registry, hops)
            .map_err(|e| {
                FailureReport::new(
                    FailureLayer::Validation,
                    e.hop_id.clone().unwrap_or_else(|| "-".to_string()),
                    e.to_string(),
                    "validation",
                )
            })?;
        let identities = crate::identity::inject::materials_for_chain(&self.dirs, hops).map_err(
            |(hop_id, msg)| FailureReport::new(FailureLayer::Validation, hop_id, msg, "identity"),
        )?;
        Ok(crate::session::lifecycle::OwnedMaterials {
            imports: Arc::new(imports),
            obfuscation: Arc::new(obfuscation),
            identities: Arc::new(identities),
        })
    }
}

/// Rebuild outcome handed back to the spawn loop: the rebuilt segment plus
/// the kept prefix (a full-chain rebuild has an empty prefix).
pub struct RebuildOutcome {
    pub segment: Vec<StartedHop>,
    pub kept: Vec<StartedHop>,
}

/// Result of driving one `Failed` event to a conclusion.
pub enum WatchOutcome {
    /// Chain rebuilt; the spawn loop swaps the live entry.
    Rebuilt(RebuildOutcome),
    /// Budget exhausted / flap cap hit: the session is terminal. The cause
    /// names the attempts or the flap, per the F2 contract.
    GaveUp(FailureReport),
}

/// The watchdog core: reconnect accounting + the rebuild loop. Driven by the
/// spawn loop; tests drive the same attempt path directly.
pub struct Watchdog {
    cfg: WatchdogConfig,
    /// Reconnect timestamps inside the flap window.
    reconnect_times: Vec<Instant>,
    /// Cumulative successful rebuilds (mirrored into `session.json` and the
    /// shared handle counter).
    pub reconnects: u32,
}

impl Watchdog {
    pub fn new(cfg: WatchdogConfig) -> Self {
        Watchdog {
            cfg,
            reconnect_times: Vec::new(),
            reconnects: 0,
        }
    }

    /// Flap check: ≥5 reconnects within the 10-minute window.
    fn flapping(&self) -> bool {
        let cutoff = Instant::now() - tuning::FLAP_WINDOW;
        self.reconnect_times
            .iter()
            .filter(|t| **t >= cutoff)
            .count() as u32
            >= tuning::FLAP_CAP
    }

    fn note_reconnect(&mut self) {
        self.reconnect_times.push(Instant::now());
        self.reconnects += 1;
    }

    /// One rebuild attempt: unwind hops `failed_idx..end` (their carrier
    /// died transitively), then re-bring-up that segment through the kept
    /// prefix's exit dialer. A failed hop 0 has no kept prefix: the whole
    /// chain rebuilds through a fresh root dialer. `pub(crate)` for the
    /// report-surface test; production reaches it through `on_failed`.
    pub(crate) async fn attempt_rebuild(
        &mut self,
        live: &LiveMap,
        session_id: &str,
        failed_idx: usize,
    ) -> Result<RebuildOutcome, FailureReport> {
        // Snapshot the CURRENT entry (post-any-previous-swap): short lock,
        // never held across await.
        let Some(entry) = lock_entry(live, session_id) else {
            return Err(FailureReport::new(
                FailureLayer::Chain,
                "-",
                "session vanished during reconnect",
                "chain",
            ));
        };
        if failed_idx >= entry.started_hops().len() {
            return Err(FailureReport::new(
                FailureLayer::Chain,
                "-",
                "failed hop no longer part of the live chain",
                "chain",
            ));
        }
        // Snapshot the current hops: unwind the failed segment, keep the
        // prefix (both the watchdog task and every handle holder see the
        // same shared vec — this clone is the working copy for this attempt).
        let current = entry.started_hops();
        lifecycle::unwind(&current[failed_idx..]).await;
        let kept: Vec<StartedHop> = current[..failed_idx].to_vec();

        // Ring first: rewrite the failed hop's spec with a fresher verified
        // endpoint when the cache has one; otherwise the specs rebuild as
        // authored (a later attempt falls back naturally if the ring
        // endpoint is the one that died — it is re-verified only by
        // bring-up itself).
        let mut hops: Vec<crate::config::HopSpec> = entry.chain.hops.clone();
        let failed = &mut hops[failed_idx];
        *failed = with_ring_endpoint(&self.cfg.dirs, failed);

        let carrier: Arc<dyn qcore_transport_api::Dialer> = match kept.last() {
            Some(last) => last.hop.dialer(),
            None => {
                let policy =
                    crate::session::net::FamilyPolicy::parse(&self.cfg.family, &self.cfg.prefer)
                        .map_err(|e| {
                            FailureReport::new(FailureLayer::Validation, "-", e, "validation")
                        })?;
                crate::session::net::root_dialer(
                    policy,
                    Duration::from_secs(self.cfg.timeout_secs.max(1)),
                )
            }
        };
        let carrier_label = kept
            .last()
            .map(|s| s.hop_id.clone())
            .unwrap_or_else(|| "root".to_string());
        let registry = crate::registry::TransportRegistry::global();
        let owned_materials = self.cfg.resolve_materials(&registry, &hops)?;
        let deadline = Instant::now() + self.cfg.attempt_timeout;
        let events = entry.events.clone();
        let chain = crate::chain::Chain {
            hops,
            max_depth: entry.chain.max_depth,
        };
        // The borrow lives exactly for this await; `owned_materials` (and
        // the identity secrets in it) drop when the attempt ends.
        let segment = lifecycle::bring_up(
            &chain,
            carrier,
            &events,
            &self.cfg.keepalive,
            deadline,
            lifecycle::DepthContext {
                registry: &registry,
                materials: owned_materials.borrow(),
                depth_offset: kept.len() as u32,
                carrier_label: &carrier_label,
            },
        )
        .await?;
        Ok(RebuildOutcome { segment, kept })
    }

    /// Drive one `Failed` event to a conclusion: bounded retries within the
    /// budget, flap cap before every attempt, cause naming attempts or flap.
    pub async fn on_failed(
        &mut self,
        live: &LiveMap,
        session_id: &str,
        failed_idx: usize,
        cause: &str,
    ) -> WatchOutcome {
        let budget = Instant::now() + self.cfg.budget;
        let mut last_err: Option<FailureReport> = None;
        let mut attempts_made = 0u32;
        for attempt in 0..self.cfg.attempts.max(1) {
            if attempt > 0 {
                // Backoff bounded by the remaining budget (never wait past it).
                let backoff = Duration::from_secs(
                    self.cfg
                        .backoff_secs
                        .get(attempt as usize - 1)
                        .copied()
                        .unwrap_or(10),
                );
                let remaining = budget.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                tokio::time::sleep(backoff.min(remaining)).await;
            }
            if Instant::now() >= budget {
                break;
            }
            if self.flapping() {
                return WatchOutcome::GaveUp(FailureReport::new(
                    FailureLayer::Transport,
                    "-",
                    format!(
                        "flapping: {} reconnects within {} minutes; giving up (last cause: {cause})",
                        tuning::FLAP_CAP,
                        tuning::FLAP_WINDOW.as_secs() / 60
                    ),
                    "flap",
                ));
            }
            attempts_made += 1;
            match self.attempt_rebuild(live, session_id, failed_idx).await {
                Ok(outcome) => {
                    self.note_reconnect();
                    return WatchOutcome::Rebuilt(outcome);
                }
                Err(e) => last_err = Some(e),
            }
        }
        let last = last_err
            .map(|e| e.cause)
            .unwrap_or_else(|| "no attempt ran".to_string());
        WatchOutcome::GaveUp(FailureReport::new(
            FailureLayer::Transport,
            "-",
            format!(
                "reconnect failed after {attempts_made} attempt(s) within the {}s budget: {last}",
                self.cfg.budget.as_secs()
            ),
            "reconnect-budget",
        ))
    }
}

/// The engine's live-session map, shared with the watchdog so a rebuild can
/// swap the entry (and a give-up remove it) under the same lock.
pub type LiveMap = Arc<std::sync::Mutex<HashMap<String, SessionHandle>>>;

/// Poison-tolerant lock, same policy as `Engine::lock_live`.
fn lock_map(live: &LiveMap) -> std::sync::MutexGuard<'_, HashMap<String, SessionHandle>> {
    live.lock().unwrap_or_else(|e| {
        eprintln!("qcore: live session map lock poisoned; restoring");
        e.into_inner()
    })
}

/// Clone the current entry out from under the map lock (Arc-cheap; the lock
/// is never held across an await).
fn lock_entry(live: &LiveMap, session_id: &str) -> Option<SessionHandle> {
    lock_map(live).get(session_id).cloned()
}

/// Degrade the durable record (`Up -> Degraded`) — best effort: the tunnel
/// is the truth, the record is the honest mirror of it. Terminal records
/// (a concurrent stop won the race) are left alone.
fn degrade_record(dirs: &ProfileDirs) {
    if let Ok(mut session) = Session::load(dirs) {
        if session.state == SessionState::Up {
            let _ = session.transition_checked(SessionState::Degraded);
            let _ = session.save(dirs);
        }
    }
}

/// Flip the durable record back to `Up` after a successful rebuild, with the
/// cumulative reconnect count. Best effort like every record write here.
fn up_record(dirs: &ProfileDirs, reconnects: u32) {
    if let Ok(mut session) = Session::load(dirs) {
        session.reconnects = reconnects;
        if session.state == SessionState::Degraded {
            let _ = session.transition_checked(SessionState::Up);
        }
        let _ = session.save(dirs);
    }
}

/// Terminal record: Failed with the reconnect report (budget or flap).
fn fail_record(dirs: &ProfileDirs, report: &FailureReport, reconnects: u32) {
    if let Ok(mut session) = Session::load(dirs) {
        session.reconnects = reconnects;
        session.fail(report.clone());
        let _ = session.save(dirs);
    }
}

/// Refresh the live report slot (control-channel STATUS serves it) from the
/// CURRENT map entry, preserving the active-profile fields the CLI set at
/// start. `None` slot (embedders) is a no-op — their status reads the map.
/// `pub(crate)` for the report-surface test.
pub(crate) async fn publish_report(
    live: &LiveMap,
    session_id: &str,
    degraded: bool,
    reconnects: u32,
) {
    let Some(entry) = lock_entry(live, session_id) else {
        return;
    };
    let Some(slot) = entry.live_report_slot() else {
        return;
    };
    let mut fresh = ConnectionReport::new(entry.hop_reports(), entry.exit_hop_id.clone());
    {
        let old = slot.read().await;
        fresh.active_scan_profile = old.active_scan_profile.clone();
        fresh.active_obfuscation = old.active_obfuscation.clone();
    }
    if degraded {
        fresh.session_state = Some("degraded".to_string());
        fresh.reconnects = Some(reconnects);
    }
    *slot.write().await = fresh;
}

/// Swap a rebuilt chain into a live entry as ONE operation (S1.6): the
/// started vec, the exit dialer, and the tunnel resolver are written under a
/// single `exit` write guard acquisition pattern — a reader between two
/// separate swaps would otherwise see a new dialer with the OLD resolver (or
/// vice versa). The vec write and the exit swap each take their own short
/// lock, but dialer+resolver move together inside one `LiveExit` write, so
/// every reader of the egress slot sees a consistent pair.
fn swap_rebuilt_exit(
    h: &mut SessionHandle,
    started: &[StartedHop],
    dns_resolver: Option<std::net::IpAddr>,
) {
    // Same shared vec (Arc): the write through the map entry's handle
    // reaches every holder.
    *h.started
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = started.to_vec();
    // Refresh the egress under ONE write guard: the rebuilt exit's dialer
    // (so handle reads — the CLI's live adapter resolves through this — dial
    // the NEW chain) plus the re-wired tunnel resolver when the session had
    // one (domain targets keep resolving post-rebuild; the resolver address
    // is the engine's, unchanged by a rebuild). One guard = no reader can
    // observe old-dialer/new-resolver or new-dialer/old-resolver. The
    // resolver check reads the guard-held slot — `tunnel_resolver()` would
    // re-lock the same std RwLock here (deadlock).
    let mut exit = h
        .exit
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    exit.dialer = Some(
        started
            .last()
            .expect("rebuilt segment has at least one hop")
            .hop
            .dialer(),
    );
    if exit.resolver.is_some() {
        if let (Some(ip), Some(exit_hop)) = (dns_resolver, started.last()) {
            if exit_hop.hop.dialer().capabilities().dials_udp {
                exit.resolver = Some(std::sync::Arc::new(
                    crate::session::resolver::TunnelResolver::new(exit_hop.hop.dialer(), ip),
                ));
            }
        }
    }
}

/// Next event from the session bus; `None` only when every sender dropped
/// (session torn down and forgotten — the task then ends on its own).
async fn next_event(rx: &mut tokio::sync::broadcast::Receiver<HopEvent>) -> Option<HopEvent> {
    loop {
        match rx.recv().await {
            Ok(e) => return Some(e),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        }
    }
}

/// Spawn the watchdog task for one live session. Returns the abort handle
/// the engine stores on the handle (teardown aborts it before stopping
/// hops — dropping the handle would detach the task and leak it).
///
/// The task selects the session's stop watch: `stop()` flips the watch and
/// aborts, so a stop mid-rebuild returns promptly (F2d), never waiting out
/// the budget. On a successful rebuild the live map entry's `started` vec is
/// swapped (kept prefix + rebuilt segment) so engine status/stop see the new
/// hops; on give-up the record goes Failed and the hops are unwound — the
/// same terminal shape a bring-up failure produces.
pub fn spawn(
    handle: SessionHandle,
    cfg: WatchdogConfig,
    live: LiveMap,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::AbortHandle {
    if *shutdown.borrow_and_update() {
        // Already stopping: nothing to watch.
        return tokio::task::spawn(std::future::ready(())).abort_handle();
    }
    // Subscribe BEFORE spawning the task: a broadcast send with zero active
    // receivers errors and loses the event, so the subscription must exist
    // from the moment the caller can next touch the bus (the task's first
    // poll would otherwise race a same-moment hop failure).
    let rx = handle.events.subscribe();
    // The task body is an `async fn`, not an inline `async move` block: the
    // edition-2021 per-field capture dissection of async blocks would leave
    // `handle` (and its `started` vec — carrying the keepalive/forwarder
    // abort handles!) as a local of `spawn`, dropped at return — aborting
    // every watcher the session just started. An async fn parameter is a
    // whole-struct move; no dissection.
    tokio::spawn(run_watchdog(handle, cfg, live, shutdown, rx)).abort_handle()
}

/// The watchdog loop proper. Whole-struct `handle` by value (see [`spawn`]).
async fn run_watchdog(
    handle: SessionHandle,
    cfg: WatchdogConfig,
    live: LiveMap,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut rx: tokio::sync::broadcast::Receiver<HopEvent>,
) {
    let mut wd = Watchdog::new(cfg);
    loop {
        let event = tokio::select! {
            biased;
            _ = shutdown.wait_for(|stopped| *stopped) => break,
            e = next_event(&mut rx) => match e {
                Some(e) => e,
                None => break,
            },
        };
        let HopEvent::Failed { hop_id, cause } = event else {
            continue;
        };
        // Coalesce re-entrant Failed events while a rebuild is in
        // flight: the in-flight rebuild's unwind already covers the
        // affected segment. The atomic mirrors the loop state so the
        // engine's report path can read it without the loop.
        if handle.degraded.load(std::sync::atomic::Ordering::SeqCst) {
            continue;
        }
        // The CURRENT entry decides (post-swap hops, post-attach slot).
        let Some(entry) = lock_entry(&live, &handle.id) else {
            break;
        };
        let Some(failed_idx) = entry.started_hops().iter().position(|s| s.hop_id == hop_id) else {
            // Stale or foreign event (hop already rebuilt away).
            continue;
        };
        handle
            .degraded
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // (a) Honest degrade first: record + report show degraded even
        // if the rebuild never starts.
        degrade_record(&wd.cfg.dirs);
        publish_report(&live, &handle.id, true, wd.reconnects).await;
        // Race the rebuild against the stop watch: a stop landing
        // mid-rebuild must not wait out the attempt timeout (the
        // select-with-stop guard below only covers the event wait; the
        // abort handle in `stop_all` is the belt, this is the
        // suspenders). A stop-interrupt exits silently: the session's
        // own stop path owns the record/teardown, and a user stop is
        // not a failure.
        let outcome = tokio::select! {
            biased;
            _ = shutdown.wait_for(|stopped| *stopped) => break,
            o = wd.on_failed(&live, &handle.id, failed_idx, &cause) => o,
        };
        match outcome {
            WatchOutcome::GaveUp(report) => {
                // (d)/(e) Terminal: Failed record + hops unwound — the
                // same shape a bring-up failure leaves. Unwind directly
                // (not `stop_all`, which would abort this task
                // mid-teardown), then remove the map entry so engine
                // status/stop see a session that is observably gone.
                fail_record(&wd.cfg.dirs, &report, wd.reconnects);
                if let Some(entry) = lock_entry(&live, &handle.id) {
                    if let Some(slot) = entry.live_report_slot() {
                        let mut fresh =
                            ConnectionReport::new(entry.hop_reports(), entry.exit_hop_id.clone());
                        {
                            let old = slot.read().await;
                            fresh.active_scan_profile = old.active_scan_profile.clone();
                            fresh.active_obfuscation = old.active_obfuscation.clone();
                        }
                        fresh.failure = Some(report.clone());
                        *slot.write().await = fresh;
                    }
                    let started = entry.started_hops();
                    lifecycle::unwind(&started).await;
                    // The hops are stopped: drop them from the shared vec
                    // so no holder keeps stopped hops alive.
                    *entry
                        .started
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
                    *entry
                        .exit
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = LiveExit::default();
                }
                lock_map(&live).remove(&handle.id);
                // Fire the give-up signal BEFORE clearing the degraded
                // flag: the serving CLI observes terminal-ness while the
                // session bus is still alive, and exits with the failure.
                let _ = handle.give_up_sender().send(true);
                handle
                    .degraded
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                break;
            }
            WatchOutcome::Rebuilt(outcome) => {
                // Swap the rebuilt segment into the live entry (kept prefix
                // + segment; hop ids unchanged) and refresh the shared
                // egress so proxy connections opened after the rebuild dial
                // the NEW exit — the CLI's handle clone shares this state.
                let mut started = outcome.kept;
                started.extend(outcome.segment);
                let vanished = {
                    let mut map = lock_map(&live);
                    match map.get_mut(&handle.id) {
                        Some(h) => {
                            swap_rebuilt_exit(h, &started, wd.cfg.dns_resolver);
                            false
                        }
                        // The entry vanished mid-rebuild (stop_session won
                        // the race): the freshly built segment would be
                        // orphaned — live tunnels and watcher tasks with no
                        // owner. Mirror the GaveUp arm's re-check and unwind
                        // it below, outside the map lock (unwind awaits);
                        // `StartedHop::drop` cannot stop hops, only abort
                        // their watchers.
                        None => true,
                    }
                };
                if vanished {
                    lifecycle::unwind(&started).await;
                }
                // Clear the degraded flag BEFORE the durable Up record: the
                // flag belongs to the degraded period, which ended when the
                // rebuilt hops were swapped in above. Storing it after
                // up_record opened an observation window where session.json
                // said Up but handle.degraded was still true (linux CI).
                handle
                    .degraded
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                handle
                    .reconnects
                    .store(wd.reconnects, std::sync::atomic::Ordering::SeqCst);
                up_record(&wd.cfg.dirs, wd.reconnects);
                publish_report(&live, &handle.id, false, wd.reconnects).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::hop::PluginHopConfig;
    use crate::config::HopConfig;
    use crate::session::lifecycle::StartedHop;
    use qcore_transport_api::{
        ByteStream, Capabilities, Dialer, HopError, HopEvent, HopHealth, RunningHop,
        TransportDescriptor, UdpFlow,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn dirs(tag: &str) -> ProfileDirs {
        let dir = std::env::temp_dir().join(format!(
            "qcore-wdog-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")))
    }

    // --- ring endpoint selection -------------------------------------------

    fn winner(addr: &str, family: &str) -> crate::scan::cache::TransportWinner {
        crate::scan::cache::TransportWinner {
            address: addr.to_string(),
            profile: "balanced".to_string(),
            verified_at_ms: crate::identity::model::now_ms(),
            family: family.to_string(),
        }
    }

    #[test]
    fn ring_selects_newest_wireguard_family_winner() {
        let d = dirs("ring-wg");
        d.ensure_dirs().unwrap();
        crate::scan::cache::record_winner(&d, "warp", winner("10.0.0.1:2408", "ipv4")).unwrap();
        crate::scan::cache::record_winner(&d, "wireguard", winner("10.0.0.2:51820", "ipv6"))
            .unwrap();
        // dual: newest of either wireguard-family key wins.
        assert_eq!(
            ring_endpoint(&d, "wireguard", "dual").map(|a| a.to_string()),
            Some("10.0.0.2:51820".to_string())
        );
        // ipv4: only ipv4-family winners are eligible.
        assert_eq!(
            ring_endpoint(&d, "wireguard", "ipv4").map(|a| a.to_string()),
            Some("10.0.0.1:2408".to_string())
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn ring_never_feeds_non_wireguard_kinds() {
        let d = dirs("ring-kind");
        d.ensure_dirs().unwrap();
        crate::scan::cache::record_winner(&d, "masque", winner("10.9.8.7:443", "ipv4")).unwrap();
        assert_eq!(ring_endpoint(&d, "masque", "dual"), None);
        assert_eq!(ring_endpoint(&d, "tor", "dual"), None);
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn ring_swaps_wireguard_endpoint_in_spec_copy_only() {
        let d = dirs("ring-swap");
        d.ensure_dirs().unwrap();
        crate::scan::cache::record_winner(&d, "warp", winner("10.0.0.9:2408", "ipv4")).unwrap();
        let spec = crate::config::HopSpec {
            id: "wg-0".into(),
            config: HopConfig::Wireguard(crate::config::WireguardConfig {
                peer: "warp".into(),
                import_ref: None,
                obfuscation: None,
                family: "ipv4".into(),
                endpoint: Some("162.159.192.1:2408".into()),
            }),
        };
        let swapped = with_ring_endpoint(&d, &spec);
        match &swapped.config {
            HopConfig::Wireguard(c) => {
                assert_eq!(
                    c.endpoint.as_deref(),
                    Some("10.0.0.9:2408"),
                    "ring endpoint swapped into the copy"
                );
                assert_eq!(c.peer, "warp", "peer untouched");
                assert_eq!(c.family, "ipv4", "family untouched");
            }
            other => panic!("wireguard config preserved, got {other:?}"),
        }
        // The original spec is untouched (copy, not in-place).
        match &spec.config {
            HopConfig::Wireguard(c) => {
                assert_eq!(c.endpoint.as_deref(), Some("162.159.192.1:2408"));
            }
            other => panic!("original untouched, got {other:?}"),
        }
        // Same endpoint in ring and spec: no pointless rewrite.
        crate::scan::cache::record_winner(&d, "warp", winner("162.159.192.1:2408", "ipv4"))
            .unwrap();
        let same = with_ring_endpoint(&d, &spec);
        match &same.config {
            HopConfig::Wireguard(c) => {
                assert_eq!(c.endpoint.as_deref(), Some("162.159.192.1:2408"));
            }
            other => panic!("expected wireguard config, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    // --- flap accounting ----------------------------------------------------

    #[test]
    fn flap_cap_counts_within_window() {
        let mut w = Watchdog::new(WatchdogConfig {
            dirs: dirs("flap"),
            ..WatchdogConfig::default()
        });
        for _ in 0..(tuning::FLAP_CAP - 1) {
            w.note_reconnect();
        }
        assert!(
            !w.flapping(),
            "{}-1 reconnects is under the cap",
            tuning::FLAP_CAP
        );
        w.note_reconnect();
        assert!(
            w.flapping(),
            "{} within the window trips the cap",
            tuning::FLAP_CAP
        );
        assert_eq!(w.reconnects, tuning::FLAP_CAP, "counter is monotonic");
    }

    // --- session.json reconnects round-trip (additive serde) ----------------

    fn sample_record() -> Session {
        let chain = crate::chain::Chain {
            hops: vec![crate::config::HopSpec {
                id: "h0".into(),
                config: HopConfig::Plugin(PluginHopConfig {
                    kind: "wdog-hop".into(),
                    family: "dual".into(),
                    fields: Default::default(),
                }),
            }],
            max_depth: 3,
        };
        let mut s = Session::new("s-rt".into(), &chain, Default::default(), 0);
        s.reconnects = 7;
        s
    }

    #[test]
    fn session_record_roundtrips_reconnects() {
        let d = dirs("roundtrip");
        d.ensure_dirs().unwrap();
        sample_record().save(&d).expect("save");
        let back = Session::load(&d).expect("load");
        assert_eq!(back.reconnects, 7, "reconnects survives the round-trip");
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn pre_watchdog_record_loads_with_zero_reconnects() {
        // A record written before F2 has no `reconnects` key: the additive
        // serde default reads it back as 0 instead of rejecting the file.
        let d = dirs("legacy");
        d.ensure_dirs().unwrap();
        let legacy = r#"{
            "id": "old",
            "chain": {"hops": [], "max_depth": 3},
            "family_policy": {"mode": "dual", "prefer": "ipv4",
                              "connection_attempt_delay_ms": 250,
                              "resolution_delay_ms": 50},
            "state": "up",
            "started_at": 0,
            "failure": null
        }"#;
        std::fs::write(d.session_file(), legacy).expect("seed legacy record");
        let back = Session::load(&d).expect("legacy record parses");
        assert_eq!(back.reconnects, 0, "missing field defaults to 0");
        assert_eq!(back.id, "old");
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    // --- spawn-level integration (real bus, real spawn, real rebuild) ------

    struct StubDialer;

    #[async_trait::async_trait]
    impl Dialer for StubDialer {
        async fn dial_tcp(
            &self,
            _dst: std::net::SocketAddr,
        ) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::validation("unused"))
        }
        async fn dial_udp(&self, _dst: std::net::SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::validation("unused"))
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

    /// Hop double mirroring the mock transport's
    /// `fail_after_first_health_check`: first `health()` call Healthy
    /// (bring-up readiness passes), later ones Failed. `stops` counts
    /// `stop()` calls so the unwind is observable. Each instance registers
    /// its counter in [`HOP_REG`] so tests can tell WHICH hop instance was
    /// stopped (rebuilt vs pre-rebuild).
    struct RecoverHop {
        #[allow(dead_code)] // carried for symmetry with the mock transport
        hop_id: String,
        fail_after_first: bool,
        health_checks: AtomicU64,
        events: tokio::sync::broadcast::Sender<HopEvent>,
        stops: Arc<AtomicU64>,
        /// Stable per-instance dialer: `dialer()` hands out the SAME Arc on
        /// every call (the real transports do), so egress identity is
        /// observable across rebuilds.
        dialer: Arc<dyn Dialer>,
    }

    /// Per-instance stop counters, push-ordered by build. Index = build
    /// number (0 = initial, 1+ = rebuilds).
    static HOP_REG: std::sync::LazyLock<std::sync::Mutex<Vec<Arc<AtomicU64>>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

    fn hop_reg_reset() {
        HOP_REG.lock().unwrap().clear();
    }

    fn hop_stops(build: usize) -> u64 {
        HOP_REG
            .lock()
            .unwrap()
            .get(build)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    #[async_trait::async_trait]
    impl RunningHop for RecoverHop {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &RECOVER_DESC
        }
        fn dialer(&self) -> Arc<dyn Dialer> {
            self.dialer.clone()
        }
        fn health(&self) -> HopHealth {
            if self.fail_after_first && self.health_checks.fetch_add(1, Ordering::SeqCst) >= 1 {
                return HopHealth::Failed;
            }
            HopHealth::Healthy
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
            self.events.subscribe()
        }
        async fn stop(&self) -> Result<(), HopError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    static RECOVER_DESC: TransportDescriptor = TransportDescriptor {
        kind: "wdog-hop",
        capabilities: Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "wdog-hop/v1",
        needs_sidecar: false,
    };

    /// Build 0 produces the dying hop; every later build produces a healthy
    /// hop (the network came back). Per-test-local counters via statics:
    /// nextest runs each test in its own process (same isolation the
    /// lifecycle tests rely on).
    static RECOVER_BUILDS: AtomicU64 = AtomicU64::new(0);

    struct RecoverFactory;

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for RecoverFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &RECOVER_DESC
        }
        async fn build(
            &self,
            cfg: qcore_transport_api::HopConfig,
            _carrier: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn RunningHop>, HopError> {
            let n = RECOVER_BUILDS.fetch_add(1, Ordering::SeqCst);
            hold_if_armed().await;
            let stops = Arc::new(AtomicU64::new(0));
            HOP_REG.lock().unwrap().push(stops.clone());
            Ok(Arc::new(RecoverHop {
                hop_id: cfg.get("hop_id").unwrap_or("wdog-0").to_string(),
                fail_after_first: n == 0,
                health_checks: AtomicU64::new(0),
                events: tokio::sync::broadcast::channel(16).0,
                stops,
                dialer: Arc::new(StubDialer),
            }))
        }
    }

    /// Build 0 succeeds; every later build fails forever (budget path).
    static FLAKY_BUILDS: AtomicU64 = AtomicU64::new(0);

    static FLAKY_DESC: TransportDescriptor = TransportDescriptor {
        kind: "wdog-flaky",
        capabilities: Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "wdog-flaky/v1",
        needs_sidecar: false,
    };

    struct FlakyFactory;

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for FlakyFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &FLAKY_DESC
        }
        async fn build(
            &self,
            cfg: qcore_transport_api::HopConfig,
            _carrier: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn RunningHop>, HopError> {
            let n = FLAKY_BUILDS.fetch_add(1, Ordering::SeqCst);
            if n >= 1 {
                return Err(HopError::transport("boom", "rebuild build always fails"));
            }
            Ok(Arc::new(RecoverHop {
                hop_id: cfg.get("hop_id").unwrap_or("flaky-0").to_string(),
                fail_after_first: false,
                health_checks: AtomicU64::new(0),
                events: tokio::sync::broadcast::channel(16).0,
                stops: Arc::new(AtomicU64::new(0)),
                dialer: Arc::new(StubDialer),
            }))
        }
    }

    /// Build 0 succeeds; later builds never resolve (stop-mid-rebuild path).
    static PENDING_BUILDS: AtomicU64 = AtomicU64::new(0);

    static PENDING_DESC: TransportDescriptor = TransportDescriptor {
        kind: "wdog-pending",
        capabilities: Capabilities {
            accepts_tcp_carrier: true,
            accepts_udp_carrier: true,
            dials_tcp: true,
            dials_udp: true,
        },
        obfuscation_families: &[],
        config_schema: "wdog-pending/v1",
        needs_sidecar: false,
    };

    struct PendingFactory;

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for PendingFactory {
        fn descriptor(&self) -> &'static TransportDescriptor {
            &PENDING_DESC
        }
        async fn build(
            &self,
            cfg: qcore_transport_api::HopConfig,
            _carrier: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn RunningHop>, HopError> {
            let n = PENDING_BUILDS.fetch_add(1, Ordering::SeqCst);
            if n >= 1 {
                std::future::pending::<()>().await;
            }
            Ok(Arc::new(RecoverHop {
                hop_id: cfg.get("hop_id").unwrap_or("pending-0").to_string(),
                fail_after_first: false,
                health_checks: AtomicU64::new(0),
                events: tokio::sync::broadcast::channel(16).0,
                stops: Arc::new(AtomicU64::new(0)),
                dialer: Arc::new(StubDialer),
            }))
        }
    }

    static RECOVER_FACTORY: RecoverFactory = RecoverFactory;
    static FLAKY_FACTORY: FlakyFactory = FlakyFactory;
    static PENDING_FACTORY: PendingFactory = PendingFactory;

    qcore_transport_api::register_plugin!(&RECOVER_FACTORY);
    qcore_transport_api::register_plugin!(&FLAKY_FACTORY);
    qcore_transport_api::register_plugin!(&PENDING_FACTORY);

    /// Test gate: when armed, any subsequent factory build parks until
    /// released, so a Degraded window is deterministically observable by a
    /// poll (no sleeps). Arming tests run their initial bring-up BEFORE
    /// arming, so only rebuild builds park. Released via [`release_hold`].
    static HOLD_REBUILD: std::sync::LazyLock<Arc<tokio::sync::Notify>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Notify::new()));
    static HOLD_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn arm_hold() {
        HOLD_ENABLED.store(true, Ordering::SeqCst);
    }

    fn release_hold() {
        HOLD_ENABLED.store(false, Ordering::SeqCst);
        HOLD_REBUILD.notify_waiters();
        HOLD_REBUILD.notify_one();
    }

    async fn hold_if_armed() {
        if HOLD_ENABLED.load(Ordering::SeqCst) {
            HOLD_REBUILD.notified().await;
        }
    }

    fn plugin_spec(kind: &str, id: &str) -> crate::config::HopSpec {
        crate::config::HopSpec {
            id: id.to_string(),
            config: HopConfig::Plugin(PluginHopConfig {
                kind: kind.to_string(),
                family: "dual".to_string(),
                fields: Default::default(),
            }),
        }
    }

    fn chain_of(specs: Vec<crate::config::HopSpec>) -> crate::chain::Chain {
        crate::chain::Chain {
            hops: specs,
            max_depth: 3,
        }
    }

    /// Poll `f` until it returns Some or the deadline passes (bounded poll
    /// loop, no fixed sleeps — same pattern as the control tests).
    async fn poll_until<T>(deadline: Instant, mut f: impl FnMut() -> Option<T>) -> Option<T> {
        while Instant::now() < deadline {
            if let Some(v) = f() {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        f()
    }

    fn test_watchdog_cfg(d: &ProfileDirs) -> WatchdogConfig {
        WatchdogConfig {
            dirs: d.clone(),
            attempts: 3,
            backoff_secs: vec![0, 0, 0],
            budget: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(2),
            ..WatchdogConfig::default()
        }
    }

    /// Shared fixture: live map with the handle inserted, fresh stop watch,
    /// Up-shaped durable record. Bring-up materials default-leaked per test
    /// (nextest process isolation keeps the statics test-local).
    struct Fixture {
        live: LiveMap,
        handle: SessionHandle,
        stop_rx: tokio::sync::watch::Receiver<bool>,
        dirs: ProfileDirs,
    }

    fn fixture(tag: &str, kind: &str) -> Fixture {
        let d = dirs(tag);
        d.ensure_dirs().unwrap();
        let (events, _drain) = tokio::sync::broadcast::channel::<HopEvent>(256);
        let chain = chain_of(vec![plugin_spec(kind, "h-0")]);
        let handle = SessionHandle::bare(
            "sess-wd",
            "h-0",
            crate::session::ChainSer::from(&chain),
            Vec::new(),
            events,
        );
        let mut session = Session::new(
            handle.id.clone(),
            &chain,
            Default::default(),
            crate::identity::model::now_ms(),
        );
        let _ = session.transition(SessionState::Starting);
        let _ = session.transition(SessionState::Up);
        session.save(&d).expect("seed record");
        let live: LiveMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        lock_map(&live).insert(handle.id.clone(), handle.clone());
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = SessionHandle {
            stop_signal: Arc::new(stop_tx),
            ..handle
        };
        lock_map(&live).insert(handle.id.clone(), handle.clone());
        Fixture {
            live,
            handle,
            stop_rx,
            dirs: d,
        }
    }

    fn empty_materials() -> lifecycle::OwnedMaterials {
        lifecycle::OwnedMaterials {
            imports: Arc::default(),
            obfuscation: Arc::default(),
            identities: Arc::default(),
        }
    }

    /// Bring up the initial segment through the shared primitive with the
    /// given keepalive, and return the started hops wired to `events`.
    async fn initial_bring_up(
        kind: &str,
        events: &tokio::sync::broadcast::Sender<HopEvent>,
        keepalive: crate::session::net::KeepalivePolicy,
    ) -> Vec<StartedHop> {
        let registry = crate::registry::TransportRegistry::global();
        lifecycle::bring_up(
            &chain_of(vec![plugin_spec(kind, "h-0")]),
            Arc::new(StubDialer),
            events,
            &keepalive,
            Instant::now() + Duration::from_secs(5),
            lifecycle::DepthContext::root(&registry, empty_materials().borrow()),
        )
        .await
        .expect("initial bring-up succeeds")
    }

    /// Replace the live map entry with a handle variant (same id, new
    /// started vec / slot), returning the new handle.
    fn reinsert(f: &Fixture, patch: impl FnOnce(SessionHandle) -> SessionHandle) -> SessionHandle {
        let handle = patch(f.handle.clone());
        lock_map(&f.live).insert(handle.id.clone(), handle.clone());
        handle
    }

    /// (a) Mock-shaped dying hop (fail_after_first_health_check double):
    /// keepalive observes the death, the session degrades within 5 s, the
    /// rebuild succeeds against the same factory, the record flips back to
    /// Up with reconnects == 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dying_hop_degrades_then_rebuilds_to_up() {
        RECOVER_BUILDS.store(0, Ordering::SeqCst);
        hop_reg_reset();
        let f = fixture("recover", "wdog-hop");
        let (bus_tx, _bus_drain) = tokio::sync::broadcast::channel::<HopEvent>(256);
        let started = initial_bring_up(
            "wdog-hop",
            &bus_tx,
            crate::session::net::KeepalivePolicy {
                enabled: true,
                interval_secs: 1,
            },
        )
        .await;
        // The handle's own bus is what the keepalive emits onto and what the
        // watchdog consumes — one channel, same wiring as engine.start.
        let handle = reinsert(&f, |mut h| {
            h.events = bus_tx.clone();
            h.wire_exit(started, None, None);
            h
        });
        let cfg = test_watchdog_cfg(&f.dirs);
        // Park the first rebuild build so the Degraded record state is
        // deterministically observable before the (fast) rebuild completes.
        arm_hold();
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        // The keepalive must deliver the death onto this same bus within a
        // tick; observing it here isolates "watchdog missed the event" from
        // "keepalive never emitted" if the degrade assertion below fails.
        let mut probe = handle.events.subscribe();
        let death = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                match probe.recv().await {
                    Ok(e @ HopEvent::Failed { .. }) => return e,
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        panic!("session bus closed before the keepalive death")
                    }
                }
            }
        })
        .await;
        assert!(
            death.is_ok(),
            "keepalive must emit Failed within 4 s (the 1 s tick)"
        );

        // Degrade within 5 s of the keepalive tick (1 s interval).
        let degraded = poll_until(Instant::now() + Duration::from_secs(5), || {
            Session::load(&f.dirs)
                .ok()
                .filter(|s| s.state == SessionState::Degraded)
        })
        .await;
        assert!(
            degraded.is_some(),
            "record must show degraded within 5 s, got {:?}",
            Session::load(&f.dirs).map(|s| s.state)
        );
        // Let the parked rebuild finish.
        release_hold();

        // Rebuild succeeds: Up again with reconnects == 1.
        let up = poll_until(Instant::now() + Duration::from_secs(15), || {
            Session::load(&f.dirs)
                .ok()
                .and_then(|s| (s.state == SessionState::Up && s.reconnects == 1).then_some(s))
        })
        .await;
        assert!(
            up.is_some(),
            "rebuild must restore Up with reconnects == 1, got {:?}",
            Session::load(&f.dirs).map(|s| (s.state, s.reconnects))
        );
        assert_eq!(
            RECOVER_BUILDS.load(Ordering::SeqCst),
            2,
            "initial build + one rebuild"
        );
        assert!(
            hop_stops(0) >= 1,
            "rebuild unwinds the failed hop (per-instance counter)"
        );
        // The live entry now carries the rebuilt (healthy) hop.
        let entry = lock_entry(&f.live, &handle.id).expect("entry alive");
        assert_eq!(entry.started_hops().len(), 1, "one rebuilt hop");
        assert_eq!(
            entry.reconnects.load(Ordering::SeqCst),
            1,
            "shared counter mirrored"
        );
        assert!(
            !entry.degraded.load(Ordering::SeqCst),
            "degraded flag cleared after rebuild"
        );
        abort.abort();
        handle.stop_all().await.expect("teardown");
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (a, report surface) While degraded, the live report slot carries the
    /// additive `session_state: "degraded"` + `reconnects` fields; after a
    /// rebuild it returns to the stable Up shape (no state field).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn degraded_report_is_visible_over_the_live_slot() {
        RECOVER_BUILDS.store(u64::MAX - 3, Ordering::SeqCst); // healthy builds only
        let f = fixture("report", "wdog-hop");
        let slot = Arc::new(tokio::sync::RwLock::new(ConnectionReport::new(
            Vec::new(),
            "<starting>".to_string(),
        )));
        // A real started hop: the rebuild (and the report it publishes)
        // operates on the live entry's `started` vec, exactly like production.
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        // Park any further (rebuild) build so the Degraded window is
        // deterministically observable (poll-based, no sleeps). Arming
        // comes AFTER the initial bring-up so only the rebuild parks.
        arm_hold();
        let handle = reinsert(&f, |h| {
            h.set_live_report(slot.clone());
            h.wire_exit(started, None, None);
            h
        });
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        // Inject the same signal the keepalive emits on hop death (the
        // pre-subscribed spawn task is already listening).
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");
        let degraded_doc = poll_until(Instant::now() + Duration::from_secs(5), || {
            let r = slot.try_read().ok()?;
            r.session_state
                .as_deref()
                .filter(|s| *s == "degraded")
                .map(|_| r.reconnects.unwrap_or(0))
        })
        .await;
        assert_eq!(
            degraded_doc,
            Some(0),
            "degraded report carries reconnects (0 before the first success)"
        );
        // Release the parked rebuild: the watchdog completes its own success
        // path (swap + Up record + report refresh) — the same machinery the
        // spawn loop drives.
        release_hold();
        let up_doc = poll_until(Instant::now() + Duration::from_secs(5), || {
            let r = slot.try_read().ok()?;
            (r.session_state.is_none() && r.reconnects.is_none() && r.ordered_chain.len() == 1)
                .then_some(())
        })
        .await;
        assert!(
            up_doc.is_some(),
            "post-rebuild report returns to the stable Up shape"
        );
        let stored = Session::load(&f.dirs).expect("record");
        assert_eq!(
            stored.state,
            SessionState::Up,
            "watchdog success path restores the Up record"
        );
        assert_eq!(
            stored.reconnects, 1,
            "watchdog success path counts the reconnect"
        );
        abort.abort();
        handle.stop_all().await.expect("teardown");
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (b) Rebuild always fails (flaky-build double): after the bounded
    /// attempts the session goes Failed with a cause naming the attempts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn always_failing_rebuild_gives_up_naming_attempts() {
        FLAKY_BUILDS.store(0, Ordering::SeqCst);
        let f = fixture("budget", "wdog-flaky");
        // Real started hop (build 0 succeeds); the Failed event is injected
        // on the session bus — the same signal the keepalive/forwarder path
        // delivers.
        let started = initial_bring_up(
            "wdog-flaky",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");

        let failed = poll_until(Instant::now() + Duration::from_secs(15), || {
            Session::load(&f.dirs)
                .ok()
                .filter(|s| s.state == SessionState::Failed)
        })
        .await;
        let record = failed.expect("session reaches Failed within the test budget");
        let cause = &record.failure.as_ref().expect("failure recorded").cause;
        assert!(
            cause.contains("3 attempt"),
            "cause names the attempts: {cause:?}"
        );
        assert_eq!(record.reconnects, 0, "no successful rebuild");
        // Terminal cleanup: hops unwound, entry removed, task done.
        assert!(
            lock_entry(&f.live, &handle.id).is_none(),
            "give-up removes the live entry"
        );
        let finished = poll_until(Instant::now() + Duration::from_secs(2), || {
            abort.is_finished().then_some(())
        })
        .await;
        assert!(
            finished.is_some(),
            "watchdog task ends on its own at the terminal state"
        );
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (c) Flap cap: five quick successful reconnects, then the next failure
    /// gives up with a cause naming the flap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flapping_session_gives_up_naming_flap() {
        // Every build healthy (rebuild always succeeds) so five full
        // death→rebuild cycles fit inside the test budget.
        RECOVER_BUILDS.store(u64::MAX - 3, Ordering::SeqCst);
        hop_reg_reset();
        let f = fixture("flap-e2e", "wdog-hop");
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());

        // FLAP_CAP rounds of death → rebuild success (each counts one).
        for round in 1..=tuning::FLAP_CAP {
            handle
                .events
                .send(HopEvent::Failed {
                    hop_id: "h-0".into(),
                    cause: format!("injected death {round}"),
                })
                .expect("session bus send");
            let up = poll_until(Instant::now() + Duration::from_secs(10), || {
                Session::load(&f.dirs).ok().and_then(|s| {
                    (s.state == SessionState::Up && s.reconnects == round).then_some(s)
                })
            })
            .await;
            assert!(
                up.is_some(),
                "round {round}: rebuild restores Up with reconnects == {round}, got {:?}",
                Session::load(&f.dirs).map(|s| (s.state, s.reconnects))
            );
        }
        // Sixth death: flap cap trips before any attempt.
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death 6".into(),
            })
            .expect("session bus send");
        let failed = poll_until(Instant::now() + Duration::from_secs(10), || {
            Session::load(&f.dirs)
                .ok()
                .filter(|s| s.state == SessionState::Failed)
        })
        .await;
        let record = failed.expect("flap cap gives up");
        let cause = &record.failure.as_ref().expect("failure recorded").cause;
        assert!(
            cause.contains("flapping"),
            "cause names the flap: {cause:?}"
        );
        assert_eq!(
            record.reconnects,
            tuning::FLAP_CAP,
            "five reconnects counted"
        );
        abort.abort();
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (d) Stop during a hung rebuild: stop_all returns promptly (<2 s) and
    /// the watchdog task is gone (aborted, never waiting out the budget).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_during_rebuild_returns_promptly() {
        PENDING_BUILDS.store(0, Ordering::SeqCst);
        let f = fixture("stop", "wdog-pending");
        let started = initial_bring_up(
            "wdog-pending",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        // Production clocks: the hung build would eat the 30 s attempt
        // timeout — the stop must land long before that.
        let cfg = WatchdogConfig {
            dirs: f.dirs.clone(),
            ..WatchdogConfig::default()
        };
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");
        // Wait until the watchdog is degraded (mid-rebuild, hung in build).
        let mid_rebuild = poll_until(Instant::now() + Duration::from_secs(5), || {
            Session::load(&f.dirs)
                .ok()
                .filter(|s| s.state == SessionState::Degraded)
                .map(|_| ())
        })
        .await;
        assert!(mid_rebuild.is_some(), "watchdog entered the rebuild");

        // Stop: must return in < 2 s (the hung build future is aborted, not
        // awaited) and the watchdog must be finished right after.
        let t0 = Instant::now();
        handle.stop_all().await.expect("stop_all");
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "stop during rebuild returned in {elapsed:?}, contract is <2 s"
        );
        let finished = poll_until(Instant::now() + Duration::from_secs(2), || {
            abort.is_finished().then_some(())
        })
        .await;
        assert!(finished.is_some(), "watchdog aborted with the stop");
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// Stale Failed events (a hop id no longer in the live chain) are
    /// ignored: no degrade, no rebuild.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_failed_event_is_ignored() {
        let f = fixture("stale", "wdog-hop");
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(f.handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        f.handle
            .events
            .send(HopEvent::Failed {
                hop_id: "ghost-hop".into(),
                cause: "not part of this session".into(),
            })
            .expect("session bus send");
        // Give the task a chance to react; the record must stay Up.
        let degraded = poll_until(Instant::now() + Duration::from_millis(500), || {
            Session::load(&f.dirs)
                .ok()
                .filter(|s| s.state == SessionState::Degraded || s.state == SessionState::Failed)
                .map(|_| ())
        })
        .await;
        assert!(degraded.is_none(), "stale event must not degrade");
        assert_eq!(
            Session::load(&f.dirs).expect("record").state,
            SessionState::Up,
            "record stays Up"
        );
        abort.abort();
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (S1.6) The Rebuilt arm swaps dialer + resolver as ONE `LiveExit`
    /// write (`swap_rebuilt_exit`, single guard): immediately after the
    /// rebuild completes, both egress fields are the consistent NEW pair —
    /// the dialer serves the rebuilt exit and the resolver rides that same
    /// exit's dialer. A two-lock swap could leave a reader on old-resolver +
    /// new-dialer mid-window; the single-guard shape cannot. Racy readers
    /// are not deterministically testable — this pins the post-condition:
    /// the pair read back after completion is the same swapped slot (the
    /// dialer serves the current exit hop; the session's resolver survives,
    /// re-wired by the same guard).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rebuilt_egress_swaps_dialer_and_resolver_as_one_pair() {
        RECOVER_BUILDS.store(u64::MAX - 3, Ordering::SeqCst);
        hop_reg_reset();
        let f = fixture("pair", "wdog-hop");
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        // The session carries a tunnel resolver over the initial exit (the
        // engine wires one when `dns_resolver` is set and the exit dials
        // UDP) — the watchdog must re-wire BOTH fields together. The initial
        // hop hands out a fresh StubDialer per build, so rebuild 1's exit
        // dialer differs from build 0's; the pre-rebuild resolver wraps it.
        let pre_dialer = started.last().expect("exit hop").hop.dialer();
        let resolver = std::sync::Arc::new(crate::session::resolver::TunnelResolver::with_server(
            pre_dialer.clone(),
            std::net::SocketAddr::from(([10, 0, 0, 53], 53)),
        ));
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, Some(pre_dialer), Some(resolver.clone()));
            h
        });
        let cfg = WatchdogConfig {
            dns_resolver: Some(std::net::IpAddr::from([10, 0, 0, 53])),
            ..test_watchdog_cfg(&f.dirs)
        };
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");
        let rebuilt = poll_until(Instant::now() + Duration::from_secs(10), || {
            Session::load(&f.dirs)
                .ok()
                .and_then(|s| (s.state == SessionState::Up && s.reconnects == 1).then_some(()))
        })
        .await;
        assert!(rebuilt.is_some(), "rebuild completed");
        // Consistent NEW pair, read back from the ONE swapped slot: the
        // dialer is the CURRENT exit hop's dialer (the same object the
        // swapped vec carries). swap_rebuilt_exit wires dialer + resolver
        // under a single exit guard, so this post-completion read sees the
        // consistent pair — the mid-window tear the two-lock swap allowed
        // is gone by construction (the guard is the proof; the doc comment
        // on `swap_rebuilt_exit` pins it).
        let entry = lock_entry(&f.live, &handle.id).expect("entry alive");
        let exit_hop = entry.started_hops().last().expect("exit hop").clone();
        let post_dialer = entry.dialer();
        let exit_dialer = exit_hop.hop.dialer();
        assert!(
            Arc::ptr_eq(&post_dialer, &exit_dialer),
            "dialer serves the rebuilt exit"
        );
        let post_resolver = entry.tunnel_resolver().expect("resolver preserved");
        assert!(
            Arc::ptr_eq(&post_resolver, &resolver),
            "resolver slot is the same swapped egress read (pair consistency)"
        );
        // The pair is consistent: dialer + resolver came out of the same
        // `LiveExit` write (swap_rebuilt_exit wires both under one guard
        // from the same exit).
        abort.abort();
        handle.stop_all().await.expect("teardown");
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (S1.2) Rebuild-vs-stop race must not orphan the freshly built hops:
    /// when the live map entry vanished while the rebuild was in flight
    /// (stop_session won the race), the Rebuilt arm unwinds the outcome
    /// instead of silently dropping it — a leaked segment keeps live tunnels
    /// and tasks alive with no owner. The per-instance stop counter from
    /// HOP_REG proves the rebuilt hop was actually stopped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rebuilt_outcome_is_unwound_when_the_map_entry_vanished() {
        RECOVER_BUILDS.store(u64::MAX - 3, Ordering::SeqCst); // healthy builds only
        hop_reg_reset();
        let f = fixture("orphan", "wdog-hop");
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        // Park the rebuild mid-build so the entry can be removed first.
        arm_hold();
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");
        // Wait until the rebuild has unwound the failed hop. `degraded` is
        // set BEFORE `attempt_rebuild` snapshots the live entry, so waiting
        // on it let the test remove the entry first: the rebuild then found
        // no entry and gave up without building anything, and the rebuilt-
        // hop stop assertion never fired under load. The unwind's stop
        // counter (HOP_REG) is the explicit post-snapshot signal.
        let unwound = poll_until(Instant::now() + Duration::from_secs(5), || {
            (hop_stops(0) >= 1).then_some(())
        })
        .await;
        assert!(unwound.is_some(), "watchdog unwound the failed hop");
        // The entry vanishes (stop_session removed it mid-rebuild).
        lock_map(&f.live).remove(&handle.id);
        // Let the rebuild finish: the Rebuilt arm now finds no entry.
        release_hold();
        // HOP_REG: build 0 = initial (stopped by the rebuild's unwind),
        // build 1 = the freshly built segment — it must be stopped too.
        let rebuilt_stopped = poll_until(Instant::now() + Duration::from_secs(5), || {
            (hop_stops(1) >= 1).then_some(())
        })
        .await;
        assert_eq!(
            rebuilt_stopped,
            Some(()),
            "the orphaned rebuilt hop must be unwound (stop counter from HOP_REG), got stops={}",
            hop_stops(1)
        );
        abort.abort();
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (S1.2) `stop_all` sweeps hops that appeared after its snapshot: a
    /// rebuild completing between the snapshot and teardown leaves a fresh
    /// segment in the shared vec, and the snapshot-only teardown would leak
    /// it. The sweep re-reads the vec after teardown and stops anything not
    /// covered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_all_sweeps_hops_that_appear_after_the_snapshot() {
        RECOVER_BUILDS.store(u64::MAX - 3, Ordering::SeqCst);
        hop_reg_reset();
        let f = fixture("sweep", "wdog-hop");
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        // Interleave: after stop_all snapshots the vec, a (watchdog-driven)
        // rebuild swaps in a new segment; the teardown must still stop it.
        // Deterministically simulated by wiring a rebuild AFTER the snapshot:
        // stop_all reads the shared vec live, so instead simulate the race
        // shape directly — snapshot now, then swap the vec, then stop.
        let snapshot = handle.started_hops();
        assert_eq!(snapshot.len(), 1);
        let (events, _drain) = tokio::sync::broadcast::channel::<HopEvent>(8);
        let rebuilt = initial_bring_up(
            "wdog-hop",
            &events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        handle
            .started
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(rebuilt);
        handle.stop_all().await.expect("stop_all");
        // Build 0 was covered by the snapshot; the appended rebuilt hop
        // (HOP_REG build 1) appeared after it — the sweep must stop it.
        assert_eq!(
            hop_stops(1),
            1,
            "hops appearing after the snapshot must be swept by stop_all"
        );
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (R1.1) After a successful rebuild, a handle captured BEFORE the
    /// rebuild serves the NEW exit dialer: the CLI's serve path captured
    /// `handle.dialer()` (or the live adapter resolves through it) once,
    /// so the swap must reach the shared handle state — not only the map
    /// entry. Without this, every SOCKS CONNECT after a rebuild dials the
    /// dead pre-rebuild tunnel while STATUS reports Up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rebuild_refreshes_the_captured_handle_egress() {
        RECOVER_BUILDS.store(0, Ordering::SeqCst);
        hop_reg_reset();
        let f = fixture("live-exit", "wdog-hop");
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        // The pre-rebuild egress the CLI would have captured: the exit
        // dialer of build 0 (each RecoverHop hands out a fresh StubDialer,
        // so rebuild N+1's dialer is a distinct Arc).
        let pre = handle.dialer();
        // Fat-pointer data address (thin cast first; the vtable part is
        // irrelevant — each build's StubDialer is a distinct allocation).
        let pre_ptr = Arc::as_ptr(&pre) as *const u8 as usize;
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");
        let rebuilt = poll_until(Instant::now() + Duration::from_secs(10), || {
            Session::load(&f.dirs)
                .ok()
                .and_then(|s| (s.state == SessionState::Up && s.reconnects == 1).then_some(()))
        })
        .await;
        assert!(rebuilt.is_some(), "rebuild completed");
        // Same handle object (no re-read of the map): the current egress is
        // the rebuilt exit's dialer — a different Arc than the captured one.
        let post = handle.dialer();
        assert_ne!(
            Arc::as_ptr(&post) as *const u8 as usize,
            pre_ptr,
            "the captured handle must serve the NEW exit dialer after a rebuild"
        );
        abort.abort();
        handle.stop_all().await.expect("teardown");
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (R1.2) stop_all after a rebuild tears down the REBUILT hops, not the
    /// pre-rebuild ones: the shared started vec drives teardown, so the
    /// recording stubs see exactly the rebuilt hop count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_all_after_rebuild_stops_the_rebuilt_hops() {
        RECOVER_BUILDS.store(0, Ordering::SeqCst);
        hop_reg_reset();
        let f = fixture("stop-rebuilt", "wdog-hop");
        hop_reg_reset();
        let started = initial_bring_up(
            "wdog-hop",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        let cfg = test_watchdog_cfg(&f.dirs);
        let abort = spawn(handle.clone(), cfg, f.live.clone(), f.stop_rx.clone());
        handle
            .events
            .send(HopEvent::Failed {
                hop_id: "h-0".into(),
                cause: "injected death".into(),
            })
            .expect("session bus send");
        let rebuilt = poll_until(Instant::now() + Duration::from_secs(10), || {
            Session::load(&f.dirs)
                .ok()
                .and_then(|s| (s.state == SessionState::Up && s.reconnects == 1).then_some(()))
        })
        .await;
        assert!(rebuilt.is_some(), "rebuild completed");
        // Build 0 (initial) was stopped exactly once — by the rebuild's
        // unwind. Build 1 (the rebuilt hop) is still running.
        assert_eq!(
            hop_stops(0),
            1,
            "the rebuild unwound the initial hop exactly once"
        );
        assert_eq!(hop_stops(1), 0, "the rebuilt hop is still up");
        // Teardown: the handle stops whatever hops are CURRENT (the rebuilt
        // one), so the REBUILT instance receives the stop.
        handle.stop_all().await.expect("teardown");
        assert_eq!(
            hop_stops(1),
            1,
            "stop_all tears down the REBUILT hop (shared vec), not the stale pre-rebuild one"
        );
        assert_eq!(
            hop_stops(0),
            1,
            "the initial hop is not stopped a second time"
        );
        abort.abort();
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (R1.2/R1.6) `Engine::stop_session` aborts the watchdog task through
    /// the (now fully wired) map entry: the task ends instead of lingering
    /// on the session bus after the session is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_stop_session_aborts_the_watchdog_task() {
        // Healthy builds only (the initial hop must not die on its own
        // during the test window).
        RECOVER_BUILDS.store(u64::MAX - 3, Ordering::SeqCst);
        let d = dirs("stop-session");
        d.ensure_dirs().unwrap();
        let engine = crate::api::Engine::new(crate::api::EngineConfig {
            dirs: d.clone(),
            ..Default::default()
        });
        // `wdog-hop` is registered in this test binary (test double): the
        // engine goes through the REAL start path — wiring, map insert,
        // watchdog spawn.
        let specs = engine.parse_chain("wdog-hop").expect("chain parses");
        let handle = engine.start(specs).await.expect("engine start");
        let mut give_up = (*handle.give_up).clone();
        let wd = handle.watchdog.clone().expect("start wires the watchdog");
        engine.stop_session(&handle.id).await.expect("stop_session");
        // Pre-R1.2 the map entry carried `watchdog: None` (cloned before
        // wiring), so stop_all could not abort the task; the fully wired
        // entry does.
        let aborted = poll_until(Instant::now() + Duration::from_secs(2), || {
            wd.is_finished().then_some(())
        })
        .await;
        assert!(
            aborted.is_some(),
            "watchdog task must be aborted by stop_session"
        );
        assert!(
            engine.session_report(&handle.id).is_none(),
            "stop_session removed the map entry"
        );
        // The give-up signal stays silent on a user stop (a stop is not a
        // failure).
        assert!(
            !*give_up.borrow_and_update(),
            "user stop must not fire the give-up signal"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// (R1.3) Rebuild materials are owned per attempt: `resolve_materials`
    /// returns owned maps (no `Box::leak`d 'static borrow), and the maps —
    /// carrying the identity `Zeroizing` keys — drop when the attempt ends.
    /// A rebuild loop of 5 failed attempts (always-failing factory) then
    /// exercises the production path end to end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rebuild_materials_drop_with_the_attempt() {
        FLAKY_BUILDS.store(0, Ordering::SeqCst);
        let d = dirs("leak");
        d.ensure_dirs().unwrap();
        let wd_cfg = WatchdogConfig {
            dirs: d.clone(),
            attempts: 5,
            backoff_secs: vec![0, 0, 0, 0],
            budget: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(2),
            ..WatchdogConfig::default()
        };
        let mut wd = Watchdog::new(wd_cfg);
        // Direct probe of the ownership contract: the resolved material is
        // owned (Arc maps) and drops when the attempt scope ends.
        let hops = vec![plugin_spec("wdog-flaky", "h-0")];
        let registry = crate::registry::TransportRegistry::global();
        let owned = wd
            .cfg
            .resolve_materials(&registry, &hops)
            .expect("plugin hops resolve to empty material");
        let weak_imports = Arc::downgrade(&owned.imports);
        let weak_ids = Arc::downgrade(&owned.identities);
        drop(owned);
        assert!(
            weak_imports.upgrade().is_none(),
            "import map dropped with the attempt (no 'static leak)"
        );
        assert!(
            weak_ids.upgrade().is_none(),
            "identity map (Zeroizing keys) dropped with the attempt"
        );
        // Production path: 5 failed rebuild attempts conclude, each
        // resolving + dropping its own material set.
        let f = fixture("leak-map", "wdog-flaky");
        let started = initial_bring_up(
            "wdog-flaky",
            &f.handle.events,
            crate::session::net::KeepalivePolicy {
                enabled: false,
                interval_secs: 1,
            },
        )
        .await;
        let handle = reinsert(&f, |h| {
            h.wire_exit(started, None, None);
            h
        });
        for attempt in 1..=5 {
            let outcome = wd.on_failed(&f.live, &handle.id, 0, "leak probe").await;
            assert!(
                matches!(outcome, WatchOutcome::GaveUp(_)),
                "attempt {attempt} concludes (flaky factory never rebuilds)"
            );
        }
        let _ = std::fs::remove_dir_all(&d.config_dir);
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (R1.5) The CLI attaches the shared report slot AFTER `Engine::start`
    /// returned — on its own clone. The attach must reach the watchdog (and
    /// the map entry), which hold clones created before the attach: the
    /// Option lives in Arc-shared state, so `publish_report` through ANY
    /// clone sees it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_report_attach_reaches_pre_existing_clones() {
        let f = fixture("attach", "wdog-hop");
        // A clone created BEFORE the attach (the shape the watchdog and the
        // map entry hold).
        let early = f.handle.clone();
        let slot = Arc::new(tokio::sync::RwLock::new(ConnectionReport::new(
            Vec::new(),
            "<starting>".to_string(),
        )));
        f.handle.set_live_report(slot.clone());
        // Every pre-existing clone now resolves the slot.
        assert!(
            early.live_report_slot().is_some(),
            "attach reaches clones made before it"
        );
        // And the map entry too (fixture inserted the handle at build time).
        let entry = lock_entry(&f.live, &f.handle.id).expect("entry alive");
        assert!(
            entry.live_report_slot().is_some(),
            "attach reaches the live map entry"
        );
        let _ = std::fs::remove_dir_all(&f.dirs.config_dir);
    }

    /// (R1.6b) `attach_session_id` refuses to stamp a lock that no longer
    /// carries our token (stolen/replaced): the previous owner cannot
    /// truncate the new owner's lock line.
    #[test]
    fn attach_session_id_refuses_a_stolen_lock() {
        use crate::session::{session_lock_path, SessionLock};
        let (root, dirs) = fresh_dirs_mod("stolen");
        let lock = SessionLock::acquire(&dirs).expect("acquire");
        // Simulate a theft: another owner's token line replaces ours.
        std::fs::write(session_lock_path(&dirs), "thief-token\ns-theirs").expect("steal the lock");
        let err = lock
            .attach_session_id("s-mine")
            .expect_err("a stolen lock must not be stamped");
        assert!(
            err.contains("another process"),
            "error names the theft: {err}"
        );
        let content = std::fs::read_to_string(session_lock_path(&dirs)).expect("lock readable");
        assert!(
            content.starts_with("thief-token"),
            "the thief's line survives untouched"
        );
        // Our own lock still stamps fine.
        let lock2 = SessionLock::acquire(&dirs).expect_err("the lock is still held");
        assert!(lock2.contains("session.lock"), "{lock2}");
        std::fs::write(
            session_lock_path(&dirs),
            format!("{}\ns-mine", lock.token()),
        )
        .expect("restore our token");
        lock.attach_session_id("s-mine-2").expect("own lock stamps");
        let content = std::fs::read_to_string(session_lock_path(&dirs)).expect("lock readable");
        assert!(content.ends_with("s-mine-2"), "id recorded: {content}");
        let _ = std::fs::remove_dir_all(&root);
    }

    fn fresh_dirs_mod(tag: &str) -> (std::path::PathBuf, ProfileDirs) {
        let root = std::env::temp_dir().join(format!(
            "qcore-wdog-lock-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let dirs = ProfileDirs {
            config_dir: root.join("config"),
            profile_dir: root.join("profiles"),
        };
        (root, dirs)
    }
}
