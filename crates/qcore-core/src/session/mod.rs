//! Session lifecycle, durable state, reconnect sink, report.
//!
//! State machine: `validating -> starting -> up -> (degraded) -> stopped`,
//! with `validating|starting|up -> failed` on error. No transition from
//! `failed` without a new session. Durable `session.json` distinguishes dead
//! vs unverifiable records (contracts/cli.md `status`).

pub mod control;
pub mod lifecycle;
pub mod nest;
pub mod net;
pub mod proxy;
pub mod reconnect;
pub mod report;
pub mod resolver;
pub mod watchdog;

use crate::chain::Chain;
use crate::config::profile_dir::ProfileDirs;
use crate::session::lifecycle::StartedHop;
use crate::session::net::FamilyPolicy;
use crate::session::report::{health_status, HopReport};
use qcore_transport_api::{
    ByteStream, Capabilities, Dialer, FailureReport, HopError, HopErrorKind, HopEvent, UdpFlow,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    Validating,
    Starting,
    Up,
    Degraded,
    Failed,
    Stopped,
}

/// Typed illegal-transition error (issue #16: `Result<_, String>` → typed
/// errors where the boundary demands it).
///
/// `Session::transition` keeps its `Result<(), String>` signature (no
/// breaking change): it delegates to [`Session::transition_checked`] and
/// renders the typed error. New callers that match on failure modes should
/// use `transition_checked` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    pub from: SessionState,
    pub to: SessionState,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal session transition {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}

/// Durable session record (`session.json`). Never contains secrets: the chain
/// carries only `import_ref`s, never keys.
///
/// `reconnects` is additive (#serde default): records written before F2 read
/// back with `0`, and future readers ignore unknown fields — an old binary
/// reading a new record is fine (serde deny-unknown is NOT set here for this
/// reason, pinned by the round-trip test below).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub chain: ChainSer,
    pub family_policy: FamilyPolicy,
    pub state: SessionState,
    pub started_at: u64,
    pub failure: Option<FailureReport>,
    /// Successful in-place hop rebuilds by the watchdog (F2). Monotonic per
    /// session; `0` for records predating the watchdog (serde default).
    #[serde(default)]
    pub reconnects: u32,
}

/// Serializable chain summary stored in the session record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSer {
    pub hops: Vec<crate::config::HopSpec>,
    pub max_depth: u32,
}

impl From<&Chain> for ChainSer {
    fn from(c: &Chain) -> Self {
        ChainSer {
            hops: c.hops.clone(),
            max_depth: c.max_depth,
        }
    }
}

impl Session {
    pub fn new(id: String, chain: &Chain, family_policy: FamilyPolicy, now: u64) -> Self {
        Session {
            id,
            chain: ChainSer::from(chain),
            family_policy,
            state: SessionState::Validating,
            started_at: now,
            failure: None,
            reconnects: 0,
        }
    }

    /// Enforce the state machine. Failing transitions are programming errors.
    /// Kept for compatibility; delegates to [`Session::transition_checked`].
    pub fn transition(&mut self, to: SessionState) -> Result<(), String> {
        self.transition_checked(to).map_err(|e| e.to_string())
    }

    /// Enforce the state machine, returning a typed [`TransitionError`].
    /// Prefer this in new code that matches on failure modes.
    pub fn transition_checked(&mut self, to: SessionState) -> Result<(), TransitionError> {
        let from = self.state;
        let ok = matches!(
            (from, to),
            (SessionState::Validating, SessionState::Starting)
                | (SessionState::Validating, SessionState::Failed)
                | (SessionState::Starting, SessionState::Up)
                | (SessionState::Starting, SessionState::Failed)
                | (SessionState::Up, SessionState::Degraded)
                | (SessionState::Up, SessionState::Stopped)
                | (SessionState::Up, SessionState::Failed)
                | (SessionState::Degraded, SessionState::Up)
                | (SessionState::Degraded, SessionState::Stopped)
                | (SessionState::Degraded, SessionState::Failed)
        );
        if ok {
            self.state = to;
            Ok(())
        } else {
            Err(TransitionError { from, to })
        }
    }

    pub fn fail(&mut self, report: FailureReport) {
        self.failure = Some(report);
        let _ = self.transition(SessionState::Failed);
        // `transition` to Failed is legal from validating/starting/up/degraded;
        // force it for terminal bookkeeping even from stopped.
        self.state = SessionState::Failed;
    }

    /// Persist the durable session record atomically: serialize first, then
    /// write a uniquely-named temp sibling in the same directory, harden its
    /// permissions (`0600` on Unix; Windows inherits the directory ACL — see
    /// `control::write_control_file`), and rename over `session.json` so a
    /// process crash never leaves a torn record for the next `read()` to
    /// misread (power loss is a different failure class: no `sync_all` yet,
    /// owned by the durability wave). Synchronous fs on purpose: the state
    /// machine saves from sync paths.
    ///
    /// A present-but-unparseable destination (crash/disk-full tear) is
    /// backed up to `session.json.corrupt` before the replace — forensics
    /// are kept, the torn record is never silently clobbered (same contract
    /// as `reconnect::ensure_identity`).
    pub fn save(&self, dirs: &ProfileDirs) -> std::io::Result<()> {
        dirs.ensure_dirs()?;
        let dest = dirs.session_file();
        if let Ok(raw) = std::fs::read_to_string(&dest) {
            if serde_json::from_str::<Session>(&raw).is_err() {
                let backup = dest.with_extension("json.corrupt");
                let _ = std::fs::write(&backup, &raw);
            }
        }
        let json = serde_json::to_string_pretty(self).expect("session serializes");
        atomic_write_session(&dest, json.as_bytes())
    }

    pub fn load(dirs: &ProfileDirs) -> std::io::Result<Session> {
        let raw = std::fs::read_to_string(dirs.session_file())?;
        serde_json::from_str(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Atomic temp+rename write for the session record, mirroring
/// [`crate::session::control::write_control_file`] (same permissions story).
fn atomic_write_session(dest: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    let tmp = control::temp_sibling_for(dest);
    let write_res = (|| {
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            use std::io::Write as _;
            f.write_all(body)?;
            f.flush()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        control::rename_with_retry(&tmp, dest)?;
        Ok::<(), std::io::Error>(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_res
}

/// Blocking over the control channel: converge a probe outcome to the
/// durable record (and drop the stale rendezvous when convergence proves
/// the control file points at a dead-or-foreign listener). Shared by the
/// status confirmation path and the stop path.
fn converge_dead(dirs: &ProfileDirs, session: &Session) {
    let mut dead = session.clone();
    dead.state = SessionState::Stopped;
    // Best-effort on purpose: the control probe already proved death, so a
    // save failure must not turn a conclusive verdict into Unverifiable.
    // The next `status` re-probes and converges again.
    let _ = dead.save(dirs);
    control::remove_control_file(dirs);
}

/// Handle to a live session (US1 lifecycle populates running hops).
/// Cloneable so the engine can track live sessions while callers hold one.
///
/// The mutable session surfaces are shared state, not per-clone copies:
/// the engine, the CLI, and the watchdog all hold clones of one handle, and
/// the F2 watchdog swaps hops/exits on rebuild — every holder must observe
/// the swap. `started` and `exit` are therefore `Arc<RwLock<..>>` and the
/// accessors (`dialer`, `tunnel_resolver`, `hop_reports`, `stop_all`) read
/// the CURRENT contents at call time.
///
/// F2 fields (all additive, defaulted via [`SessionHandle::bare`]):
/// - `stop_signal`: the session's stop broadcast, selected by the watchdog
///   so `stop()` interrupts a rebuild promptly (watch → abort).
/// - `live_report`: the control-channel report slot the CLI publishes into;
///   the watchdog refreshes it on degrade/rebuild (state string
///   `"degraded"` + reconnect count) — the listener itself is untouched.
/// - `reconnects`/`degraded`: atomic mirrors of the watchdog state so the
///   engine's own reporting path never needs the record file.
/// - `watchdog`: abort handle owned like the per-hop watcher handles —
///   teardown aborts before stopping hops.
/// - `give_up`: watchdog terminal signal (watch, `true` = gave up); the
///   serving CLI selects on it and exits the process with the failure
///   report instead of idling on a Failed session holding the lock.
#[derive(Clone)]
pub struct SessionHandle {
    pub id: String,
    pub exit_hop_id: String,
    pub chain: ChainSer,
    /// Current hops, shared across handle clones: the watchdog replaces the
    /// contents after unwind+rebuild, so `stop_all`/reports/egress always
    /// see whatever hops are live right now. A std lock is deliberate: the
    /// critical sections only clone/swap a `Vec<Arc<..>>` (no await, no IO
    /// while held), and every consumer — engine reports, FFI, the CLI proxy
    /// serve loop — is sync or must not block on the runtime.
    pub(crate) started: Arc<std::sync::RwLock<Vec<StartedHop>>>,
    /// Current egress (exit dialer + tunnel resolver), refreshed by the
    /// watchdog on rebuild so a CLI proxy that captured this handle serves
    /// new connections through the rebuilt exit without learning about
    /// rebuilds. `None` dialer = fall back to the live exit hop (the
    /// bare/embedder shape where no swap can occur).
    pub(crate) exit: Arc<std::sync::RwLock<LiveExit>>,
    pub events: tokio::sync::broadcast::Sender<HopEvent>,
    /// Stop broadcast (`watch`): flipped by the session's stop path; the
    /// watchdog selects on it. `false` = running.
    pub stop_signal: Arc<tokio::sync::watch::Sender<bool>>,
    /// Live report slot served by the control channel (`None` for
    /// embedders whose status reads the engine map directly). Shared-state
    /// holder: the CLI attaches the slot AFTER `Engine::start` returned
    /// (the slot's content is built from the started hops), and the attach
    /// must reach the watchdog — which holds earlier handle clones — so the
    /// Option lives inside an Arc the clones share (`set_live_report`).
    pub(crate) live_report:
        Arc<std::sync::RwLock<Option<Arc<tokio::sync::RwLock<report::ConnectionReport>>>>>,
    /// Successful watchdog rebuilds so far (0 until the first one).
    pub reconnects: Arc<std::sync::atomic::AtomicU32>,
    /// True while the watchdog is rebuilding (degraded window).
    pub degraded: Arc<std::sync::atomic::AtomicBool>,
    /// Watchdog abort handle, set once the engine spawns the task.
    /// Same ownership rule as keepalive/forwarder: teardown aborts.
    pub(crate) watchdog: Option<tokio::task::AbortHandle>,
    /// Watchdog give-up signal (`true` = terminal Failed, hops unwound,
    /// entry removed). The serving CLI selects on it to exit the process.
    pub give_up: Arc<tokio::sync::watch::Receiver<bool>>,
    /// Sender half of [`SessionHandle::give_up`] (watchdog terminal path).
    /// Held by the handle so the receiver never reads `Closed`.
    pub(crate) give_up_tx: Arc<tokio::sync::watch::Sender<bool>>,
}

/// The current egress of a session: what new proxy connections dial through.
/// The watchdog swaps both fields after a successful rebuild; the initial
/// value is set by `Engine::start` from the freshly brought-up exit hop.
#[derive(Clone, Default)]
pub struct LiveExit {
    pub dialer: Option<Arc<dyn Dialer>>,
    pub resolver: Option<Arc<crate::session::resolver::TunnelResolver>>,
}

/// Egress for a session whose hops are gone (watchdog give-up cleared the
/// started vec and reset the exit slot): every dial fails closed with a
/// clear cause instead of panicking on the missing-hop fallback. Per-hop
/// capabilities honestly report "dials nothing", so the proxy's UDP gate
/// refuses and per-connection SOCKS tasks reply 0x01 cleanly.
struct DeadDialer;

const DEAD_EGRESS_MSG: &str = "session exited: egress is dead (watchdog gave up)";

#[async_trait::async_trait]
impl Dialer for DeadDialer {
    async fn dial_tcp(&self, _dst: std::net::SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        Err(HopError::new(HopErrorKind::Shutdown, None, DEAD_EGRESS_MSG))
    }

    async fn dial_udp(&self, _dst: std::net::SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        Err(HopError::new(HopErrorKind::Shutdown, None, DEAD_EGRESS_MSG))
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

/// Egress adapter that stays live across watchdog rebuilds (R1.1): the proxy
/// serve path captures ONE dialer for the session's lifetime, so it must
/// consult the handle's CURRENT exit per dial — a once-evaluated `Arc<dyn
/// Dialer>` pins the pre-rebuild tunnel and every CONNECT after a successful
/// rebuild would fail against the dead exit while STATUS reports Up.
/// Delegation is per-call (each CONNECT dials once through `dialer()`);
/// capabilities read the current exit too (family gating follows the live
/// chain, not a dead one).
struct LiveDialer {
    handle: SessionHandle,
}

#[async_trait::async_trait]
impl Dialer for LiveDialer {
    async fn dial_tcp(&self, dst: std::net::SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
        self.handle.dialer().dial_tcp(dst).await
    }

    async fn dial_udp(&self, dst: std::net::SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
        self.handle.dialer().dial_udp(dst).await
    }

    fn capabilities(&self) -> Capabilities {
        self.handle.dialer().capabilities()
    }

    fn nested_mtu(&self) -> Option<u16> {
        self.handle.dialer().nested_mtu()
    }
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let started = self.started_hops();
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("exit_hop_id", &self.exit_hop_id)
            .field("resolver", &self.tunnel_resolver().is_some())
            .field(
                "degraded",
                &self.degraded.load(std::sync::atomic::Ordering::SeqCst),
            )
            .field(
                "reconnects",
                &self.reconnects.load(std::sync::atomic::Ordering::SeqCst),
            )
            .field(
                "hops",
                &started.iter().map(|s| s.hop_id.clone()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl SessionHandle {
    /// Test/embedder-facing constructor defaulting every F2 field (fresh
    /// stop signal, no report slot, zero reconnects, no watchdog yet).
    /// Production builds handles through [`crate::api::Engine::start`].
    pub fn bare(
        id: impl Into<String>,
        exit_hop_id: impl Into<String>,
        chain: ChainSer,
        started: Vec<StartedHop>,
        events: tokio::sync::broadcast::Sender<HopEvent>,
    ) -> Self {
        let (stop_tx, _) = tokio::sync::watch::channel(false);
        let (give_up_tx, give_up_rx) = tokio::sync::watch::channel(false);
        SessionHandle {
            id: id.into(),
            exit_hop_id: exit_hop_id.into(),
            chain,
            started: Arc::new(std::sync::RwLock::new(started)),
            exit: Arc::new(std::sync::RwLock::new(LiveExit::default())),
            events,
            stop_signal: Arc::new(stop_tx),
            live_report: Arc::new(std::sync::RwLock::new(None)),
            reconnects: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            degraded: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            watchdog: None,
            give_up: Arc::new(give_up_rx),
            give_up_tx: Arc::new(give_up_tx),
        }
    }

    /// Snapshot of the current hops (post-any-rebuild). Short std lock:
    /// clones the `Vec<Arc<..>>` out, never held across an await.
    pub fn started_hops(&self) -> Vec<StartedHop> {
        self.started
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Set the initial (pre-watchdog) hops and egress. Called once by
    /// `Engine::start` after bring-up; later swaps belong to the watchdog.
    pub(crate) fn wire_exit(
        &self,
        started: Vec<StartedHop>,
        dialer: Option<Arc<dyn Dialer>>,
        resolver: Option<Arc<crate::session::resolver::TunnelResolver>>,
    ) {
        *self.write_started() = started;
        *self.write_exit() = LiveExit { dialer, resolver };
    }

    /// Sender half of the give-up signal (watchdog terminal path).
    pub(crate) fn give_up_sender(&self) -> Arc<tokio::sync::watch::Sender<bool>> {
        self.give_up_tx.clone()
    }

    /// A dialer that stays live across watchdog rebuilds (R1.1): every dial
    /// delegates to the CURRENT exit dialer. The proxy serve path captures
    /// one dialer for the session's lifetime — a once-evaluated `Arc<dyn
    /// Dialer>` would pin the pre-rebuild tunnel and every CONNECT after a
    /// successful rebuild would fail against the dead exit while STATUS
    /// reports Up.
    pub fn live_dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(LiveDialer {
            handle: self.clone(),
        })
    }

    /// Attach the control-channel report slot. Reaches every handle clone
    /// (the watchdog's included — the Option is shared through an Arc), so
    /// a CLI attaching the slot after `start` still gets watchdog
    /// degrade/reconnect publishes on it (R1.5).
    pub fn set_live_report(&self, slot: Arc<tokio::sync::RwLock<report::ConnectionReport>>) {
        *self
            .live_report
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(slot);
    }

    /// The attached report slot, if any (watchdog publish path).
    pub fn live_report_slot(&self) -> Option<Arc<tokio::sync::RwLock<report::ConnectionReport>>> {
        self.live_report
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Poison-tolerant write guard (same restore policy as the live map).
    fn write_started(&self) -> std::sync::RwLockWriteGuard<'_, Vec<StartedHop>> {
        self.started
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_exit(&self) -> std::sync::RwLockWriteGuard<'_, LiveExit> {
        self.exit
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Egress of the CURRENT exit hop (fresh Arc per call): after a watchdog
    /// rebuild this is the rebuilt exit, so per-connection reads in the
    /// proxy serve path always dial the live chain. When the session's hops
    /// are gone (give-up cleared the vec and reset the exit slot) this fails
    /// closed with a dead dialer — between give-up and process exit,
    /// per-connection tasks holding the handle get a clean dial error, never
    /// a panic.
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        if let Some(d) = self
            .exit
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .dialer
            .clone()
        {
            return d;
        }
        if let Some(hop) = self.started_hops().last() {
            return hop.hop.dialer();
        }
        Arc::new(DeadDialer)
    }

    /// Tunnel resolver over the CURRENT exit hop's UDP egress, if one was
    /// wired (and re-wired by the watchdog after rebuilds).
    pub fn tunnel_resolver(&self) -> Option<Arc<crate::session::resolver::TunnelResolver>> {
        self.exit
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolver
            .clone()
    }

    /// Per-hop family/endpoint/status/nesting/obfuscation/drops in declared
    /// order (of the CURRENT hops — post-rebuild after a swap).
    pub fn hop_reports(&self) -> Vec<HopReport> {
        self.started_hops()
            .iter()
            .map(|s| HopReport {
                hop_id: s.hop_id.clone(),
                kind: s.kind.clone(),
                family: s.family.clone(),
                endpoint: s.endpoint.clone(),
                status: health_status(s.hop.health()),
                via: s.via.clone(),
                nested: s.nested,
                mtu: s.inner_mtu,
                obfuscation: s.obfuscation.clone(),
                dropped: s.congested_drops.load(std::sync::atomic::Ordering::Relaxed),
            })
            .collect()
    }

    /// Tear down all hops reverse-order (exit first). Keepalive watchers and
    /// event forwarders are aborted before their hops stop (same ownership
    /// rule as `unwind`). The session stop signal flips FIRST so the F2
    /// watchdog selects out of a rebuild promptly — a stop never waits out
    /// the reconnect budget — and the watchdog task itself aborts with the
    /// other watchers.
    /// The CURRENT hop set is torn down (the shared vec: a rebuilt session
    /// stops the rebuilt hops, not the pre-rebuild ones).
    /// Best effort like `unwind`: a failing exit hop must not abandon inner
    /// hops still running.
    pub async fn stop_all(&self) -> Result<(), qcore_transport_api::HopError> {
        let mut first_err = None;
        // Signal + abort the watchdog and every per-hop watcher first, yield
        // so aborts land, then stop hops: same anti-race phasing as `unwind`.
        let _ = self.stop_signal.send(true);
        if let Some(wd) = &self.watchdog {
            wd.abort();
        }
        // The CURRENT hop set (shared vec): a post-rebuild teardown stops
        // the rebuilt hops, not the pre-rebuild ones (R1.2).
        let started = self.started_hops();
        let stopped_ids: std::collections::HashSet<String> =
            started.iter().map(|s| s.hop_id.clone()).collect();
        for s in started.iter() {
            if let Some(keepalive) = &s.keepalive {
                keepalive.abort();
            }
            if let Some(forwarder) = &s.forwarder {
                forwarder.abort();
            }
        }
        tokio::task::yield_now().await;
        for s in started.iter().rev() {
            if let Err(e) = s.hop.stop().await {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        // Sweep the race window (S1.2): a rebuild completing between the
        // snapshot above and teardown swaps a fresh segment into the shared
        // vec — snapshot-only teardown would orphan it (live tunnels, no
        // owner). Re-read the vec and stop anything the snapshot did not
        // cover (matched by hop id; a same-id rebuild replaced hops the
        // snapshot already stopped). Best effort like the main loop: the
        // sweep never abandons remaining hops on an error.
        let late = self.started_hops();
        let late_uncovered: Vec<&crate::session::lifecycle::StartedHop> = late
            .iter()
            .filter(|s| !stopped_ids.contains(&s.hop_id))
            .collect();
        if !late_uncovered.is_empty() {
            for s in late_uncovered.iter() {
                if let Some(keepalive) = &s.keepalive {
                    keepalive.abort();
                }
                if let Some(forwarder) = &s.forwarder {
                    forwarder.abort();
                }
            }
            tokio::task::yield_now().await;
            for s in late_uncovered.into_iter().rev() {
                if let Err(e) = s.hop.stop().await {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }
}

/// Honest status read from the state dir (contracts/cli.md `status`):
/// a live-looking record is confirmed over the token-authenticated control
/// channel; refused/unreachable confirms the process is dead; anything else
/// is `Unverifiable` (fail closed, never a false green).
///
/// Convergence guarantee: when the listener explicitly answers `ERR bad
/// token`, the record is proven stale — our session always holds the token,
/// so a port owned by a *different* session (or a later session reusing the
/// port) answered. That is proof of death for *our* session, and the probe
/// converges to [`SessionStatus::Dead`], persisting the record as Stopped
/// and dropping the stale rendezvous. Silence, refusal (connection refused),
/// or timeouts stay `Unverifiable` where they carry no such proof
/// (`ConnectionRefused` still proves death: nothing is listening).
///
/// Start gating: before bringing up a new session, call
/// [`SessionStatus::assert_startable`] — a Live or Unverifiable record means
/// another session may still own the control channel, and a second start
/// would orphan the first.
#[derive(Debug)]
pub enum SessionStatus {
    NotRunning,
    Dead { id: String },
    Unverifiable { session: Session },
    Live { report: report::ConnectionReport },
}

/// Why a new session must not start. Actionable: the message names the
/// blocking record and the command that clears it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartBlocker {
    pub reason: String,
}

impl std::fmt::Display for StartBlocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for StartBlocker {}

/// Synthetic session for an unparseable record: the id is unknown (the file
/// could not be read), so callers fail closed on the variant, not the id.
fn corrupt_placeholder() -> Session {
    Session {
        id: "unknown".to_string(),
        chain: ChainSer {
            hops: Vec::new(),
            max_depth: 0,
        },
        family_policy: FamilyPolicy::default(),
        state: SessionState::Up,
        started_at: 0,
        failure: None,
        reconnects: 0,
    }
}

impl SessionStatus {
    pub fn read(dirs: &ProfileDirs) -> SessionStatus {
        let session = match Session::load(dirs) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SessionStatus::NotRunning,
            // A present-but-unparseable record is not "no session": fail
            // closed as unverifiable, never a false green or a false empty.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                return SessionStatus::Unverifiable {
                    session: corrupt_placeholder(),
                }
            }
            // Any other read error (permissions, sharing violations) still
            // means a record we cannot read: fail closed, never a false
            // "no session".
            Err(_) => {
                return SessionStatus::Unverifiable {
                    session: corrupt_placeholder(),
                }
            }
            Ok(s) => s,
        };
        match session.state {
            SessionState::Stopped | SessionState::Failed => SessionStatus::Dead { id: session.id },
            _ => Self::confirm(&session, dirs),
        }
    }

    /// Confirm a live-looking record over the control channel. The only
    /// replies that prove anything:
    /// - a well-formed `ConnectionReport` → Live;
    /// - `ERR bad token` → the listener is *not* our session (ours always
    ///   holds the token) → Dead + records converged;
    /// - connection refused → nothing listens there → Dead + converged.
    ///
    /// Everything else (timeouts, protocol garbage) proves nothing →
    /// Unverifiable, records untouched.
    fn confirm(session: &Session, dirs: &ProfileDirs) -> SessionStatus {
        let Some(info) = control::read_control_file(dirs) else {
            // No control rendezvous (pre-detach record, crashed writer):
            // cannot confirm liveness -> fail closed.
            return SessionStatus::Unverifiable {
                session: session.clone(),
            };
        };
        let addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            info.port,
        );
        match control::query_status(addr, &info.token) {
            Ok(doc) => match serde_json::from_str::<report::ConnectionReport>(&doc) {
                Ok(report) => SessionStatus::Live { report },
                Err(_) => SessionStatus::Unverifiable {
                    session: session.clone(),
                },
            },
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // `query_status` maps a non-OK protocol reply to
                // PermissionDenied carrying the reply line. `ERR bad token`
                // is the listener proving it is NOT our session (ours holds
                // this token): converge to dead. Any other ERR text stays
                // unverifiable — it proves nothing about our session.
                if e.to_string().starts_with("ERR bad token") {
                    converge_dead(dirs, session);
                    SessionStatus::Dead {
                        id: session.id.clone(),
                    }
                } else {
                    SessionStatus::Unverifiable {
                        session: session.clone(),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                converge_dead(dirs, session);
                SessionStatus::Dead {
                    id: session.id.clone(),
                }
            }
            Err(_) => SessionStatus::Unverifiable {
                session: session.clone(),
            },
        }
    }

    /// Stop-path probe verdict for a live-looking record: what the control
    /// channel reply proves about *our* session. `BadToken` is conclusive
    /// (the listener is foreign — ours always holds the token); CLI `stop`
    /// consumes this to converge instead of stopping at Unverifiable.
    pub fn stop_probe(dirs: &ProfileDirs) -> StopProbeVerdict {
        let session = match Session::load(dirs) {
            Ok(s) => s,
            Err(_) => return StopProbeVerdict::NoRecord,
        };
        match session.state {
            SessionState::Stopped | SessionState::Failed => StopProbeVerdict::AlreadyDead,
            _ => {
                let Some(info) = control::read_control_file(dirs) else {
                    return StopProbeVerdict::Unverifiable;
                };
                let addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    info.port,
                );
                match control::query_status(addr, &info.token) {
                    Ok(_) => StopProbeVerdict::Live,
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        if e.to_string().starts_with("ERR bad token") {
                            // Foreign listener on the rendezvous port: our
                            // session is gone. Converge the records so the
                            // next status reports dead, not stale-up.
                            converge_dead(dirs, &session);
                            StopProbeVerdict::BadToken
                        } else {
                            StopProbeVerdict::Unverifiable
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        converge_dead(dirs, &session);
                        StopProbeVerdict::Dead
                    }
                    Err(_) => StopProbeVerdict::Unverifiable,
                }
            }
        }
    }

    /// Start gate: an actionable error when a previous session record still
    /// claims the profile — Live (confirmed running) or Unverifiable
    /// (present, cannot disprove). Starting a second session would orphan
    /// the first's control channel. Dead and absent records start cleanly.
    ///
    /// Note the asymmetry with [`SessionStatus::read`]: this gate does NOT
    /// probe the control channel (no socket opens here — a start gate is
    /// called on the hot path before validation, and a wedged listener must
    /// not hang every start). A stale-Live-looking record is still refused:
    /// `qcore stop` converges it cheaply, and the message says so.
    pub fn assert_startable(dirs: &ProfileDirs) -> Result<(), StartBlocker> {
        let session = match Session::load(dirs) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            // Unparseable record: fail closed — a torn record may hide a
            // live session (its control channel would still answer).
            Err(_) => {
                return Err(StartBlocker {
                    reason: "existing session record is unreadable — run `qcore stop` first"
                        .to_string(),
                })
            }
            Ok(s) => Some(s),
        };
        if let Some(session) = &session {
            if !matches!(session.state, SessionState::Stopped | SessionState::Failed) {
                return Err(StartBlocker {
                    reason: format!(
                        "session already running (id {}); `qcore stop` first",
                        session.id
                    ),
                });
            }
        }
        // The record is absent or terminal, but a starter may own the lock
        // already (`session.json` lands only after the hops are up). A
        // stale lock is ignored here and stolen by `SessionLock::acquire`.
        if let Some(id) = fresh_session_lock(dirs) {
            return Err(StartBlocker {
                reason: if id.is_empty() {
                    "another connect is starting (session.lock is held); retry once it is up"
                        .to_string()
                } else {
                    format!("session already running (id {id}); `qcore stop` first")
                },
            });
        }
        Ok(())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            SessionStatus::Live { .. } => 0,
            SessionStatus::NotRunning => 10,
            SessionStatus::Dead { .. } => 1,
            SessionStatus::Unverifiable { .. } => 12,
        }
    }
}

/// What the stop-path probe proved (see [`SessionStatus::stop_probe`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopProbeVerdict {
    /// No durable record: nothing to stop or converge.
    NoRecord,
    /// Record exists but is already terminal (Stopped/Failed).
    AlreadyDead,
    /// The control channel answered STATUS with a live report.
    Live,
    /// Nothing listens on the rendezvous port: session dead, records
    /// converged.
    Dead,
    /// The listener explicitly rejected our token: it is not our session.
    /// Conclusive proof our session is gone; records converged.
    BadToken,
    /// The reply carried no proof either way: fail closed.
    Unverifiable,
}

/// `session.json` is written only after the hops are up, so two `connect`
/// processes can both pass [`SessionStatus::assert_startable`] during the
/// startup window and then race over `control.json`/`session.json`. This
/// lock closes that window: `create_new` plus an owner token (the same
/// pattern as `identity::store::acquire_lock`), taken before the first
/// durable write and held until the session stops.
///
/// Staleness is age-based (10 minutes), mirroring the identity lock. A live
/// session past that age cannot be stolen in practice: its `session.json`
/// exists, and the start gate refuses on the record before the lock is even
/// considered. The lock's own verdict is authoritative only for the
/// pre-record window.
pub struct SessionLock {
    path: std::path::PathBuf,
    token: String,
}

const SESSION_LOCK_STALE: std::time::Duration = std::time::Duration::from_secs(600);

impl std::fmt::Debug for SessionLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLock")
            .field("path", &self.path)
            .field("token", &"<redacted>")
            .finish()
    }
}

pub fn session_lock_path(dirs: &ProfileDirs) -> std::path::PathBuf {
    dirs.config_dir.join("session.lock")
}

fn session_lock_token() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}-{n}", std::process::id())
}

fn session_lock_is_stale(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| t.elapsed().map(|d| d > SESSION_LOCK_STALE).unwrap_or(false))
        .unwrap_or(false)
}

/// Session id recorded by a fresh lock, if one exists (`Some("")` when the
/// file is unreadable/truncated: still held, just unnamed).
fn fresh_session_lock(dirs: &ProfileDirs) -> Option<String> {
    let path = session_lock_path(dirs);
    if session_lock_is_stale(&path) {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    Some(content.lines().nth(1).unwrap_or("").trim().to_string())
}

impl SessionLock {
    /// Take the session lock, stealing a stale (crashed predecessor) one.
    pub fn acquire(dirs: &ProfileDirs) -> Result<SessionLock, String> {
        dirs.ensure_dirs()
            .map_err(|e| format!("session lock dir unavailable: {e}"))?;
        let path = session_lock_path(dirs);
        let token = session_lock_token();
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write as _;
                // Best-effort owner mark: an untagged lock still excludes
                // (create_new won), it just cannot be stolen precisely.
                let _ = f.write_all(token.as_bytes());
                Ok(SessionLock { path, token })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if session_lock_is_stale(&path) {
                    let _ = std::fs::remove_file(&path);
                    return SessionLock::acquire(dirs);
                }
                Err("another session is starting or running (session.lock is held); wait for it to \
                     come up or run `qcore stop`"
                    .to_string())
            }
            Err(e) => Err(format!("session lock failed: {e}")),
        }
    }

    /// Owner token, used to prove this process still holds the lock.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Record the engine-assigned session id for diagnostics and for the
    /// next starter's blocker message. The token line stays first. The
    /// overwrite is owner-checked: if the lock file no longer carries our
    /// token (stolen by another starter), fail instead of truncating the
    /// new owner's lock (R1.6).
    pub fn attach_session_id(&self, session_id: &str) -> Result<(), String> {
        use std::io::Write as _;
        // Read-modify-write under an ownership check: a plain truncate-open
        // would clobber a thief's token line between the read and the write.
        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("session lock update failed: {e}"))?;
        if content.lines().next() != Some(self.token.as_str()) {
            return Err("session lock is held by another process; id not recorded".to_string());
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|e| format!("session lock update failed: {e}"))?;
        f.write_all(format!("{}\n{session_id}", self.token).as_bytes())
            .map_err(|e| format!("session lock update failed: {e}"))
    }

    /// Fail when the file no longer carries our token (stolen or replaced).
    pub fn assert_ours(&self, dirs: &ProfileDirs) -> Result<(), String> {
        let path = session_lock_path(dirs);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("session lock `{}`: {e}", path.display()))?;
        if content.lines().next() == Some(self.token.as_str()) {
            Ok(())
        } else {
            Err(format!(
                "session lock `{}` is held by another process",
                path.display()
            ))
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        // Only unlink our own lock (same contract as the identity lock): a
        // stale-steal by another process must not be undone here.
        match std::fs::read_to_string(&self.path) {
            Ok(content) if content.lines().next() == Some(self.token.as_str()) => {
                let _ = std::fs::remove_file(&self.path);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use crate::config::{HopConfig, TorConfig};

    fn session() -> Session {
        let chain = Chain {
            hops: vec![crate::config::HopSpec {
                id: "tor0".into(),
                config: HopConfig::Tor(TorConfig {
                    family: "dual".into(),
                }),
            }],
            max_depth: 3,
        };
        Session::new("s1".into(), &chain, FamilyPolicy::default(), 0)
    }

    #[test]
    fn happy_path_transitions() {
        let mut s = session();
        s.transition(SessionState::Starting).unwrap();
        s.transition(SessionState::Up).unwrap();
        s.transition(SessionState::Degraded).unwrap();
        s.transition(SessionState::Stopped).unwrap();
    }

    #[test]
    fn no_transition_from_failed_without_new_session() {
        let mut s = session();
        s.transition(SessionState::Starting).unwrap();
        s.fail(FailureReport::new(
            qcore_transport_api::FailureLayer::Transport,
            "tor0",
            "boom",
            "dial",
        ));
        assert_eq!(s.state, SessionState::Failed);
        assert!(s.transition(SessionState::Up).is_err());
        assert!(s.transition(SessionState::Stopped).is_err());
    }

    #[test]
    fn typed_transition_names_both_states() {
        let mut s = session();
        let err = s
            .transition_checked(SessionState::Up)
            .expect_err("validating -> up is illegal");
        assert_eq!(
            err,
            TransitionError {
                from: SessionState::Validating,
                to: SessionState::Up,
            }
        );
        assert_eq!(
            err.to_string(),
            "illegal session transition Validating -> Up"
        );
        // Compat shim renders the same message.
        assert_eq!(s.transition(SessionState::Up).unwrap_err(), err.to_string());
    }

    #[test]
    fn missing_state_file_is_not_running() {
        let dirs = ProfileDirs::resolve(
            Some(std::env::temp_dir().join(format!("qcore-nostate-{}", std::process::id()))),
            None,
        );
        assert!(matches!(
            SessionStatus::read(&dirs),
            SessionStatus::NotRunning
        ));
        assert_eq!(SessionStatus::NotRunning.exit_code(), 10);
    }

    fn fresh_dirs(tag: &str) -> (std::path::PathBuf, ProfileDirs) {
        let root = std::env::temp_dir().join(format!(
            "qcore-status-{tag}-{}-{}",
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

    /// Serve one control-channel listener that always rejects the token, on
    /// a fresh loopback port. Returns (addr, shutdown-join).
    async fn serve_bad_token_listener() -> std::net::SocketAddr {
        use tokio::io::AsyncBufReadExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut lines = tokio::io::BufReader::new(r).lines();
                    let _ = lines.next_line().await;
                    use tokio::io::AsyncWriteExt as _;
                    let _ = w.write_all(b"ERR bad token\n").await;
                });
            }
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bad_token_probe_converges_to_dead_not_unverifiable() {
        // A live-looking record + a rendezvous pointing at a listener that
        // explicitly answers `ERR bad token`: that listener is NOT our
        // session (ours always holds the token), so the probe proves death
        // and must converge the records instead of lingering Unverifiable.
        let (root, dirs) = fresh_dirs("badtoken");
        dirs.ensure_dirs().expect("dirs");
        let mut s = session();
        s.transition(SessionState::Starting)
            .expect("starting then up");
        s.transition(SessionState::Up).expect("up");
        s.save(&dirs).expect("seed record");
        let addr = serve_bad_token_listener().await;
        let info = control::ControlInfo {
            port: addr.port(),
            token: control::new_token(),
            pid: std::process::id(),
        };
        control::write_control_file(&dirs, &info).expect("seed rendezvous");

        let status = SessionStatus::read(&dirs);
        match &status {
            SessionStatus::Dead { id } => assert_eq!(id, "s1", "proven-dead id"),
            other => panic!("bad-token probe must converge to Dead, got {other:?}"),
        }
        // Convergence is durable: the record reads back Stopped and the
        // stale rendezvous is gone.
        let stored = Session::load(&dirs).expect("record survives");
        assert_eq!(stored.state, SessionState::Stopped, "converged record");
        assert!(
            control::read_control_file(&dirs).is_none(),
            "stale rendezvous removed"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_probe_bad_token_is_conclusive_and_converges() {
        // Stop-path twin of the status convergence: the helper the CLI wave
        // consumes must map BadToken -> Dead-shaped outcome.
        let (root, dirs) = fresh_dirs("stop-badtoken");
        dirs.ensure_dirs().expect("dirs");
        let mut s = session();
        s.transition(SessionState::Starting)
            .expect("starting then up");
        s.transition(SessionState::Up).expect("up");
        s.save(&dirs).expect("seed record");
        let addr = serve_bad_token_listener().await;
        control::write_control_file(
            &dirs,
            &control::ControlInfo {
                port: addr.port(),
                token: control::new_token(),
                pid: std::process::id(),
            },
        )
        .expect("seed rendezvous");

        assert_eq!(
            SessionStatus::stop_probe(&dirs),
            StopProbeVerdict::BadToken,
            "explicit ERR bad token proves the listener is foreign"
        );
        let stored = Session::load(&dirs).expect("record survives");
        assert_eq!(stored.state, SessionState::Stopped, "converged record");
        assert!(control::read_control_file(&dirs).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn assert_startable_gates_on_live_record_only() {
        let (root, dirs) = fresh_dirs("startable");
        dirs.ensure_dirs().expect("dirs");
        // No record at all: startable.
        SessionStatus::assert_startable(&dirs).expect("no record starts");
        // Terminal record: startable.
        let mut done = session();
        done.transition(SessionState::Failed).expect("failed");
        done.save(&dirs).expect("dead record");
        SessionStatus::assert_startable(&dirs).expect("dead record starts");
        // Live-looking record: blocked, with the actionable message.
        let mut live = session();
        live.transition(SessionState::Starting)
            .expect("starting then up");
        live.transition(SessionState::Up).expect("up");
        live.save(&dirs).expect("live record");
        let err = SessionStatus::assert_startable(&dirs).expect_err("live record blocks");
        assert!(
            err.reason.contains("session already running")
                && err.reason.contains("s1")
                && err.reason.contains("qcore stop"),
            "actionable message: {}",
            err.reason
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn assert_startable_fails_closed_on_unreadable_record() {
        let (root, dirs) = fresh_dirs("startable-corrupt");
        dirs.ensure_dirs().expect("dirs");
        std::fs::write(dirs.session_file(), "not json").expect("seed torn record");
        let err = SessionStatus::assert_startable(&dirs).expect_err("torn record blocks");
        assert!(
            err.reason.contains("qcore stop"),
            "message names the fix: {}",
            err.reason
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn session_save_read_roundtrips_atomically() {
        let (root, dirs) = fresh_dirs("save-rt");
        dirs.ensure_dirs().expect("dirs");
        let mut s = session();
        s.transition(SessionState::Starting)
            .expect("starting then up");
        s.transition(SessionState::Up).expect("up");
        s.save(&dirs).expect("save");
        let back = Session::load(&dirs).expect("roundtrip");
        assert_eq!(back.id, "s1");
        assert_eq!(back.state, SessionState::Up);
        // Atomicity shape: no temp siblings left behind after a clean save.
        let parent = dirs.session_file().parent().expect("parent").to_path_buf();
        let residue: Vec<String> = std::fs::read_dir(&parent)
            .expect("list")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("session.json.tmp."))
            .collect();
        assert!(residue.is_empty(), "temp residue: {residue:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_never_clobbers_a_corrupt_record_silently() {
        // A present-but-unparseable record is corruption (crash tear): save
        // must keep forensics (`session.json.corrupt`) before replacing it,
        // same contract as `ensure_identity`.
        let (root, dirs) = fresh_dirs("save-corrupt");
        dirs.ensure_dirs().expect("dirs");
        const TORN: &str = "{\"id\":\"torn\", \"chain\":";
        std::fs::write(dirs.session_file(), TORN).expect("seed torn record");
        let mut s = session();
        s.transition(SessionState::Starting)
            .expect("starting then up");
        s.transition(SessionState::Up).expect("up");
        s.save(&dirs).expect("save over corrupt");
        let backup = dirs.session_file().with_extension("json.corrupt");
        let kept = std::fs::read_to_string(&backup).expect("corrupt original kept");
        assert_eq!(kept, TORN, "forensic copy is byte-identical");
        // And the new record is the one we wrote.
        let back = Session::load(&dirs).expect("new record parses");
        assert_eq!(back.id, "s1");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unreadable_state_file_is_unverifiable_not_not_running() {
        let root = std::env::temp_dir().join(format!(
            "qcore-noread-{}-{}",
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
        dirs.ensure_dirs().expect("dirs created");
        std::fs::write(dirs.session_file(), "not json").expect("seed invalid record");
        assert!(
            matches!(
                SessionStatus::read(&dirs),
                SessionStatus::Unverifiable { .. }
            ),
            "a present-but-unreadable record fails closed, never 'no session'"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    struct StopProbe {
        stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        fail: bool,
        events: tokio::sync::broadcast::Sender<HopEvent>,
    }

    static STOP_PROBE_DESCRIPTOR: qcore_transport_api::TransportDescriptor =
        qcore_transport_api::TransportDescriptor {
            kind: "stop-probe",
            capabilities: qcore_transport_api::Capabilities {
                accepts_tcp_carrier: false,
                accepts_udp_carrier: false,
                dials_tcp: false,
                dials_udp: false,
            },
            obfuscation_families: &[],
            config_schema: "stop-probe/v1",
            needs_sidecar: false,
        };

    struct StubStopDialer;

    #[async_trait::async_trait]
    impl Dialer for StubStopDialer {
        async fn dial_tcp(
            &self,
            _dst: std::net::SocketAddr,
        ) -> Result<Box<dyn qcore_transport_api::ByteStream>, qcore_transport_api::HopError>
        {
            Err(qcore_transport_api::HopError::validation("unused"))
        }
        async fn dial_udp(
            &self,
            _dst: std::net::SocketAddr,
        ) -> Result<Box<dyn qcore_transport_api::UdpFlow>, qcore_transport_api::HopError> {
            Err(qcore_transport_api::HopError::validation("unused"))
        }
        fn capabilities(&self) -> qcore_transport_api::Capabilities {
            qcore_transport_api::Capabilities {
                accepts_tcp_carrier: false,
                accepts_udp_carrier: false,
                dials_tcp: false,
                dials_udp: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl qcore_transport_api::RunningHop for StopProbe {
        fn descriptor(&self) -> &'static qcore_transport_api::TransportDescriptor {
            &STOP_PROBE_DESCRIPTOR
        }
        fn dialer(&self) -> Arc<dyn Dialer> {
            Arc::new(StubStopDialer)
        }
        fn health(&self) -> qcore_transport_api::HopHealth {
            qcore_transport_api::HopHealth::Healthy
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
            self.events.subscribe()
        }
        async fn stop(&self) -> Result<(), qcore_transport_api::HopError> {
            self.stopped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if self.fail {
                return Err(qcore_transport_api::HopError::validation("exit boom"));
            }
            Ok(())
        }
    }

    fn started_probe(
        id: &str,
        fail: bool,
        stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> crate::session::lifecycle::StartedHop {
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        crate::session::lifecycle::StartedHop {
            hop_id: id.to_string(),
            kind: "stop-probe".to_string(),
            family: "ipv4".to_string(),
            endpoint: None,
            via: "root".to_string(),
            nested: false,
            inner_mtu: 1500,
            obfuscation: None,
            hop: Arc::new(StopProbe {
                stopped,
                fail,
                events: tx,
            }),
            congested_drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            keepalive: None,
            forwarder: None,
        }
    }

    #[tokio::test]
    async fn stop_all_continues_past_exit_failure() {
        let inner_stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exit_stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = SessionHandle::bare(
            "s-stop",
            "exit",
            ChainSer {
                hops: vec![],
                max_depth: 3,
            },
            vec![
                started_probe("inner", false, inner_stopped.clone()),
                started_probe("exit", true, exit_stopped.clone()),
            ],
            tokio::sync::broadcast::channel(8).0,
        );
        let err = handle.stop_all().await.expect_err("exit error surfaces");
        assert!(err.message.contains("exit boom"), "got: {err:?}");
        assert!(
            exit_stopped.load(std::sync::atomic::Ordering::SeqCst),
            "exit stop ran"
        );
        assert!(
            inner_stopped.load(std::sync::atomic::Ordering::SeqCst),
            "inner stop still ran after exit failure"
        );
    }

    /// (S1.1) Post-give-up egress fails closed: the watchdog's GaveUp arm
    /// clears the started vec and resets the exit slot, so `dialer()` has no
    /// hop to fall back on. Per-connection SOCKS tasks holding the handle
    /// between give-up and process exit must get a dialer that returns a
    /// clear error — never a panic. The dead dialer keeps the Dialer shape
    /// (capabilities) so the proxy's UDP gating answers honestly (nothing
    /// dials), and dial_tcp/dial_udp fail with "session exited" so the SOCKS
    /// path replies 0x01 cleanly.
    #[tokio::test]
    async fn dialer_after_give_up_fails_closed_never_panics() {
        let (events, _drain) = tokio::sync::broadcast::channel(8);
        let handle = SessionHandle::bare(
            "s-dead",
            "exit",
            ChainSer {
                hops: vec![],
                max_depth: 3,
            },
            vec![],
            events,
        );
        // The exact shape the GaveUp arm leaves behind: hops cleared, exit
        // slot reset to default before the map entry is removed.
        handle.wire_exit(Vec::new(), None, None);
        let d = handle.dialer();
        assert_eq!(
            d.capabilities(),
            Capabilities {
                accepts_tcp_carrier: false,
                accepts_udp_carrier: false,
                dials_tcp: false,
                dials_udp: false,
            },
            "dead egress admits it dials nothing (UDP gate refuses honestly)"
        );
        let dst = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
        let tcp = match d.dial_tcp(dst).await {
            Err(e) => e,
            Ok(_) => panic!("dead egress must refuse TCP"),
        };
        assert!(
            tcp.message.contains("session exited"),
            "error names the cause: {tcp:?}"
        );
        let udp = match d.dial_udp(dst).await {
            Err(e) => e,
            Ok(_) => panic!("dead egress must refuse UDP"),
        };
        assert!(
            udp.message.contains("session exited"),
            "error names the cause: {udp:?}"
        );
        // The LiveDialer adapter (the proxy's captured egress) resolves
        // through the same fail-closed path per call.
        let live = handle.live_dialer();
        let err = match live.dial_tcp(dst).await {
            Err(e) => e,
            Ok(_) => panic!("adapter must fail closed too"),
        };
        assert!(
            err.message.contains("session exited"),
            "adapter error names the cause: {err:?}"
        );
        assert!(
            !live.capabilities().dials_udp,
            "adapter capabilities follow the dead egress"
        );
    }

    /// H2.5: `session.json` appears only after hops are up, so two connects
    /// could both pass the start gate during startup. The lock closes that
    /// window: held by the first starter, blocks the second, gone after a
    /// clean stop.
    #[test]
    fn session_lock_blocks_a_second_start_until_released() {
        let (root, dirs) = fresh_dirs("lock-block");
        let lock = SessionLock::acquire(&dirs).expect("first starter takes the lock");
        lock.attach_session_id("s-live-1").expect("record the id");

        let second = SessionLock::acquire(&dirs).expect_err("second acquire must fail");
        assert!(second.contains("session.lock"), "names the lock: {second}");
        let blocker = SessionStatus::assert_startable(&dirs).expect_err("lock blocks the gate");
        assert!(
            blocker.reason.contains("s-live-1"),
            "blocker names the holder: {}",
            blocker.reason
        );

        drop(lock);
        assert!(
            !session_lock_path(&dirs).exists(),
            "clean stop deletes the lock"
        );
        assert!(
            SessionStatus::assert_startable(&dirs).is_ok(),
            "a released lock unblocks the next start"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// H2.5: a lock left by a crashed predecessor is stolen after the same
    /// 10-minute window the identity lock uses (mirrored owner-token
    /// pattern), and a foreign owner never passes the ownership check.
    #[test]
    fn stale_session_lock_is_stolen_and_foreign_owners_are_rejected() {
        let (root, dirs) = fresh_dirs("lock-stale");
        dirs.ensure_dirs().expect("dirs");
        let path = session_lock_path(&dirs);
        std::fs::write(&path, "crashed-holder\ns-old").expect("seed stale lock");
        let aged = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open lock");
        aged.set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(601)),
        )
        .expect("age the lock past the stale window");
        drop(aged);

        assert!(
            SessionStatus::assert_startable(&dirs).is_ok(),
            "an aged lock does not block"
        );
        let lock = SessionLock::acquire(&dirs).expect("aged lock is stolen");
        lock.assert_ours(&dirs).expect("stealer owns the lock");
        std::fs::write(&path, "someone-else\ns-x").expect("swap the owner");
        assert!(
            lock.assert_ours(&dirs).is_err(),
            "another owner's token is not ours"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
