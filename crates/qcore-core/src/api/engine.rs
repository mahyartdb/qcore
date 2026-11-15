//! Engine facade: preflight, start, status, subscribe, stop.
//!
//! Validation is total: an invalid chain never partially starts (FR-027).
//! Preflight validates chain + profiles + config without starting a hop or
//! opening a socket (FR-029).

use crate::api::version::{ABI_VERSION, API_VERSION, SCHEMA_VERSION};
use crate::chain::{ChainBuilder, ChainError, ExpandedHop};
use crate::config::profile_dir::ProfileDirs;
use crate::config::HopSpec;
use crate::identity::report::report_for_error as to_report;
use crate::registry::TransportRegistry;
use crate::session::lifecycle;
use crate::session::net::{root_dialer, FamilyPolicy, KeepalivePolicy};
use crate::session::resolver::TunnelResolver;
use crate::session::SessionHandle;
use qcore_transport_api::{FailureLayer, FailureReport, HopEvent};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub dirs: ProfileDirs,
    pub max_depth: u32,
    pub family: String,
    pub prefer: String,
    pub timeout_secs: u64,
    pub keepalive: KeepalivePolicy,
    /// DNS resolver address reachable from inside the tunnel (used for
    /// SOCKS5 ATYP=domain targets so domain names never hit the OS
    /// resolver). `None` keeps domain targets refused (fail closed). The
    /// CLI defaults this to the WARP resolver for the warp/wireguard
    /// family; see [`crate::session::resolver::DEFAULT_DNS_RESOLVER`].
    pub dns_resolver: Option<std::net::IpAddr>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            dirs: ProfileDirs::resolve(None, None),
            max_depth: 3,
            family: "dual".into(),
            prefer: "ipv4".into(),
            timeout_secs: 30,
            keepalive: KeepalivePolicy::default(),
            dns_resolver: None,
        }
    }
}

/// Preflight verdict: valid with expanded depth, or the blocking error.
#[derive(Debug)]
pub enum Preflight {
    Ok { depth: usize },
    Rejected(ChainError),
}

/// Outcome of [`Engine::ensure_warp_for_specs`]: whether anything was
/// freshly registered, which roles are now ready, and a human notice for
/// stderr when registration happened inline.
#[derive(Debug)]
pub struct EnsureWarp {
    pub fresh: bool,
    pub roles: Vec<crate::identity::store::IdentityRole>,
    pub notice: Option<String>,
}

/// The engine. Owns config + registry; sessions are built per start.
/// `live` is `Arc`-shared with the F2 watchdog so a rebuild can swap the
/// live entry (and a give-up remove it) under the same lock.
pub struct Engine {
    config: EngineConfig,
    registry: TransportRegistry,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    live: crate::session::watchdog::LiveMap,
}

impl Engine {
    /// Poison-tolerant guard for the live-session map. A poisoned mutex is
    /// restored (contents preserved) and the restore is logged so restores
    /// stay visible instead of silently masking bugs.
    fn lock_live(&self) -> std::sync::MutexGuard<'_, HashMap<String, SessionHandle>> {
        self.live.lock().unwrap_or_else(|e| {
            eprintln!("qcore: live session map lock poisoned; restoring");
            e.into_inner()
        })
    }

    pub fn new(config: EngineConfig) -> Self {
        let (events, _) = tokio::sync::broadcast::channel(256);
        Engine {
            config,
            registry: TransportRegistry::global(),
            events,
            live: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn registry(&self) -> &TransportRegistry {
        &self.registry
    }

    /// Profile/config dirs this engine was built with (FFI/embedders).
    pub fn config_dirs(&self) -> ProfileDirs {
        self.config.dirs.clone()
    }

    pub fn versions() -> (&'static str, u32, &'static str) {
        (API_VERSION, ABI_VERSION, SCHEMA_VERSION)
    }

    /// Validate a chain + profiles + config without starting a hop or opening
    /// a socket (FR-029, SC-002d).
    pub fn preflight(&self, specs: Vec<ExpandedHop>) -> Preflight {
        let presets = match crate::chain::preset::resolve_presets(&self.config.dirs) {
            Ok(p) => p,
            Err(e) => return Preflight::Rejected(e),
        };
        match ChainBuilder::new(&self.registry, self.config.max_depth).build_with(specs, &presets) {
            Ok(chain) => {
                // US2: every wireguard `import=<ref>` must resolve (file reads
                // only — still zero sockets).
                if let Err(e) = crate::config::import::check_refs(&self.config.dirs, &chain.hops) {
                    return Preflight::Rejected(e);
                }
                // US5: obfuscation profiles must be compatible (FR-021).
                if let Err(e) = crate::config::obfuscation::resolve_for_chain(
                    &self.config.dirs,
                    &self.registry,
                    &chain.hops,
                ) {
                    return Preflight::Rejected(e);
                }
                Preflight::Ok {
                    depth: chain.depth(),
                }
            }
            Err(e) => Preflight::Rejected(e),
        }
    }

    /// Validate then bring up hops in declared order within the
    /// CONNECTION_TIMEOUT_SECONDS budget (default 30). Fail-closed: any
    /// validation or bring-up failure returns `FailureReport` with zero
    /// partial state left behind (FR-027).
    pub async fn start(&self, specs: Vec<ExpandedHop>) -> Result<SessionHandle, FailureReport> {
        let policy = FamilyPolicy::parse(&self.config.family, &self.config.prefer)
            .map_err(|e| FailureReport::new(FailureLayer::Validation, "-", e, "validation"))?;
        let presets = crate::chain::preset::resolve_presets(&self.config.dirs).map_err(|e| {
            FailureReport::new(
                FailureLayer::Validation,
                e.hop_id.clone().unwrap_or_else(|| "-".to_string()),
                e.to_string(),
                "validation",
            )
        })?;
        let chain = ChainBuilder::new(&self.registry, self.config.max_depth)
            .build_with(specs, &presets)
            .map_err(|e| {
                FailureReport::new(
                    FailureLayer::Validation,
                    e.hop_id.clone().unwrap_or_else(|| "-".to_string()),
                    e.to_string(),
                    "validation",
                )
            })?;
        let carrier = root_dialer(policy, Duration::from_secs(self.config.timeout_secs.max(1)));
        let deadline = Instant::now() + Duration::from_secs(self.config.timeout_secs.max(1));
        // US2: merge stored import material (endpoint/keys/AWG params) for
        // resolution at build time; secrets stay in memory only.
        let imports =
            crate::config::import::materialize(&self.config.dirs, &chain.hops).map_err(|e| {
                FailureReport::new(
                    FailureLayer::Validation,
                    e.hop_id.clone().unwrap_or_else(|| "-".to_string()),
                    e.to_string(),
                    "validation",
                )
            })?;
        // US5: resolve obfuscation applications (FR-021 gate before start).
        let obfuscation = crate::config::obfuscation::resolve_for_chain(
            &self.config.dirs,
            &self.registry,
            &chain.hops,
        )
        .map_err(|e| {
            FailureReport::new(
                FailureLayer::Validation,
                e.hop_id.clone().unwrap_or_else(|| "-".to_string()),
                e.to_string(),
                "validation",
            )
        })?;
        // 002: merge stored identities + cached endpoints into warp/masque
        // hops (in memory only). Fail-closed naming the hop and the fix
        // before any socket opens.
        let identities =
            crate::identity::inject::materials_for_chain(&self.config.dirs, &chain.hops).map_err(
                |(hop_id, msg)| {
                    FailureReport::new(FailureLayer::Validation, hop_id, msg, "identity")
                },
            )?;
        let started = lifecycle::bring_up(
            &chain,
            carrier,
            &self.events,
            &self.config.keepalive,
            deadline,
            lifecycle::DepthContext::root(
                &self.registry,
                lifecycle::BringUpMaterials {
                    imports: &imports,
                    obfuscation: &obfuscation,
                    identities: &identities,
                },
            ),
        )
        .await?;
        let exit_hop_id = chain
            .exit()
            .map(|h| h.id.clone())
            .unwrap_or_else(|| "-".to_string());
        // Tunnel resolver for ATYP=domain targets (FR-013c): built only when
        // the EXIT hop's runtime dialer can actually carry the DNS datagram
        // (capability read, never a kind match). No resolver + a domain
        // target keeps the fail-closed refusal in the proxy.
        let resolver = match (&self.config.dns_resolver, started.last()) {
            (Some(ip), Some(exit)) if exit.hop.dialer().capabilities().dials_udp => Some(
                std::sync::Arc::new(TunnelResolver::new(exit.hop.dialer(), *ip)),
            ),
            _ => None,
        };
        let exit_dialer = started.last().map(|h| h.hop.dialer());
        let mut handle = SessionHandle::bare(
            new_session_id(),
            exit_hop_id,
            crate::session::ChainSer::from(&chain),
            Vec::new(),
            self.events.clone(),
        );
        handle.wire_exit(started, exit_dialer, resolver);
        // F2 watchdog: subscribe to the session bus; on any hop Failed it
        // degrades honestly and rebuilds through the same primitives with a
        // bounded budget. The abort handle rides the handle so `stop_all`
        // (CLI stop, engine stop, FFI free) interrupts it first.
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        handle.stop_signal = Arc::new(stop_tx);
        let wd_abort = crate::session::watchdog::spawn(
            handle.clone(),
            crate::session::watchdog::WatchdogConfig {
                dirs: self.config.dirs.clone(),
                keepalive: self.config.keepalive.clone(),
                timeout_secs: self.config.timeout_secs,
                family: self.config.family.clone(),
                prefer: self.config.prefer.clone(),
                dns_resolver: self.config.dns_resolver,
                ..Default::default()
            },
            self.live.clone(),
            stop_rx,
        );
        handle.watchdog = Some(wd_abort);
        // Map entry lands only AFTER the handle is fully wired (stop signal
        // + watchdog abort handle + live exits): the watchdog rebuild/give-up
        // paths and `Engine::stop_session` read this entry's stop channel and
        // abort handle — a pre-wired clone would carry a dead stop watch and
        // no watchdog (R1.2).
        self.lock_live().insert(handle.id.clone(), handle.clone());
        Ok(handle)
    }

    /// Current session status from the durable state dir. A present-but-
    /// unconfirmed record reports `Unverifiable` (fail-closed); liveness via
    /// the control socket lands in US1 with detach (T046).
    pub fn status(&self) -> crate::session::SessionStatus {
        crate::session::SessionStatus::read(&self.config.dirs)
    }

    /// Push-based hop event stream across all live sessions (never polls).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
        self.events.subscribe()
    }

    /// Connection report for one live session (`None` when unknown).
    /// Powers the C ABI / embedders' per-session status (FR-003c).
    /// Poison-tolerant: a poisoned map restores and reports `None` for
    /// unknown ids, never panics. The handle is cloned out from under the
    /// lock before building the report so report construction never holds
    /// the map lock.
    ///
    /// Self-reaping: when every hop of the session reports Failed/Stopped
    /// (the session died on its own — transport failure, not an explicit
    /// stop), the entry is removed from `live` so a dead session cannot
    /// linger forever. The report is still returned once (the final report
    /// — callers learn *what* died); the next call reports `None`.
    pub fn session_report(&self, id: &str) -> Option<crate::session::report::ConnectionReport> {
        let handle = { self.lock_live().get(id).cloned() }?;
        let reports = handle.hop_reports();
        if self_dead(&reports) {
            self.lock_live().remove(id);
        }
        let mut report =
            crate::session::report::ConnectionReport::new(reports, handle.exit_hop_id.clone());
        // F2 honesty: a degraded (rebuild-in-flight) session reports the
        // state + reconnect count; the Up shape stays field-free (stable
        // JSON contract — see report.rs additive-field pins).
        if handle.degraded.load(std::sync::atomic::Ordering::SeqCst) {
            report.session_state = Some("degraded".to_string());
            report.reconnects = Some(handle.reconnects.load(std::sync::atomic::Ordering::SeqCst));
        }
        Some(report)
    }

    /// Tear down one live session by id.
    pub async fn stop_session(&self, id: &str) -> Result<(), FailureReport> {
        let handle = {
            self.lock_live().remove(id).ok_or_else(|| {
                FailureReport::new(FailureLayer::Chain, "-", "no such live session", "chain")
            })?
        };
        handle.stop_all().await.map_err(|e| {
            FailureReport::new(
                FailureLayer::Chain,
                handle.exit_hop_id.clone(),
                e.message,
                "shutdown",
            )
        })
    }

    /// Tear down all live sessions (exit-first per session). Best effort:
    /// every handle is removed and stopped even when earlier stops fail; the
    /// first failure is reported once after the sweep.
    pub async fn stop(&self) -> Result<(), FailureReport> {
        let handles: Vec<SessionHandle> = {
            let map = self.lock_live();
            map.values().cloned().collect()
        };
        let mut first_err = None;
        for handle in handles {
            let removed = { self.lock_live().remove(&handle.id) }.is_some();
            if !removed {
                continue;
            }
            if let Err(e) = handle.stop_all().await {
                if first_err.is_none() {
                    first_err = Some(FailureReport::new(
                        FailureLayer::Chain,
                        handle.exit_hop_id.clone(),
                        e.message,
                        "shutdown",
                    ));
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Load a stored provider identity (002). `None` on missing, corrupt,
    /// partial, or secret-missing records — the caller re-registers.
    pub fn load_identity(
        &self,
        role: crate::identity::store::IdentityRole,
    ) -> Option<crate::identity::model::ProviderIdentity> {
        crate::identity::store::load(&self.config.dirs, role)
    }

    /// Persist a provider identity atomically (002 FR-002).
    pub fn save_identity(
        &self,
        role: crate::identity::store::IdentityRole,
        id: &crate::identity::model::ProviderIdentity,
    ) -> Result<(), String> {
        crate::identity::store::save(&self.config.dirs, role, id)
    }

    /// How many WARP identities these specs need: every WARP hop without
    /// import material (an explicit `endpoint=` still needs identity keys),
    /// capped at 2 (outer + inner for GOOL-like pairs). Read-only: presets
    /// resolve from dirs, zero sockets (FR-003). The predicate must match
    /// [`crate::identity::inject::materials_for_chain`] exactly — that is
    /// the hop set inject resolves identity material for at start, so a
    /// hop counted here must be a hop inject demands an identity for.
    pub fn warp_identities_needed(&self, specs: &[ExpandedHop]) -> Result<usize, ChainError> {
        let presets = crate::chain::preset::resolve_presets(&self.config.dirs)?;
        let hops = crate::chain::preset::expand(specs.to_vec(), &presets)?;
        let mut need = 0;
        for h in &hops {
            if let crate::config::HopConfig::Wireguard(c) = &h.config {
                if c.peer == "warp" && c.import_ref.is_none() {
                    need += 1;
                }
            }
        }
        Ok(need.min(2))
    }

    /// Ensure stored-or-fresh identities for what `specs` needs (002 FR-003):
    /// reuse healthy stored identities, auto-register when none is stored
    /// (or the stored one is refused). GOOL-shaped specs get the outer+inner
    /// pair. Fails closed with a `RegistrationReport` (blocked vs refused).
    pub async fn ensure_warp_for_specs(
        &self,
        specs: &[ExpandedHop],
        opts: &crate::identity::register::ProviderOptions,
        license: Option<&crate::config::secret::SecretString>,
    ) -> Result<EnsureWarp, crate::identity::report::RegistrationReport> {
        use crate::identity::report::{RegistrationReport, ReportAction};
        let needed = self
            .warp_identities_needed(specs)
            .map_err(|e| RegistrationReport {
                action: ReportAction::Blocked,
                identity: None,
                endpoint: None,
                cause: format!("cannot resolve chain presets: {e}"),
                license_applied: false,
            })?;
        if needed == 0 {
            return Ok(EnsureWarp {
                fresh: false,
                roles: Vec::new(),
                notice: None,
            });
        }
        let roles: Vec<crate::identity::store::IdentityRole> = if needed >= 2 {
            vec![
                crate::identity::store::IdentityRole::Outer,
                crate::identity::store::IdentityRole::Inner,
            ]
        } else {
            vec![crate::identity::store::IdentityRole::Outer]
        };
        // Snapshot to detect fresh provisioning (reuse leaves ids untouched).
        let before: Vec<Option<String>> = roles
            .iter()
            .map(|r| self.load_identity(*r).map(|id| id.device_id))
            .collect();
        if roles.len() == 2 {
            crate::identity::gool::provision_pair(&self.config.dirs, opts, license, true)
                .await
                .map_err(to_report)?;
        } else {
            crate::identity::gool::provision_role(
                &self.config.dirs,
                crate::identity::store::IdentityRole::Outer,
                opts,
                license,
                true,
            )
            .await
            .map_err(to_report)?;
        }
        let fresh = roles
            .iter()
            .zip(before.iter())
            .any(|(r, prev)| self.load_identity(*r).map(|id| id.device_id) != *prev);
        Ok(EnsureWarp {
            fresh,
            roles: roles.clone(),
            notice: if fresh {
                Some(format!(
                    "registered fresh WARP identity ({})",
                    roles
                        .iter()
                        .map(|r| match r {
                            crate::identity::store::IdentityRole::Outer => "outer",
                            crate::identity::store::IdentityRole::Inner => "inner",
                        })
                        .collect::<Vec<_>>()
                        .join("+")
                ))
            } else {
                None
            },
        })
    }

    /// Register one fresh identity into a role (002 US1): the `register`
    /// command's engine half. Thin, public, and CLI-parity covered.
    pub async fn register_warp(
        &self,
        role: crate::identity::store::IdentityRole,
        opts: &crate::identity::register::ProviderOptions,
        license: Option<&crate::config::secret::SecretString>,
    ) -> crate::identity::report::RegistrationReport {
        use crate::identity::report::{RegistrationReport, ReportAction};
        let outcome = match crate::identity::register::register_fresh(opts, license).await {
            Ok(o) => o,
            Err(e) => return to_report(e),
        };
        if let Err(e) = self.save_identity(role, &outcome.identity) {
            return RegistrationReport {
                action: ReportAction::Blocked,
                identity: None,
                endpoint: None,
                cause: format!("identity store failed: {e}"),
                license_applied: false,
            };
        }
        let mut cause = format!(
            "fresh identity provisioned and stored via {}",
            outcome.family
        );
        if let Some(note) = outcome.license_note {
            cause.push_str(&format!(" ({note})"));
        }
        RegistrationReport {
            action: ReportAction::Registered,
            identity: Some(outcome.identity.device_id.clone()),
            endpoint: None,
            cause,
            license_applied: outcome.license_applied,
        }
    }

    /// Pre-connect identity check (002 FR-004/FR-005/T028/T032): ensure
    /// identities, then refresh each stored (non-fresh) role once. A refusal
    /// renews automatically (single re-registration, then the caller
    /// proceeds); anything else keeps the identity and the connect
    /// continues — the failure, if real, surfaces from the tunnel itself.
    /// MASQUE credentials inside the rotation window rotate inline when the
    /// chain needs MASQUE (failures defer with a notice — the credential is
    /// still valid until expiry).
    ///
    /// Fatal vs notice-and-proceed (documented contract): refusal-class
    /// errors ([`ReportAction::Refused`], and the no-stored-identity shape
    /// of Blocked whose cause names `qcore register`) are fatal — the
    /// connect cannot proceed without an identity. Every other Blocked
    /// (provider unreachable / rejected / protocol garbage on the refresh
    /// path) is a transient failure: the stored identity is kept, a notice
    /// is emitted, and the connect proceeds. Returns stderr notices or the
    /// fatal report.
    pub async fn preconnect_identity(
        &self,
        specs: &[ExpandedHop],
        opts: &crate::identity::register::ProviderOptions,
        license: Option<&crate::config::secret::SecretString>,
    ) -> Result<Option<String>, crate::identity::report::RegistrationReport> {
        use crate::identity::report::ReportAction;
        use crate::identity::store::IdentityRole;
        // Pre-ensure snapshot: per-role freshness + whether a MASQUE
        // credential is about to be lost to re-registration.
        let snapshot: Vec<(IdentityRole, Option<String>, bool)> =
            [IdentityRole::Outer, IdentityRole::Inner]
                .iter()
                .map(|r| {
                    let loaded = self.load_identity(*r);
                    let had_masque = loaded.as_ref().is_some_and(|id| id.masque.is_some());
                    (*r, loaded.map(|id| id.device_id), had_masque)
                })
                .collect();
        let ensured = self.ensure_warp_for_specs(specs, opts, license).await?;
        let mut notices = Vec::new();
        if let Some(n) = ensured.notice {
            notices.push(n);
        }
        let masque_needed = self.specs_need_masque(specs);
        for role in &ensured.roles {
            let (prev_id, had_masque) = snapshot
                .iter()
                .find(|(r, _, _)| r == role)
                .map(|(_, id, m)| (id.clone(), *m))
                .unwrap_or((None, false));
            let current_id = self.load_identity(*role).map(|id| id.device_id);
            let fresh_this_role = current_id != prev_id;
            if fresh_this_role {
                if had_masque {
                    notices.push(
                        "re-registered with a fresh identity; MASQUE credential needs re-enrollment (`qcore renew --masque-only`)".to_string(),
                    );
                }
            } else {
                let report = crate::identity::renew::renew_role(
                    &self.config.dirs,
                    *role,
                    opts,
                    license,
                    false,
                )
                .await;
                match report.action {
                    ReportAction::Reused => {}
                    ReportAction::Refused => return Err(report),
                    // Blocked splits by content (fail closed naming the
                    // class): the no-stored-identity shape means the connect
                    // cannot proceed (ensure should have registered one —
                    // treat as fatal). Every other Blocked is a transient
                    // refresh failure (unreachable/rejected/protocol): the
                    // identity is kept and the connect proceeds — the
                    // documented contract; a real failure surfaces from the
                    // tunnel itself.
                    ReportAction::Blocked => {
                        if report.identity.is_none() {
                            return Err(report);
                        }
                        notices.push(format!(
                            "{}: {}",
                            match role {
                                IdentityRole::Outer => "warp",
                                IdentityRole::Inner => "warp-inner",
                            },
                            report.cause
                        ));
                    }
                    ReportAction::ReRegistered if had_masque => {
                        notices.push(report.cause.clone());
                        notices.push(
                            "previous MASQUE credential did not carry over; re-enroll with `qcore renew --masque-only`".to_string(),
                        );
                    }
                    _ => notices.push(format!(
                        "{}: {}",
                        match role {
                            IdentityRole::Outer => "warp",
                            IdentityRole::Inner => "warp-inner",
                        },
                        report.cause
                    )),
                }
            }
            // Connect-time MASQUE rotation (FR-005): only when the chain
            // needs MASQUE and the credential sits inside its window.
            if masque_needed {
                let in_window = self
                    .load_identity(*role)
                    .and_then(|id| id.masque)
                    .is_some_and(|c| c.needs_rotation(crate::identity::model::now_ms()));
                if in_window {
                    let rotated = crate::identity::renew::renew_role(
                        &self.config.dirs,
                        *role,
                        opts,
                        None,
                        true,
                    )
                    .await;
                    match rotated.action {
                        ReportAction::Reused => {}
                        ReportAction::Rotated => notices.push(rotated.cause),
                        _ => notices.push(format!(
                            "MASQUE rotation deferred ({}); proceeding with the current credential",
                            rotated.cause
                        )),
                    }
                }
            }
        }
        if notices.is_empty() {
            Ok(None)
        } else {
            Ok(Some(notices.join("; ")))
        }
    }

    /// Whether these specs need MASQUE (a concrete masque hop or the `mim`
    /// preset). Read-only; resolution failures mean validation fails later
    /// anyway, so they answer `false` here.
    fn specs_need_masque(&self, specs: &[ExpandedHop]) -> bool {
        let Ok(presets) = crate::chain::preset::resolve_presets(&self.config.dirs) else {
            return false;
        };
        let Ok(hops) = crate::chain::preset::expand(specs.to_vec(), &presets) else {
            return false;
        };
        hops.iter()
            .any(|h| matches!(h.config, crate::config::HopConfig::Masque(_)))
    }

    /// Enroll (or confirm) the MASQUE credential for a role (002
    /// FR-005/T033): enrolls when missing, rotates inside the window,
    /// confirms otherwise. Thin over the MASQUE-only renewal path so the
    /// `register` flow and `renew --masque-only` share one implementation.
    pub async fn enroll_masque(
        &self,
        role: crate::identity::store::IdentityRole,
        opts: &crate::identity::register::ProviderOptions,
    ) -> crate::identity::report::RegistrationReport {
        crate::identity::renew::renew_role(&self.config.dirs, role, opts, None, true).await
    }

    /// Parse user-authored hop specs (single-hop CLI form; full grammar in US3).
    pub fn parse_single_hop(kind: &str, opts: &str) -> Result<HopSpec, ChainError> {
        crate::chain::parse_single_hop(kind, opts)
    }

    /// [`Engine::parse_single_hop`] against this engine's registry (see
    /// `parse_single_hop_in`): shortcut resolution honors filtered
    /// registries instead of the linked global set.
    pub fn parse_single_hop_in(&self, kind: &str, opts: &str) -> Result<HopSpec, ChainError> {
        crate::chain::parse_single_hop_in(kind, opts, &self.registry)
    }

    /// Parse a full chain expression (`hop (, hop)*`, preset names, `@label`;
    /// contracts/cli.md grammar) with profile-dir presets.
    pub fn parse_chain(&self, expr: &str) -> Result<Vec<ExpandedHop>, ChainError> {
        let presets = crate::chain::preset::resolve_presets(&self.config.dirs)?;
        crate::chain::parse::parse_chain(expr, &self.registry, &presets)
    }

    /// Same as [`Engine::parse_chain`] but sharing the auto-id counter `n`
    /// across calls (repeatable `--hop` accumulates in argv order).
    pub fn parse_chain_with_counter(
        &self,
        expr: &str,
        n: &mut u32,
    ) -> Result<Vec<ExpandedHop>, ChainError> {
        let presets = crate::chain::preset::resolve_presets(&self.config.dirs)?;
        crate::chain::parse::parse_chain_with_counter(expr, &self.registry, &presets, n)
    }
}

fn new_session_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("sess-{ms}-{n}")
}

/// True when every hop reports a terminal-dead status (Failed/Stopped).
/// A session in this state can never carry traffic again — the engine
/// reaps it from `live` so status stops serving a corpse. Cheap: reads the
/// hops' atomic health, no locks held beyond the map op, no IO.
fn self_dead(reports: &[crate::session::report::HopReport]) -> bool {
    !reports.is_empty()
        && reports
            .iter()
            .all(|h| h.status == "failed" || h.status == "stopped")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ChainSer, SessionHandle};

    fn test_engine() -> Engine {
        Engine::new(EngineConfig::default())
    }

    fn dummy_handle(id: &str) -> SessionHandle {
        let (events, _) = tokio::sync::broadcast::channel(8);
        SessionHandle::bare(
            id.to_string(),
            "exit-0",
            ChainSer {
                hops: Vec::new(),
                max_depth: 3,
            },
            Vec::new(),
            events,
        )
    }

    /// Poison `engine.live` by panicking while holding the guard. The guard
    /// is dropped during unwind, so the next `lock()` observes poisoning.
    fn poison_live(engine: &Engine) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = engine.live.lock().expect("test setup lock holds");
            panic!("intentional test poison");
        }));
        assert!(
            engine.live.is_poisoned(),
            "test setup must leave the live map poisoned"
        );
    }

    #[test]
    fn session_report_survives_poison_and_preserves_entries() {
        let engine = test_engine();
        engine
            .lock_live()
            .insert("s1".to_string(), dummy_handle("s1"));
        poison_live(&engine);
        // Restore-and-continue: the pre-poison entry is still reported.
        let report = engine.session_report("s1");
        assert!(report.is_some(), "poisoned map must not panic; s1 survives");
        assert_eq!(
            report.expect("checked above").exit_hop_id,
            "exit-0",
            "restored entry keeps its exit hop"
        );
        // Unknown ids report None, never panic.
        assert!(
            engine.session_report("missing").is_none(),
            "unknown id on a poisoned map is None"
        );
    }

    #[test]
    fn session_report_unknown_on_poisoned_empty_map_is_none() {
        let engine = test_engine();
        poison_live(&engine);
        assert!(
            engine.session_report("anything").is_none(),
            "poisoned empty map reports None, never panics"
        );
        // The map is usable after restore: inserts still land.
        engine
            .lock_live()
            .insert("s2".to_string(), dummy_handle("s2"));
        assert!(
            engine.session_report("s2").is_some(),
            "map usable after poison restore"
        );
    }

    #[tokio::test]
    async fn stop_session_survives_poison() {
        let engine = test_engine();
        engine
            .lock_live()
            .insert("s1".to_string(), dummy_handle("s1"));
        poison_live(&engine);
        // Empty `started` vec stops cleanly; the point is no panic and the
        // entry is reaped from the restored map.
        engine
            .stop_session("s1")
            .await
            .expect("stop on poisoned map succeeds");
        assert!(
            engine.session_report("s1").is_none(),
            "stopped session is gone"
        );
        // Unknown id on a (previously) poisoned map is a typed failure, not
        // a panic.
        let err = engine
            .stop_session("missing")
            .await
            .expect_err("unknown session fails closed");
        assert!(
            err.to_string().contains("no such live session"),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn stop_all_survives_poison() {
        let engine = test_engine();
        engine
            .lock_live()
            .insert("s1".to_string(), dummy_handle("s1"));
        engine
            .lock_live()
            .insert("s2".to_string(), dummy_handle("s2"));
        poison_live(&engine);
        engine
            .stop()
            .await
            .expect("stop-all on poisoned map succeeds");
        assert!(engine.session_report("s1").is_none());
        assert!(engine.session_report("s2").is_none());
    }

    static FAILING_STOP_DESCRIPTOR: qcore_transport_api::TransportDescriptor =
        qcore_transport_api::TransportDescriptor {
            kind: "failing-stop",
            capabilities: qcore_transport_api::Capabilities {
                accepts_tcp_carrier: false,
                accepts_udp_carrier: false,
                dials_tcp: false,
                dials_udp: false,
            },
            obfuscation_families: &[],
            config_schema: "failing-stop/v1",
            needs_sidecar: false,
        };

    struct FailingStopHop {
        stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    struct UnusedDialer;

    #[async_trait::async_trait]
    impl qcore_transport_api::Dialer for UnusedDialer {
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
    impl qcore_transport_api::RunningHop for FailingStopHop {
        fn descriptor(&self) -> &'static qcore_transport_api::TransportDescriptor {
            &FAILING_STOP_DESCRIPTOR
        }
        fn dialer(&self) -> std::sync::Arc<dyn qcore_transport_api::Dialer> {
            std::sync::Arc::new(UnusedDialer)
        }
        fn health(&self) -> qcore_transport_api::HopHealth {
            qcore_transport_api::HopHealth::Healthy
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
            tokio::sync::broadcast::channel(1).0.subscribe()
        }
        async fn stop(&self) -> Result<(), qcore_transport_api::HopError> {
            self.stopped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Err(qcore_transport_api::HopError::validation("stop boom"))
        }
    }

    fn failing_handle(
        id: &str,
        stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> SessionHandle {
        let (events, _) = tokio::sync::broadcast::channel(8);
        SessionHandle::bare(
            id.to_string(),
            "exit-f",
            ChainSer {
                hops: Vec::new(),
                max_depth: 3,
            },
            vec![crate::session::lifecycle::StartedHop {
                hop_id: id.to_string(),
                kind: "failing-stop".to_string(),
                family: "ipv4".to_string(),
                endpoint: None,
                via: "root".to_string(),
                nested: false,
                inner_mtu: 1500,
                obfuscation: None,
                hop: std::sync::Arc::new(FailingStopHop { stopped }),
                congested_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                keepalive: None,
                forwarder: None,
            }],
            events,
        )
    }

    /// Hop whose health is a fixed, configurable value (reaping tests).
    struct StaticHealthHop {
        health: qcore_transport_api::HopHealth,
    }

    #[async_trait::async_trait]
    impl qcore_transport_api::RunningHop for StaticHealthHop {
        fn descriptor(&self) -> &'static qcore_transport_api::TransportDescriptor {
            &FAILING_STOP_DESCRIPTOR
        }
        fn dialer(&self) -> std::sync::Arc<dyn qcore_transport_api::Dialer> {
            std::sync::Arc::new(UnusedDialer)
        }
        fn health(&self) -> qcore_transport_api::HopHealth {
            self.health
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
            tokio::sync::broadcast::channel(1).0.subscribe()
        }
        async fn stop(&self) -> Result<(), qcore_transport_api::HopError> {
            Ok(())
        }
    }

    /// Mid-session death double (H1.5): health is Healthy for the FIRST call
    /// (bring-up readiness passes, exactly the mock transport's
    /// `fail_after_first_health_check` mode this test mirrors) and Failed
    /// for every later call — the shape of a real transport dying after a
    /// green start (wg tunnel expiry, sidecar death).
    struct DiesAfterStartHop {
        health_checks: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl qcore_transport_api::RunningHop for DiesAfterStartHop {
        fn descriptor(&self) -> &'static qcore_transport_api::TransportDescriptor {
            &FAILING_STOP_DESCRIPTOR
        }
        fn dialer(&self) -> std::sync::Arc<dyn qcore_transport_api::Dialer> {
            std::sync::Arc::new(UnusedDialer)
        }
        fn health(&self) -> qcore_transport_api::HopHealth {
            let n = self
                .health_checks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n >= 1 {
                qcore_transport_api::HopHealth::Failed
            } else {
                qcore_transport_api::HopHealth::Healthy
            }
        }
        fn events(&self) -> tokio::sync::broadcast::Receiver<HopEvent> {
            tokio::sync::broadcast::channel(16).0.subscribe()
        }
        async fn stop(&self) -> Result<(), qcore_transport_api::HopError> {
            Ok(())
        }
    }

    fn handle_with_health(id: &str, health: qcore_transport_api::HopHealth) -> SessionHandle {
        let (events, _) = tokio::sync::broadcast::channel(8);
        SessionHandle::bare(
            id.to_string(),
            "exit-d",
            ChainSer {
                hops: Vec::new(),
                max_depth: 3,
            },
            vec![crate::session::lifecycle::StartedHop {
                hop_id: "h-0".to_string(),
                kind: "static-health".to_string(),
                family: "ipv4".to_string(),
                endpoint: None,
                via: "root".to_string(),
                nested: false,
                inner_mtu: 1500,
                obfuscation: None,
                hop: std::sync::Arc::new(StaticHealthHop { health }),
                congested_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                keepalive: None,
                forwarder: None,
            }],
            events,
        )
    }

    #[test]
    fn session_report_reaps_a_self_dead_session_but_reports_it_once() {
        let engine = test_engine();
        engine.lock_live().insert(
            "dead".to_string(),
            handle_with_health("dead", qcore_transport_api::HopHealth::Failed),
        );
        // First call: the final report is still served (callers learn what
        // died), and the entry is reaped from `live`.
        let report = engine
            .session_report("dead")
            .expect("final report served once");
        assert_eq!(report.ordered_chain.len(), 1);
        assert_eq!(report.ordered_chain[0].status, "failed");
        assert!(
            engine.lock_live().get("dead").is_none(),
            "self-dead session reaped from the live map"
        );
        // Subsequent calls: gone — a dead session cannot linger forever.
        assert!(
            engine.session_report("dead").is_none(),
            "reaped session reports None afterwards"
        );
    }

    #[test]
    fn session_report_keeps_alive_and_partial_sessions() {
        let engine = test_engine();
        engine.lock_live().insert(
            "up".to_string(),
            handle_with_health("up", qcore_transport_api::HopHealth::Healthy),
        );
        // Healthy: stays live across repeated reads.
        for _ in 0..3 {
            let report = engine.session_report("up").expect("healthy persists");
            assert_eq!(report.ordered_chain[0].status, "up");
        }
        assert!(engine.lock_live().get("up").is_some());
        // Degraded and Starting are not terminal: no reaping either.
        engine.lock_live().insert(
            "degraded".to_string(),
            handle_with_health("degraded", qcore_transport_api::HopHealth::Degraded),
        );
        engine
            .session_report("degraded")
            .expect("degraded session serves");
        assert!(engine.lock_live().get("degraded").is_some());
    }

    #[test]
    fn self_dead_requires_every_hop_dead() {
        // Empty `started` (never happens from a real bring-up) must not be
        // reaped: an empty report is not proof of death.
        assert!(!self_dead(&[]));
        // One failed hop is dead.
        let one_failed = vec![crate::session::report::HopReport {
            hop_id: "h".into(),
            kind: "k".into(),
            family: "ipv4".into(),
            endpoint: None,
            status: "failed".into(),
            via: "root".into(),
            nested: false,
            mtu: 1500,
            obfuscation: None,
            dropped: 0,
        }];
        assert!(self_dead(&one_failed));
        // A mixed chain with one healthy hop is not dead.
        let mut mixed = one_failed.clone();
        mixed.push(crate::session::report::HopReport {
            status: "up".into(),
            ..one_failed[0].clone()
        });
        assert!(!self_dead(&mixed));
    }

    /// Real-path mid-session death (H1.5): a started hop whose health flips
    /// Healthy→Failed after bring-up (the mock transport's
    /// `fail_after_first_health_check` mode; against a real transport this
    /// is wg tunnel expiry or sidecar death, and the `HopEvent::Failed`
    /// below is the same signal the hop's event forwarder fans into the
    /// session bus). The report must self-reap: final failed report served
    /// ONCE, entry reaped, subsequent reports None. The predecessor's
    /// reaper tests used fixed-health stubs; this one exercises the death
    /// transition itself on the live path.
    #[tokio::test]
    async fn mid_session_hop_death_self_reaps_through_session_report() {
        let engine = test_engine();
        let dying = DiesAfterStartHop {
            health_checks: std::sync::atomic::AtomicU64::new(0),
        };
        let (_events, _drain) = tokio::sync::broadcast::channel::<HopEvent>(8);
        let handle = SessionHandle::bare(
            "dying",
            "exit-die",
            ChainSer {
                hops: Vec::new(),
                max_depth: 3,
            },
            Vec::new(),
            engine.events.clone(),
        );
        let started_hop = crate::session::lifecycle::StartedHop {
            hop_id: "die-0".to_string(),
            kind: "mock".to_string(),
            family: "ipv4".to_string(),
            endpoint: None,
            via: "root".to_string(),
            nested: false,
            inner_mtu: 1500,
            obfuscation: None,
            hop: std::sync::Arc::new(dying),
            congested_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            keepalive: None,
            forwarder: None,
        };
        handle.wire_exit(vec![started_hop], None, None);
        // Bring-up read the health first: the hop started green.
        assert_eq!(
            handle.started_hops()[0].hop.health(),
            qcore_transport_api::HopHealth::Healthy,
            "bring-up readiness probe sees a healthy hop"
        );
        engine.lock_live().insert("dying".to_string(), handle);

        // The transport dies mid-session: the Failed event fans into the
        // session bus (embedder-visible via subscribe()); the engine's own
        // sender is the same channel `start()` forwards hop events onto.
        // A subscriber must exist (as the embedder/forwarder would) — a
        // broadcast with zero receivers drops sends.
        let mut bus = engine.subscribe();
        engine
            .events
            .send(HopEvent::Failed {
                hop_id: "die-0".to_string(),
                cause: "mock transport failed after first health check".to_string(),
            })
            .expect("session bus send");
        let delivered = tokio::time::timeout(std::time::Duration::from_secs(2), bus.recv())
            .await
            .expect("event arrives")
            .expect("recv ok");
        assert!(
            matches!(delivered, HopEvent::Failed { .. }),
            "embedder sees the mid-session death on the bus: {delivered:?}"
        );

        // First report AFTER the death: the final failed report, served once.
        let report = engine
            .session_report("dying")
            .expect("final report served once");
        assert_eq!(report.ordered_chain.len(), 1);
        assert_eq!(report.ordered_chain[0].hop_id, "die-0");
        assert_eq!(
            report.ordered_chain[0].status, "failed",
            "mid-session death reads as failed, not up"
        );
        assert!(
            engine.lock_live().get("dying").is_none(),
            "self-dead session reaped from the live map"
        );
        // Subsequent calls: gone — a dead session cannot linger forever.
        assert!(
            engine.session_report("dying").is_none(),
            "reaped session reports None afterwards"
        );
    }

    // --- preconnect_identity classification tests -------------------------

    fn preconnect_dirs(tag: &str) -> (std::path::PathBuf, ProfileDirs) {
        let root = std::env::temp_dir().join(format!(
            "qcore-preconnect-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let dirs = ProfileDirs::resolve(Some(root.join("config")), Some(root.join("profiles")));
        (root, dirs)
    }

    /// Single warp hop spec for preconnect tests (needs exactly the Outer
    /// role, so `ensure_warp_for_specs` covers it).
    fn warp_specs() -> Vec<ExpandedHop> {
        vec![ExpandedHop::Hop(HopSpec {
            id: "wg-0".to_string(),
            config: crate::config::HopConfig::Wireguard(crate::config::WireguardConfig {
                peer: "warp".to_string(),
                import_ref: None,
                obfuscation: None,
                family: "dual".to_string(),
                endpoint: Some("162.159.192.1:2408".to_string()),
            }),
        })]
    }

    fn seed_outer_identity(dirs: &ProfileDirs) {
        crate::identity::store::save(
            dirs,
            crate::identity::store::IdentityRole::Outer,
            &crate::identity::model::ProviderIdentity {
                device_id: "dev-pre-1".to_string(),
                access_token: crate::config::secret::SecretString::new("tok"),
                private_key_b64: crate::config::secret::SecretString::new(
                    "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                ),
                peer_key_b64: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=".to_string(),
                interface_v4: "172.16.0.2".to_string(),
                interface_v6: "2606:4700:110::2".to_string(),
                masque: None,
                refused: false,
                license_upgraded: false,
            },
        )
        .expect("seeds identity");
    }

    #[tokio::test]
    async fn preconnect_transient_refresh_failure_proceeds_with_notice() {
        // Refresh times out (provider unreachable class): the stored
        // identity is kept and preconnect must PROCEED with a notice — the
        // documented contract (the failure, if real, surfaces from the
        // tunnel itself), not a fatal Err.
        let (_root, dirs) = preconnect_dirs("transient");
        dirs.ensure_dirs().expect("dirs");
        seed_outer_identity(&dirs);
        let engine = Engine::new(EngineConfig {
            dirs: dirs.clone(),
            ..EngineConfig::default()
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        // Holds connections open: every provider call times out.
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt as _;
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                });
            }
        });

        let opts = crate::identity::register::ProviderOptions {
            provider_base: format!("http://{addr}/v0test"),
            timeout_secs: 1,
            family: "dual".to_string(),
        };
        let outcome = engine.preconnect_identity(&warp_specs(), &opts, None).await;
        server.abort();
        let notice = outcome
            .expect("transient refresh failure must proceed, not fail")
            .expect("a notice names the failure");
        assert!(
            notice.contains("identity kept"),
            "notice explains the kept identity: {notice}"
        );
        // The stored identity survived untouched.
        assert_eq!(
            engine
                .load_identity(crate::identity::store::IdentityRole::Outer)
                .expect("kept")
                .device_id,
            "dev-pre-1"
        );
        let _ = std::fs::remove_dir_all(&_root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn preconnect_missing_identity_is_fatal() {
        // The no-stored-identity shape of Blocked (identity: None, cause
        // names `qcore register`) means the connect cannot proceed: fatal.
        let (_root, dirs) = preconnect_dirs("missing");
        dirs.ensure_dirs().expect("dirs");
        let engine = Engine::new(EngineConfig {
            dirs: dirs.clone(),
            ..EngineConfig::default()
        });
        // No fixture, no stored identity: ensure_warp_for_specs will try to
        // register against a dead endpoint → Blocked, identity: None.
        let dead = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let opts = crate::identity::register::ProviderOptions {
            provider_base: format!("http://{dead}/v0test"),
            timeout_secs: 1,
            family: "dual".to_string(),
        };
        let err = engine
            .preconnect_identity(&warp_specs(), &opts, None)
            .await
            .expect_err("no identity + dead provider is fatal");
        assert_eq!(err.action, crate::identity::report::ReportAction::Blocked);
        assert!(err.identity.is_none(), "the fatal shape");
        let _ = std::fs::remove_dir_all(&_root);
    }

    #[test]
    fn warp_identities_needed_matches_inject_predicate() {
        // The count predicate must agree with `materials_for_chain` (inject
        // resolves identity material for exactly these hops): a hop counted
        // here but not injectable (or vice versa) breaks the auto-register
        // contract. Representative shapes: explicit-endpoint warp hop,
        // import hop, non-warp hop, plain warp hop.
        let dir = std::env::temp_dir().join(format!(
            "qcore-engine-pair-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let dirs = crate::config::profile_dir::ProfileDirs::resolve(
            Some(dir.join("config")),
            Some(dir.join("profiles")),
        );
        let engine = Engine::new(EngineConfig {
            dirs: dirs.clone(),
            ..EngineConfig::default()
        });
        // Seed the outer identity so inject resolves warp hops (its
        // contract: stored identity + endpoint from chain or cache).
        crate::identity::store::save(
            &dirs,
            crate::identity::store::IdentityRole::Outer,
            &crate::identity::model::ProviderIdentity {
                device_id: "dev-pair-1".to_string(),
                access_token: crate::config::secret::SecretString::new("tok"),
                private_key_b64: crate::config::secret::SecretString::new(
                    "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                ),
                peer_key_b64: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=".to_string(),
                interface_v4: "172.16.0.2".to_string(),
                interface_v6: "2606:4700:110::2".to_string(),
                masque: None,
                refused: false,
                license_upgraded: false,
            },
        )
        .expect("seeds identity");
        let wg = |peer: &str, endpoint: Option<&str>, import: Option<&str>| HopSpec {
            id: format!("wg-{peer}-{import:?}-{endpoint:?}"),
            config: crate::config::HopConfig::Wireguard(crate::config::WireguardConfig {
                peer: peer.to_string(),
                import_ref: import.map(str::to_string),
                obfuscation: None,
                family: "dual".to_string(),
                endpoint: endpoint.map(str::to_string),
            }),
        };
        let masque = |endpoint: Option<&str>| HopSpec {
            id: format!("masque-{endpoint:?}"),
            config: crate::config::HopConfig::Masque(crate::config::MasqueConfig {
                alpn: "h3".to_string(),
                obfuscation: None,
                family: "dual".to_string(),
                endpoint: endpoint.map(str::to_string),
            }),
        };
        let expanded = |hops: &[HopSpec]| {
            hops.iter()
                .map(|h| ExpandedHop::Hop(h.clone()))
                .collect::<Vec<_>>()
        };
        let inject_count = |hops: &[HopSpec]| {
            crate::identity::inject::materials_for_chain(&dirs, hops)
                .map(|m| m.len())
                .unwrap_or_else(|(hop, msg)| {
                    panic!("inject must resolve for the pairing test: {hop}: {msg}")
                })
        };
        // Explicit-endpoint warp hop: identity keys still needed (the
        // endpoint removes only the scan requirement).
        let explicit = vec![wg("warp", Some("162.159.192.1:2408"), None)];
        let needed = engine
            .warp_identities_needed(&expanded(&explicit))
            .expect("presets resolve");
        assert_eq!(needed, 1, "explicit-endpoint warp hop needs an identity");
        assert_eq!(needed, inject_count(&explicit));
        // Import hop: no identity (its keys come from the import store);
        // inject skips it too, so the counts pair at zero.
        let imported = vec![wg("imported", None, Some("ref"))];
        let needed = engine
            .warp_identities_needed(&expanded(&imported))
            .expect("presets resolve");
        assert_eq!(needed, 0, "import hop carries its own keys");
        assert_eq!(needed, inject_count(&imported));
        // Non-warp shapes: identity-free hops count zero on both sides.
        let plain = vec![
            wg("personal", Some("203.0.113.9:51820"), None),
            masque(Some("162.159.192.1:443")),
        ];
        let needed = engine
            .warp_identities_needed(&expanded(&plain))
            .expect("presets resolve");
        assert_eq!(needed, 0, "non-warp hops need no identity");
        assert_eq!(needed, inject_count(&plain));
        // Mixed chain: the warp hop is the only identity consumer.
        let mixed = vec![
            wg("warp", Some("162.159.192.1:2408"), None),
            masque(Some("162.159.192.1:443")),
            wg("imported", None, Some("ref")),
        ];
        let needed = engine
            .warp_identities_needed(&expanded(&mixed))
            .expect("presets resolve");
        assert_eq!(needed, 1);
        assert_eq!(needed, inject_count(&mixed));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stop_all_reports_first_error_but_stops_every_session() {
        let engine = test_engine();
        let fail_stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        engine.lock_live().insert(
            "s-fail".to_string(),
            failing_handle("s-fail", fail_stopped.clone()),
        );
        engine
            .lock_live()
            .insert("s-ok".to_string(), dummy_handle("s-ok"));
        let err = engine
            .stop()
            .await
            .expect_err("failing session surfaces one report");
        assert!(err.to_string().contains("stop boom"), "got: {err:?}");
        assert_eq!(err.hop_id, "exit-f");
        assert!(
            fail_stopped.load(std::sync::atomic::Ordering::SeqCst),
            "failing session's stop ran"
        );
        assert!(
            engine.session_report("s-ok").is_none(),
            "healthy session reaped despite the earlier failure"
        );
        assert!(
            engine.session_report("s-fail").is_none(),
            "failed session removed from live map"
        );
    }

    #[tokio::test]
    async fn stop_all_second_session_still_stops_after_first_fails() {
        let engine = test_engine();
        let fail_stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        engine.lock_live().insert(
            "s-fail".to_string(),
            failing_handle("s-fail", fail_stopped.clone()),
        );
        engine.lock_live().insert(
            "s-second".to_string(),
            failing_handle("s-second", second_stopped.clone()),
        );
        let err = engine.stop().await.expect_err("first error reported");
        assert!(err.to_string().contains("stop boom"), "got: {err:?}");
        assert!(
            fail_stopped.load(std::sync::atomic::Ordering::SeqCst),
            "first failing session's stop ran"
        );
        assert!(
            second_stopped.load(std::sync::atomic::Ordering::SeqCst),
            "second session's stop still ran after the first errored"
        );
    }
}
