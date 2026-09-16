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
use crate::session::SessionHandle;
use qcore_transport_api::{FailureLayer, FailureReport, HopEvent};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
pub struct Engine {
    config: EngineConfig,
    registry: TransportRegistry,
    events: tokio::sync::broadcast::Sender<HopEvent>,
    live: std::sync::Mutex<HashMap<String, SessionHandle>>,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        let (events, _) = tokio::sync::broadcast::channel(256);
        Engine {
            config,
            registry: TransportRegistry::global(),
            events,
            live: std::sync::Mutex::new(HashMap::new()),
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
            &self.registry,
            &chain,
            carrier,
            &self.events,
            &self.config.keepalive,
            deadline,
            lifecycle::BringUpMaterials {
                imports: &imports,
                obfuscation: &obfuscation,
                identities: &identities,
            },
        )
        .await?;
        let exit_hop_id = chain
            .exit()
            .map(|h| h.id.clone())
            .unwrap_or_else(|| "-".to_string());
        let handle = SessionHandle {
            id: new_session_id(),
            exit_hop_id,
            chain: crate::session::ChainSer::from(&chain),
            started,
            events: self.events.clone(),
        };
        self.live
            .lock()
            .expect("live map")
            .insert(handle.id.clone(), handle.clone());
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
    pub fn session_report(&self, id: &str) -> Option<crate::session::report::ConnectionReport> {
        self.live.lock().expect("live map").get(id).map(|h| {
            crate::session::report::ConnectionReport::new(h.hop_reports(), h.exit_hop_id.clone())
        })
    }

    /// Tear down one live session by id.
    pub async fn stop_session(&self, id: &str) -> Result<(), FailureReport> {
        let handle = self
            .live
            .lock()
            .expect("live map")
            .remove(id)
            .ok_or_else(|| {
                FailureReport::new(FailureLayer::Chain, "-", "no such live session", "chain")
            })?;
        handle.stop_all().await.map_err(|e| {
            FailureReport::new(
                FailureLayer::Chain,
                handle.exit_hop_id.clone(),
                e.message,
                "shutdown",
            )
        })
    }

    /// Tear down all live sessions (exit-first per session).
    pub async fn stop(&self) -> Result<(), FailureReport> {
        let ids: Vec<String> = self
            .live
            .lock()
            .expect("live map")
            .keys()
            .cloned()
            .collect();
        for id in ids {
            self.stop_session(&id).await?;
        }
        Ok(())
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

    /// How many WARP identities these specs need: WARP hops without
    /// endpoint/import material, capped at 2 (outer + inner for GOOL-like
    /// pairs). Read-only: presets resolve from dirs, zero sockets (FR-003).
    pub fn warp_identities_needed(&self, specs: &[ExpandedHop]) -> Result<usize, ChainError> {
        let presets = crate::chain::preset::resolve_presets(&self.config.dirs)?;
        let hops = crate::chain::preset::expand(specs.to_vec(), &presets)?;
        let mut need = 0;
        for h in &hops {
            if let crate::config::HopConfig::Wireguard(c) = &h.config {
                if c.peer == "warp" && c.endpoint.is_none() && c.import_ref.is_none() {
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
    /// still valid until expiry). Returns stderr notices or a fatal report.
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
                    ReportAction::Blocked => return Err(report),
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

    /// Parse a full chain expression (`hop (, hop)*`, preset names, `@label`;
    /// contracts/cli.md grammar) with profile-dir presets.
    pub fn parse_chain(&self, expr: &str) -> Result<Vec<ExpandedHop>, ChainError> {
        let presets = crate::chain::preset::resolve_presets(&self.config.dirs)?;
        crate::chain::parse::parse_chain(expr, &self.registry, &presets)
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
