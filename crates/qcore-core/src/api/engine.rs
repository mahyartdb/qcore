//! Engine facade: preflight, start, status, subscribe, stop.
//!
//! Validation is total: an invalid chain never partially starts (FR-027).
//! Preflight validates chain + profiles + config without starting a hop or
//! opening a socket (FR-029).

use crate::api::version::{ABI_VERSION, API_VERSION, SCHEMA_VERSION};
use crate::chain::{ChainBuilder, ChainError, ExpandedHop};
use crate::config::profile_dir::ProfileDirs;
use crate::config::HopSpec;
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
