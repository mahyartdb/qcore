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

use crate::chain::Chain;
use crate::config::profile_dir::ProfileDirs;
use crate::session::lifecycle::StartedHop;
use crate::session::net::FamilyPolicy;
use crate::session::report::{health_status, HopReport};
use qcore_transport_api::{Dialer, FailureReport, HopEvent};
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub chain: ChainSer,
    pub family_policy: FamilyPolicy,
    pub state: SessionState,
    pub started_at: u64,
    pub failure: Option<FailureReport>,
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

    pub fn save(&self, dirs: &ProfileDirs) -> std::io::Result<()> {
        dirs.ensure_dirs()?;
        let json = serde_json::to_string_pretty(self).expect("session serializes");
        std::fs::write(dirs.session_file(), json)
    }

    pub fn load(dirs: &ProfileDirs) -> std::io::Result<Session> {
        let raw = std::fs::read_to_string(dirs.session_file())?;
        serde_json::from_str(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Handle to a live session (US1 lifecycle populates running hops).
/// Cloneable so the engine can track live sessions while callers hold one.
#[derive(Clone)]
pub struct SessionHandle {
    pub id: String,
    pub exit_hop_id: String,
    pub chain: ChainSer,
    pub started: Vec<StartedHop>,
    pub events: tokio::sync::broadcast::Sender<HopEvent>,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("exit_hop_id", &self.exit_hop_id)
            .field(
                "hops",
                &self
                    .started
                    .iter()
                    .map(|s| s.hop_id.clone())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl SessionHandle {
    /// Egress of the exit (last) hop.
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.started
            .last()
            .expect("session has at least one hop")
            .hop
            .dialer()
    }

    /// Per-hop family/endpoint/status/nesting/obfuscation/drops in declared order.
    pub fn hop_reports(&self) -> Vec<HopReport> {
        self.started
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
    /// rule as `unwind`).
    /// Best effort like `unwind`: a failing exit hop must not abandon inner
    /// hops still running.
    pub async fn stop_all(&self) -> Result<(), qcore_transport_api::HopError> {
        let mut first_err = None;
        // Abort all watchers first, yield so aborts land, then stop hops:
        // same anti-race phasing as `unwind`.
        for s in self.started.iter() {
            if let Some(keepalive) = &s.keepalive {
                keepalive.abort();
            }
            if let Some(forwarder) = &s.forwarder {
                forwarder.abort();
            }
        }
        tokio::task::yield_now().await;
        for s in self.started.iter().rev() {
            if let Err(e) = s.hop.stop().await {
                if first_err.is_none() {
                    first_err = Some(e);
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
#[derive(Debug)]
pub enum SessionStatus {
    NotRunning,
    Dead { id: String },
    Unverifiable { session: Session },
    Live { report: report::ConnectionReport },
}

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
            Err(_) => return SessionStatus::NotRunning,
            Ok(s) => s,
        };
        match session.state {
            SessionState::Stopped | SessionState::Failed => SessionStatus::Dead { id: session.id },
            _ => Self::confirm(&session, dirs),
        }
    }

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
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                SessionStatus::Dead {
                    id: session.id.clone(),
                }
            }
            Err(_) => SessionStatus::Unverifiable {
                session: session.clone(),
            },
        }
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
        let handle = SessionHandle {
            id: "s-stop".to_string(),
            exit_hop_id: "exit".to_string(),
            chain: ChainSer {
                hops: vec![],
                max_depth: 3,
            },
            started: vec![
                started_probe("inner", false, inner_stopped.clone()),
                started_probe("exit", true, exit_stopped.clone()),
            ],
            events: tokio::sync::broadcast::channel(8).0,
        };
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
}
