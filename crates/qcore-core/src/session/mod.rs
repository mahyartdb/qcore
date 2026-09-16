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
    pub fn transition(&mut self, to: SessionState) -> Result<(), String> {
        let ok = matches!(
            (self.state, to),
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
            Err(format!(
                "illegal session transition {:?} -> {to:?}",
                self.state
            ))
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

    /// Per-hop family/endpoint/status/nesting/obfuscation in declared order.
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
            })
            .collect()
    }

    /// Tear down all hops reverse-order (exit first).
    pub async fn stop_all(&self) -> Result<(), qcore_transport_api::HopError> {
        for s in self.started.iter().rev() {
            s.hop.stop().await?;
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

impl SessionStatus {
    pub fn read(dirs: &ProfileDirs) -> SessionStatus {
        let session = match Session::load(dirs) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SessionStatus::NotRunning,
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
}
