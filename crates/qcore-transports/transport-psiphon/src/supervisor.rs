//! Psiphon/Cfon sidecar supervisor (FR-001a/001b, constitution Sidecar Trust
//! Boundary).
//!
//! The Psiphon client is an external hop process exposing a local proxy; the
//! Rust core dials it (research R6, Oblivion/warp-plus shape). Bounded
//! supervision: explicit executable path (never resolved from PATH), minimal
//! environment, stdout readiness handshake before use, capped restarts, secret
//! delivery via stdin (never argv), teardown on session end and on drop.
//! Restarts exhausted or readiness failed => fail closed naming sidecar,
//! cause, and exhausted bound.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// Readiness announcement the sidecar MUST print on stdout:
/// `QCORE_SIDECAR_READY socks5=127.0.0.1:PORT`
pub const READY_PREFIX: &str = "QCORE_SIDECAR_READY socks5=";

/// How a secret reaches the sidecar. Stdin is implemented (write-once at
/// spawn, handle kept open); never argv (FR-001b). Debug never leaks bytes.
pub struct SidecarSecret {
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for SidecarSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.payload.len())
    }
}

impl Clone for SidecarSecret {
    fn clone(&self) -> Self {
        SidecarSecret {
            payload: self.payload.clone(),
        }
    }
}

/// Sidecar launch configuration.
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Explicit executable path. Never resolved from PATH by default.
    pub exe_path: PathBuf,
    pub args: Vec<String>,
    /// Secret bytes delivered on stdin (never argv).
    pub secret: Option<SidecarSecret>,
    pub ready_timeout: Duration,
    /// Restart cap. Exhaustion fails the session closed (FR-001a).
    pub max_restarts: u32,
}

impl SidecarConfig {
    pub fn new(exe_path: PathBuf) -> Self {
        SidecarConfig {
            exe_path,
            args: Vec::new(),
            secret: None,
            ready_timeout: Duration::from_secs(20),
            max_restarts: 3,
        }
    }
}

/// A running, ready sidecar.
pub struct RunningSidecar {
    child: Option<tokio::process::Child>,
    socks_addr: SocketAddr,
    restarts_used: u32,
    max_restarts: u32,
    exe_label: String,
}

/// Bounded supervisor.
pub struct SidecarSupervisor {
    config: SidecarConfig,
}

impl SidecarSupervisor {
    pub fn new(config: SidecarConfig) -> Self {
        SidecarSupervisor { config }
    }

    /// Spawn + readiness handshake. Fails closed naming sidecar + cause.
    pub async fn spawn(&self) -> Result<RunningSidecar, String> {
        self.spawn_attempt(0).await
    }

    async fn spawn_attempt(&self, restarts_used: u32) -> Result<RunningSidecar, String> {
        let label = self.config.exe_path.display().to_string();
        if !self.config.exe_path.is_file() {
            return Err(format!(
                "sidecar `{label}`: executable not found (explicit path required)"
            ));
        }
        let mut cmd = tokio::process::Command::new(&self.config.exe_path);
        cmd.args(&self.config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // Minimal environment: inherit nothing secret-bearing.
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env(
                "SYSTEMROOT",
                std::env::var_os("SYSTEMROOT").unwrap_or_default(),
            )
            .kill_on_drop(true);
        // Secrets travel on stdin, never argv: assert none of the args looks
        // secret-bearing is the caller's job; the supervisor never appends any.
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("sidecar `{label}`: spawn: {e}"))?;

        // Deliver the secret on stdin first (write-once; handle kept by child
        // table until drop).
        if let Some(secret) = &self.config.secret {
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(&secret.payload).await {
                    let _ = child.kill().await;
                    return Err(format!("sidecar `{label}`: stdin secret delivery: {e}"));
                }
                if let Err(e) = stdin.write_all(b"\n").await {
                    let _ = child.kill().await;
                    return Err(format!("sidecar `{label}`: stdin secret delivery: {e}"));
                }
                // Keep stdin open (some clients block on EOF); drop closes it.
                std::mem::forget(stdin);
            }
        } else {
            // No secret: close stdin so sidecars waiting on a secret line see
            // EOF instead of blocking serve forever.
            drop(child.stdin.take());
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("sidecar `{label}`: no stdout pipe for readiness handshake"))?;
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let deadline = tokio::time::sleep(self.config.ready_timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    let _ = child.kill().await;
                    return Err(format!(
                        "sidecar `{label}`: readiness handshake timed out after {:?}",
                        self.config.ready_timeout
                    ));
                }
                line = lines.next_line() => {
                    match line {
                        Err(e) => {
                            let _ = child.kill().await;
                            return Err(format!("sidecar `{label}`: stdout: {e}"));
                        }
                        Ok(None) => {
                            // EOF before READY: exited early?
                            let status = child.wait().await.ok();
                            return Err(format!(
                                "sidecar `{label}`: exited before readiness (status={status:?})"
                            ));
                        }
                        Ok(Some(l)) => {
                            if let Some(addr) = l.strip_prefix(READY_PREFIX) {
                                match addr.trim().parse::<SocketAddr>() {
                                    Ok(socks_addr) => {
                                        return Ok(RunningSidecar {
                                            child: Some(child),
                                            socks_addr,
                                            restarts_used,
                                            max_restarts: self.config.max_restarts,
                                            exe_label: label,
                                        });
                                    }
                                    Err(_) => continue, // ignore non-conforming lines
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Restart policy hook: revive an exited sidecar while restarts remain,
    /// else fail closed naming the exhausted bound (FR-001a).
    pub async fn ensure_running(&self, running: &mut RunningSidecar) -> Result<(), String> {
        let alive = match running.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        };
        if alive {
            return Ok(());
        }
        if running.restarts_used >= running.max_restarts {
            return Err(format!(
                "sidecar `{}`: exited; restart cap {} exhausted (fail closed)",
                running.exe_label, running.max_restarts
            ));
        }
        let mut revived = self.spawn_attempt(running.restarts_used + 1).await?;
        running.child = revived.child.take();
        running.socks_addr = revived.socks_addr;
        running.restarts_used = revived.restarts_used;
        Ok(())
    }
}

impl RunningSidecar {
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Teardown on session end (kill-on-drop covers the rest).
    pub async fn teardown(mut self) {
        self.shutdown().await;
    }

    /// Orderly shutdown without consuming (for `stop()` behind a lock).
    pub async fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}

impl Drop for RunningSidecar {
    fn drop(&mut self) {
        // Best-effort synchronous kill; teardown() is the orderly path.
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}
