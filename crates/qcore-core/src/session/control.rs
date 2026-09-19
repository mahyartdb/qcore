//! Token-authenticated loopback control channel (US1 T046).
//!
//! `status`/`stop` locate a detached (or foreground) session through
//! `session.json` plus this channel. The bearer token lives in `control.json`
//! next to the state file; the file's directory permissions are the secrecy
//! boundary (same as `identity.toml`). New module (not `session/mod.rs`)
//! because the wire protocol + listener lifecycle is distinct from the state
//! machine. The server side is async (runs inside the session process); the
//! client side is blocking `std` so `status` stays synchronous.

use crate::config::profile_dir::ProfileDirs;
use crate::session::report::ConnectionReport;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

/// How long `status`/`stop` wait for the control channel before failing
/// closed (unverifiable) or reporting dead.
pub const CONTROL_TIMEOUT: Duration = Duration::from_millis(500);

/// Persisted rendezvous: where the session process listens and the token it
/// demands. Written after a successful start, removed on stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlInfo {
    pub port: u16,
    pub token: String,
    pub pid: u32,
}

pub fn control_file(dirs: &ProfileDirs) -> std::path::PathBuf {
    dirs.session_file()
        .parent()
        .map(|p| p.join("control.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("control.json"))
}

pub fn write_control_file(dirs: &ProfileDirs, info: &ControlInfo) -> std::io::Result<()> {
    dirs.ensure_dirs()?;
    std::fs::write(
        control_file(dirs),
        serde_json::to_string(info).expect("ControlInfo is a plain serializable struct"),
    )
}

pub fn read_control_file(dirs: &ProfileDirs) -> Option<ControlInfo> {
    let raw = std::fs::read_to_string(control_file(dirs)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn remove_control_file(dirs: &ProfileDirs) {
    let _ = std::fs::remove_file(control_file(dirs));
}

/// Bearer token: process id + nanos + counter, hex-encoded. Unpredictable
/// enough for a loopback channel whose file is the real boundary.
pub fn new_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{}-{:x}", std::process::id(), ns, n)
}

/// Serve the control channel until a valid STOP arrives. STATUS replies with
/// the live report; STOP replies OK and resolves `stopped`.
pub async fn serve_control(
    listener: tokio::net::TcpListener,
    token: String,
    report: ConnectionReport,
    stopped: tokio::sync::oneshot::Sender<()>,
) {
    let report_json = crate::session::report::to_json(&report);
    let mut stopped = Some(stopped);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let token = token.clone();
        let report_json = report_json.clone();
        // STOP consumes the sender exactly once; further STOPs get ERR.
        let stop_slot = &mut stopped;
        let mut done = false;
        handle_one(stream, &token, |kind| {
            if kind == "STOP" {
                if let Some(tx) = stop_slot.take() {
                    let _ = tx.send(());
                    done = true;
                    "OK STOPPED\n".to_string()
                } else {
                    "ERR already stopping\n".to_string()
                }
            } else {
                format!("OK {report_json}\n")
            }
        })
        .await;
        if done {
            break;
        }
    }
}

async fn handle_one(
    stream: tokio::net::TcpStream,
    token: &str,
    mut respond: impl FnMut(&str) -> String,
) {
    let (r, mut w) = stream.into_split();
    let mut lines = tokio::io::BufReader::new(r).lines();
    let Ok(Some(line)) = lines.next_line().await else {
        return;
    };
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let presented = parts.next().unwrap_or("");
    let reply = if presented != token {
        "ERR bad token\n".to_string()
    } else if cmd == "STATUS" || cmd == "STOP" {
        respond(cmd)
    } else {
        "ERR unknown command\n".to_string()
    };
    use tokio::io::AsyncWriteExt;
    let _ = w.write_all(reply.as_bytes()).await;
}

/// Blocking STATUS query. Ok(report JSON) on live, Err(kind) otherwise:
/// `NotConnected` (refused/timeout: process dead) vs `Unverifiable`.
pub fn query_status(addr: std::net::SocketAddr, token: &str) -> std::io::Result<String> {
    let mut stream = std::net::TcpStream::connect_timeout(&addr, CONTROL_TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("STATUS {token}\n").as_bytes())?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    line.strip_prefix("OK ")
        .map(|s| s.trim_end().to_string())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                line.trim().to_string(),
            )
        })
}

/// Blocking STOP command. Ok(()) when the session acknowledged stopping.
pub fn send_stop(addr: std::net::SocketAddr, token: &str) -> std::io::Result<()> {
    let mut stream = std::net::TcpStream::connect_timeout(&addr, CONTROL_TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("STOP {token}\n").as_bytes())?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    if line.starts_with("OK") {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            line.trim().to_string(),
        ))
    }
}
