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

/// Atomically persist the rendezvous file: serialize first, write a
/// uniquely-named temp file in the same directory, harden its permissions,
/// then rename over `control.json` so readers never see a half-written
/// document.
///
/// On Unix the temp file is chmodded to `0600` (owner-only) before the
/// rename; the renamed file keeps those permissions. On Windows there is no
/// POSIX mode bit: hardening is best-effort (the file inherits the parent
/// directory ACL, which remains the secrecy boundary, same as
/// `identity.toml`). Rust's std has no stable API for setting Windows file
/// ACLs owner-only, so no `cfg(windows)` permission call is attempted.
pub fn write_control_file(dirs: &ProfileDirs, info: &ControlInfo) -> std::io::Result<()> {
    dirs.ensure_dirs()?;
    let dest = control_file(dirs);
    let raw = serde_json::to_string(info).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("control info not serializable: {e}"),
        )
    })?;
    let tmp = temp_sibling(&dest);
    let write_res = (|| {
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(raw.as_bytes())?;
            f.flush()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &dest)?;
        Ok::<(), std::io::Error>(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_res
}

/// Unique temp sibling for atomic rename: same directory (same filesystem),
/// never a fixed name (parallel writers/tests must not collide).
fn temp_sibling(dest: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
    let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let mut name = dest.as_os_str().to_owned();
    name.push(format!(".tmp.{}-{n}", std::process::id()));
    std::path::PathBuf::from(name)
}

pub fn read_control_file(dirs: &ProfileDirs) -> Option<ControlInfo> {
    let raw = std::fs::read_to_string(control_file(dirs)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn remove_control_file(dirs: &ProfileDirs) {
    let _ = std::fs::remove_file(control_file(dirs));
}

/// Bearer token: 128 bits from the OS RNG, lowercase hex-encoded (32
/// chars, same length as before). The file's directory permissions are the
/// primary secrecy boundary; the token must still not be enumerable by a
/// loopback peer. OS randomness fails closed (`expect` with reason) rather
/// than falling back to pid/time/counter material, which a loopback peer
/// could enumerate.
pub fn new_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS randomness for control token");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Serve the control channel until a valid STOP arrives. STATUS replies with
/// the live report; STOP replies OK and resolves `stopped`.
///
/// The report lives behind a shared [`RwLock`] so the session process can
/// publish fresh health without restarting the listener; each connection is
/// handled on its own task so a slow reader never blocks STATUS/STOP, and
/// transient accept errors continue instead of killing the channel.
pub async fn serve_control(
    listener: tokio::net::TcpListener,
    token: String,
    report: ConnectionReport,
    stopped: tokio::sync::oneshot::Sender<()>,
) {
    let report = std::sync::Arc::new(tokio::sync::RwLock::new(report));
    serve_control_shared(listener, token, report, stopped).await
}

/// [`serve_control`] with a shared live report. Prefer this when the report
/// updates after bring-up; the compat wrapper above snapshots once.
pub async fn serve_control_shared(
    listener: tokio::net::TcpListener,
    token: String,
    report: std::sync::Arc<tokio::sync::RwLock<ConnectionReport>>,
    stopped: tokio::sync::oneshot::Sender<()>,
) {
    let stopped = std::sync::Arc::new(tokio::sync::Mutex::new(Some(stopped)));
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, _) = match res {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let token = token.clone();
                let report = report.clone();
                let stopped = stopped.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    handle_shared(stream, &token, &report, &stopped, &shutdown).await;
                });
            }
            _ = shutdown.notified() => break,
        }
    }
}

/// Maximum inbound control line: commands are `STATUS <token>` / `STOP
/// <token>` (short). A peer sending megabytes without a newline holds a task
/// and buffer forever; cap and drop instead.
const MAX_CONTROL_LINE: u64 = 4096;

/// Length-prefixed fold comparison: no early exit on content, and the length
/// difference folds into the accumulator (loopback-only channel; this raises
/// the bar over byte-compare without a crypto dependency).
fn tokens_equal(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let n = ab.len().max(bb.len());
    let mut diff = ab.len() ^ bb.len();
    for i in 0..n {
        let x = if i < ab.len() { ab[i] } else { 0 };
        let y = if i < bb.len() { bb[i] } else { 0 };
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

async fn handle_shared(
    stream: tokio::net::TcpStream,
    token: &str,
    report: &tokio::sync::RwLock<ConnectionReport>,
    stopped: &tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    shutdown: &tokio::sync::Notify,
) {
    let (r, mut w) = stream.into_split();
    // Bound the inbound line before buffering it.
    use tokio::io::AsyncReadExt as _;
    let mut lines = tokio::io::BufReader::new(r.take(MAX_CONTROL_LINE)).lines();
    let Ok(Some(line)) = lines.next_line().await else {
        return;
    };
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let presented = parts.next().unwrap_or("");
    let reply = if !tokens_equal(presented, token) {
        "ERR bad token\n".to_string()
    } else if cmd == "STATUS" {
        let report = report.read().await;
        format!("OK {}\n", crate::session::report::to_json(&report))
    } else if cmd == "STOP" {
        // STOP consumes the sender exactly once; further STOPs get ERR.
        let mut slot = stopped.lock().await;
        if let Some(tx) = slot.take() {
            let _ = tx.send(());
            shutdown.notify_one();
            "OK STOPPED\n".to_string()
        } else {
            "ERR already stopping\n".to_string()
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn is_hex32(s: &str) -> bool {
        s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    #[test]
    fn tokens_are_128bit_hex_and_unique_over_large_sample() {
        // Tight loop: same pid, likely same-nanosecond clock. The old
        // pid+nanos+counter shape differed only in counter bits here; OS
        // randomness must still yield all-unique tokens.
        let n = 1024;
        let mut seen = std::collections::HashSet::with_capacity(n);
        for _ in 0..n {
            let t = new_token();
            assert!(is_hex32(&t), "token must be 32 lowercase hex chars");
            assert_eq!(t, t.to_ascii_lowercase(), "token hex must be lowercase");
            assert!(seen.insert(t), "duplicate token in {n} samples");
        }
    }

    #[test]
    fn control_file_round_trips_and_leaves_no_temp() {
        let root = std::env::temp_dir().join(format!(
            "qcore-ctl-{}-{}",
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
        let info = ControlInfo {
            port: 12731,
            token: new_token(),
            pid: std::process::id(),
        };
        write_control_file(&dirs, &info).expect("write control file");
        let back = read_control_file(&dirs).expect("control file reads back");
        assert_eq!(back.port, info.port);
        assert_eq!(back.pid, info.pid);
        assert!(tokens_equal(&back.token, &info.token));
        // Atomicity residue: no temp siblings left behind.
        let parent = control_file(&dirs)
            .parent()
            .expect("control file has a parent")
            .to_path_buf();
        let mut leftover = Vec::new();
        for entry in std::fs::read_dir(&parent).expect("list control dir") {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("control.json.tmp.") {
                leftover.push(name);
            }
        }
        assert!(leftover.is_empty(), "temp residue: {leftover:?}");
        // Overwrite path renames cleanly too.
        let info2 = ControlInfo {
            port: 12732,
            token: new_token(),
            pid: std::process::id(),
        };
        write_control_file(&dirs, &info2).expect("rewrite control file");
        let back2 = read_control_file(&dirs).expect("rewritten file reads back");
        assert_eq!(back2.port, 12732);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn control_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "qcore-ctl-perm-{}-{}",
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
        let info = ControlInfo {
            port: 12733,
            token: new_token(),
            pid: std::process::id(),
        };
        write_control_file(&dirs, &info).expect("write control file");
        let mode = std::fs::metadata(control_file(&dirs))
            .expect("stat control file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "control.json must be owner-only");
        let _ = std::fs::remove_dir_all(&root);
    }
}
