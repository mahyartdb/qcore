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
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;

/// How long `status`/`stop` wait for the control channel before failing
/// closed (unverifiable) or reporting dead.
pub const CONTROL_TIMEOUT: Duration = Duration::from_millis(500);

/// Persisted rendezvous: where the session process listens and the token it
/// demands. Written after a successful start, removed on stop.
#[derive(Clone, Serialize, Deserialize)]
pub struct ControlInfo {
    pub port: u16,
    pub token: String,
    pub pid: u32,
}

impl std::fmt::Debug for ControlInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlInfo")
            .field("port", &self.port)
            .field("token", &"<redacted>")
            .field("pid", &self.pid)
            .finish()
    }
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
        rename_with_retry(&tmp, &dest)?;
        Ok::<(), std::io::Error>(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_res
}

/// Unique temp sibling for atomic rename: same directory (same filesystem),
/// never a fixed name (parallel writers/tests must not collide). Also used
/// by the session-record writer so every durable file shares one shape.
pub(crate) fn temp_sibling_for(dest: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
    let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let mut name = dest.as_os_str().to_owned();
    name.push(format!(".tmp.{}-{n}", std::process::id()));
    std::path::PathBuf::from(name)
}

/// Private alias kept for the existing control.rs call sites.
fn temp_sibling(dest: &std::path::Path) -> std::path::PathBuf {
    temp_sibling_for(dest)
}

/// Backoff for [`rename_with_retry`]: one immediate try, then these three
/// retries.
const RENAME_RETRY_DELAYS_MS: [u64; 3] = [10, 40, 120];

/// Windows `MoveFileEx` reports a *transient* sharing violation while a
/// reader, indexer, or AV scanner still holds either path; unix renames are
/// atomic with no equivalent. Only the two Windows lock codes are retried —
/// anything else (permissions, missing source) is a real error.
fn rename_error_is_transient(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(e.raw_os_error(), Some(5) | Some(32))
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

/// Commit a temp+sibling rename, retrying transient Windows sharing
/// violations (see [`rename_error_is_transient`]). Shared by every durable
/// writer (control/session/identity/cache) so the platform workaround lives
/// in one place.
pub(crate) fn rename_with_retry(
    from: &std::path::Path,
    to: &std::path::Path,
) -> std::io::Result<()> {
    let mut delays = RENAME_RETRY_DELAYS_MS.iter();
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => match delays.next() {
                Some(ms) if rename_error_is_transient(&e) => {
                    std::thread::sleep(Duration::from_millis(*ms));
                }
                _ => return Err(e),
            },
        }
    }
}

/// Control token shape: 128 bits of OS randomness, hex-encoded = exactly 32
/// ASCII hex characters (see [`new_token`]). Validated on read: the token is
/// interpolated into `STATUS {token}` / `STOP {token}` request lines, so a
/// tampered file with `token = "x\nX: y\n"` would otherwise be line
/// injection against whatever loopback service shares the port.
fn valid_token(token: &str) -> bool {
    token.len() == TOKEN_LEN && token.bytes().all(|b| b.is_ascii_hexdigit())
}

const TOKEN_LEN: usize = 32;

/// Read the rendezvous file, failing closed on *any* problem (unreadable,
/// unparseable, or an invalid token shape): callers treat `None` as "cannot
/// confirm liveness", the same outcome a tampered file must produce.
pub fn read_control_file(dirs: &ProfileDirs) -> Option<ControlInfo> {
    read_control_file_checked(dirs).ok().flatten()
}

/// [`read_control_file`] with the rejection reason surfaced (tests and
/// diagnostics). A missing file is `Ok(None)`; a present-but-invalid file is
/// `Err` naming `control.json` and the offending field.
pub fn read_control_file_checked(dirs: &ProfileDirs) -> Result<Option<ControlInfo>, String> {
    let path = control_file(dirs);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("control file `{}`: {e}", path.display())),
    };
    let info: ControlInfo = serde_json::from_str(&raw)
        .map_err(|e| format!("control file `{}`: {e}", path.display()))?;
    if !valid_token(&info.token) {
        return Err(format!(
            "control file `{}`: field `token` must be exactly {TOKEN_LEN} ASCII hex characters",
            path.display()
        ));
    }
    Ok(Some(info))
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
    serve_control_with(
        listener,
        token,
        report,
        stopped,
        PRE_AUTH_TIMEOUT,
        CONTROL_CONNECTION_DEADLINE,
    )
    .await
}

/// [`serve_control_shared`] with explicit timeouts, so tests exercise the
/// real accept loop without waiting the production deadlines out.
async fn serve_control_with(
    listener: tokio::net::TcpListener,
    token: String,
    report: std::sync::Arc<tokio::sync::RwLock<ConnectionReport>>,
    stopped: tokio::sync::oneshot::Sender<()>,
    pre_auth: Duration,
    connection_deadline: Duration,
) {
    let stopped = std::sync::Arc::new(tokio::sync::Mutex::new(Some(stopped)));
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    // Bounded fan-out: a hostile loopback peer opening sockets in a loop must
    // not spawn unbounded tasks/buffers. Over the cap the socket is dropped
    // immediately (silent: core has no logger; the bound is the contract, and
    // the close is the only signal the peer needs).
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));
    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, _) = match res {
                    Ok(v) => v,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let token = token.clone();
                let report = report.clone();
                let stopped = stopped.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_shared(
                        stream,
                        &token,
                        &report,
                        &stopped,
                        &shutdown,
                        pre_auth,
                        connection_deadline,
                    )
                    .await;
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

/// Pre-auth deadline: the first control line must arrive within this. A peer
/// that connects and never sends otherwise holds a connection slot forever.
const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Whole-exchange deadline (read command + write reply). The per-line cap
/// bounds bytes, not time: a slow-drip peer (1 byte/s under
/// [`MAX_CONTROL_LINE`]) could otherwise keep the task alive for hours. Real
/// exchanges are sub-second, so this bound is generous.
const CONTROL_CONNECTION_DEADLINE: Duration = Duration::from_secs(60);

/// Concurrent control connections served at once (see the semaphore in
/// [`serve_control_with`]). STATUS/STOP are one-shot clients; 16 covers any
/// legitimate burst.
const MAX_CONTROL_CONNECTIONS: usize = 16;

/// Our listener's fixed token-mismatch line. Also the classification prefix
/// callers key on to prove a foreign listener (`SessionStatus::confirm`,
/// `stop_probe`, CLI `is_bad_token`).
const ERR_BAD_TOKEN: &str = "ERR bad token";

/// Fixed error text for a token-mismatch reply (PermissionDenied). Carries no
/// peer bytes; the `ERR bad token` prefix stays because the convergence
/// contract above is textual.
const CONTROL_BAD_TOKEN: &str = "ERR bad token (listener rejected the token)";

/// Fixed error text for any other non-OK reply. The raw reply line is
/// attacker-controlled (a hostile service on the shared loopback port can put
/// `X: injected` after its status line), so it never reaches the error
/// surface — only the fixed classification does.
const CONTROL_UNEXPECTED_REPLY: &str = "control listener sent an unexpected reply";

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
    pre_auth: Duration,
    connection_deadline: Duration,
) {
    // Whole-exchange bound: the per-line cap bounds bytes, not time — a peer
    // trickling one byte at a time could otherwise keep the task (and a
    // connection slot) alive indefinitely. Real exchanges are sub-second.
    let _ = tokio::time::timeout(
        connection_deadline,
        exchange(stream, token, report, stopped, shutdown, pre_auth),
    )
    .await;
}

async fn exchange(
    stream: tokio::net::TcpStream,
    token: &str,
    report: &tokio::sync::RwLock<ConnectionReport>,
    stopped: &tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    shutdown: &tokio::sync::Notify,
    pre_auth: Duration,
) {
    let (r, mut w) = stream.into_split();
    // Bound the inbound line before buffering it.
    use tokio::io::AsyncReadExt as _;
    let mut lines = tokio::io::BufReader::new(r.take(MAX_CONTROL_LINE)).lines();
    // Pre-auth deadline: nothing arriving is a stalled/hostile peer, not a
    // command; drop the connection and its slot.
    let line = match tokio::time::timeout(pre_auth, lines.next_line()).await {
        Ok(Ok(Some(line))) => line,
        _ => return,
    };
    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let presented = parts.next().unwrap_or("");
    let reply = if !tokens_equal(presented, token) {
        format!("{ERR_BAD_TOKEN}\n")
    } else if cmd == "STATUS" {
        let report = report.read().await;
        format!("OK {}\n", crate::session::report::to_json(&report))
    } else if cmd == "STOP" {
        // STOP consumes the sender exactly once; further STOPs get ERR.
        let mut slot = stopped.lock().await;
        if let Some(tx) = slot.take() {
            if tx.send(()).is_ok() {
                shutdown.notify_one();
                "OK STOPPED\n".to_string()
            } else {
                shutdown.notify_one();
                "ERR supervisor gone; stop signal lost\n".to_string()
            }
        } else {
            "ERR already stopping\n".to_string()
        }
    } else {
        "ERR unknown command\n".to_string()
    };
    use tokio::io::AsyncWriteExt;
    let _ = w.write_all(reply.as_bytes()).await;
}

/// Client read budget: overall reply deadline from connect, plus a
/// per-read cap. `read` loops internally on short reads, so a per-read
/// timeout alone never bounds total time; the deadline does.
const CLIENT_REPLY_DEADLINE: Duration = Duration::from_secs(3);
const CLIENT_PER_READ_CAP: Duration = Duration::from_secs(2);
/// Reply ceiling: a control reply is one short line; anything larger is a
/// runaway peer, not a protocol message.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Read one newline-terminated reply under the overall deadline, into a
/// fixed buffer. Deadline exceeded or the 64 KiB cap hit fails closed
/// naming the control channel.
fn read_reply_line(stream: &mut std::net::TcpStream, deadline: Instant) -> std::io::Result<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control channel reply exceeded the deadline",
            ));
        }
        let remaining = deadline - now;
        stream.set_read_timeout(Some(remaining.min(CLIENT_PER_READ_CAP)))?;
        let n = match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control channel closed before a full reply",
                ));
            }
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "control channel reply timed out",
                ));
            }
            Err(e) => return Err(e),
        };
        if let Some(pos) = chunk[..n].iter().position(|&b| b == b'\n') {
            raw.extend_from_slice(&chunk[..pos]);
            return Ok(String::from_utf8_lossy(&raw).into_owned());
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_REPLY_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "control channel reply exceeded the size cap",
            ));
        }
    }
}

/// Fixed-string error for a non-OK reply. Never includes the peer's text: a
/// hostile listener on the shared loopback port can craft the line.
/// Classification is prefix-based (`ERR bad token …`), matching the
/// convergence contract consumers apply to this error's text.
fn rejection_error(line: &str) -> std::io::Error {
    let msg = if line.trim_end().starts_with(ERR_BAD_TOKEN) {
        CONTROL_BAD_TOKEN
    } else {
        CONTROL_UNEXPECTED_REPLY
    };
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
}

/// Reject a token that cannot go on the wire (see [`valid_token`]).
fn checked_token(token: &str) -> std::io::Result<&str> {
    if valid_token(token) {
        Ok(token)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control token is not 32 ASCII hex characters",
        ))
    }
}

/// Blocking STATUS query. Ok(report JSON) on live, Err(kind) otherwise:
/// `NotConnected` (refused/timeout: process dead) vs `Unverifiable`.
/// A protocol `ERR ...` reply maps to `PermissionDenied` with a fixed message
/// — `ERR bad token (listener rejected the token)` is the listener's proof
/// that it is not our session (callers converge on it; see
/// [`crate::session::SessionStatus`]). No peer-controlled bytes ride the
/// error surface: a hostile reply may carry `X: injected` and never reaches
/// a sink.
pub fn query_status(addr: std::net::SocketAddr, token: &str) -> std::io::Result<String> {
    // The token is validated-format before interpolation: newline/space
    // injection into the request line is structurally impossible.
    let token = checked_token(token)?;
    let deadline = Instant::now() + CLIENT_REPLY_DEADLINE;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, CONTROL_TIMEOUT)?;
    stream.write_all(format!("STATUS {token}\n").as_bytes())?;
    let line = read_reply_line(&mut stream, deadline)?;
    match line.strip_prefix("OK ") {
        Some(report) => Ok(report.trim_end().to_string()),
        None => Err(rejection_error(&line)),
    }
}

/// Blocking STOP command. Ok(()) when the session acknowledged stopping.
pub fn send_stop(addr: std::net::SocketAddr, token: &str) -> std::io::Result<()> {
    // Validated like [`query_status`]: no whitespace/newline token can reach
    // the `STOP {token}` request line.
    let token = checked_token(token)?;
    let deadline = Instant::now() + CLIENT_REPLY_DEADLINE;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, CONTROL_TIMEOUT)?;
    stream.write_all(format!("STOP {token}\n").as_bytes())?;
    let line = read_reply_line(&mut stream, deadline)?;
    if line.starts_with("OK") {
        Ok(())
    } else {
        Err(rejection_error(&line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_hex32(s: &str) -> bool {
        s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    #[test]
    fn control_info_debug_redacts_token() {
        let token = new_token();
        let info = ControlInfo {
            port: 12730,
            token: token.clone(),
            pid: 4242,
        };
        let dbg = format!("{info:?}");
        assert!(
            !dbg.contains(&token),
            "Debug must not leak the token: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "token field redacted: {dbg}");
        assert!(dbg.contains("12730"), "port printed normally: {dbg}");
        assert!(dbg.contains("4242"), "pid printed normally: {dbg}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_when_supervisor_receiver_dropped_replies_err() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let token = new_token();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        drop(rx);
        tokio::spawn(serve_control(
            listener,
            token.clone(),
            ConnectionReport::new(Vec::new(), "exit".to_string()),
            tx,
        ));
        send_stop(addr, &token).expect_err("receiver-dropped STOP must not report OK");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_with_live_supervisor_replies_ok_and_resolves() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let token = new_token();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let report = std::sync::Arc::new(tokio::sync::RwLock::new(ConnectionReport::new(
            Vec::new(),
            "exit".to_string(),
        )));
        tokio::spawn(serve_control_shared(listener, token.clone(), report, tx));
        send_stop(addr, &token).expect("live supervisor STOP replies OK");
        tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("stop signal resolved")
            .expect("sender alive");
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
    fn control_file_with_invalid_token_fails_closed_naming_field() {
        let root = std::env::temp_dir().join(format!(
            "qcore-ctl-token-{}-{}",
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
        std::fs::create_dir_all(&dirs.config_dir).expect("config dir");
        // 31 chars, a newline-injection payload, and a 32-char non-hex string
        // all fail closed: the token is a protocol field, not free text.
        for (label, token) in [
            ("short", "a".repeat(31)),
            ("newline", "x\nX: y\n".to_string()),
            ("non-hex", "z".repeat(32)),
        ] {
            let raw = serde_json::json!({"port": 12730, "token": token, "pid": 1}).to_string();
            std::fs::write(control_file(&dirs), raw).expect("writes control.json");
            let err = read_control_file_checked(&dirs).expect_err(label);
            assert!(err.contains("control.json"), "{label}: {err}");
            assert!(err.contains("token"), "{label}: names the field: {err}");
            assert!(
                read_control_file(&dirs).is_none(),
                "{label}: Option wrapper fails closed"
            );
        }
        // A well-formed token still loads.
        write_control_file(
            &dirs,
            &ControlInfo {
                port: 12730,
                token: new_token(),
                pid: 1,
            },
        )
        .expect("valid control file");
        assert!(read_control_file(&dirs).is_some());
        assert!(read_control_file_checked(&dirs)
            .expect("valid file")
            .is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// One-shot fake listener that returns `reply` to a single connection,
    /// after consuming the request line (so the close does not RST the reply
    /// away).
    async fn serve_reply_once(reply: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            use tokio::io::AsyncReadExt as _;
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            use tokio::io::AsyncWriteExt as _;
            let _ = s.write_all(reply.as_bytes()).await;
            let _ = s.shutdown().await;
        });
        addr
    }

    /// The error surface carries a fixed classification, never peer bytes: a
    /// hostile service on the shared loopback port must not be able to inject
    /// text into stderr/JSON via its reply line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hostile_reply_text_never_reaches_the_error() {
        // Same-line injection attempt.
        let addr = serve_reply_once("ERR bad token X: injected\n").await;
        let err = query_status(addr, &new_token()).expect_err("non-OK reply");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), CONTROL_BAD_TOKEN);
        assert!(!err.to_string().contains("X: injected"), "{err}");

        // Any other ERR line: fixed generic text, still no peer bytes.
        let addr = serve_reply_once("ERR nope X: injected\n").await;
        let err = query_status(addr, &new_token()).expect_err("non-OK reply");
        assert_eq!(err.to_string(), CONTROL_UNEXPECTED_REPLY);
        assert!(!err.to_string().contains("X: injected"), "{err}");

        // Second-line injection (the exact shape from the finding): only the
        // first line is read, and it is classified rather than echoed.
        let addr = serve_reply_once("ERR bad token\nX: injected\n").await;
        let err = query_status(addr, &new_token()).expect_err("non-OK reply");
        assert_eq!(err.to_string(), CONTROL_BAD_TOKEN);
        assert!(!err.to_string().contains("X: injected"), "{err}");
    }

    /// A peer that connects and sends nothing must not hold a connection slot
    /// past the pre-auth deadline.
    #[tokio::test]
    async fn stalled_pre_auth_peer_is_dropped_at_the_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
        let report = std::sync::Arc::new(tokio::sync::RwLock::new(ConnectionReport::new(
            Vec::new(),
            "exit".to_string(),
        )));
        tokio::spawn(serve_control_with(
            listener,
            new_token(),
            report,
            tx,
            Duration::from_millis(100),
            Duration::from_secs(30),
        ));
        let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
        use tokio::io::AsyncReadExt as _;
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            other => panic!("expected EOF after the pre-auth deadline, got {other:?}"),
        }
    }

    /// Unbounded spawn per accept is a task-exhaustion primitive: 20
    /// concurrent connections against 16 slots must serve 16 and drop 4.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_connections_are_capped_at_sixteen() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
        let report = std::sync::Arc::new(tokio::sync::RwLock::new(ConnectionReport::new(
            Vec::new(),
            "exit".to_string(),
        )));
        tokio::spawn(serve_control_with(
            listener,
            new_token(),
            report,
            tx,
            // Long enough that held connections stay open through the probe.
            Duration::from_secs(5),
            Duration::from_secs(60),
        ));
        let mut clients = Vec::new();
        for _ in 0..20 {
            clients.push(tokio::net::TcpStream::connect(addr).await.expect("connect"));
        }
        // Poll the condition (no fixed sleep): the accept loop drains the
        // backlog asynchronously, so wait until exactly four sockets are at
        // EOF or the deadline proves the cap is not working.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut shed;
        loop {
            shed = clients
                .iter()
                .filter(|c| matches!(c.try_read(&mut [0u8; 1]), Ok(0)))
                .count();
            if shed == 4 || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(shed, 4, "20 connections - 16 slots = 4 shed");
        let held = clients
            .iter()
            .filter(|c| c.try_read(&mut [0u8; 1]).is_err())
            .count();
        assert_eq!(held, 16, "the rest stay open waiting for a command");
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

    #[test]
    fn rename_with_retry_commits_the_temp_file() {
        let root = std::env::temp_dir().join(format!(
            "qcore-rename-{}-{}",
            std::process::id(),
            new_token()
        ));
        std::fs::create_dir_all(&root).expect("temp dir");
        let from = root.join("record.tmp");
        let to = root.join("record.json");
        std::fs::write(&from, b"{}").expect("seed temp");
        rename_with_retry(&from, &to).expect("rename commits");
        assert_eq!(std::fs::read(&to).expect("destination exists"), b"{}");
        assert!(!from.exists(), "temp is gone after the rename");
        let err = rename_with_retry(&from, &to).expect_err("missing source never succeeds");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn only_transient_windows_locks_are_retried() {
        assert_eq!(RENAME_RETRY_DELAYS_MS, [10, 40, 120]);
        assert!(rename_error_is_transient(
            &std::io::Error::from_raw_os_error(5)
        ));
        assert!(rename_error_is_transient(
            &std::io::Error::from_raw_os_error(32)
        ));
        assert!(!rename_error_is_transient(
            &std::io::Error::from_raw_os_error(2)
        ));
        assert!(!rename_error_is_transient(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }
}
