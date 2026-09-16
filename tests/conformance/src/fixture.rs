//! Loopback fake-provider fixture double (002 T008).
//!
//! Speaks the same JSON shape as the real registration API
//! (`POST <base>/reg`, `GET <base>/reg/<id>`, `PATCH <base>/reg/<id>`,
//! `PUT <base>/reg/<id>/account`) over plaintext HTTP on 127.0.0.1 —
//! reachable only through the test-only provider override, never the
//! default `https://` provider. Modes:
//!
//! - [`FixtureMode::Accept`]: every call succeeds (fresh ids per POST).
//! - [`FixtureMode::RefuseIdentity`]: registration still succeeds, but any
//!   `GET`/`PATCH` for an existing id answers 404 — the renewal story's
//!   "old identity is dead" signal.
//! - [`FixtureMode::Timeout`]: connections are held open with no answer —
//!   the client's timeout fires (identity is kept, never renewed).
//!
//! The fixture NEVER echoes request bodies: license keys and tokens that
//! arrive in requests must not appear in any artifact (FR-010/FR-012).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Fixture behavior (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureMode {
    Accept,
    RefuseIdentity,
    Timeout,
}

/// A running fixture: `base_url()` points the client override at it.
/// Dropping aborts the serve loop.
pub struct Fixture {
    base_url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    /// Bind 127.0.0.1:0 and serve `mode` until dropped.
    pub async fn start(mode: FixtureMode) -> Self {
        Self::start_on(mode, "127.0.0.1").await
    }

    /// Bind [::1]:0 and serve `mode` until dropped (dual-stack proofs).
    pub async fn start_v6(mode: FixtureMode) -> Self {
        Self::start_on(mode, "::1").await
    }

    /// Bind `host:0` and serve `mode` until dropped.
    pub async fn start_on(mode: FixtureMode, host: &str) -> Self {
        let listener = tokio::net::TcpListener::bind(format!("{host}:0"))
            .await
            .expect("fixture binds loopback");
        let addr = listener.local_addr().expect("fixture addr");
        let host_part = if addr.is_ipv6() {
            format!("[{}]", addr.ip())
        } else {
            addr.ip().to_string()
        };
        let counter = Arc::new(AtomicU64::new(1));
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    serve_one(socket, mode, counter).await;
                });
            }
        });
        Fixture {
            base_url: format!("http://{host_part}:{}/v0fixture", addr.port()),
            task,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_one(mut socket: tokio::net::TcpStream, mode: FixtureMode, counter: Arc<AtomicU64>) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    // Headers first.
    loop {
        let Ok(n) = socket.read(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 65536 {
            break;
        }
    }
    let header_end = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i + 4,
        None => return,
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let content_length = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < header_end + content_length.min(1_048_576) {
        let Ok(n) = socket.read(&mut buf).await else {
            return;
        };
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let request_line = head.lines().next().unwrap_or("").to_string();

    if mode == FixtureMode::Timeout {
        // Hold the connection: the client's timeout must fire.
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        return;
    }

    let n = counter.fetch_add(1, Ordering::SeqCst);
    let body = route(&request_line, mode, n);
    let (status, payload) = match body {
        Some(b) => ("200 OK", b),
        None => (
            "404 Not Found",
            r#"{"error":"unknown identity"}"#.to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
}

/// Route one request. `None` = 404 unknown identity (refusal signal).
fn route(request_line: &str, mode: FixtureMode, n: u64) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let peer_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x42u8; 32]);
    let fresh_identity = || {
        format!(
            concat!(
                "{{\"id\":\"fixture-dev-{n}\",\"token\":\"fixture-token-{n}\",",
                "\"config\":{{\"peers\":[{{\"public_key\":\"{peer}\",",
                "\"endpoint\":{{\"v4\":\"162.159.192.1:2408\"}}}}],",
                "\"interface\":{{\"addresses\":{{\"v4\":\"172.16.0.2/32\",",
                "\"v6\":\"2606:4700:110::2/128\"}}}}}},",
                "\"account\":{{\"type\":\"free\"}}}}"
            ),
            n = n,
            peer = peer_key
        )
    };
    match (method, path) {
        ("POST", p) if p.ends_with("/reg") => Some(fresh_identity()),
        ("GET", p) if p.contains("/reg/") => match mode {
            // Refresh echoes the requested id with stable material: a
            // healthy identity refreshes to itself (changed = false).
            FixtureMode::Accept => Some(refreshed_identity(path, &peer_key)),
            FixtureMode::RefuseIdentity | FixtureMode::Timeout => None,
        },
        ("PATCH", p) if p.contains("/reg/") => match mode {
            FixtureMode::Accept => Some(r#"{"enrolled":true}"#.to_string()),
            FixtureMode::RefuseIdentity | FixtureMode::Timeout => None,
        },
        ("PUT", p) if p.contains("/account") => match mode {
            FixtureMode::Accept => Some(r#"{"account":{"license":"active"}}"#.to_string()),
            FixtureMode::RefuseIdentity | FixtureMode::Timeout => None,
        },
        _ => Some(r#"{"ok":true}"#.to_string()),
    }
}

/// Refresh answer for `GET <base>/reg/<id>`: the requested id echoed back
/// with stable addresses, so a healthy refresh reports `changed = false`.
/// The token is derived from the id (never from request bodies — the
/// fixture never echoes those, FR-010/FR-012).
fn refreshed_identity(path: &str, peer_key: &str) -> String {
    let id = path.rsplit('/').next().unwrap_or("fixture-dev-0");
    let safe: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let id = if safe.is_empty() {
        "fixture-dev-0".to_string()
    } else {
        safe
    };
    format!(
        concat!(
            "{{\"id\":\"{id}\",\"token\":\"fixture-token-{id}\",",
            "\"config\":{{\"peers\":[{{\"public_key\":\"{peer}\",",
            "\"endpoint\":{{\"v4\":\"162.159.192.1:2408\"}}}}],",
            "\"interface\":{{\"addresses\":{{\"v4\":\"172.16.0.2/32\",",
            "\"v6\":\"2606:4700:110::2/128\"}}}}}},",
            "\"account\":{{\"type\":\"free\"}}}}"
        ),
        id = id,
        peer = peer_key
    )
}
