//! Shared test-only helpers (T7 stories 22): per-test unique temp dirs and
//! guaranteed-closed ephemeral ports, so parallel runs neither collide nor
//! assume fixed closed ports (e.g. `127.0.0.1:1` may be filtered rather than
//! refused on some hosts, and `pid`-only dir names collide across threads of
//! one nextest binary).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique scratch dir: `prefix-pid-counter`. Callers create/remove as before;
/// the counter makes same-process parallel tests disjoint.
pub fn unique_dir(prefix: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// A loopback addr whose port was just bound `:0` and released: guaranteed
/// closed at return (modulo a racing third-party bind). Prefer over fixed
/// ports in unreachable/fail-closed tests.
pub fn closed_port() -> SocketAddr {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind for closed port");
    let addr = listener.local_addr().expect("ephemeral addr");
    drop(listener);
    addr
}
