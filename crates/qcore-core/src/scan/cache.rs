//! Per-transport last-known-good cache (002 FR-008, data-model
//! `EndpointCacheEntry`).
//!
//! `endpoints.json` gains a `winners` map (transport → winner) beside the
//! legacy top-level `last_known_good`, which is kept updated for the
//! pre-002 reader (`reconnect::last_known_good`). Rule: a cached winner is
//! re-verified (fast TCP path) before use; failure evicts that transport's
//! entry and the caller runs a full scan (FR-008).

use crate::config::profile_dir::ProfileDirs;
use crate::identity::model::now_ms;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

/// One cached winner. `address` is text (`ip:port`) so the file stays
/// hand-inspectable; unparseable entries read as absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportWinner {
    pub address: String,
    pub profile: String,
    pub verified_at_ms: u64,
    pub family: String,
}

impl TransportWinner {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address.parse().ok()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    last_known_good: Option<String>,
    #[serde(default)]
    winners: BTreeMap<String, TransportWinner>,
}

/// Same-process RMW serializer (#15 perf batch: the cache is read-modify-
/// write, so concurrent `record_winner` calls for different transports lost
/// updates — last writer clobbered the first. Poisoning is recovered, never
/// fatal: the cache is best-effort, and the atomic replace below means a
/// recovered lock still never leaves a torn file). Cross-process races
/// remain (no file locking — documented follow-up); the atomic replace at
/// least guarantees readers never see torn JSON.
static CACHE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_cache() -> std::sync::MutexGuard<'static, ()> {
    CACHE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn read_file(dirs: &ProfileDirs) -> CacheFile {
    std::fs::read_to_string(dirs.endpoints_file())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_file(dirs: &ProfileDirs, file: &CacheFile) -> Result<(), String> {
    dirs.ensure_dirs().map_err(|e| e.to_string())?;
    let body = serde_json::to_string(file).map_err(|e| e.to_string())?;
    // Atomic replace: temp + rename, so concurrent readers never observe a
    // half-written file. Temp name carries the pid so concurrent processes
    // never share it; a stale temp from a crashed writer is simply
    // overwritten by the next write.
    let path = dirs.endpoints_file();
    let tmp = path.with_file_name(format!(".endpoints.{}.tmp", std::process::id()));
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

/// All cached winners (tolerant: missing/corrupt file → empty, never fatal).
pub fn read_winners(dirs: &ProfileDirs) -> BTreeMap<String, TransportWinner> {
    read_file(dirs).winners
}

/// Record a transport's winner, preserving other transports. The legacy
/// top-level `last_known_good` follows the newest winner for old readers.
/// Serialized against concurrent same-process writers (see `CACHE_LOCK`).
pub fn record_winner(
    dirs: &ProfileDirs,
    transport: &str,
    winner: TransportWinner,
) -> Result<(), String> {
    let _guard = lock_cache();
    let mut file = read_file(dirs);
    file.last_known_good = Some(winner.address.clone());
    file.winners.insert(transport.to_string(), winner);
    write_file(dirs, &file)
}

/// Set the legacy top-level `last_known_good` WITHOUT touching the winners
/// map. `persist_verified` used to rewrite the whole file with only
/// `last_known_good`, wiping every other transport's winner on each scan;
/// this is the atomicity-preserving spelling. Serialized like `record_winner`.
pub fn persist_last_known_good(dirs: &ProfileDirs, addr: SocketAddr) -> Result<(), String> {
    let _guard = lock_cache();
    let mut file = read_file(dirs);
    file.last_known_good = Some(addr.to_string());
    write_file(dirs, &file)
}

/// Fast path: TCP re-verify the cached winner for `transport`+`family`.
/// Hit returns the address plus connect latency; miss evicts that entry
/// (family mismatches miss WITHOUT evicting — the entry belongs to another
/// family's scan). Winners were traffic-verified when recorded; the
/// re-verify is a reachability confirmation, not a re-proof.
pub async fn verify_winner_first(
    dirs: &ProfileDirs,
    transport: &str,
    family: &str,
    timeout: Duration,
) -> Option<(SocketAddr, u64)> {
    let winner = read_winners(dirs).get(transport)?.clone();
    if family != "dual" && winner.family != family {
        return None;
    }
    let addr = winner.socket_addr()?;
    let t0 = std::time::Instant::now();
    // Any unsuccessful re-verify (refused, timeout, reset) evicts: a winner
    // that does not answer quickly is not a fast path.
    let ok = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !ok {
        evict_winner(dirs, transport);
        return None;
    }
    touch_verified_at(dirs, transport);
    Some((addr, t0.elapsed().as_millis() as u64))
}

fn evict_winner(dirs: &ProfileDirs, transport: &str) {
    let _guard = lock_cache();
    let mut file = read_file(dirs);
    if file.winners.remove(transport).is_some() {
        let _ = write_file(dirs, &file);
    }
}

/// Per-transport stale eviction (F1): drop only `transport`'s winner after an
/// empty scan, preserving siblings. The legacy `last_known_good` follows a
/// remaining winner when one exists (so reconnect keeps working); it is
/// cleared only when no winners remain. Deletes the file when fully empty
/// (legacy-only stale files included).
pub fn evict_stale_transport(dirs: &ProfileDirs, transport: &str) -> Result<(), String> {
    let _guard = lock_cache();
    let mut file = read_file(dirs);
    file.winners.remove(transport);
    if file.winners.is_empty() {
        file.last_known_good = None;
    } else if !file
        .winners
        .values()
        .any(|w| Some(&w.address) == file.last_known_good.as_ref())
    {
        if let Some((_, w)) = file.winners.first_key_value() {
            file.last_known_good = Some(w.address.clone());
        }
    }
    if file.winners.is_empty() && file.last_known_good.is_none() {
        let path = dirs.endpoints_file();
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    write_file(dirs, &file)
}

fn touch_verified_at(dirs: &ProfileDirs, transport: &str) {
    let _guard = lock_cache();
    let mut file = read_file(dirs);
    if let Some(w) = file.winners.get_mut(transport) {
        w.verified_at_ms = now_ms();
        let _ = write_file(dirs, &file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(tag: &str) -> ProfileDirs {
        let dir = std::env::temp_dir().join(format!("qcore-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")));
        d.ensure_dirs().unwrap();
        d
    }

    fn winner(addr: &str) -> TransportWinner {
        TransportWinner {
            address: addr.to_string(),
            profile: "balanced".to_string(),
            verified_at_ms: now_ms(),
            family: "ipv4".to_string(),
        }
    }

    #[test]
    fn record_and_read_round_trip() {
        let d = dirs("rt");
        assert!(read_winners(&d).is_empty());
        record_winner(&d, "warp", winner("127.0.0.1:2408")).unwrap();
        record_winner(&d, "masque", winner("127.0.0.1:443")).unwrap();
        let map = read_winners(&d);
        assert_eq!(map.len(), 2);
        assert_eq!(map["warp"].address, "127.0.0.1:2408");
        // Legacy reader still sees the newest winner.
        assert_eq!(
            crate::session::reconnect::last_known_good(&d),
            Some("127.0.0.1:443".parse().unwrap())
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn corrupt_cache_reads_empty() {
        let d = dirs("corrupt");
        std::fs::write(d.endpoints_file(), "{oops").unwrap();
        assert!(read_winners(&d).is_empty());
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// Failing-first (#15): concurrent same-process writers for different
    /// transports must not lose updates. Pre-fix this failed: read-modify-
    /// write without serialization meant the last writer clobbered the first
    /// (lost winners). Rounds raise the race window; the lock makes every
    /// round pass deterministically.
    #[test]
    fn concurrent_writers_keep_all_transports() {
        let d = dirs("conc");
        for _ in 0..10 {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
            std::thread::scope(|s| {
                for (i, t) in ["warp", "masque", "tor", "psiphon"].iter().enumerate() {
                    let b = barrier.clone();
                    let d = &d;
                    s.spawn(move || {
                        b.wait(); // release all writers at once
                        record_winner(d, t, winner(&format!("127.0.0.1:{}", 2400 + i)))
                            .expect("records under contention");
                    });
                }
            });
            let map = read_winners(&d);
            assert_eq!(map.len(), 4, "no winner lost to a concurrent write");
        }
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// `persist_last_known_good` sets the legacy LKG without wiping sibling
    /// transports' winners (the old whole-file rewrite in `persist_verified`
    /// destroyed them on every scan).
    #[test]
    fn persist_lkg_preserves_sibling_winners() {
        let d = dirs("lkgkeep");
        record_winner(&d, "warp", winner("127.0.0.1:2408")).unwrap();
        record_winner(&d, "masque", winner("127.0.0.1:443")).unwrap();
        persist_last_known_good(&d, "127.0.0.1:51820".parse().unwrap()).unwrap();
        let map = read_winners(&d);
        assert_eq!(map.len(), 2, "sibling winners survive LKG persist");
        assert_eq!(map["warp"].address, "127.0.0.1:2408");
        let raw = std::fs::read_to_string(d.endpoints_file()).unwrap();
        assert!(raw.contains("127.0.0.1:51820"), "LKG updated: {raw}");
        // No torn temp files left behind.
        let parent = d.endpoints_file().parent().unwrap().to_path_buf();
        assert!(
            std::fs::read_dir(&parent).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_str()
                .unwrap_or("")
                .ends_with(".tmp")),
            "atomic replace cleans up its temp"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }
}
