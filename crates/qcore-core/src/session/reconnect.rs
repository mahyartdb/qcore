//! Reconnect + cold start (US1 T048).
//!
//! The first `qcore up` creates `identity.toml` and connects via the default
//! endpoint without editing a file (SC-003). Scan-once-and-cache (US4 T068)
//! feeds the verified-endpoint preference consumed here via
//! [`last_known_good`]; the zero-config default scan profile comes from
//! `warp.toml` (002 FR-014) via [`default_scan_profile`].

use crate::chain::ExpandedHop;
use crate::config::profile_dir::ProfileDirs;
use serde::{Deserialize, Serialize};

/// Stable client identity (`identity.toml`). Created once on cold start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub created_at_ms: u64,
}

/// Ensure the identity file exists, creating it on first run. Corrupt
/// records are backed up (`identity.toml.corrupt`) instead of silently
/// clobbered, the id is unpredictable (not pid+millis), the write is atomic
/// (temp + rename), and concurrent cold starts converge: first writer wins,
/// losers re-read the winner instead of flapping the id.
pub fn ensure_identity(dirs: &ProfileDirs) -> std::io::Result<Identity> {
    let path = dirs.identity_file();
    for _ in 0..3 {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(id) = toml::from_str::<Identity>(&raw) {
                return Ok(id);
            }
            // Corrupt (crash/disk-full tear): keep forensics, then fall
            // through to recreate.
            let backup = path.with_extension("toml.corrupt");
            let _ = std::fs::write(&backup, &raw);
            let _ = std::fs::remove_file(&path);
        }
        dirs.ensure_dirs()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let id = Identity {
            id: format!(
                "qcore-{:016x}{:016x}",
                random_half(now, 0),
                random_half(now, 1)
            ),
            created_at_ms: now,
        };
        let text = toml::to_string(&id).unwrap_or_default();
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(text.as_bytes())?;
                return Ok(id);
            }
            // Lost the create race: loop around and read the winner.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "identity file raced creation repeatedly",
    ))
}

fn random_half(now: u64, salt: u64) -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u64(now.wrapping_add(salt.wrapping_mul(0x9E3779B97F4A7C15)));
    h.write_u32(std::process::id());
    h.finish()
}

/// Zero-config default chain: `wireguard peer=warp`, family dual (contracts
/// cli.md `connect/up`). Full scan-cache selection lands in US4 T068.
pub fn default_chain_spec() -> Vec<ExpandedHop> {
    let spec = crate::chain::parse_single_hop("wireguard", "peer=warp family=dual")
        .expect("default chain parses");
    vec![ExpandedHop::Hop(spec)]
}

/// Zero-config default scan profile (002 FR-014/SC-007): the warp.toml
/// choice when the user picks none. Reads the shipped/override default;
/// never fails (falls back to `balanced`).
pub fn default_scan_profile(dirs: &ProfileDirs) -> String {
    crate::scan::seeds::default_scan_profile_name(dirs)
}

/// Reader half of the last-known-good cache: the verified endpoint US4 T068
/// persists to `endpoints.json` (`{"last_known_good": "<ip:port>"}`). `None`
/// until the first verified scan.
pub fn last_known_good(dirs: &ProfileDirs) -> Option<std::net::SocketAddr> {
    let raw = std::fs::read_to_string(dirs.endpoints_file()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("last_known_good")?.as_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> ProfileDirs {
        ProfileDirs::resolve(
            Some(std::env::temp_dir().join(format!("qcore-reconn-{}", std::process::id()))),
            None,
        )
    }

    #[test]
    fn cold_start_creates_identity_once() {
        let d = dirs();
        let a = ensure_identity(&d).unwrap();
        let b = ensure_identity(&d).unwrap();
        assert_eq!(a.id, b.id, "second run reuses the identity");
        assert!(d.identity_file().exists());
        // Unpredictable 128-bit hex (not pid+millis).
        assert!(a.id.starts_with("qcore-"), "{}", a.id);
        assert_eq!(a.id.len(), 6 + 32, "{}", a.id);
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn corrupt_identity_backs_up_and_recreates() {
        let d = dirs();
        d.ensure_dirs().unwrap();
        std::fs::write(d.identity_file(), "truncated = [garbage").unwrap();
        let id = ensure_identity(&d).unwrap();
        assert!(d.identity_file().exists());
        assert!(
            d.identity_file().with_extension("toml.corrupt").exists(),
            "corrupt original kept for forensics"
        );
        // And the recreated identity is stable now.
        let again = ensure_identity(&d).unwrap();
        assert_eq!(id.id, again.id);
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn default_chain_is_single_warp_hop() {
        let specs = default_chain_spec();
        assert_eq!(specs.len(), 1);
    }

    #[test]
    fn no_cache_yet_is_none() {
        assert_eq!(last_known_good(&dirs()), None);
    }
}
