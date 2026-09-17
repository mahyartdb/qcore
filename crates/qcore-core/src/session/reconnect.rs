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

/// Ensure the identity file exists, creating it on first run.
pub fn ensure_identity(dirs: &ProfileDirs) -> std::io::Result<Identity> {
    let path = dirs.identity_file();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(id) = toml::from_str::<Identity>(&raw) {
            return Ok(id);
        }
    }
    dirs.ensure_dirs()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let id = Identity {
        id: format!("qcore-{}-{}", std::process::id(), now),
        created_at_ms: now,
    };
    std::fs::write(&path, toml::to_string(&id).unwrap_or_default())?;
    Ok(id)
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
