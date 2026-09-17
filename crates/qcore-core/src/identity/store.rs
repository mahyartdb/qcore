//! Atomic identity store (002 FR-002, research R2).
//!
//! One TOML record per role in the config dir (`identity-warp.toml`,
//! `identity-warp-inner.toml` for GOOL), user-readable-only, written
//! atomically (temp file + rename). Secrets (access token, device key,
//! MASQUE key) live in the [`SecretStore`] (OS keyring, 0600 file fallback)
//! under a service name derived from the config dir, so parallel profiles
//! and test dirs never share secret namespaces.
//!
//! Read contract: missing, corrupt, or partial records read as *missing*
//! (`None`) — the caller re-registers, never crashes (FR-002). A process
//! race is settled by an exclusive lock file: exactly one registration
//! wins; the loser fails closed.

use crate::config::profile_dir::ProfileDirs;
use crate::config::secret::SecretStore;
use crate::identity::model::{MasqueCredential, ProviderIdentity};
use serde::{Deserialize, Serialize};

/// Which identity slot: outer (default WARP) or inner (GOOL second hop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRole {
    Outer,
    Inner,
}

impl IdentityRole {
    fn file_name(self) -> &'static str {
        match self {
            IdentityRole::Outer => "identity-warp.toml",
            IdentityRole::Inner => "identity-warp-inner.toml",
        }
    }

    fn account_prefix(self) -> &'static str {
        match self {
            IdentityRole::Outer => "warp-outer",
            IdentityRole::Inner => "warp-inner",
        }
    }
}

/// Identity record file for a role (field names are contractual —
/// contracts/profiles.md).
pub fn identity_file(dirs: &ProfileDirs, role: IdentityRole) -> std::path::PathBuf {
    dirs.config_dir.join(role.file_name())
}

/// Display name for a role in user-facing messages ("warp"/"warp-inner").
/// Distinct from [`IdentityRole::account_prefix`] (secret-store namespace).
pub(crate) fn role_name(role: IdentityRole) -> &'static str {
    match role {
        IdentityRole::Outer => "warp",
        IdentityRole::Inner => "warp-inner",
    }
}
fn secret_store(dirs: &ProfileDirs) -> SecretStore {
    // Per-dir service namespace: temp test dirs, parallel profiles, and the
    // real profile never collide in a shared OS keyring. Stable FNV-1a —
    // NOT DefaultHasher, whose output is explicitly unstable across
    // releases and would silently orphan the namespace (forced
    // re-registration) on toolchain upgrades.
    let h = namespace_hash(&dirs.config_dir.to_string_lossy());
    SecretStore::new(format!("qcore-identity-{h:016x}"), dirs.config_dir.clone())
}

/// Stable 64-bit FNV-1a (see [`secret_store`]).
fn namespace_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityRecord {
    device_id: String,
    peer_key_b64: String,
    interface_v4: String,
    interface_v6: String,
    #[serde(default)]
    refused: bool,
    #[serde(default)]
    license_upgraded: bool,
    #[serde(default)]
    masque: Option<MasqueRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MasqueRecord {
    cert_pem: String,
    issued_at_ms: u64,
    lifetime_days: u64,
    renew_before_days: u64,
}

/// Load a stored identity. `None` on missing, corrupt, partial, or
/// secret-missing records — the caller treats all four as "no identity"
/// and re-registers (FR-002).
pub fn load(dirs: &ProfileDirs, role: IdentityRole) -> Option<ProviderIdentity> {
    let raw = std::fs::read_to_string(identity_file(dirs, role)).ok()?;
    let rec: IdentityRecord = toml::from_str(&raw).ok()?;
    if rec.device_id.is_empty() || rec.peer_key_b64.is_empty() {
        return None;
    }
    let store = secret_store(dirs);
    let pfx = role.account_prefix();
    let access_token = store.get(&format!("{pfx}/access_token")).ok()?;
    let private_key_b64 = store.get(&format!("{pfx}/private_key")).ok()?;
    if access_token.is_empty() || private_key_b64.is_empty() {
        return None;
    }
    let masque = match rec.masque {
        Some(m) => {
            let key_pem = store.get(&format!("{pfx}/masque_key")).ok()?;
            if key_pem.is_empty() || m.cert_pem.is_empty() {
                return None;
            }
            Some(MasqueCredential {
                cert_pem: m.cert_pem,
                key_pem,
                issued_at_ms: m.issued_at_ms,
                lifetime_days: m.lifetime_days,
                renew_before_days: m.renew_before_days,
            })
        }
        None => None,
    };
    Some(ProviderIdentity {
        device_id: rec.device_id,
        access_token,
        private_key_b64,
        peer_key_b64: rec.peer_key_b64,
        interface_v4: rec.interface_v4,
        interface_v6: rec.interface_v6,
        masque,
        refused: rec.refused,
        license_upgraded: rec.license_upgraded,
    })
}

/// Save an identity: exclusive lock → secrets → atomic record → unlock.
/// Fails closed when another registration holds the lock (exactly one
/// winner; no merged store).
pub fn save(dirs: &ProfileDirs, role: IdentityRole, id: &ProviderIdentity) -> Result<(), String> {
    dirs.ensure_dirs().map_err(|e| e.to_string())?;
    let _lock = acquire_lock(dirs, role)?;
    let store = secret_store(dirs);
    let pfx = role.account_prefix();
    // Secrets first; the record rename commits.
    store
        .put(&format!("{pfx}/access_token"), &id.access_token)
        .map_err(|e| format!("identity secret store failed: {e}"))?;
    store
        .put(&format!("{pfx}/private_key"), &id.private_key_b64)
        .map_err(|e| format!("identity secret store failed: {e}"))?;
    let masque = match &id.masque {
        Some(m) => {
            store
                .put(&format!("{pfx}/masque_key"), &m.key_pem)
                .map_err(|e| format!("identity secret store failed: {e}"))?;
            Some(MasqueRecord {
                cert_pem: m.cert_pem.clone(),
                issued_at_ms: m.issued_at_ms,
                lifetime_days: m.lifetime_days,
                renew_before_days: m.renew_before_days,
            })
        }
        None => None,
    };
    let rec = IdentityRecord {
        device_id: id.device_id.clone(),
        peer_key_b64: id.peer_key_b64.clone(),
        interface_v4: id.interface_v4.clone(),
        interface_v6: id.interface_v6.clone(),
        refused: id.refused,
        license_upgraded: id.license_upgraded,
        masque,
    };
    let text = toml::to_string(&rec).map_err(|e| format!("identity encode failed: {e}"))?;
    atomic_write_0600(&identity_file(dirs, role), text.as_bytes())
}

/// Best-effort removal of a role's record (used only to discard a replaced
/// identity's file; secrets are overwritten by the next save).
pub fn discard_record(dirs: &ProfileDirs, role: IdentityRole) {
    let _ = std::fs::remove_file(identity_file(dirs, role));
}

/// Write `bytes` to `path` atomically (temp file in the same dir + rename)
/// with user-only permissions on unix (0o600). Windows has no mode bits;
/// the config dir ACL is the boundary there.
fn atomic_write_0600(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tmp = path.with_extension(format!("tmp.{}-{}", std::process::id(), n));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("identity write failed: {e}"))?;
        use std::io::Write;
        f.write_all(bytes)
            .map_err(|e| format!("identity write failed: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, bytes).map_err(|e| format!("identity write failed: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("identity commit failed: {e}"))?;
    Ok(())
}

/// Exclusive registration lock. A live lock fails the second writer; a lock
/// older than 10 minutes is stolen (crashed predecessor).
fn acquire_lock(dirs: &ProfileDirs, role: IdentityRole) -> Result<LockGuard, String> {
    let path = dirs.config_dir.join(format!("{}.lock", role.file_name()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => Ok(LockGuard { path }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let stale = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(|t| t.elapsed().map(|d| d.as_secs() > 600).unwrap_or(false))
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_file(&path);
                return acquire_lock(dirs, role);
            }
            Err("another registration is in progress for this identity".to_string())
        }
        Err(e) => Err(format!("identity lock failed: {e}")),
    }
}

struct LockGuard {
    path: std::path::PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::secret::SecretString;
    use crate::identity::model::now_ms;

    fn dirs(tag: &str) -> ProfileDirs {
        let dir = std::env::temp_dir().join(format!(
            "qcore-idstore-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")))
    }

    fn sample() -> ProviderIdentity {
        ProviderIdentity {
            device_id: "dev-1".into(),
            access_token: SecretString::new("tok-1"),
            private_key_b64: SecretString::new("cHJpdmF0ZTE="),
            peer_key_b64: "cGVlcjE=".into(),
            interface_v4: "172.16.0.2".into(),
            interface_v6: "2606:4700:110::2".into(),
            masque: None,
            refused: false,
            license_upgraded: false,
        }
    }

    #[test]
    fn round_trip_and_missing() {
        let d = dirs("rt");
        assert!(load(&d, IdentityRole::Outer).is_none());
        save(&d, IdentityRole::Outer, &sample()).expect("saves");
        let back = load(&d, IdentityRole::Outer).expect("loads");
        assert_eq!(back.device_id, "dev-1");
        assert_eq!(back.access_token.expose(), b"tok-1");
        assert!(!back.refused);
        // Roles are independent namespaces.
        assert!(load(&d, IdentityRole::Inner).is_none());
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn corrupt_reads_as_missing() {
        let d = dirs("corrupt");
        d.ensure_dirs().unwrap();
        std::fs::write(identity_file(&d, IdentityRole::Outer), "not = [valid").unwrap();
        assert!(load(&d, IdentityRole::Outer).is_none());
        std::fs::write(identity_file(&d, IdentityRole::Outer), "device_id = \"\"").unwrap();
        assert!(load(&d, IdentityRole::Outer).is_none());
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn second_writer_fails_closed() {
        let d = dirs("race");
        d.ensure_dirs().unwrap();
        let _first = acquire_lock(&d, IdentityRole::Outer).expect("first lock");
        let err = save(&d, IdentityRole::Outer, &sample()).unwrap_err();
        assert!(err.contains("in progress"), "loser fails closed: {err}");
        assert!(
            load(&d, IdentityRole::Outer).is_none(),
            "no half-written store"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn namespace_hash_is_stable_known_answer() {
        // Guards the keyring namespace against hasher swaps: DefaultHasher
        // is release-unstable and would silently orphan stored identities.
        assert_eq!(namespace_hash(""), 0xcbf29ce484222325);
        let a = namespace_hash("/tmp/qcore-test-profile");
        assert_eq!(a, namespace_hash("/tmp/qcore-test-profile"));
        assert_ne!(a, namespace_hash("/tmp/qcore-test-profile-2"));
    }
}
