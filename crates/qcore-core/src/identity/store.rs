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
use crate::config::secret::{namespace_hash, namespace_input, SecretStore, SecretString};
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
    // Per-dir service namespace (shared FNV-1a helpers in
    // `crate::config::secret`, also used by the import store): temp test
    // dirs, parallel profiles, and the real profile never collide in a
    // shared OS keyring.
    let h = namespace_hash(&namespace_input(dirs));
    SecretStore::new(format!("qcore-identity-{h:016x}"), dirs.config_dir.clone())
}

/// Sync marker binding one save's secrets to its record (crash-window
/// guard): FNV-1a over `device_id || 0x00 || access_token`, hex-encoded so it
/// stores as an ordinary secret string.
fn sync_marker(device_id: &str, token: &SecretString) -> String {
    let mut input = Vec::with_capacity(device_id.len() + 1 + token.expose().len());
    input.extend_from_slice(device_id.as_bytes());
    input.push(0);
    input.extend_from_slice(token.expose());
    format!("{:016x}", namespace_hash(&input))
}
/// Pre-FNV service namespace (master): `DefaultHasher` over the lossy path.
/// Migration-only — never use for new namespaces. Reproduces entries
/// written by binaries whose toolchain shares the current SipHash-1-3 (all
/// toolchains since 1.13 in practice). On a miss the read contract still
/// holds (missing → re-register), so an unrecoverable legacy name degrades
/// to today's behavior, never to an error.
fn legacy_service_name(dirs: &ProfileDirs) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    dirs.config_dir.to_string_lossy().hash(&mut h);
    format!("qcore-identity-{:016x}", h.finish())
}

fn legacy_secret_store(dirs: &ProfileDirs) -> SecretStore {
    SecretStore::new(legacy_service_name(dirs), dirs.config_dir.clone())
}

/// Resolve one secret account: current namespace first, legacy namespace on
/// miss only — never on empty. An empty current-namespace value is
/// corruption, which the read contract maps to missing, not to a stale
/// rescue. New saves always go to the current namespace.
fn get_account(
    new: &SecretStore,
    legacy: &SecretStore,
    account: &str,
) -> Result<SecretString, String> {
    match new.get(account) {
        Err(_) => legacy.get(account),
        ok => ok,
    }
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
    // Partial records read as missing (module contract): empty ids/keys,
    // empty interface addresses (injected verbatim downstream), or a peer
    // key that is not 32 bytes are all corruption, never a healthy load.
    if rec.device_id.is_empty()
        || rec.peer_key_b64.is_empty()
        || rec.interface_v4.is_empty()
        || rec.interface_v6.is_empty()
        || rec.interface_v4.parse::<std::net::IpAddr>().is_err()
        || rec.interface_v6.parse::<std::net::IpAddr>().is_err()
        || crate::config::import::b64_decode_32(&rec.peer_key_b64).is_err()
    {
        return None;
    }
    let store = secret_store(dirs);
    let legacy = legacy_secret_store(dirs);
    let pfx = role.account_prefix();
    let access_token = get_account(&store, &legacy, &format!("{pfx}/access_token")).ok()?;
    let private_key_b64 = get_account(&store, &legacy, &format!("{pfx}/private_key")).ok()?;
    if access_token.is_empty() || private_key_b64.is_empty() {
        return None;
    }
    let masque = match rec.masque {
        Some(m) => {
            // Degenerate lifecycles poison rotation instead of failing
            // closed: `lifetime 0` is permanently expired, `renew_before >
            // lifetime` rotates on every renew. Both read as missing.
            if m.lifetime_days == 0 || m.renew_before_days > m.lifetime_days {
                return None;
            }
            let key_pem = get_account(&store, &legacy, &format!("{pfx}/masque_key")).ok()?;
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
    // Secrets and record are written in two steps (secrets, then atomic
    // rename): a crash between them pairs a new token with an old device id
    // (or vice versa) and the next load would burn the identity with a
    // spurious `Refused`. The sync marker ties one save's secrets to its
    // record: mismatch reads as missing (re-register), never as refusal.
    // Absent marker = pre-marker record: accept (back-compat; every save
    // since writes one, so partial states always carry a stale marker).
    if let Ok(marker) = get_account(&store, &legacy, &format!("{pfx}/sync")) {
        if !marker.is_empty()
            && marker.expose() != sync_marker(&rec.device_id, &access_token).as_bytes()
        {
            return None;
        }
    }
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
    // Crash-window guard (see `load`): binds this save's secrets to the
    // record about to be committed. Written before the rename so any torn
    // state carries a stale marker and reads as missing, never mismatched.
    store
        .put(
            &format!("{pfx}/sync"),
            &SecretString::new(sync_marker(&id.device_id, &id.access_token)),
        )
        .map_err(|e| format!("identity secret store failed: {e}"))?;
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
    atomic_write_0600(&identity_file(dirs, role), text.as_bytes())?;
    // Migration hygiene: the identity now lives under the current namespace.
    // Drop any legacy-namespace keyring copies while the registration lock
    // is still held (no concurrent load can observe a half-migrated state).
    // Keyring only — the file fallback is shared, not a copy. Failures are
    // ignored: leftovers are inert, loads prefer the current namespace.
    let legacy = legacy_secret_store(dirs);
    legacy.delete_keyring(&format!("{pfx}/access_token"));
    legacy.delete_keyring(&format!("{pfx}/private_key"));
    legacy.delete_keyring(&format!("{pfx}/masque_key"));
    Ok(())
}

/// Best-effort removal of a role's record (used only to discard a replaced
/// identity's file; secrets are overwritten by the next save).
pub fn discard_record(dirs: &ProfileDirs, role: IdentityRole) {
    let _ = std::fs::remove_file(identity_file(dirs, role));
}

/// Write `bytes` to `path` atomically (temp file in the same dir + rename)
/// with user-only permissions on unix (0o600). Windows has no mode bits;
/// the config dir ACL is the boundary there (see `config::secret` module
/// docs: per-user default dir; `--config` into shared locations is operator
/// responsibility).
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
        // Durability: a power loss after `rename` without fsync loses the
        // new record while the secrets already rotated (compounds the
        // crash window the sync marker guards).
        f.sync_all()
            .map_err(|e| format!("identity write failed: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, bytes).map_err(|e| format!("identity write failed: {e}"))?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Do not litter `*.tmp.*` files on the rename error path.
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("identity commit failed: {e}"));
    }
    #[cfg(unix)]
    {
        // Best-effort directory sync so the rename itself survives a crash.
        // Ignored on failure: the record is still atomically committed.
        if let Ok(dir) = std::fs::File::open(path.parent().unwrap_or(std::path::Path::new("."))) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Exclusive registration lock. A live lock fails the second writer; a lock
/// older than 10 minutes is stolen (crashed predecessor). The file carries
/// an owner token so a holder never unlinks another holder's live lock on
/// drop (the old unconditional unlink let a third writer in mid-registration).
fn acquire_lock(dirs: &ProfileDirs, role: IdentityRole) -> Result<LockGuard, String> {
    let path = dirs.config_dir.join(format!("{}.lock", role.file_name()));
    let token = format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        lock_counter()
    );
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            // Best-effort owner mark: a lock file we cannot tag still
            // excludes (create_new won), it just cannot be stolen precisely.
            let _ = f.write_all(token.as_bytes());
            Ok(LockGuard { path, token })
        }
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

fn lock_counter() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

struct LockGuard {
    path: std::path::PathBuf,
    token: String,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Only unlink our own lock: another holder's live file must survive
        // our drop (stale-steal already removed only 10-minute-old files).
        match std::fs::read_to_string(&self.path) {
            Ok(content) if content == self.token => {
                let _ = std::fs::remove_file(&self.path);
            }
            // Untagged lock from an older binary: fall back to the old
            // behavior (remove) — it predates tokens, and leaving it would
            // wedge registration for 10 minutes.
            Ok(content) if content.is_empty() => {
                let _ = std::fs::remove_file(&self.path);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::secret::SecretString;
    use crate::identity::model::{now_ms, MasqueCredential};

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
            // 32 zero bytes (valid length; content never leaves the store).
            peer_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
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
    fn partial_record_reads_as_missing() {
        let d = dirs("partial");
        d.ensure_dirs().unwrap();
        // Empty interface addresses must not load as healthy.
        let mut partial = sample();
        partial.interface_v4 = String::new();
        save(&d, IdentityRole::Outer, &partial).expect("saves");
        assert!(
            load(&d, IdentityRole::Outer).is_none(),
            "empty v4 reads as missing"
        );
        // Degenerate masque lifecycle must not load as healthy.
        let mut bad_life = sample();
        bad_life.masque = Some(MasqueCredential {
            cert_pem: "cert".into(),
            key_pem: SecretString::new("key"),
            issued_at_ms: now_ms(),
            lifetime_days: 7,
            renew_before_days: 365,
        });
        save(&d, IdentityRole::Outer, &bad_life).expect("saves");
        assert!(
            load(&d, IdentityRole::Outer).is_none(),
            "renew_before > lifetime reads as missing"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn torn_save_reads_as_missing_not_mismatched() {
        // Crash between secrets and record: new token, old device id. The
        // sync marker must fail this toward missing (re-register), never
        // toward a mismatched pair that burns the identity as refused.
        let d = dirs("torn");
        save(&d, IdentityRole::Outer, &sample()).expect("saves");
        // Rotate only the token secret (simulated torn write).
        secret_store(&d)
            .put(
                "warp-outer/access_token",
                &SecretString::new("tok-NEW-uncommitted"),
            )
            .expect("torn put");
        assert!(
            load(&d, IdentityRole::Outer).is_none(),
            "torn secrets read as missing"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn lock_drop_keeps_foreign_lock() {
        let d = dirs("locktok");
        d.ensure_dirs().unwrap();
        let first = acquire_lock(&d, IdentityRole::Outer).expect("first lock");
        // A foreign live lock file must survive our drop.
        let foreign = acquire_lock(&d, IdentityRole::Outer);
        assert!(foreign.is_err(), "second writer still fails closed");
        drop(first);
        // Our own file was ours: gone after drop.
        let path = d
            .config_dir
            .join(format!("{}.lock", IdentityRole::Outer.file_name()));
        assert!(!path.exists(), "own lock unlinked on drop");
        // A planted foreign lock is never unlinked by our guard.
        std::fs::write(&path, "someone-else").unwrap();
        let guard = LockGuard {
            path: path.clone(),
            token: "ours".to_string(),
        };
        drop(guard);
        assert!(path.exists(), "foreign lock survives foreign drop");
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
        assert_eq!(namespace_hash(b""), 0xcbf29ce484222325);
        let a = namespace_hash(b"/tmp/qcore-test-profile");
        assert_eq!(a, namespace_hash(b"/tmp/qcore-test-profile"));
        assert_ne!(a, namespace_hash(b"/tmp/qcore-test-profile-2"));
    }

    #[test]
    fn namespace_input_is_canonical() {
        let base =
            std::env::temp_dir().join(format!("qcore-idns-{}-{}", std::process::id(), now_ms()));
        let hashed = |d: &ProfileDirs| namespace_hash(&namespace_input(d));
        let plain = ProfileDirs::resolve(Some(base.clone()), None);
        // Trailing separator: same directory, must share one namespace.
        let slashed = ProfileDirs::resolve(
            Some(std::path::PathBuf::from(format!("{}\\", base.display()))),
            None,
        );
        assert_eq!(hashed(&plain), hashed(&slashed));
        // Separator style: same directory, one namespace.
        let fwd = ProfileDirs::resolve(
            Some(std::path::PathBuf::from(
                base.to_string_lossy().replace('\\', "/"),
            )),
            None,
        );
        assert_eq!(hashed(&plain), hashed(&fwd));
        #[cfg(windows)]
        {
            // Windows filesystems are case-insensitive: `Profile` and
            // `PROFILE` are one directory, not two namespaces.
            let upper = ProfileDirs::resolve(
                Some(std::path::PathBuf::from(
                    base.to_string_lossy().to_ascii_uppercase(),
                )),
                None,
            );
            assert_eq!(hashed(&plain), hashed(&upper));
        }
        // Distinct directories still namespace apart.
        let other = ProfileDirs::resolve(Some(base.join("other")), None);
        assert_ne!(hashed(&plain), hashed(&other));
    }

    #[test]
    fn legacy_service_name_is_deterministic() {
        let d = dirs("legacy-det");
        assert_eq!(legacy_service_name(&d), legacy_service_name(&d));
    }

    #[test]
    fn account_falls_back_to_legacy_namespace() {
        let tag = format!("fb-{}-{}", std::process::id(), now_ms());
        let new_dir = std::env::temp_dir().join(format!("qcore-idfb-new-{tag}"));
        let legacy_dir = std::env::temp_dir().join(format!("qcore-idfb-leg-{tag}"));
        let _ = std::fs::remove_dir_all(&new_dir);
        let _ = std::fs::remove_dir_all(&legacy_dir);
        let new = SecretStore::new(format!("qcore-test-new-{tag}"), new_dir.clone());
        let legacy = SecretStore::new(format!("qcore-test-legacy-{tag}"), legacy_dir.clone());
        legacy
            .put("warp-outer/access_token", &SecretString::new("legacy-tok"))
            .expect("legacy put");
        // Current namespace misses; the legacy namespace answers.
        let v = get_account(&new, &legacy, "warp-outer/access_token").expect("resolves");
        assert_eq!(v.expose(), b"legacy-tok");
        // Current-namespace hit wins over legacy.
        new.put("warp-outer/access_token", &SecretString::new("new-tok"))
            .expect("new put");
        let v2 = get_account(&new, &legacy, "warp-outer/access_token").expect("resolves");
        assert_eq!(v2.expose(), b"new-tok");
        let _ = std::fs::remove_dir_all(&new_dir);
        let _ = std::fs::remove_dir_all(&legacy_dir);
    }
}
