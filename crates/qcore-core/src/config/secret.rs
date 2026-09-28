//! Secret storage (research R11, FR-026).
//!
//! Secrets are parsed at the boundary, held in zeroizing wrappers, and stored
//! via the OS keyring when available with a 0600 file fallback (Unix; on
//! Windows the fallback file inherits the directory ACLs — see below). They
//! are never logged, persisted unencrypted elsewhere, or passed on process
//! argv.
//!
//! Memory (#8: `zeroize`, earliest-`drop`): [`SecretString`] derives
//! `Zeroize`/`ZeroizeOnDrop`, and every transient plaintext copy (the `put`
//! value, the keyring `&str` bridge, request buffers in `identity::register`
//! and `identity::masque`) rides `Zeroizing`, so the wipe is vetted rather
//! than hand-rolled. Transients are dropped at earliest last-use by
//! convention; no linear-type enforcement exists without newtype churn —
//! rejected as over-engineering.
//!
//! `mlock`/`VirtualLock` (#8: rejected). The file fallback is plaintext-at-
//! rest under 0600/inherited ACLs and the tokens are low-value ephemeral;
//! locking pages would not raise that bar, needs privileges/limits, and adds
//! per-platform edge cases. Swap exposure is accepted and documented here.
//!
//! Windows ACLs (#8: no new dependency). The bar is (1) the default config
//! dir is per-user (`%USERPROFILE%\.qcore`, inheriting user-only profile
//! ACLs), and (2) this documented boundary: `--config` pointing at a
//! shared/world-readable location is operator responsibility — the fallback
//! file inherits whatever ACLs that directory carries.
//!
//! Filename encoding v1 (#8): account names are escaped injectively (see
//! [`encode_account`]) so distinct accounts never share one fallback file.
//! Files written pre-v1 keep resolving through a dual read; writes always
//! use v1. Legacy read support drops no earlier than qcore-core 0.4.0
//! (constitution Independent Versioning: stored-format deprecation window).

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::profile_dir::ProfileDirs;

/// Zeroizing secret string. Zeroes on drop; never `Display`s the value.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    inner: Vec<u8>,
}

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        // The `String` bridge is wiped on scope exit: `into()` moves the
        // caller's buffer here and `Zeroizing` zeroes it on drop, so only
        // the `Vec<u8>` copy below survives.
        let s = Zeroizing::new(s.into());
        SecretString {
            inner: s.as_bytes().to_vec(),
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Length omitted deliberately: secret length is a side channel
        // (it distinguishes key sizes and aids brute-force sizing).
        write!(f, "<redacted>")
    }
}

/// Secret store: OS keyring first, 0600 file fallback.
pub struct SecretStore {
    service: String,
    fallback_dir: std::path::PathBuf,
}

/// v1 account-filename encoding: injective escape so distinct accounts
/// never share one fallback file. ASCII alphanumerics and `-` pass
/// through; `_` → `__`, `/` → `_s`, `.` → `_d`; any other char escapes
/// per UTF-8 byte as `_xHH` (lowercase hex). Names without `_`, `/`,
/// `.`, or exotic chars (e.g. `wg-home`) encode exactly as the legacy
/// sanitizer did, so those files need no migration.
pub(crate) fn encode_account(account: &str) -> String {
    let mut out = String::with_capacity(account.len());
    for b in account.bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' => out.push(b as char),
            b'_' => out.push_str("__"),
            b'/' => out.push_str("_s"),
            b'.' => out.push_str("_d"),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("_x");
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

impl SecretStore {
    pub fn new(service: impl Into<String>, fallback_dir: std::path::PathBuf) -> Self {
        SecretStore {
            service: service.into(),
            fallback_dir,
        }
    }

    /// Bounded retry for OS-keyring calls. Credential APIs (Credential
    /// Manager, Keychain, Secret Service) fail transiently under parallel
    /// load, and the suite hammers them from dozens of threads. Three
    /// attempts, still fails closed: a persistent error surfaces unchanged
    /// after ~10ms, so this masks transients, not real failures. No new
    /// at-rest data, nothing logged. The 5ms sleeps can briefly block a
    /// tokio worker, but only on keyring-failure paths that already perform
    /// blocking file fallback IO.
    fn keyring_retry<T, E>(mut op: impl FnMut() -> Result<T, E>) -> Result<T, E> {
        let mut attempt = 0u32;
        loop {
            match op() {
                ok @ Ok(_) => return ok,
                Err(_) if attempt < 2 => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn put(&self, account: &str, secret: &SecretString) -> Result<(), String> {
        // Transient plaintext copy (the keyring `&str` bridge): wiped on
        // drop via `Zeroizing` (pre-v1 this was a plain `String` that was
        // never wiped).
        let value = Zeroizing::new(String::from_utf8_lossy(secret.expose()).into_owned());
        if Self::put_keyring(&self.service, account, &value) {
            return Ok(());
        }
        self.put_file(account, &value)
    }

    /// Keyring write guarded by a fresh-handle read-back: sandboxed
    /// credential stores can acknowledge writes they never serve back, which
    /// would otherwise strand the secret (writable but unreadable).
    fn put_keyring(service: &str, account: &str, value: &str) -> bool {
        let Ok(entry) = Self::keyring_retry(|| keyring::Entry::new(service, account)) else {
            return false;
        };
        if Self::keyring_retry(|| entry.set_password(value)).is_err() {
            return false;
        }
        match Self::keyring_retry(|| keyring::Entry::new(service, account)) {
            Ok(probe) => Self::keyring_retry(|| probe.get_password())
                .map(|back| back == value)
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    pub fn get(&self, account: &str) -> Result<SecretString, String> {
        match Self::keyring_retry(|| keyring::Entry::new(&self.service, account)) {
            Ok(entry) => match Self::keyring_retry(|| entry.get_password()) {
                Ok(pw) => Ok(SecretString::new(pw)),
                Err(_) => self.get_file(account),
            },
            Err(_) => self.get_file(account),
        }
    }

    /// Best-effort removal of one account from the OS keyring only. The file
    /// fallback is namespace-independent — legacy and current stores share
    /// the same fallback dir and account files — so deleting files here
    /// would destroy current-namespace secrets. Only used for
    /// post-migration cleanup of legacy-namespace keyring copies; failures
    /// are silently ignored (leftovers are inert — loads prefer the current
    /// namespace).
    pub fn delete_keyring(&self, account: &str) {
        if let Ok(entry) = keyring::Entry::new(&self.service, account) {
            let _ = entry.delete_credential();
        }
    }

    fn account_path(&self, account: &str) -> std::path::PathBuf {
        self.fallback_dir
            .join(format!("{}.secret", encode_account(account)))
    }

    /// Pre-v1 sanitizer (many-to-one: `/`, `.`, and every other unsafe char
    /// onto `_`). Read-only: [`SecretStore::get_file`] consults it when the
    /// v1 name misses, so fallback files written before v1 keep resolving.
    /// Writes always use v1; legacy read support drops no earlier than
    /// qcore-core 0.4.0 (see module docs).
    fn legacy_account_path(&self, account: &str) -> std::path::PathBuf {
        let safe: String = account
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.fallback_dir.join(format!("{safe}.secret"))
    }

    #[cfg(unix)]
    fn put_file(&self, account: &str, value: &str) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(&self.fallback_dir).map_err(|e| e.to_string())?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.account_path(account))
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(value.as_bytes())
            })
            .map_err(|e| e.to_string())
    }

    #[cfg(not(unix))]
    fn put_file(&self, account: &str, value: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.fallback_dir).map_err(|e| e.to_string())?;
        std::fs::write(self.account_path(account), value).map_err(|e| e.to_string())
    }

    fn get_file(&self, account: &str) -> Result<SecretString, String> {
        // Dual read across the v1 encoding window: v1 name first, legacy
        // name on miss only. A legacy hit is returned as-is (no
        // read-path rewrite); the next `put` consolidates onto v1.
        match std::fs::read_to_string(self.account_path(account)) {
            Ok(text) => Ok(SecretString::new(text)),
            Err(current_err) => {
                let legacy = self.legacy_account_path(account);
                if legacy != self.account_path(account) {
                    if let Ok(text) = std::fs::read_to_string(&legacy) {
                        return Ok(SecretString::new(text));
                    }
                }
                Err(current_err.to_string())
            }
        }
    }
}

/// Canonical bytes hashed for a per-dir keyring service namespace:
/// separators normalized to `/`, trailing separators trimmed (drive roots
/// kept), and — on Windows only — ASCII-lowercased, because the filesystem
/// is case-insensitive there and `Profile` vs `PROFILE` are one directory.
/// Byte-level over the raw OS encoding, never `to_string_lossy`: distinct
/// paths must never collapse onto one namespace via U+FFFD substitution.
pub(crate) fn namespace_input(dirs: &ProfileDirs) -> Vec<u8> {
    let raw = dirs.config_dir.as_os_str().as_encoded_bytes();
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        out.push(if b == b'\\' { b'/' } else { b });
    }
    while out.len() > 1 && out.ends_with(b"/") && !out.ends_with(b":/") {
        out.pop();
    }
    #[cfg(windows)]
    out.make_ascii_lowercase();
    out
}

/// Stable 64-bit FNV-1a service-namespace hash. NOT `DefaultHasher`, whose
/// output is explicitly unstable across releases and would silently orphan
/// the namespace (forced re-registration) on toolchain upgrades. FNV-1a is
/// only an opaque bucket label (the keyring ACLs are the security
/// boundary), so a non-cryptographic hash is sufficient; determinism is
/// the requirement.
pub(crate) fn namespace_hash(s: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in s {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_returns_first_success_without_repeating() {
        let mut calls = 0;
        let r: Result<&str, &str> = SecretStore::keyring_retry(|| {
            calls += 1;
            Ok("ok")
        });
        assert_eq!(r, Ok("ok"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn retry_recovers_from_transients() {
        let mut calls = 0;
        let r: Result<&str, &str> = SecretStore::keyring_retry(|| {
            calls += 1;
            if calls < 3 {
                Err("transient")
            } else {
                Ok("ok")
            }
        });
        assert_eq!(r, Ok("ok"));
        assert_eq!(calls, 3);
    }

    #[test]
    fn retry_fails_closed_after_three_attempts() {
        let mut calls = 0;
        let r: Result<&str, &str> = SecretStore::keyring_retry(|| {
            calls += 1;
            Err("persistent")
        });
        assert_eq!(r, Err("persistent"));
        assert_eq!(calls, 3, "bounded: masks transients, not real failures");
    }

    #[test]
    fn debug_never_leaks_value() {
        let s = SecretString::new("supersecret-private-key");
        assert!(!format!("{s:?}").contains("supersecret"));
        // Length is a side channel: the format is exactly `<redacted>`.
        assert_eq!(format!("{s:?}"), "<redacted>");
    }

    #[test]
    fn file_fallback_round_trip() {
        let dir = std::env::temp_dir().join(format!("qcore-secret-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Force the file path by using an account the keyring cannot hold is
        // platform-dependent; instead verify the file helpers directly.
        let store = SecretStore::new("qcore-test", dir.clone());
        store
            .put_file("wg-home", "private-key-bytes")
            .expect("put_file");
        let back = store.get_file("wg-home").expect("get_file");
        assert_eq!(back.expose(), b"private-key-bytes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_get_round_trips_through_either_backend() {
        let dir = std::env::temp_dir().join(format!("qcore-secret-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = SecretStore::new("qcore-test", dir.clone());
        store
            .put(
                "import/wg-home/interface.private_key",
                &SecretString::new("round-trip-value"),
            )
            .expect("put");
        let back = store
            .get("import/wg-home/interface.private_key")
            .expect("get");
        assert_eq!(back.expose(), b"round-trip-value");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_keyring_never_touches_files() {
        // The file fallback is namespace-independent: legacy and current
        // stores share it. Keyring cleanup must therefore never delete
        // files, or it would destroy current-namespace secrets.
        let dir = std::env::temp_dir().join(format!("qcore-secret-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("setup");
        std::fs::write(dir.join("sentinel"), "stay").expect("setup");
        let store = SecretStore::new("qcore-test-nonexistent", dir.clone());
        store.delete_keyring("warp-outer/access_token");
        assert_eq!(
            std::fs::read_to_string(dir.join("sentinel")).expect("sentinel"),
            "stay"
        );
        let entries: Vec<_> = std::fs::read_dir(&dir).expect("readdir").collect();
        assert_eq!(entries.len(), 1, "cleanup created residue: {entries:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn account_encoding_is_injective_over_real_accounts() {
        // Pre-v1 the sanitizer mapped `/`, `.`, and every other unsafe char
        // onto `_`, so distinct accounts shared one fallback file. v1 must
        // keep every real-world account apart.
        let accounts = [
            "warp-outer/access_token",
            "warp-outer_access_token",
            "warp-outer.access_token",
            "warp-outer__access_token",
            "warp-inner/masque_key",
            "import/wg-home/interface.private_key",
            "import/wg-home/interface_private_key",
        ];
        let mut seen = std::collections::HashSet::new();
        for a in accounts {
            assert!(seen.insert(encode_account(a)), "collision for {a}");
        }
        // Simple names are migration-free: v1 matches the legacy file.
        assert_eq!(encode_account("wg-home"), "wg-home");
    }

    #[test]
    fn file_fallback_reads_legacy_then_writes_v1() {
        let dir = std::env::temp_dir().join(format!("qcore-secret-mig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("setup");
        let store = SecretStore::new("qcore-test", dir.clone());
        // v1 and legacy names differ for this account (it carries `/`, `_`).
        assert_ne!(
            store.account_path("warp-outer/access_token"),
            store.legacy_account_path("warp-outer/access_token"),
            "test needs an account the encodings disagree on"
        );
        // A pre-v1 file at the legacy name still resolves (dual read).
        std::fs::write(
            store.legacy_account_path("warp-outer/access_token"),
            "legacy-bytes",
        )
        .expect("seed");
        let back = store
            .get_file("warp-outer/access_token")
            .expect("legacy resolves");
        assert_eq!(back.expose(), b"legacy-bytes");
        // Writes land on the v1 name only; the legacy file is untouched.
        store
            .put_file("warp-outer/access_token", "new-bytes")
            .expect("put");
        assert_eq!(
            std::fs::read_to_string(store.account_path("warp-outer/access_token"))
                .expect("v1 written"),
            "new-bytes"
        );
        assert_eq!(
            std::fs::read_to_string(store.legacy_account_path("warp-outer/access_token"))
                .expect("legacy intact"),
            "legacy-bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_string_wipes_through_zeroize() {
        // The wipe is the vetted `zeroize` impl, not a hand-rolled loop:
        // `Zeroize` zeroes the buffer in place.
        let mut s = SecretString::new("wipe-me");
        assert_eq!(s.expose(), b"wipe-me");
        s.zeroize();
        assert!(s.expose().iter().all(|&b| b == 0));
    }
}
