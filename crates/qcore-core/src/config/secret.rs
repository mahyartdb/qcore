//! Secret storage (research R11, FR-026).
//!
//! Secrets are parsed at the boundary, held in zeroizing wrappers, and stored
//! via the OS keyring when available with a 0600 file fallback (Unix; on
//! Windows the fallback file inherits the directory ACLs). They are never
//! logged, persisted unencrypted elsewhere, or passed on process argv.

use std::fmt;

/// Zeroizing secret string. Zeroes on drop; never `Display`s the value.
pub struct SecretString {
    inner: Vec<u8>,
}

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        SecretString {
            inner: s.into().into_bytes(),
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        for b in self.inner.iter_mut() {
            // Volatile so the wipe is never optimized away.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
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

impl SecretStore {
    pub fn new(service: impl Into<String>, fallback_dir: std::path::PathBuf) -> Self {
        SecretStore {
            service: service.into(),
            fallback_dir,
        }
    }

    pub fn put(&self, account: &str, secret: &SecretString) -> Result<(), String> {
        let value = String::from_utf8_lossy(secret.expose()).into_owned();
        if Self::put_keyring(&self.service, account, &value) {
            return Ok(());
        }
        self.put_file(account, &value)
    }

    /// Keyring write guarded by a fresh-handle read-back: sandboxed
    /// credential stores can acknowledge writes they never serve back, which
    /// would otherwise strand the secret (writable but unreadable).
    fn put_keyring(service: &str, account: &str, value: &str) -> bool {
        let Ok(entry) = keyring::Entry::new(service, account) else {
            return false;
        };
        if entry.set_password(value).is_err() {
            return false;
        }
        match keyring::Entry::new(service, account) {
            Ok(probe) => probe
                .get_password()
                .map(|back| back == value)
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    pub fn get(&self, account: &str) -> Result<SecretString, String> {
        match keyring::Entry::new(&self.service, account) {
            Ok(entry) => match entry.get_password() {
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
        std::fs::read_to_string(self.account_path(account))
            .map(SecretString::new)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
