//! Profile/config directory resolution (FR-028).
//!
//! Identity and secrets live under the config dir; scan/obfuscation/
//! composition profiles live under the profile dir. Either may be overridden
//! (`--config`, `--profile-dir`); defaults resolve per-OS.

use std::path::PathBuf;

/// Resolved directories for one engine instance.
#[derive(Debug, Clone)]
pub struct ProfileDirs {
    /// Identity + `session.json` + `endpoints.json` (may embed secret refs).
    pub config_dir: PathBuf,
    /// Scan/obfuscation/composition data (no secrets; replaceable freely).
    pub profile_dir: PathBuf,
}

impl ProfileDirs {
    pub fn resolve(config: Option<PathBuf>, profile_dir: Option<PathBuf>) -> Self {
        let base = dirs_base();
        ProfileDirs {
            config_dir: config.unwrap_or_else(|| base.join("config")),
            profile_dir: profile_dir.unwrap_or_else(|| base.join("profiles")),
        }
    }

    pub fn identity_file(&self) -> PathBuf {
        self.config_dir.join("identity.toml")
    }

    pub fn session_file(&self) -> PathBuf {
        self.config_dir.join("session.json")
    }

    pub fn endpoints_file(&self) -> PathBuf {
        self.config_dir.join("endpoints.json")
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.profile_dir)?;
        Ok(())
    }
}

fn dirs_base() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
    {
        return home.join(".qcore");
    }
    PathBuf::from(".qcore")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dirs_win_over_defaults() {
        let d = ProfileDirs::resolve(
            Some(PathBuf::from("/tmp/cfg")),
            Some(PathBuf::from("/tmp/prof")),
        );
        assert_eq!(d.identity_file(), PathBuf::from("/tmp/cfg/identity.toml"));
        assert_eq!(d.session_file(), PathBuf::from("/tmp/cfg/session.json"));
    }
}
