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
        resolve_from(env_bases(), config, profile_dir, false)
            .expect("resolution without a required base cannot fail")
    }

    /// Like [`ProfileDirs::resolve`], but fails when the platform cannot
    /// supply a default. Android hosts (cdylib embedders) usually have
    /// neither `HOME` nor `USERPROFILE`; letting the config dir fall back to
    /// a relative `.qcore` would put the identity wherever the process CWD
    /// happens to point, so the caller must name `config_dir` instead.
    pub fn try_resolve(
        config: Option<PathBuf>,
        profile_dir: Option<PathBuf>,
    ) -> Result<Self, String> {
        resolve_from(
            env_bases(),
            config,
            profile_dir,
            cfg!(target_os = "android"),
        )
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

/// Candidate user-home bases in platform precedence order.
///
/// Windows must not consult `HOME`: Git Bash/MSYS exports `HOME=/c/Users/<name>`,
/// which win32 resolves against the current drive (`E:\c\Users\...`) instead of
/// the profile directory. That splits the identity between shells and points it
/// at a tree other local users can write. `USERPROFILE` (then `LOCALAPPDATA`)
/// are the only Windows answers; POSIX hosts keep `HOME` first.
fn home_candidates(
    home: Option<&str>,
    userprofile: Option<&str>,
    localappdata: Option<&str>,
) -> Vec<PathBuf> {
    // One of these is ignored per platform by design; see the doc comment.
    let _ = home;
    let _ = localappdata;
    #[cfg(windows)]
    let ordered = [userprofile, localappdata];
    #[cfg(not(windows))]
    let ordered = [home, userprofile];
    ordered.into_iter().flatten().map(PathBuf::from).collect()
}

fn env_bases() -> Vec<PathBuf> {
    home_candidates(
        std::env::var("HOME").ok().as_deref(),
        std::env::var("USERPROFILE").ok().as_deref(),
        std::env::var("LOCALAPPDATA").ok().as_deref(),
    )
    .into_iter()
    .map(|base| base.join(".qcore"))
    .collect()
}

fn relative_defaults() -> (PathBuf, PathBuf) {
    (
        PathBuf::from(".qcore").join("config"),
        PathBuf::from(".qcore").join("profiles"),
    )
}

fn resolve_from(
    bases: Vec<PathBuf>,
    config: Option<PathBuf>,
    profile_dir: Option<PathBuf>,
    require_config: bool,
) -> Result<ProfileDirs, String> {
    let base = bases.into_iter().next();
    let config_dir = config.or_else(|| base.as_ref().map(|b| b.join("config")));
    let profile_dir = profile_dir.or_else(|| base.as_ref().map(|b| b.join("profiles")));
    let (config_default, profile_default) = relative_defaults();
    let config_dir = match config_dir {
        Some(dir) => dir,
        None if require_config => {
            return Err(
                "config_dir is required on this platform: HOME/USERPROFILE are unset, so no \
                 default location exists; pass an absolute writable config_dir in the engine config"
                    .to_string(),
            )
        }
        None => config_default,
    };
    Ok(ProfileDirs {
        config_dir,
        profile_dir: profile_dir.unwrap_or(profile_default),
    })
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

    /// H2.1: Git Bash/MSYS sets `HOME=/c/Users/<name>`, which Windows
    /// resolves against the current drive (`E:\c\Users\...`) — a directory
    /// the Authenticated Users group can modify — and splits the identity
    /// from PowerShell sessions. Windows must never consult HOME.
    #[cfg(windows)]
    #[test]
    fn windows_ignores_posix_shaped_home() {
        let posix_home = Some("/c/Users/qmahyar");
        let profile = Some(r"C:\Users\qmahyar");
        let local = Some(r"C:\Users\qmahyar\AppData\Local");
        assert_eq!(
            home_candidates(posix_home, profile, local),
            vec![
                PathBuf::from(r"C:\Users\qmahyar"),
                PathBuf::from(r"C:\Users\qmahyar\AppData\Local")
            ],
            "USERPROFILE wins, LOCALAPPDATA follows, HOME is dropped"
        );
        assert_eq!(
            home_candidates(posix_home, None, local),
            vec![PathBuf::from(r"C:\Users\qmahyar\AppData\Local")],
            "LOCALAPPDATA is the Windows fallback"
        );
        assert!(
            home_candidates(posix_home, None, None).is_empty(),
            "a POSIX-shaped HOME alone must never become the base"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_keeps_home_first() {
        assert_eq!(
            home_candidates(Some("/home/user"), Some("/srv/profile"), None),
            vec![PathBuf::from("/home/user"), PathBuf::from("/srv/profile")],
            "unix HOME first, USERPROFILE only as a fallback"
        );
    }

    /// H2.2: with no platform home (Android cdylib: HOME/USERPROFILE both
    /// unset) a null-config engine has no writable default; resolution must
    /// fail closed naming the field the embedder has to pass instead of
    /// landing `.qcore` in a read-only CWD.
    #[test]
    fn missing_platform_default_fails_closed_naming_config_dir() {
        let err = resolve_from(Vec::new(), None, None, true).expect_err("no base, no config");
        assert!(err.contains("config_dir"), "names the requirement: {err}");

        let dirs = resolve_from(Vec::new(), Some(PathBuf::from("/data/cfg")), None, true)
            .expect("an explicit config_dir needs no platform base");
        assert_eq!(dirs.config_dir, PathBuf::from("/data/cfg"));
        assert_eq!(
            dirs.profile_dir,
            PathBuf::from(".qcore").join("profiles"),
            "profiles carry no secrets; the relative default stays"
        );

        // Hosts WITH a home keep the historical relative fallback.
        let d = resolve_from(Vec::new(), None, None, false).expect("relative default");
        assert_eq!(d.config_dir, PathBuf::from(".qcore").join("config"));
        assert_eq!(d.profile_dir, PathBuf::from(".qcore").join("profiles"));
    }
}
