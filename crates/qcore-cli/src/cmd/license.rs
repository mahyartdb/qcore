//! Shared license-key input (002 FR-010): flag (warns) > file > TTY
//! prompt > none. Resolves to a [`SecretString`] before crossing into the
//! engine; the key is never echoed, logged, reported, or persisted.
//!
//! TTY no-echo (#13: explicitly deferred, not silently dropped). The prompt
//! below echoes input; scripts and the cautious must use `--license-file`.
//! A no-echo prompt needs OS console APIs (Unix termios / Windows console
//! mode) via a new dependency, which needs supply-chain review — deferred.
//! This notice is the tracking record.

use crate::exit;
use qcore_core::config::secret::SecretString;

/// Resolve the license key from flag/file/prompt. Flag use prints a
/// one-line stderr warning (visible to other processes via argv).
pub fn resolve(
    license_key: Option<&str>,
    license_file: Option<&std::path::Path>,
    non_interactive: bool,
) -> Result<Option<SecretString>, i32> {
    if license_key.is_some() && license_file.is_some() {
        eprintln!("qcore: --license-key and --license-file conflict (exit 6)");
        return Err(exit::USAGE);
    }
    if let Some(k) = license_key {
        eprintln!(
            "qcore: warning: --license-key is visible to other processes on this machine; prefer --license-file"
        );
        return Ok(Some(SecretString::new(k)));
    }
    if let Some(path) = license_file {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            eprintln!(
                "qcore: cannot read --license-file `{}`: {e}",
                path.display()
            );
            exit::USAGE
        })?;
        let key = raw.trim().to_string();
        if key.is_empty() {
            eprintln!("qcore: --license-file is empty (exit 6)");
            return Err(exit::USAGE);
        }
        return Ok(Some(SecretString::new(key)));
    }
    if !non_interactive && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // Echoing prompt (see module docs: no-echo deferred pending a
        // vetted console-API dependency); scripts and the cautious should
        // use --license-file.
        eprint!("provider license key (empty to skip): ");
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::BufRead::read_line(&mut std::io::BufReader::new(std::io::stdin()), &mut line)
            .is_err()
        {
            return Ok(None);
        }
        let key = line.trim().to_string();
        if key.is_empty() {
            return Ok(None);
        }
        return Ok(Some(SecretString::new(key)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_and_file_conflict_is_usage_error() {
        let r = resolve(
            Some("k"),
            Some(&std::env::temp_dir().join("qcore-test-license.toml")),
            false,
        );
        assert_eq!(r.unwrap_err(), crate::exit::USAGE);
    }

    #[test]
    fn missing_file_is_usage_error() {
        let r = resolve(
            None,
            Some(&std::env::temp_dir().join("qcore-test-missing-license")),
            true,
        );
        assert_eq!(r.unwrap_err(), crate::exit::USAGE);
    }

    #[test]
    fn empty_file_is_usage_error() {
        let path = std::env::temp_dir().join(format!("qcore-license-empty-{}", std::process::id()));
        std::fs::write(&path, "  \n").expect("temp license fixture is writable");
        let r = resolve(None, Some(&path), true);
        let _ = std::fs::remove_file(&path);
        assert_eq!(r.unwrap_err(), crate::exit::USAGE);
    }

    #[test]
    fn non_interactive_without_input_resolves_none() {
        assert!(matches!(resolve(None, None, true), Ok(None)));
    }
}
