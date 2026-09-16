//! Shared license-key input (002 FR-010): flag (warns) > file > TTY
//! prompt > none. Resolves to a [`SecretString`] before crossing into the
//! engine; the key is never echoed, logged, reported, or persisted.

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
        // Note: line input echoes; scripts and the cautious should use
        // --license-file.
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
