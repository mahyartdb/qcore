//! `import` / `export` (US2 T064): WireGuard/AmneziaWG configs as chainable hops.
//!
//! `import <file>` parses, preserves every field, and stores the record under
//! `<config_dir>/imports/<ref>.toml` with secrets in the secret store (exit 0
//! prints the ref; rejection is exit 5 naming each offending field).
//! `export <ref>` reproduces values equivalently with secrets redacted
//! (FR-024/FR-026, SC-004); the conf text goes to stdout (results), all
//! diagnostics to stderr.

use qcore_core::config::export::{export_redacted, from_stored};
use qcore_core::config::import::{load_import, store_import, ConfigImport};
use qcore_core::config::profile_dir::ProfileDirs;

use crate::exit;

pub fn run_import(path: &str, json: bool, dirs: &ProfileDirs, _quiet: bool) -> i32 {
    let imp = match ConfigImport::parse(std::path::Path::new(path)) {
        Ok(imp) => imp,
        Err(e) => {
            // IO failure is a usage error, not a content rejection.
            exit::diag_exit(exit::USAGE, &format!("cannot read {path}: {e}"));
            return exit::USAGE;
        }
    };
    if imp.verdict != qcore_core::config::import::ImportVerdict::Accepted {
        // The core caps reasons at 20 + one `…and N more` marker; this loop
        // prints that verbatim. Anything else here is a core-contract bug,
        // not something the CLI should re-truncate.
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "ref": imp.ref_name,
                    "unknown_fields": imp.unknown_fields,
                    "reasons": imp.reasons,
                })
            );
        } else {
            eprintln!("qcore: import rejected (exit 5)");
            for r in &imp.reasons {
                eprintln!("  {r}");
            }
        }
        return exit::IMPORT_REJECTED;
    }
    match store_import(dirs, &imp) {
        Ok(stored_ref) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "ref": stored_ref,
                        "format": match imp.source_format {
                            qcore_core::config::import::SourceFormat::Wireguard => "wireguard",
                            qcore_core::config::import::SourceFormat::Amneziawg => "amneziawg",
                        },
                    })
                );
            } else {
                // Results on stdout (stderr is diagnostics): the ref is the
                // result, printed even when quiet suppresses diagnostics.
                println!("{stored_ref}");
            }
            exit::SUCCESS
        }
        Err(e) => {
            exit::diag_exit(exit::HOP_FAILURE, &format!("import failed: {e}"));
            exit::HOP_FAILURE
        }
    }
}

pub fn run_export(import_ref: &str, json: bool, dirs: &ProfileDirs) -> i32 {
    let (stored, secrets) = match load_import(dirs, import_ref) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("qcore: {e}");
            return exit::IMPORT_REJECTED;
        }
    };
    let imp = from_stored(&stored, secrets, std::path::Path::new(import_ref));
    let text = export_redacted(&imp);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "ref": import_ref,
                "format": match stored.source_format {
                    qcore_core::config::import::SourceFormat::Wireguard => "wireguard",
                    qcore_core::config::import::SourceFormat::Amneziawg => "amneziawg",
                },
                "config": text,
            })
        );
    } else {
        print!("{text}");
    }
    exit::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_mode_import_succeeds_even_when_quiet() {
        // The ref is a result (stdout), not a diagnostic: `quiet` (stderr
        // suppression) must not turn success into failure or skip storage.
        let base = std::env::temp_dir().join(format!("qcore-cli-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dirs = ProfileDirs::resolve(Some(base.join("cfg")), Some(base.join("prof")));
        dirs.ensure_dirs().unwrap();
        for quiet in [false, true] {
            let rc = run_import("../../tests/fixtures/standard-wg.conf", false, &dirs, quiet);
            // When run from the crate dir the relative fixture resolves;
            // fall back to the workspace-root path when needed.
            let rc = if rc == exit::USAGE
                && !std::path::Path::new("../../tests/fixtures/standard-wg.conf").exists()
            {
                run_import("tests/fixtures/standard-wg.conf", false, &dirs, quiet)
            } else {
                rc
            };
            assert_eq!(rc, exit::SUCCESS, "quiet={quiet}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
