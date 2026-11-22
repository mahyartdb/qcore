//! `import` / `export` (US2 T064): WireGuard/AmneziaWG configs as chainable hops.
//!
//! `import <file>` parses, preserves every field, and stores the record under
//! `<config_dir>/imports/<ref>.toml` with secrets in the secret store (exit 0
//! prints the ref; rejection is exit 5 naming each offending field).
//! `export <ref>` reproduces values equivalently with secrets redacted
//! (FR-024/FR-026, SC-004); the conf text goes to stdout (results), all
//! diagnostics to stderr.

use qcore_core::config::export::{export_redacted, from_stored};
use qcore_core::config::import::{load_import, store_import, ConfigImport, ImportLoadError};
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
            let code = export_failure_code(&e);
            exit::diag_exit(code, &e.to_string());
            if json {
                // One failure document on stdout, shaped like run_import's
                // rejection (contracts/cli.md §1); an export has no field
                // list, so the message rides in `reasons`.
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "ref": import_ref,
                        "reasons": [e.to_string()],
                    })
                );
            }
            return code;
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

/// `load_import` reports WHY it failed as a typed error; the contract splits
/// the variants across exit codes: a missing/unreadable record or a
/// malformed ref is usage (6); corrupt stored content or an unavailable
/// secret is an import rejection (5) (contracts/cli.md §2 row 5). The
/// mapping rides the variant, never the message text, so rewording a
/// message cannot move a failure between exit codes.
fn export_failure_code(e: &ImportLoadError) -> i32 {
    match e {
        ImportLoadError::UnknownRef(_) | ImportLoadError::InvalidRef(_) => exit::USAGE,
        ImportLoadError::Corrupt(_) | ImportLoadError::SecretUnavailable(_) => {
            exit::IMPORT_REJECTED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_failure_codes_split_usage_from_rejection() {
        // Classification rides the typed variant (contracts/cli.md §2 row 5:
        // missing/unreadable record and bad ref = 6, content = 5).
        assert_eq!(
            export_failure_code(&ImportLoadError::UnknownRef(
                "unknown import `x` (see `qcore import`)".into()
            )),
            exit::USAGE
        );
        assert_eq!(
            export_failure_code(&ImportLoadError::InvalidRef(
                "invalid import ref `../x`".into()
            )),
            exit::USAGE
        );
        assert_eq!(
            export_failure_code(&ImportLoadError::Corrupt(
                "import record: unknown field `garbage`".into()
            )),
            exit::IMPORT_REJECTED
        );
        assert_eq!(
            export_failure_code(&ImportLoadError::SecretUnavailable(
                "import `x` secret `interface.private_key` unavailable: keyring gone".into()
            )),
            exit::IMPORT_REJECTED
        );
    }

    #[test]
    fn export_failure_classification_is_reword_resistant() {
        // The old classifier sniffed message prefixes (`starts_with`), so any
        // rewording silently moved a failure between exit codes: a missing
        // record reported as "no stored import ..." no longer matched
        // "unknown import " and fell through to exit 5. Variants are immune
        // to wording — assert the SAME message text misclassifies under the
        // string rule but classifies correctly under the typed one.
        let reworded_unknown = "no stored import `x`: nothing to export";
        let reworded_corrupt = "unknown import `x`: field `garbage` is garbage";
        let legacy_prefix_rule = |msg: &str| {
            if msg.starts_with("unknown import ") || msg.starts_with("invalid import ref ") {
                exit::USAGE
            } else {
                exit::IMPORT_REJECTED
            }
        };
        // A reworded missing record: the old rule calls it a rejection (5),
        // the typed rule keeps it usage (6).
        assert_eq!(legacy_prefix_rule(reworded_unknown), exit::IMPORT_REJECTED);
        assert_eq!(
            export_failure_code(&ImportLoadError::UnknownRef(reworded_unknown.into())),
            exit::USAGE
        );
        // A reworded corruption whose text happens to START with the unknown
        // marker: the old rule calls it usage (6), the typed rule keeps it a
        // rejection (5).
        assert_eq!(legacy_prefix_rule(reworded_corrupt), exit::USAGE);
        assert_eq!(
            export_failure_code(&ImportLoadError::Corrupt(reworded_corrupt.into())),
            exit::IMPORT_REJECTED
        );
    }

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
