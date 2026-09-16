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

pub fn run_import(path: &str, json: bool, dirs: &ProfileDirs, quiet: bool) -> i32 {
    let imp = match ConfigImport::parse(std::path::Path::new(path)) {
        Ok(imp) => imp,
        Err(e) => {
            // IO failure is a usage error, not a content rejection.
            eprintln!("qcore: cannot read {path}: {e}");
            return exit::USAGE;
        }
    };
    if imp.verdict != qcore_core::config::import::ImportVerdict::Accepted {
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
            } else if !quiet {
                eprintln!("imported `{stored_ref}`");
            }
            exit::SUCCESS
        }
        Err(e) => {
            eprintln!("qcore: import failed: {e}");
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
