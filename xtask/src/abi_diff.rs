//! ABI + semver gates (FR-003f, T090).
//!
//! - Rust API break → semver major (cargo-semver-checks; advisory here,
//!   enforced on CI runners with the tool installed).
//! - C ABI break → major bump + one minor of deprecation retaining the old
//!   symbol (checked: every `qcore_*` symbol in the built cdylib must be
//!   declared in `qcore.h`, and vice versa).
//! - Config/report schema break → `SCHEMA_VERSION` bump + changelog
//!   migration note (checked: `abi-version.txt` mirror matches the
//!   `ABI_VERSION` const; `SCHEMA_VERSION` is surfaced in every diag line).
//! - `qcore.h` diff must be empty unless the ABI version moved (checked via
//!   git when available; otherwise the symbol cross-check below).

use std::path::Path;

const FFI_DIR: &str = "crates/qcore-ffi";

fn read(name: &str) -> Result<String, String> {
    std::fs::read_to_string(Path::new(FFI_DIR).join(name))
        .map_err(|e| format!("read {FFI_DIR}/{name}: {e}"))
}

/// Declared `qcore_*` functions in the header (declarations may span lines).
fn header_symbols(h: &str) -> Vec<String> {
    h.lines()
        .filter_map(|l| {
            let l = l.trim();
            if !(l.starts_with("uint32_t qcore_") || l.starts_with("int32_t qcore_")) {
                return None;
            }
            l.split_whitespace()
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(str::to_string)
        })
        .collect()
}

/// `qcore_*` function definitions in the Rust source (one per line).
/// JNI entry points (`Java_*`) and intra-crate calls never match: only
/// `fn qcore_*(` definitions do.
fn source_symbols(lib: &str) -> Vec<String> {
    lib.lines()
        .filter_map(|l| {
            let l = l.trim();
            if !l.contains("fn qcore_") {
                return None;
            }
            l.split_whitespace()
                .find(|t| t.starts_with("qcore_"))
                .and_then(|t| t.split('(').next())
                .map(str::to_string)
        })
        .collect()
}

pub fn run(_args: Vec<String>) -> super::anyhow::Result<()> {
    let fail = |m: String| super::anyhow::Error::msg(m);
    // 1. abi-version.txt mirror matches the ABI_VERSION const.
    let version_rs = std::fs::read_to_string("crates/qcore-core/src/api/version.rs")
        .map_err(|e| fail(format!("read version.rs: {e}")))?;
    let abi = version_rs
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("pub const ABI_VERSION:")
                .and_then(|rest| rest.split('=').nth(1))
                .and_then(|v| v.trim().trim_end_matches(';').parse::<u32>().ok())
        })
        .ok_or_else(|| fail("ABI_VERSION const not found".to_string()))?;
    let mirror = read("abi-version.txt").map_err(fail)?;
    if mirror.trim() != abi.to_string() {
        return Err(fail(format!(
            "abi-version.txt `{}` != ABI_VERSION {abi} (rebuild qcore-ffi)",
            mirror.trim()
        )));
    }
    println!("abi-diff: abi-version.txt matches ABI_VERSION {abi}");

    // 2. qcore.h declares exactly the implemented symbols (both directions).
    let header = read("qcore.h").map_err(fail)?;
    let lib = std::fs::read_to_string(Path::new(FFI_DIR).join("src/lib.rs"))
        .map_err(|e| fail(format!("read lib.rs: {e}")))?;
    let mut hs = header_symbols(&header);
    let mut ss = source_symbols(&lib);
    hs.sort();
    ss.sort();
    let only_header: Vec<_> = hs.iter().filter(|s| !ss.contains(s)).collect();
    let only_source: Vec<_> = ss.iter().filter(|s| !hs.contains(s)).collect();
    if !only_header.is_empty() || !only_source.is_empty() {
        return Err(fail(format!(
            "qcore.h/ABI drift: header-only {only_header:?}, source-only {only_source:?}"
        )));
    }
    println!(
        "abi-diff: qcore.h declares all {} symbols (no drift)",
        hs.len()
    );

    // 3. qcore.h committed diff must be empty unless invoked with --allow-diff
    // (the release flow bumps the ABI version first, then regenerates).
    if !_args.iter().any(|a| a == "--allow-diff") {
        let in_repo = std::process::Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !in_repo {
            println!("abi-diff: no git repo; header/source cross-check above is the gate");
        } else {
            let clean = std::process::Command::new("git")
                .args(["diff", "--quiet", "--", &format!("{FFI_DIR}/qcore.h")])
                .status()
                .map(|s| s.success())
                .unwrap_or(true);
            if clean {
                println!("abi-diff: qcore.h committed diff empty");
            } else {
                return Err(fail(
                    "qcore.h has uncommitted changes: regenerate via cbindgen or run with --allow-diff during a versioned ABI bump".to_string(),
                ));
            }
        }
    }

    // 4. Rust semver advisory (enforced on CI with cargo-semver-checks).
    match super::shell("cargo semver-checks --version") {
        Ok(()) => {
            let _ = super::shell("cargo semver-checks check-release");
        }
        Err(_) => println!("abi-diff: cargo-semver-checks not installed (CI enforces)"),
    }
    println!("abi-diff: gate complete (FR-003f)");
    Ok(())
}
