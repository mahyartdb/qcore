//! Deterministic offline smoke test (SC-002a, T086).
//!
//! `cargo xtask smoke --target <triple>`: validates `<triple>` against the
//! `targets.toml` single source, runs the native offline matrix (version,
//! preflight, `ls`, import/export round-trip, empty-scan exit 4 per
//! family), then — for non-native targets — shells the per-target build and
//! checks the cdylib exports when an artifact is present.
//!
//! Live per-family connects (stub-peer session up/down over ipv4/ipv6/dual)
//! are NOT re-driven here: they run in CI as `tests-chains orderings` and
//! the `single_stack` conformance suite, which assert on the same engine
//! paths without process orchestration. Android Termux CLI runs under
//! emulator execution on CI; the cdylib/JNI library is covered by the
//! exported-symbol check below plus the `abi_consumer` conformance test.
//! Release is blocked if any required target fails build or smoke.

use std::process::Command;

const TARGETS_TOML: &str = include_str!("targets.toml");

/// Which stream an assertion's `contains` needle must appear in (FIX:
/// merged output let stream-swap regressions pass — a JSON document on
/// stderr or a diagnostic on stdout both counted as success). The CLI
/// contract has exactly two result/diagnostic streams; every assertion
/// pins the one its content legally lands on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stream {
    /// Results (JSON documents, table output).
    Stdout,
    /// Diagnostics (`qcore: ...`).
    Stderr,
}

use Stream::{Stderr, Stdout};

const QCORE_SYMBOLS: &[&str] = &[
    "qcore_abi_version",
    "qcore_engine_new",
    "qcore_engine_free",
    "qcore_engine_start",
    "qcore_engine_status_json",
    "qcore_engine_stop",
    "qcore_scan",
    "qcore_import_config",
    "qcore_export_config",
    "qcore_string_free",
    "qcore_error_free",
];

fn targets() -> Vec<String> {
    TARGETS_TOML
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("triple = ")
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .collect()
}

struct CliOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

fn cli(args: &[&str]) -> Result<CliOutput, String> {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "-q", "-p", "qcore-cli", "--"]);
    cmd.args(args);
    let out = cmd.output().map_err(|e| format!("spawn qcore-cli: {e}"))?;
    Ok(CliOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Run the CLI and assert exit code plus that `contains` appears on the
/// expected stream. `needles` may be empty (code-only assertion).
fn expect(args: &[&str], code: i32, needles: &[(&str, Stream)], what: &str) -> Result<(), String> {
    let out = cli(args)?;
    if out.code != code {
        let text = format!("{}\n{}", out.stdout, out.stderr);
        return Err(format!(
            "smoke {what}: exit {}, want {code}\n{text}",
            out.code
        ));
    }
    for (contains, stream) in needles {
        let haystack = match stream {
            Stdout => &out.stdout,
            Stderr => &out.stderr,
        };
        if !haystack.contains(contains) {
            let text = format!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
            return Err(format!(
                "smoke {what}: {stream:?} lacks `{contains}`\n{text}"
            ));
        }
    }
    println!("smoke {what}: ok");
    Ok(())
}

fn native_matrix() -> Result<(), String> {
    // JSON results on stdout (the one-document contract), diagnostics on
    // stderr: the per-assertion stream selector below makes a stream swap
    // a smoke failure instead of a silent pass.
    expect(
        &["version", "--json"],
        0,
        &[("\"abi\"", Stdout)],
        "version --json",
    )?;
    expect(
        &["preflight", "--chain", "mock"],
        0,
        &[("preflight ok", Stderr)],
        "preflight mock",
    )?;
    expect(
        &["preflight", "--chain", "mock,relay"],
        0,
        &[("preflight ok", Stderr)],
        "preflight mock,relay",
    )?;
    for family in ["ipv4", "ipv6", "dual"] {
        // Empty discovery per family: exit 4 with a shaped empty document
        // (`--output json` prints `{"ok":false,...,"candidates":[]}`) on
        // stdout, never a silent fallback and never an unshaped stdout.
        expect(
            &[
                "scan",
                "--transport",
                "mock",
                "--profile",
                "balanced",
                "--family",
                family,
                "--output",
                "json",
            ],
            4,
            &[("\"candidates\":[]", Stdout)],
            &format!("empty scan {family} exit 4"),
        )?;
    }
    // Invalid chains stay fail-closed pre-start (exit 2).
    expect(
        &["preflight", "--chain", "gool,gool"],
        2,
        &[("exit 2", Stderr)],
        "over-depth exit 2",
    )?;
    expect(
        &["ls"],
        0,
        &[("transports:", Stdout), ("obfuscation profiles:", Stdout)],
        "ls lists transports",
    )?;
    // Import rejection is exit 5 naming the field (diagnostic on stderr);
    // empty scan is exit 4 with no silent unverified fallback.
    expect(
        &["import", "tests/fixtures/bogus.conf"],
        5,
        &[("Bogus", Stderr)],
        "import rejection exit 5",
    )?;
    Ok(())
}

/// Byte-scan a cdylib/dll/so for the required `qcore_*` exports (std-only;
/// no binutils needed). Missing symbols fail the gate. The static list is
/// itself cross-checked against `qcore.h` so list rot fails loudly instead
/// of silently checking a stale set (binary scanning is inherently fuzzy:
/// debug strings can false-positive, stripped ordinals can false-negative —
/// the header/source cross-check in `abi-diff` is the precise gate, this is
/// the artifact-presence backstop).
pub fn check_cdylib_exports(path: &std::path::Path) -> Result<(), String> {
    let header = std::fs::read_to_string("crates/qcore-ffi/qcore.h")
        .map_err(|e| format!("read crates/qcore-ffi/qcore.h: {e}"))?;
    for sym in QCORE_SYMBOLS {
        if !header.contains(sym) {
            return Err(format!(
                "smoke symbol list drift: `{sym}` not declared in qcore.h"
            ));
        }
    }
    if QCORE_SYMBOLS.len() != 11 {
        return Err(format!(
            "smoke symbol list drift: {} symbols, want 11",
            QCORE_SYMBOLS.len()
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut missing = Vec::new();
    for sym in QCORE_SYMBOLS {
        if !text.contains(sym) {
            missing.push(*sym);
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "cdylib {} missing exports: {}",
            path.display(),
            missing.join(", ")
        ));
    }
    println!(
        "smoke cdylib {}: {} exports ok",
        path.display(),
        QCORE_SYMBOLS.len()
    );
    Ok(())
}

pub fn run(args: Vec<String>) -> super::anyhow::Result<()> {
    let target = args
        .iter()
        .skip_while(|a| *a != "--target")
        .nth(1)
        .cloned()
        .unwrap_or_else(|| "native".to_string());
    if target != "native" && !targets().contains(&target) {
        return Err(super::anyhow::Error::msg(format!(
            "unknown target `{target}` (see xtask/src/targets.toml)"
        )));
    }
    native_matrix().map_err(super::anyhow::Error::msg)?;
    if target == "native" {
        // Native cdylib export check: build first so a fresh checkout (or
        // cache miss) cannot silently skip the gate, then fail closed when
        // the artifact is still absent.
        super::shell("cargo build -q -p qcore-ffi")?;
        let path = std::path::Path::new("target/debug").join(super::build::cdylib_name_host());
        if !path.exists() {
            return Err(super::anyhow::Error::msg(format!(
                "cdylib artifact missing after build: {}",
                path.display()
            )));
        }
        check_cdylib_exports(&path).map_err(super::anyhow::Error::msg)?;
        println!("smoke native: ipv4/ipv6/dual OK");
        return Ok(());
    }
    // Cross target: build through the pinned backend, then check exports.
    super::shell(&format!("cargo run -q -p xtask -- build --target {target}"))?;
    // The cross artifact cannot execute here, but its presence plus the
    // export scan still gate packaging: a target that builds nothing (or
    // drops symbols) fails instead of printing build-OK. The path matches
    // the build backend (build.rs): every non-native backend builds
    // `--release`, so artifacts land in `target/<triple>/release/`.
    let artifact = super::build::cross_cdylib_path(&target);
    if !artifact.exists() {
        return Err(super::anyhow::Error::msg(format!(
            "cross artifact missing after build (expected {}); per-target smoke cannot validate an unbuilt target",
            artifact.display()
        )));
    }
    check_cdylib_exports(&artifact).map_err(super::anyhow::Error::msg)?;
    if target.contains("android") {
        println!("smoke {target}: Termux CLI + cdylib/JNI run under emulator execution on CI (ubuntu-22.04 runner)");
    }
    println!("smoke {target}: build + exports OK (execution on its runner)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::build::{artifact_dir, cdylib_name_for_triple, cross_cdylib_path};

    #[test]
    fn native_debug_dir_for_smoke_gate() {
        let p = artifact_dir("native", false);
        assert_eq!(p, std::path::PathBuf::from("target/debug"));
        let r = artifact_dir("native", true);
        assert_eq!(r, std::path::PathBuf::from("target/release"));
    }

    #[test]
    fn cross_targets_use_release_dir_matching_build_backend() {
        // build.rs backends pass `--release` for every non-native target:
        // the smoke check must look where the build actually wrote.
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-linux-android",
            "i686-pc-windows-msvc",
        ] {
            let p = artifact_dir(triple, true);
            assert_eq!(
                p,
                std::path::PathBuf::from("target")
                    .join(triple)
                    .join("release"),
                "{triple}"
            );
        }
    }

    #[test]
    fn cdylib_names_follow_target_platform_not_host() {
        assert_eq!(
            cdylib_name_for_triple("i686-pc-windows-msvc"),
            "qcore_ffi.dll"
        );
        assert_eq!(
            cdylib_name_for_triple("x86_64-unknown-linux-gnu"),
            "libqcore_ffi.so"
        );
        assert_eq!(
            cdylib_name_for_triple("aarch64-linux-android"),
            "libqcore_ffi.so"
        );
        // A windows host cross-building linux must still expect .so.
        let p = cross_cdylib_path("x86_64-unknown-linux-gnu");
        assert_eq!(
            p,
            std::path::PathBuf::from("target/x86_64-unknown-linux-gnu/release/libqcore_ffi.so")
        );
    }
}
