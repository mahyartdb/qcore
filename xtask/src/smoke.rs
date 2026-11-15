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
    status_stop_matrix().map_err(|e| format!("status/stop: {e}"))?;
    scan_json_single_document().map_err(|e| format!("scan --json: {e}"))?;
    Ok(())
}

/// Deterministic session-record exit codes (fix wave E): every shape here
/// is read straight from `SessionStatus::read` (session/mod.rs) and the
/// `run_status`/`run_stop` CLI mappings — no live session needed. Cases
/// that depend on seeded `control.json` + live-listener semantics are
/// deliberately NOT asserted here (ambiguous across hosts); the three
/// record-only shapes below are stable.
fn status_stop_matrix() -> Result<(), String> {
    // Isolated state dirs per case: `--config` redirects session.json.
    let base = std::env::temp_dir().join(format!("qcore-smoke-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).map_err(|e| format!("scratch dir: {e}"))?;

    let cli = |config: &std::path::Path, args: &[&str]| -> Result<CliOutput, String> {
        let cfg = config.to_string_lossy().into_owned();
        let mut full: Vec<&str> = vec!["--config", &cfg];
        full.extend_from_slice(args);
        cli(&full)
    };

    // 1. Fresh profile (no session.json): status → exit 10 ("no session");
    //    stop with no session → exit 10 as well.
    let fresh = base.join("fresh");
    std::fs::create_dir_all(&fresh).map_err(|e| format!("fresh dir: {e}"))?;
    let out = cli(&fresh, &["status"])?;
    if out.code != 10 {
        return Err(format!(
            "fresh status: exit {}, want 10\nstdout:\n{}\nstderr:\n{}",
            out.code, out.stdout, out.stderr
        ));
    }
    if !out.stderr.contains("no session (exit 10)") {
        return Err(format!(
            "fresh status: stderr lacks the no-session diagnostic\nstdout:\n{}\nstderr:\n{}",
            out.stdout, out.stderr
        ));
    }
    let out = cli(&fresh, &["stop"])?;
    if out.code != 10 {
        return Err(format!(
            "fresh stop: exit {}, want 10\nstdout:\n{}\nstderr:\n{}",
            out.code, out.stdout, out.stderr
        ));
    }
    println!("smoke status/stop: fresh profile exits 10 (no session): ok");

    // 2. Seeded state=stopped record: `SessionStatus::read` maps
    //    Stopped/Failed records to Dead{} (session/mod.rs) → `status` exit
    //    1. No control.json needed: the Dead branch never consults it.
    //    Layout: `session_file()` is `<config_dir>/session.json`
    //    (config/profile_dir.rs), so `--config <dir>` must find the seed
    //    directly inside `<dir>` — not a nested `config/` subdir.
    let stopped = base.join("stopped");
    std::fs::create_dir_all(&stopped).map_err(|e| format!("stopped dir: {e}"))?;
    // Chain shape mirrors Session/serde: chain.hops entries are
    // `{"id","kind",...}` (HopConfig's hand-written wire shape), max_depth
    // rides beside hops (ChainSer).
    let session = serde_json_less::json_stopped_session();
    std::fs::write(stopped.join("session.json"), session)
        .map_err(|e| format!("seed session.json: {e}"))?;
    let out = cli(&stopped, &["status"])?;
    if out.code != 1 {
        return Err(format!(
            "stopped-record status: exit {}, want 1 (dead)\nstdout:\n{}\nstderr:\n{}",
            out.code, out.stdout, out.stderr
        ));
    }
    if !out.stderr.contains("is dead (exit 1)") {
        return Err(format!(
            "stopped-record status: stderr lacks the dead diagnostic\nstdout:\n{}\nstderr:\n{}",
            out.stdout, out.stderr
        ));
    }
    println!("smoke status: seeded state=stopped record exits 1 (dead): ok");

    // 3. Corrupt record (invalid JSON): present-but-unparseable is
    //    `Unverifiable` (fail closed, never "no session") → exit 12.
    let corrupt = base.join("corrupt");
    std::fs::create_dir_all(&corrupt).map_err(|e| format!("corrupt dir: {e}"))?;
    std::fs::write(corrupt.join("session.json"), "{not json at all")
        .map_err(|e| format!("seed corrupt session.json: {e}"))?;
    let out = cli(&corrupt, &["status"])?;
    if out.code != 12 {
        return Err(format!(
            "corrupt-record status: exit {}, want 12 (unverifiable)\nstdout:\n{}\nstderr:\n{}",
            out.code, out.stdout, out.stderr
        ));
    }
    if !out.stderr.contains("unverifiable") {
        return Err(format!(
            "corrupt-record status: stderr lacks the unverifiable diagnostic\nstdout:\n{}\nstderr:\n{}",
            out.stdout, out.stderr
        ));
    }
    println!("smoke status: corrupt session.json exits 12 (unverifiable): ok");

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// `scan --json` must print exactly ONE JSON document on stdout (the
/// one-document contract): a double-print (e.g. the table AND the json
/// body, or two documents) fails the smoke even though both halves parse.
/// Counted structurally: top-level `{` at column 0 of each stdout line
/// group — good enough to catch any 2+-document stdout without a JSON
/// dependency in xtask.
fn scan_json_single_document() -> Result<(), String> {
    let out = cli(&[
        "scan",
        "--transport",
        "mock",
        "--profile",
        "balanced",
        "--family",
        "ipv4",
        "--json",
    ])?;
    // Exit 0 (found) or 4 (empty) are both legal verdicts offline; either
    // way stdout must be exactly one JSON document.
    if out.code != 0 && out.code != 4 {
        let text = format!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr);
        return Err(format!(
            "scan --json: exit {}, want 0 or 4\n{text}",
            out.code
        ));
    }
    let doc_count = count_json_documents(&out.stdout)?;
    if doc_count != 1 {
        let text = format!("stdout:\n<<<{}>>>", out.stdout);
        return Err(format!(
            "scan --json: stdout carried {doc_count} top-level JSON documents, want exactly 1\n{text}"
        ));
    }
    // And the single document must actually parse (shape check on the
    // candidates key, which both the empty and the ranked shapes carry).
    if !out.stdout.contains("\"candidates\"") {
        return Err(format!(
            "scan --json: stdout document lacks `candidates`\nstdout:\n<<<{}>>>",
            out.stdout
        ));
    }
    println!("smoke scan --json: exactly one JSON document on stdout: ok");
    Ok(())
}

/// Count top-level JSON values in `text` (xtask keeps zero deps; a tiny
/// brace-depth scanner distinguishes one document from several or zero).
/// Documents are expected whitespace-separated; strings are skipped so
/// braces inside string literals cannot confuse the count.
fn count_json_documents(text: &str) -> Result<usize, String> {
    let mut count = 0usize;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut saw_content = false;
    for c in text.chars() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                saw_content = true;
            }
            '{' | '[' => {
                if depth == 0 {
                    count += 1;
                }
                depth += 1;
                saw_content = true;
            }
            '}' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err("scan --json: unbalanced JSON on stdout".to_string());
                }
            }
            c if c.is_whitespace() => {}
            _ => saw_content = true,
        }
    }
    if depth != 0 {
        return Err("scan --json: truncated JSON on stdout".to_string());
    }
    // Bare non-JSON stdout (e.g. diagnostics leaking to the result stream)
    // counts as a broken document too.
    if count == 0 && saw_content {
        return Err("scan --json: stdout carried no JSON document".to_string());
    }
    Ok(count)
}

/// Hand-rolled `session.json` seed for the stopped-record status case (xtask
/// keeps zero serde deps): exactly the wire shape `Session`/`ChainSer`/
/// `HopConfig` serialize (config/hop.rs hand-written map with `kind` first).
mod serde_json_less {
    /// A `state: "stopped"` session with one mock hop: loads as
    /// `SessionStatus::Dead` (exit 1), no control channel consulted.
    pub fn json_stopped_session() -> String {
        r#"{
  "id": "smoke-seeded-0",
  "chain": {
    "hops": [
      {
        "id": "mock-0",
        "kind": "mock",
        "family": "dual"
      }
    ],
    "max_depth": 3
  },
  "family_policy": {
    "mode": "dual",
    "prefer": "ipv4",
    "connection_attempt_delay_ms": 250,
    "resolution_delay_ms": 50
  },
  "state": "stopped",
  "started_at": 1700000000000,
  "failure": null
}"#
        .to_string()
    }
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
    // Shared parser: both `--target X` and `--target=X` spellings; a
    // valueless flag errors instead of silently meaning native.
    let target = super::args::parse_target_arg(&args)
        .map_err(super::anyhow::Error::msg)?
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
