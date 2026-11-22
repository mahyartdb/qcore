//! Black-box contract tests: spawn the built binary and assert the streams +
//! exit codes pinned by `contracts/cli.md` (diagnostics always carry the
//! `(exit N)` suffix, usage errors are exit 6, one JSON document on stdout).

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

fn qcore(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qcore"))
        .args(args)
        .output()
        .expect("qcore binary spawns")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn exit_code(out: &Output) -> i32 {
    out.status.code().expect("qcore exits with a code")
}

/// A fresh config/profile pair: no shared state with the developer's real
/// profile dir, and a distinct directory per test (tests run in parallel).
fn temp_dirs(tag: &str) -> (PathBuf, PathBuf) {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "qcore-cli-contract-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    (base.join("cfg"), base.join("prof"))
}

fn one_json_doc(out: &Output) -> serde_json::Value {
    let text = stdout(out);
    assert_eq!(
        text.lines().count(),
        1,
        "stdout carries exactly one JSON document, got: {text:?}"
    );
    serde_json::from_str(&text).expect("stdout is one JSON document")
}

#[test]
fn usage_error_is_exit_6_with_one_diagnostic_line() {
    let out = qcore(&["--definitely-not-a-flag"]);
    assert_eq!(exit_code(&out), 6, "clap-level usage errors are exit 6");
    assert!(
        stdout(&out).is_empty(),
        "usage errors write nothing to stdout: {:?}",
        stdout(&out)
    );
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 1, "one diagnostic line, got: {err:?}");
    assert!(
        lines[0].starts_with("qcore: "),
        "diagnostic is `qcore: <msg> (exit N)`: {err:?}"
    );
    assert!(
        lines[0].ends_with("(exit 6)"),
        "diagnostic carries the exit suffix: {err:?}"
    );
    assert!(
        lines[0].contains("--definitely-not-a-flag"),
        "diagnostic names the offending argument: {err:?}"
    );
}

#[test]
fn help_and_version_stay_results_on_stdout() {
    let help = qcore(&["--help"]);
    assert_eq!(exit_code(&help), 0, "--help is not an error");
    assert!(
        stdout(&help).contains("Usage: qcore"),
        "help text goes to stdout: {:?}",
        stdout(&help)
    );
    assert!(stderr(&help).is_empty(), "help writes no diagnostic");

    let version = qcore(&["--version"]);
    assert_eq!(exit_code(&version), 0, "--version is not an error");
    assert!(
        stdout(&version).starts_with("qcore "),
        "version goes to stdout: {:?}",
        stdout(&version)
    );
    assert!(stderr(&version).is_empty(), "version writes no diagnostic");
}

#[test]
fn connect_chain_source_conflict_is_usage_with_suffix() {
    let (cfg, prof) = temp_dirs("connect-conflict");
    let out = qcore(&[
        "connect",
        "--chain",
        "mock",
        "--chain-file",
        "chain.toml",
        "--no-scan",
        "--non-interactive",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "chain-source conflicts are usage");
    assert!(stdout(&out).is_empty(), "conflict writes nothing to stdout");
    assert_eq!(
        stderr(&out).trim_end(),
        "qcore: --chain and --chain-file conflict (exit 6)",
        "conflict diagnostic keeps the contracted suffix"
    );
}

#[test]
fn license_file_read_failure_is_usage_with_suffix() {
    let (cfg, prof) = temp_dirs("license-file");
    let missing = cfg.join("no-such-license.txt");
    let out = qcore(&[
        "register",
        "--license-file",
        missing.to_str().unwrap(),
        "--non-interactive",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "unreadable --license-file is usage");
    assert!(
        stdout(&out).is_empty(),
        "no result document on this failure"
    );
    let err = stderr(&out);
    let line = err.lines().last().expect("a diagnostic line");
    assert!(
        line.starts_with("qcore: cannot read --license-file `"),
        "diagnostic names the flag and path: {err:?}"
    );
    assert!(
        line.ends_with("(exit 6)"),
        "diagnostic carries the exit suffix: {err:?}"
    );
}

#[test]
fn register_refusal_diagnostic_has_exit_suffix() {
    let (cfg, prof) = temp_dirs("register-refusal");
    // A closed loopback port: the provider round-trip fails fast with a
    // Refused/Blocked report (exit 2), which is emitted as a diagnostic.
    let out = qcore(&[
        "register",
        "--provider",
        "http://127.0.0.1:9",
        "--non-interactive",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 2, "provider refusal maps to exit 2");
    assert!(stdout(&out).is_empty(), "no result document on a refusal");
    let err = stderr(&out);
    let line = err.lines().last().expect("a diagnostic line");
    assert!(line.starts_with("qcore: "), "diagnostic shape: {err:?}");
    assert!(
        line.contains(" — "),
        "action word and cause are both present: {err:?}"
    );
    assert!(
        line.ends_with("(exit 2)"),
        "diagnostic carries the exit suffix: {err:?}"
    );
}

#[test]
fn export_missing_ref_is_usage_with_suffix() {
    let (cfg, prof) = temp_dirs("export-missing");
    let out = qcore(&[
        "export",
        "no-such-ref",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(
        exit_code(&out),
        6,
        "a missing import record is usage, not a content rejection"
    );
    assert!(
        stdout(&out).is_empty(),
        "no result document on this failure"
    );
    assert_eq!(
        stderr(&out).trim_end(),
        "qcore: unknown import `no-such-ref` (see `qcore import`) (exit 6)",
        "missing-record diagnostic carries the exit suffix"
    );
}

#[test]
fn export_corrupt_record_is_rejection_with_one_json_doc() {
    let (cfg, prof) = temp_dirs("export-corrupt");
    let imports = cfg.join("imports");
    std::fs::create_dir_all(&imports).expect("temp imports dir");
    std::fs::write(imports.join("bad.toml"), "garbage = 1\n").expect("temp record");

    let out = qcore(&[
        "export",
        "bad",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(
        exit_code(&out),
        5,
        "corrupt stored content is an import rejection"
    );
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert_eq!(doc["ref"], "bad", "failure document names the ref: {doc}");
    let reasons = doc["reasons"].as_array().expect("reasons array");
    assert!(
        reasons
            .iter()
            .any(|r| r.as_str().is_some_and(|s| s.contains("garbage"))),
        "reasons name the offending field: {doc}"
    );
    assert!(
        stderr(&out).contains("(exit 5)"),
        "diagnostic carries the exit suffix: {:?}",
        stderr(&out)
    );
}

#[test]
fn preflight_json_masks_secret_shaped_hop_id() {
    let (cfg, prof) = temp_dirs("preflight-hop-id");
    let out = qcore(&[
        "preflight",
        "--chain",
        "wireguard import=missing @deadbeefdeadbeefdeadbeefdeadbeef",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 2, "an unknown import fails validation");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "rejection document: {doc}");
    assert_eq!(
        doc["hop_id"], "<redacted>",
        "a secret-shaped hop id never reaches the JSON document: {doc}"
    );
    assert!(
        doc["reason"]
            .as_str()
            .is_some_and(|r| r.contains("unknown import")),
        "the reason still names the failure: {doc}"
    );
}

#[test]
fn preflight_text_masks_secret_shaped_hop_id_without_hiding_benign_ones() {
    let (cfg, prof) = temp_dirs("preflight-hop-id-text");
    // Four hops exceed the default max depth 3, so validation rejects at the
    // last hop with both `hop_index` and `hop_id` set (the text sink's
    // `hop {i} \`{id}\`` line) and a reason that does not echo the id.
    let run = |last: &str| {
        qcore(&[
            "preflight",
            "--chain",
            &format!("mock @one, mock @two, mock @three, mock @{last}"),
            "--config",
            cfg.to_str().unwrap(),
            "--profile-dir",
            prof.to_str().unwrap(),
        ])
    };

    let secret = "deadbeefdeadbeefdeadbeefdeadbeef";
    let out = run(secret);
    assert_eq!(exit_code(&out), 2, "over-depth chains fail validation");
    assert!(stdout(&out).is_empty(), "refusals write nothing to stdout");
    let err = stderr(&out);
    assert!(
        !err.contains(secret),
        "a secret-shaped hop id never reaches the text sink: {err:?}"
    );
    assert!(
        err.contains("hop 3 `<redacted>`:"),
        "the text sink masks the hop id in place: {err:?}"
    );
    assert!(
        err.contains("exceeds max depth"),
        "the reason still names the failure: {err:?}"
    );

    let out = run("exit");
    assert_eq!(exit_code(&out), 2, "over-depth chains fail validation");
    let err = stderr(&out);
    assert!(
        err.contains("hop 3 `exit`:"),
        "benign hop ids stay readable: {err:?}"
    );
}

/// A secret-shaped import ref echoes into the rejection `reason` (the core's
/// `unknown import` text). Both sinks must render it through the central
/// redactor — the preflight report is a diagnostic sink like any other, and
/// masking only `hop_id` would leak the ref verbatim.
#[test]
fn preflight_masks_secret_shaped_import_ref_in_reason_and_fix() {
    const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    let (cfg, prof) = temp_dirs("preflight-import-ref");
    let chain = format!("wireguard import={UUID}");
    let run = |json: bool| {
        let mut args = vec!["preflight", "--chain", chain.as_str()];
        if json {
            args.push("--json");
        }
        args.extend_from_slice(&[
            "--config",
            cfg.to_str().unwrap(),
            "--profile-dir",
            prof.to_str().unwrap(),
        ]);
        qcore(&args)
    };

    let out = run(true);
    assert_eq!(exit_code(&out), 2, "an unknown import fails validation");
    let doc = one_json_doc(&out);
    assert!(
        !stdout(&out).contains(UUID),
        "the secret-shaped ref leaked into the JSON document: {:?}",
        stdout(&out)
    );
    assert_eq!(doc["ok"], false, "rejection document: {doc}");
    assert!(
        doc["reason"]
            .as_str()
            .is_some_and(|r| r.contains("unknown import `<redacted>`")),
        "the reason masks the ref in place: {doc}"
    );
    assert_eq!(
        doc["fix"], "import the .conf first",
        "benign fix text survives: {doc}"
    );

    let out = run(false);
    assert_eq!(exit_code(&out), 2, "an unknown import fails validation");
    assert!(stdout(&out).is_empty(), "refusals write nothing to stdout");
    let err = stderr(&out);
    assert!(
        !err.contains(UUID),
        "the secret-shaped ref leaked into stderr: {err:?}"
    );
    assert!(
        err.contains("unknown import `<redacted>`"),
        "the text sink masks the ref in place: {err:?}"
    );
    assert!(
        err.contains("fix: import the .conf first"),
        "benign fix text survives: {err:?}"
    );
}

#[test]
fn timeout_outside_1_to_86400_is_usage() {
    let (cfg, prof) = temp_dirs("timeout-upper");
    // u64::MAX parses fine, so this reaches the globals gate: the range is
    // 1..=86400 (the FFI clamp), not just the <1 floor.
    let out = qcore(&[
        "connect",
        "--chain",
        "totallybogus",
        "--no-scan",
        "--non-interactive",
        "--timeout",
        "18446744073709551615",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "out-of-range globals are usage (6)");
    assert!(stdout(&out).is_empty(), "no result on a usage error");
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 1, "one diagnostic line, got: {err:?}");
    assert!(
        lines[0].starts_with("qcore: --timeout "),
        "diagnostic names the flag: {err:?}"
    );
    assert!(
        lines[0].contains("1") && lines[0].contains("86400"),
        "diagnostic names the range: {err:?}"
    );
    assert!(
        lines[0].ends_with("(exit 6)"),
        "diagnostic carries the exit suffix: {err:?}"
    );

    // One second over the cap is rejected too (no off-by-one at the boundary).
    let out = qcore(&[
        "connect",
        "--chain",
        "totallybogus",
        "--no-scan",
        "--non-interactive",
        "--timeout",
        "86401",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "86401 is outside 1..=86400");
    assert!(
        stderr(&out).contains("(exit 6)"),
        "exit suffix: {:?}",
        stderr(&out)
    );

    // The cap itself is accepted: it passes the globals gate and fails later
    // at chain validation (exit 2), never at the gate.
    let out = qcore(&[
        "connect",
        "--chain",
        "totallybogus",
        "--no-scan",
        "--non-interactive",
        "--timeout",
        "86400",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 2, "86400 passes the globals gate");
}

#[test]
fn connect_json_emits_one_failure_document_on_chain_source_errors() {
    let (cfg, prof) = temp_dirs("connect-json-resolve");
    // Invalid chain (exit 2): --json must still emit ONE document on stdout.
    let out = qcore(&[
        "connect",
        "--chain",
        "totallybogus",
        "--no-scan",
        "--non-interactive",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 2, "invalid chain is exit 2");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert_eq!(doc["hop_id"], "", "no hop started, no hop id: {doc}");
    assert!(
        doc["reason"]
            .as_str()
            .is_some_and(|r| r.contains("unknown transport or preset `totallybogus`")),
        "the document names the failure: {doc}"
    );
    let cause = doc["cause"].as_str().expect("cause is a string");
    // The reason is benign prose (no secret-like token), so the central
    // redactor must keep it byte-identical: asserting the exact text is what
    // catches an entropy-gate regression that over-redacts known-safe text.
    assert_eq!(
        cause, "chain: unknown transport or preset `totallybogus` (run `qcore ls`)",
        "a benign reason survives the redactor unmasked: {doc}"
    );
    assert_eq!(
        doc["reason"].as_str(),
        Some(cause),
        "cause and reason carry the same actionable text: {doc}"
    );
    assert!(
        stderr(&out).contains("(exit 2)"),
        "diagnostic still on stderr: {:?}",
        stderr(&out)
    );

    // Conflicting chain sources (exit 6): same one-document rule.
    let out = qcore(&[
        "connect",
        "--chain",
        "mock",
        "--chain-file",
        "chain.toml",
        "--no-scan",
        "--non-interactive",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "chain-source conflicts are usage");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert!(
        doc["reason"]
            .as_str()
            .is_some_and(|r| r.contains("--chain and --chain-file conflict")),
        "the reason names the conflict: {doc}"
    );
    assert!(
        stderr(&out).contains("(exit 6)"),
        "diagnostic still on stderr: {:?}",
        stderr(&out)
    );
}

/// Pre-start connect failures (validation ran before any hop started) still
/// honor the one-document rule: with `--json`, stdout carries exactly one
/// failure document — the `ls --json` precedent is rejection, not silence —
/// while the stderr diagnostic and exit code stay unchanged
/// (contracts/cli.md §1).
#[test]
fn connect_json_emits_one_failure_document_on_prestart_usage_failures() {
    let (cfg, prof) = temp_dirs("connect-json-prestart");

    // A malformed --bind address: usage, exit 6.
    let out = qcore(&[
        "connect",
        "--bind",
        "nope",
        "--no-scan",
        "--non-interactive",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "malformed --bind is usage");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert_eq!(doc["hop_id"], "", "no hop started, no hop id: {doc}");
    assert_eq!(doc["kind"], "usage", "usage-class shape: {doc}");
    assert!(
        doc["cause"]
            .as_str()
            .is_some_and(|c| c.contains("invalid --bind")),
        "the cause names the failure: {doc}"
    );
    assert_eq!(
        stderr(&out).trim_end(),
        "qcore: invalid --bind `nope` (expected host:port) (exit 6)",
        "the stderr diagnostic is unchanged"
    );

    // An unreadable --routing file: usage, exit 6.
    let missing = cfg.join("no-such-routing.toml");
    let out = qcore(&[
        "connect",
        "--chain",
        "mock",
        "--routing",
        missing.to_str().unwrap(),
        "--no-scan",
        "--non-interactive",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "an unreadable --routing is usage");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert!(
        doc["cause"]
            .as_str()
            .is_some_and(|c| c.contains("invalid routing rules")),
        "the cause names the failure: {doc}"
    );
    let err = stderr(&out);
    assert!(
        err.starts_with("qcore: invalid routing rules: "),
        "the diagnostic names the failure: {err:?}"
    );
    assert!(
        err.trim_end().ends_with("(exit 6)"),
        "the diagnostic keeps the exit suffix: {err:?}"
    );

    // An unacquirable session lock: usage, exit 6. A directory where
    // session.lock belongs makes the exclusive create fail; the start gate
    // does not read it as a live lock (its contents are unreadable), so this
    // is the SessionLock::acquire failure path.
    std::fs::create_dir_all(&cfg).expect("config dir");
    std::fs::create_dir_all(cfg.join("session.lock")).expect("blocking session.lock");
    let out = qcore(&[
        "connect",
        "--chain",
        "mock",
        "--no-scan",
        "--non-interactive",
        "--json",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "an unacquirable session lock is usage");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert!(
        doc["cause"]
            .as_str()
            .is_some_and(|c| c.contains("session lock")),
        "the cause names the lock failure: {doc}"
    );
    let err = stderr(&out);
    assert!(
        err.starts_with("qcore: session lock "),
        "the diagnostic names the lock failure: {err:?}"
    );
    assert!(
        err.trim_end().ends_with("(exit 6)"),
        "the diagnostic keeps the exit suffix: {err:?}"
    );

    // Non-JSON mode stays silent on stdout: diagnostics only.
    let out = qcore(&[
        "connect",
        "--bind",
        "nope",
        "--no-scan",
        "--non-interactive",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 6, "malformed --bind is usage");
    assert!(
        stdout(&out).is_empty(),
        "table mode writes nothing to stdout: {:?}",
        stdout(&out)
    );
}

#[test]
fn invalid_chain_diagnostic_keeps_suffix_on_line_one() {
    let (cfg, prof) = temp_dirs("invalid-chain-shape");
    let out = qcore(&[
        "connect",
        "--chain",
        "totallybogus",
        "--no-scan",
        "--non-interactive",
        "--config",
        cfg.to_str().unwrap(),
        "--profile-dir",
        prof.to_str().unwrap(),
    ]);
    assert_eq!(exit_code(&out), 2);
    assert!(stdout(&out).is_empty());
    let err = stderr(&out);
    let lines: Vec<&str> = err.lines().collect();
    assert!(
        lines.len() >= 2,
        "header line plus detail line, got: {err:?}"
    );
    assert_eq!(
        lines[0], "qcore: invalid chain (exit 2)",
        "the (exit N) suffix rides the HEADER line: {err:?}"
    );
    assert!(
        lines[1].starts_with("  "),
        "the detail line is indented: {err:?}"
    );
    assert!(
        !lines[1].ends_with("(exit 2)"),
        "the detail line carries no exit suffix: {err:?}"
    );
    assert!(
        lines[1].contains("unknown transport or preset"),
        "the detail names the failure: {err:?}"
    );
}

#[test]
fn bare_invocation_prints_help_to_stdout_with_usage_diagnostic() {
    let out = qcore(&[]);
    assert_eq!(exit_code(&out), 6, "no command given is a usage error");
    assert!(
        stdout(&out).contains("Usage: qcore"),
        "the full help is a result on stdout: {:?}",
        stdout(&out)
    );
    assert_eq!(
        stderr(&out).trim_end(),
        "qcore: no command given (exit 6)",
        "exactly one usage diagnostic on stderr"
    );

    // `--help` stays a success result with no diagnostic.
    let help = qcore(&["--help"]);
    assert_eq!(exit_code(&help), 0);
    assert!(stdout(&help).contains("Usage: qcore"));
    assert!(stderr(&help).is_empty());
}

#[test]
fn connect_failure_json_masks_hop_id_without_hiding_benign_ones() {
    let (cfg, prof) = temp_dirs("connect-hop-id");
    let run = |label: &str| {
        qcore(&[
            "connect",
            "--chain",
            &format!("wireguard import=missing @{label}"),
            "--no-scan",
            "--json",
            "--non-interactive",
            "--config",
            cfg.to_str().unwrap(),
            "--profile-dir",
            prof.to_str().unwrap(),
        ])
    };

    let secret_shaped = run("deadbeefdeadbeefdeadbeefdeadbeef");
    assert_eq!(exit_code(&secret_shaped), 2, "validation failure");
    let doc = one_json_doc(&secret_shaped);
    assert_eq!(doc["ok"], false, "failure document: {doc}");
    assert_eq!(
        doc["hop_id"], "<redacted>",
        "a secret-shaped hop id never reaches the JSON document: {doc}"
    );

    let benign = run("exit");
    assert_eq!(exit_code(&benign), 2, "validation failure");
    let doc = one_json_doc(&benign);
    assert_eq!(
        doc["hop_id"], "exit",
        "benign hop ids pass through unmasked: {doc}"
    );
}

/// Scan cache-IO skips ride the report as warnings and the CLI renders them
/// as plain `qcore: <warning>` diagnostics: present in table mode, suppressed
/// by `--quiet`, and still on stderr (never mixed into the single stdout
/// document) under `--json`.
#[test]
fn scan_cache_warning_rides_stderr_and_quiet_suppresses_it() {
    let (cfg, prof) = temp_dirs("scan-cache-warn");
    std::fs::create_dir_all(&prof).expect("profile dir");
    std::fs::create_dir_all(&cfg).expect("config dir");
    // One closed loopback seed: the scan verdict is honestly empty, and no
    // real network is touched.
    std::fs::write(
        prof.join("scan.toml"),
        format!(
            "{}\n[discovery.mock]\nseeds = [\"127.0.0.1:1\"]\n",
            qcore_core::scan::SHIPPED_SCAN_TOML
        ),
    )
    .expect("scan.toml");
    // A directory where endpoints.json belongs: reads tolerate it (empty
    // state) while the eviction's remove_file fails, producing the skip
    // warning.
    std::fs::create_dir_all(cfg.join("endpoints.json")).expect("blocking cache dir");

    let scan = |extra: &[&str]| {
        let mut args = vec![
            "scan",
            "--transport",
            "mock",
            "--profile",
            "turbo",
            "--family",
            "ipv4",
        ];
        args.extend_from_slice(extra);
        args.extend_from_slice(&[
            "--config",
            cfg.to_str().unwrap(),
            "--profile-dir",
            prof.to_str().unwrap(),
        ]);
        qcore(&args)
    };

    // Table mode: the warning is a diagnostic; the empty scan is exit 4 and
    // stdout stays silent.
    let out = scan(&[]);
    assert_eq!(exit_code(&out), 4, "an empty scan is exit 4");
    assert!(
        stdout(&out).is_empty(),
        "table mode keeps stdout silent: {:?}",
        stdout(&out)
    );
    let err = stderr(&out);
    assert!(
        err.lines()
            .any(|l| l.starts_with("qcore: scan cache eviction skipped")),
        "the cache skip rides stderr as `qcore: <warning>`: {err:?}"
    );
    assert!(
        err.contains("qcore: scan found nothing reachable (exit 4)"),
        "the empty-scan diagnostic keeps its contracted shape: {err:?}"
    );

    // --quiet suppresses the warning, never the failure line.
    let out = scan(&["--quiet"]);
    assert_eq!(exit_code(&out), 4, "an empty scan is exit 4");
    let err = stderr(&out);
    assert!(
        !err.contains("scan cache eviction skipped"),
        "--quiet suppresses cache warnings: {err:?}"
    );
    assert!(
        err.contains("scan found nothing reachable (exit 4)"),
        "--quiet never suppresses the failure line: {err:?}"
    );

    // --json: stdout is exactly one document; the warning still rides stderr.
    let out = scan(&["--json"]);
    assert_eq!(exit_code(&out), 4, "an empty scan is exit 4");
    let doc = one_json_doc(&out);
    assert_eq!(doc["ok"], false, "empty-scan document: {doc}");
    assert_eq!(
        doc["candidates"].as_array().map(|a| a.len()),
        Some(0),
        "empty-scan document carries no candidates: {doc}"
    );
    assert!(
        stderr(&out).contains("scan cache eviction skipped"),
        "the warning stays on stderr under --json: {:?}",
        stderr(&out)
    );
}
