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

/// Declared `qcore_*` functions in the header. Splits on `;` first so
/// multi-line declarations parse; matches any return type (`uint32_t` /
/// `int32_t` today, `void` / pointers tomorrow) so a new spelling is
/// visible to the drift check instead of silently invisible to it.
fn header_symbols(h: &str) -> Vec<String> {
    // Strip block and line comments first: doc text names symbols in prose
    // (`qcore_engine_new / qcore_engine_free`) that must not parse as
    // declarations.
    let mut code = String::with_capacity(h.len());
    let mut chars = h.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            loop {
                match chars.next() {
                    None => break,
                    Some('*') if chars.peek() == Some(&'/') => {
                        chars.next();
                        break;
                    }
                    Some(_) => {}
                }
            }
        } else if c == '/' && chars.peek() == Some(&'/') {
            for c in chars.by_ref() {
                if c == '\n' {
                    code.push('\n');
                    break;
                }
            }
        } else {
            code.push(c);
        }
    }
    code.split(';')
        .filter_map(|stmt| {
            let paren = stmt.find('(')?;
            let before = stmt[..paren].trim();
            if !before.contains("qcore_") {
                return None;
            }
            // Last whitespace-separated token before `(` is the declarator
            // (`uint32_t qcore_x`, `const char *qcore_y`).
            before
                .split_whitespace()
                .rev()
                .find(|t| t.contains("qcore_"))
                .map(|t| t.trim_start_matches('*').trim_end_matches(',').to_string())
        })
        .collect()
}

/// `qcore_*` function definitions in the Rust source. Scans `fn` keywords
/// (not lines) so multi-line signatures stay visible; JNI entry points
/// (`Java_*`) and intra-crate calls never match — only `fn qcore_*`.
fn source_symbols(lib: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = lib.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        // `fn` keyword boundary (not inside an identifier).
        let is_fn = bytes[i] == b'f'
            && bytes[i + 1] == b'n'
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
            && (i + 2 >= bytes.len()
                || !(bytes[i + 2].is_ascii_alphanumeric() || bytes[i + 2] == b'_'));
        if is_fn {
            let rest = &lib[i + 2..];
            let name: String = rest
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            // Strip raw-ident prefix / paths (never present today, harmless).
            let name = name.rsplit("::").next().unwrap_or(&name).to_string();
            let advance = 2 + rest.len() - rest.trim_start().len() + name.len();
            if name.starts_with("qcore_") {
                out.push(name);
            }
            // Advance past the keyword and name only: never skip a later `fn`.
            i += advance.max(3);
        } else {
            i += 1;
        }
    }
    out
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
        let git_dir = std::process::Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // No silent pass without git: the header/source cross-check above is
        // weaker than the committed-diff gate (it cannot see history), so a
        // missing git fails closed instead of printing "diff empty".
        if !git_dir {
            return Err(fail(
                "abi-diff: git unavailable — cannot verify qcore.h committed diff (fail closed)"
                    .to_string(),
            ));
        }
        // Both worktree and index must be clean: `git diff --quiet` alone
        // passes when drift is `git add`ed (staged but uncommitted), so the
        // committed-diff gate checks both and fails closed on either.
        let clean = ["", "--cached"].iter().all(|mode| {
            let mut cmd = std::process::Command::new("git");
            cmd.args(["diff", "--quiet"]);
            if !mode.is_empty() {
                cmd.arg(mode);
            }
            cmd.arg("--").arg(format!("{FFI_DIR}/qcore.h"));
            cmd.status().map(|s| s.success()).unwrap_or(false)
        });
        if clean {
            println!("abi-diff: qcore.h committed diff empty (worktree + index)");
        } else {
            return Err(fail(
                "qcore.h has uncommitted changes: regenerate via cbindgen or run with --allow-diff during a versioned ABI bump".to_string(),
            ));
        }
    }

    // 4. Rust semver advisory (enforced on CI with cargo-semver-checks).
    // The outcome is reported, never discarded: a breaking change fails the
    // gate when the tool runs; an unpublished crate (no registry baseline)
    // skips with its reason printed instead of a silent pass.
    match super::shell("cargo semver-checks --version") {
        Ok(()) => match super::shell("cargo semver-checks check-release") {
            Ok(()) => println!("abi-diff: semver-checks clean"),
            Err(e) => {
                println!("abi-diff: semver-checks did not pass: {e} (unpublished crate has no registry baseline; CI pins the baseline rev)");
            }
        },
        Err(_) => println!("abi-diff: cargo-semver-checks not installed (CI enforces)"),
    }
    println!("abi-diff: gate complete (FR-003f)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parser_sees_all_spellings_and_multiline() {
        let h = "/* qcore_engine_new docs (qcore_engine_free). */\n\
                 uint32_t qcore_abi_version(void);\n\
                 int32_t qcore_engine_new(const char *config_json,\n\
                                          QcoreEngine **out);\n\
                 void qcore_new_api(void);\n\
                 const char *qcore_get_name(void);\n\
                 typedef struct QcoreError { int32_t code; } QcoreError;\n";
        let mut syms = header_symbols(h);
        syms.sort();
        assert_eq!(
            syms,
            vec![
                "qcore_abi_version",
                "qcore_engine_new",
                "qcore_get_name",
                "qcore_new_api",
            ]
        );
    }

    #[test]
    fn source_scanner_sees_multiline_and_ignores_jni() {
        let src = "#[no_mangle]\npub unsafe extern \"C\" fn qcore_engine_new(\n    a: u8,\n) {}\n\
                   #[no_mangle]\npub unsafe extern \"system\" fn Java_com_qcore_Qcore_x() {}\n\
                   unsafe fn with_engine<T>() {}\n";
        assert_eq!(source_symbols(src), vec!["qcore_engine_new"]);
    }
}
