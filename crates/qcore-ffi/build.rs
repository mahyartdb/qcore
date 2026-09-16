//! Emit `abi-version.txt` from the same ffi build (T078).
//!
//! The C ABI version is declared once in
//! `crates/qcore-core/src/api/version.rs` (`ABI_VERSION`). This script
//! extracts that constant with a zero-dependency text scan and writes it to
//! `$OUT_DIR/abi-version.txt` (canonical build artifact) plus a mirror at
//! `crates/qcore-ffi/abi-version.txt` so version bumps show up as source
//! diffs. The `abi-diff` xtask gate (T090) re-checks the mirror against the
//! constant — a mismatch fails the gate.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let version_rs = manifest.join("../qcore-core/src/api/version.rs");
    let text = std::fs::read_to_string(&version_rs).expect("read version.rs");
    let abi = text
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("pub const ABI_VERSION:")
                .and_then(|rest| rest.split('=').nth(1))
                .and_then(|v| v.trim().trim_end_matches(';').parse::<u32>().ok())
        })
        .expect("ABI_VERSION const in version.rs");
    let stamp = abi.to_string();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("abi-version.txt"), &stamp).expect("write OUT_DIR stamp");
    // Checked-in mirror for diff visibility (best-effort: read-only checkouts).
    let _ = std::fs::write(manifest.join("abi-version.txt"), &stamp);
    println!("cargo:rerun-if-changed={}", version_rs.display());
}
