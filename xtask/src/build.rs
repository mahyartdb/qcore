//! Cross-build backend pins (research R9).
//!
//! - Windows MSVC targets (`i686`/`x86_64`/`aarch64-pc-windows-msvc`) build on
//!   native `windows-2022` / `windows-11-arm` runners: cross-rs cannot target MSVC.
//! - Linux `x86_64`/`i686`/`aarch64`/`armv7` (gnu; musl is a libc variant, not a
//!   separate target — see `targets.toml:1-4`, unbuilt: future) build under `cross-rs`.
//! - Android `aarch64-linux-android` / `armv7-linux-androideabi` build under
//!   `cargo-ndk`.
//! - Static musl libc-variant builds (future — no musl triple in `targets.toml`)
//!   build under `cargo-zigbuild`.
//!
//! CI shells out to these tools with the pinned invocations below; `xtask build`
//! selects the backend from the target triple in `targets.toml`.

pub const CROSS_RS_VERSION: &str = "0.2.5";
pub const CARGO_NDK_VERSION: &str = "3.2.0";
pub const CARGO_ZIGBUILD_VERSION: &str = "0.19.8";

use std::path::PathBuf;

/// Output directory of a build for `target`, mirroring the backends above:
/// every non-native backend passes `--release`, so cross artifacts land in
/// `target/<triple>/release/`. Native builds land in `target/release` when
/// the release profile is requested (packaging) and `target/debug` for the
/// smoke gate's explicit debug build.
pub fn artifact_dir(target: &str, release: bool) -> PathBuf {
    if target == "native" {
        if release {
            PathBuf::from("target").join("release")
        } else {
            PathBuf::from("target").join("debug")
        }
    } else {
        PathBuf::from("target").join(target).join("release")
    }
}

/// cdylib file name produced for a target triple: the delivery layout
/// follows the TARGET platform, not the build host (cross-compiling a
/// linux triple on Windows still yields `libqcore_ffi.so`).
pub fn cdylib_name_for_triple(target: &str) -> &'static str {
    if target.contains("-windows-") {
        "qcore_ffi.dll"
    } else if target.contains("apple-darwin") {
        "libqcore_ffi.dylib"
    } else {
        "libqcore_ffi.so"
    }
}

/// cdylib file name for a same-host (native) build.
pub fn cdylib_name_host() -> &'static str {
    if cfg!(windows) {
        "qcore_ffi.dll"
    } else if cfg!(target_os = "macos") {
        "libqcore_ffi.dylib"
    } else {
        "libqcore_ffi.so"
    }
}

/// CLI binary file name for a target triple (`qcore.exe` on windows legs).
pub fn cli_binary_name_for_triple(target: &str) -> &'static str {
    if target == "native" {
        if cfg!(windows) {
            "qcore.exe"
        } else {
            "qcore"
        }
    } else if target.contains("-windows-") {
        "qcore.exe"
    } else {
        "qcore"
    }
}

/// Full expected cdylib path for a non-native target after its pinned
/// release build; `smoke` and `package` both gate on this exact path.
pub fn cross_cdylib_path(target: &str) -> PathBuf {
    artifact_dir(target, true).join(cdylib_name_for_triple(target))
}

/// Pick the build backend for a target triple.
pub fn backend_for(target: &str) -> &'static str {
    if target.ends_with("-pc-windows-msvc") {
        "native-msvc"
    } else if target.ends_with("-linux-android") || target.ends_with("-androideabi") {
        "cargo-ndk"
    } else if target.contains("-musl") {
        "cargo-zigbuild"
    } else {
        "cross-rs"
    }
}

pub fn run(args: Vec<String>) -> super::anyhow::Result<()> {
    // Shared parser: both `--target X` and `--target=X` spellings; a
    // valueless flag errors instead of silently meaning native.
    let target = super::args::parse_target_arg(&args)
        .map_err(super::anyhow::Error::msg)?
        .unwrap_or_else(|| "native".to_string());
    let backend = if target == "native" {
        "cargo"
    } else {
        backend_for(&target)
    };
    println!("build backend for {target}: {backend} (see targets.toml)");
    let cmd = match backend {
        "native-msvc" | "cargo" => format!("cargo build --release{}", opt_target(&target)),
        "cross-rs" => format!("cross build --release --target {target}"),
        "cargo-ndk" => format!("cargo ndk --target {target} build --release"),
        "cargo-zigbuild" => format!("cargo zigbuild --release --target {target}"),
        _ => unreachable!(),
    };
    println!("pinned backends: cross-rs {CROSS_RS_VERSION}, cargo-ndk {CARGO_NDK_VERSION}, cargo-zigbuild {CARGO_ZIGBUILD_VERSION}");
    super::shell(&cmd)
}

fn opt_target(target: &str) -> String {
    if target == "native" {
        String::new()
    } else {
        format!(" --target {target}")
    }
}
