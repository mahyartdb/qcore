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
    let target = args
        .iter()
        .skip_while(|a| *a != "--target")
        .nth(1)
        .map(|s| s.as_str())
        .unwrap_or("native");
    let backend = if target == "native" {
        "cargo"
    } else {
        backend_for(target)
    };
    println!("build backend for {target}: {backend} (see targets.toml)");
    let cmd = match backend {
        "native-msvc" | "cargo" => format!("cargo build --release{}", opt_target(target)),
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
