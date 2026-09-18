mod abi_diff;
mod build;
mod release;
mod smoke;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => build::run(args.collect()),
        Some("smoke") => smoke::run(args.collect()),
        Some("package") => release::package(args.collect()),
        Some("release") => release::run(args.collect()),
        Some("abi-diff") => abi_diff::run(args.collect()),
        Some("ci") => ci(),
        other => {
            eprintln!("usage: xtask <build|smoke|package|release|abi-diff|ci> [args...]");
            eprintln!("got: {other:?}");
            std::process::exit(6);
        }
    }
}

/// Local core gate: the fast subset of the CI gate (full gate lives in
/// `.github/workflows/ci.yml`; see AGENTS.md).
fn ci() -> anyhow::Result<()> {
    // Implemented as shell delegation so CI and local runs share one definition.
    shell("cargo fmt --check")?;
    shell("cargo clippy --all-targets --all-features -- -D warnings")?;
    shell("cargo nextest run --all-features")?;
    shell("cargo nextest run -p tests-conformance")?;
    shell("cargo run -q -p xtask -- abi-diff")?;
    Ok(())
}

fn shell(cmd: &str) -> anyhow::Result<()> {
    println!("+ {cmd}");
    let (exe, args) = if cfg!(windows) {
        ("cmd".to_string(), vec!["/C".to_string(), cmd.to_string()])
    } else {
        ("sh".to_string(), vec!["-c".to_string(), cmd.to_string()])
    };
    let status = std::process::Command::new(exe).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::Error::msg(format!("command failed: {cmd}")))
    }
}

mod anyhow {
    #[derive(Debug)]
    pub struct Error(String);
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl std::error::Error for Error {}
    impl Error {
        pub fn msg(s: impl Into<String>) -> Self {
            Error(s.into())
        }
    }
    impl From<std::io::Error> for Error {
        fn from(e: std::io::Error) -> Self {
            Error(e.to_string())
        }
    }
    pub type Result<T> = std::result::Result<T, Error>;
}
