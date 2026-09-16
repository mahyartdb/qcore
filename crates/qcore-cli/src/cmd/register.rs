//! `register` (002 US1/US4): provision WARP identity/identities from the CLI,
//! enrolling each role's MASQUE credential along the way (best-effort).
//!
//! Thin over [`Engine::register_warp`] + [`Engine::enroll_masque`]: license
//! input handling (flag/prompt/file) is the only CLI-side logic, and it
//! resolves to a [`SecretString`] before crossing into the engine. `--gool`
//! provisions the outer+inner pair as two independent registrations so each
//! role is reported (and fails) on its own.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::config::secret::SecretString;
use qcore_core::identity::register::{ProviderOptions, DEFAULT_PROVIDER_BASE};
use qcore_core::identity::report::{RegistrationReport, ReportAction};
use qcore_core::identity::store::IdentityRole;

use crate::exit;

pub struct RegisterArgs {
    pub license_key: Option<String>,
    pub license_file: Option<std::path::PathBuf>,
    pub gool: bool,
    /// Hidden test-only provider override (fixture doubles; never stable).
    pub provider: Option<String>,
    pub json: bool,
    pub non_interactive: bool,
    pub dirs: ProfileDirs,
}

/// Resolve the license key via the shared helper ([`super::license`]:
/// flag (warns) > file > TTY prompt > none).
fn resolve_license(args: &RegisterArgs) -> Result<Option<SecretString>, i32> {
    super::license::resolve(
        args.license_key.as_deref(),
        args.license_file.as_deref(),
        args.non_interactive,
    )
}

pub fn provider_opts(provider: Option<&str>) -> ProviderOptions {
    ProviderOptions {
        provider_base: provider.unwrap_or(DEFAULT_PROVIDER_BASE).to_string(),
        timeout_secs: 20,
        family: "dual".to_string(),
    }
}

pub fn emit(report: &RegistrationReport, json: bool) -> i32 {
    let code = report.exit_code();
    if json {
        println!("{}", report.to_json());
    } else if code == exit::SUCCESS {
        println!(
            "{} {} — {}",
            action_word(report.action),
            report.identity.as_deref().unwrap_or("-"),
            report.cause
        );
    } else {
        eprintln!("qcore: {} — {}", action_word(report.action), report.cause);
    }
    code
}

pub fn action_word(action: ReportAction) -> &'static str {
    match action {
        ReportAction::Registered => "registered",
        ReportAction::Reused => "reused",
        ReportAction::Refreshed => "refreshed",
        ReportAction::ReRegistered => "re-registered",
        ReportAction::Rotated => "rotated",
        ReportAction::Refused => "refused",
        ReportAction::Blocked => "blocked",
    }
}

pub async fn run(args: RegisterArgs) -> i32 {
    let license = match resolve_license(&args) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let engine = Engine::new(EngineConfig {
        dirs: args.dirs.clone(),
        ..Default::default()
    });
    let opts = provider_opts(args.provider.as_deref());
    if !args.gool {
        let report =
            register_with_masque(&engine, IdentityRole::Outer, &opts, license.as_ref()).await;
        return emit(&report, args.json);
    }
    // GOOL pair: two independent registrations, each reported on its own.
    let outer = register_with_masque(&engine, IdentityRole::Outer, &opts, license.as_ref()).await;
    let inner = register_with_masque(&engine, IdentityRole::Inner, &opts, license.as_ref()).await;
    let code = if outer.exit_code() == exit::SUCCESS && inner.exit_code() == exit::SUCCESS {
        exit::SUCCESS
    } else {
        exit::INVALID
    };
    if args.json {
        let outer_json: serde_json::Value =
            serde_json::from_str(&outer.to_json()).unwrap_or(serde_json::Value::Null);
        let inner_json: serde_json::Value =
            serde_json::from_str(&inner.to_json()).unwrap_or(serde_json::Value::Null);
        println!(
            "{}",
            serde_json::json!({"outer": outer_json, "inner": inner_json})
        );
    } else {
        emit(&outer, false);
        emit(&inner, false);
    }
    code
}

/// Register one role, then best-effort enroll its MASQUE credential (002
/// T033): enrollment rides along with registration, but an enrollment
/// failure never fails a good WARP identity — the cause says it was
/// deferred and the exit stays 0.
async fn register_with_masque(
    engine: &Engine,
    role: IdentityRole,
    opts: &ProviderOptions,
    license: Option<&SecretString>,
) -> RegistrationReport {
    let mut report = engine.register_warp(role, opts, license).await;
    if report.action != ReportAction::Registered {
        return report;
    }
    match engine.enroll_masque(role, opts).await {
        enrolled if enrolled.action == ReportAction::Blocked => {
            report.cause.push_str(&format!(
                "; MASQUE enrollment deferred ({})",
                enrolled.cause
            ));
        }
        enrolled => {
            report.cause.push_str(&format!("; {}", enrolled.cause));
        }
    }
    report
}
