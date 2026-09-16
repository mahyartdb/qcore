//! `renew` (002 US3): refresh-in-place, fresh re-registration on refusal
//! signals only, MASQUE-only mode, per-hop GOOL renewal.
//!
//! Thin over [`qcore_core::identity::renew::renew_role`]: hop selection and
//! license input are the only CLI-side logic.

use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::identity::store::IdentityRole;

use crate::exit;

pub struct RenewArgs {
    pub masque_only: bool,
    /// outer | inner | both (GOOL pair default: the chain names the hop, but
    /// renew carries no chain — so both, selectable per hop).
    pub hop: String,
    pub license_key: Option<String>,
    pub license_file: Option<std::path::PathBuf>,
    /// Hidden test-only provider override (fixture doubles; never stable).
    pub provider: Option<String>,
    pub json: bool,
    pub non_interactive: bool,
    pub dirs: ProfileDirs,
}

fn selected_roles(hop: &str, dirs: &ProfileDirs) -> Result<Vec<IdentityRole>, i32> {
    match hop {
        "outer" => Ok(vec![IdentityRole::Outer]),
        "inner" => Ok(vec![IdentityRole::Inner]),
        // No chain rides along with renew, so "both" means every stored
        // identity — renewing what exists, never demanding a pair.
        "both" => {
            let existing: Vec<IdentityRole> = [IdentityRole::Outer, IdentityRole::Inner]
                .iter()
                .filter(|r| qcore_core::identity::store::load(dirs, **r).is_some())
                .copied()
                .collect();
            if existing.is_empty() {
                eprintln!("qcore: no stored identity — run `qcore register` first (exit 2)");
                return Err(exit::INVALID);
            }
            Ok(existing)
        }
        _ => {
            eprintln!("qcore: --hop must be outer|inner|both (exit 6)");
            Err(exit::USAGE)
        }
    }
}

pub async fn run(args: RenewArgs) -> i32 {
    let roles = match selected_roles(&args.hop, &args.dirs) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let license = match super::license::resolve(
        args.license_key.as_deref(),
        args.license_file.as_deref(),
        args.non_interactive,
    ) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let opts = super::register::provider_opts(args.provider.as_deref());
    let mut reports = Vec::new();
    for role in &roles {
        reports.push(
            qcore_core::identity::renew::renew_role(
                &args.dirs,
                *role,
                &opts,
                license.as_ref(),
                args.masque_only,
            )
            .await,
        );
    }
    let code = if reports.iter().all(|r| r.exit_code() == exit::SUCCESS) {
        exit::SUCCESS
    } else {
        exit::INVALID
    };
    if reports.len() == 1 {
        return super::register::emit(&reports[0], args.json);
    }
    if args.json {
        let outer: serde_json::Value =
            serde_json::from_str(&reports[0].to_json()).unwrap_or(serde_json::Value::Null);
        let inner: serde_json::Value =
            serde_json::from_str(&reports[1].to_json()).unwrap_or(serde_json::Value::Null);
        println!("{}", serde_json::json!({"outer": outer, "inner": inner}));
    } else {
        for r in &reports {
            super::register::emit(r, false);
        }
    }
    code
}
