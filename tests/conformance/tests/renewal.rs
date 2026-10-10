//! US3 renewal (002 T023, T024): a refused identity renews fresh with
//! unrelated settings byte-identical; timeouts keep the identity and go to
//! rescan instead of renewal; healthy renew is an explicit no-op.
//!
//! Fixture doubles only (offline gating): Accept registers/refreshes,
//! RefuseIdentity kills existing ids (404), Timeout holds connections.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::identity::register::ProviderOptions;
use qcore_core::identity::renew::renew_role;
use qcore_core::identity::report::ReportAction;
use qcore_core::identity::store::IdentityRole;
use tests_conformance::fixture::{Fixture, FixtureMode};
use tests_conformance::testutil::{closed_port, unique_dir};

fn work(name: &str) -> ProfileDirs {
    let dir = unique_dir(&format!("qcore-renew-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")))
}

fn engine_in(dirs: &ProfileDirs) -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig {
        dirs: dirs.clone(),
        ..Default::default()
    })
}

fn opts(fx: &Fixture) -> ProviderOptions {
    ProviderOptions {
        provider_base: fx.base_url().to_string(),
        timeout_secs: 10,
        family: "dual".to_string(),
    }
}

/// Unrelated settings that renewal MUST NOT touch.
fn seed_settings(dirs: &ProfileDirs) {
    std::fs::write(
        dirs.profile_dir.join("scan.toml"),
        "# operator customisation\ncustom = true\n",
    )
    .unwrap();
    let stale = closed_port();
    std::fs::write(
        dirs.endpoints_file(),
        serde_json::json!({"last_known_good": stale.to_string()}).to_string(),
    )
    .unwrap();
}

fn settings_snapshot(dirs: &ProfileDirs) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(dirs.profile_dir.join("scan.toml")).unwrap(),
        std::fs::read(dirs.endpoints_file()).unwrap(),
    )
}

fn assert_settings_untouched(dirs: &ProfileDirs, before: &(Vec<u8>, Vec<u8>)) {
    assert_eq!(
        std::fs::read(dirs.profile_dir.join("scan.toml")).unwrap(),
        before.0,
        "scan profile untouched"
    );
    assert_eq!(
        std::fs::read(dirs.endpoints_file()).unwrap(),
        before.1,
        "scan cache untouched"
    );
}

#[tokio::test]
async fn refused_identity_renews_fresh() {
    let dirs = work("refused");
    dirs.ensure_dirs().expect("dirs");
    seed_settings(&dirs);
    let e = engine_in(&dirs);

    // Healthy identity from the accepting provider.
    let accept = Fixture::start(FixtureMode::Accept).await;
    let first = e
        .register_warp(IdentityRole::Outer, &opts(&accept), None)
        .await;
    assert_eq!(first.action, ReportAction::Registered);
    let old_id = first.identity.clone().unwrap();
    let before = settings_snapshot(&dirs);

    // The same id is now refused: renewal provisions fresh, discards old.
    let refuse = Fixture::start(FixtureMode::RefuseIdentity).await;
    let report = renew_role(&dirs, IdentityRole::Outer, &opts(&refuse), None, false).await;
    assert_eq!(report.action, ReportAction::ReRegistered);
    assert_eq!(report.exit_code(), 0);
    let new_id = report.identity.clone().unwrap();
    assert_ne!(old_id, new_id, "fresh identity replaces the refused one");
    let stored = e.load_identity(IdentityRole::Outer).expect("stored");
    assert_eq!(stored.device_id, new_id);
    assert!(!stored.refused);
    assert_settings_untouched(&dirs, &before);
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn timeout_keeps_identity_for_rescan() {
    let dirs = work("timeout");
    dirs.ensure_dirs().expect("dirs");
    seed_settings(&dirs);
    let e = engine_in(&dirs);

    let accept = Fixture::start(FixtureMode::Accept).await;
    let first = e
        .register_warp(IdentityRole::Outer, &opts(&accept), None)
        .await;
    let old_id = first.identity.clone().unwrap();
    let before = settings_snapshot(&dirs);

    // Timeout carries no refusal signal: the identity MUST be kept, but the
    // report must be Blocked (exit 2) — never Reused/exit 0 masquerading a
    // network failure as healthy. Rescan/retry is the next step.
    let slow = Fixture::start(FixtureMode::Timeout).await;
    let slow_opts = ProviderOptions {
        provider_base: slow.base_url().to_string(),
        timeout_secs: 2,
        family: "dual".to_string(),
    };
    let report = renew_role(&dirs, IdentityRole::Outer, &slow_opts, None, false).await;
    assert_eq!(
        report.action,
        ReportAction::Blocked,
        "failed refresh is blocked"
    );
    assert_eq!(report.exit_code(), 2, "blocked renewal fails closed");
    assert!(
        report.cause.contains("rescan"),
        "names the next step: {}",
        report.cause
    );
    assert_eq!(
        e.load_identity(IdentityRole::Outer).unwrap().device_id,
        old_id,
        "same identity kept"
    );
    assert_settings_untouched(&dirs, &before);
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn healthy_renew_is_an_explicit_noop() {
    let dirs = work("healthy");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);

    let accept = Fixture::start(FixtureMode::Accept).await;
    let first = e
        .register_warp(IdentityRole::Outer, &opts(&accept), None)
        .await;
    let old_id = first.identity.clone().unwrap();

    // Refresh accepted with nothing changed: reused + says so.
    let report = renew_role(&dirs, IdentityRole::Outer, &opts(&accept), None, false).await;
    assert_eq!(report.action, ReportAction::Reused);
    assert!(
        report.cause.contains("nothing"),
        "confirms no replacement: {}",
        report.cause
    );
    assert_eq!(
        e.load_identity(IdentityRole::Outer).unwrap().device_id,
        old_id
    );
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}
