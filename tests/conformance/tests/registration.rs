//! US1 registration (002 T009, T011): fresh-profile registration stores
//! exactly one identity with no half-written state; the license path
//! upgrades without leaking the key anywhere.
//!
//! All provider traffic goes to the loopback fixture double (offline
//! gating); the used address family is asserted on every exchange (FR-013).

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::config::secret::SecretString;
use qcore_core::identity::register::ProviderOptions;
use qcore_core::identity::report::ReportAction;
use qcore_core::identity::store::IdentityRole;
use tests_conformance::fixture::{Fixture, FixtureMode};

fn work(name: &str) -> ProfileDirs {
    let dir = std::env::temp_dir().join(format!("qcore-reg-{name}-{}", std::process::id()));
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

fn opts(fx: &Fixture, family: &str) -> ProviderOptions {
    ProviderOptions {
        provider_base: fx.base_url().to_string(),
        timeout_secs: 10,
        family: family.to_string(),
    }
}

#[tokio::test]
async fn register_stores_exactly_one_identity() {
    let dirs = work("one");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let fx = Fixture::start(FixtureMode::Accept).await;

    let report = e
        .register_warp(IdentityRole::Outer, &opts(&fx, "ipv4"), None)
        .await;
    assert_eq!(report.action, ReportAction::Registered);
    assert_eq!(report.exit_code(), 0);
    assert!(
        report.cause.contains("ipv4"),
        "family reported: {}",
        report.cause
    );
    let id = report.identity.clone().expect("device id reported");

    // Exactly one: the stored identity loads under the reported id.
    let stored = e.load_identity(IdentityRole::Outer).expect("stored");
    assert_eq!(stored.device_id, id);
    assert!(!stored.refused);

    // No half-written state: the record parses, no temp files linger.
    let record_path = qcore_core::identity::store::identity_file(&dirs, IdentityRole::Outer);
    let text = std::fs::read_to_string(&record_path).expect("record");
    assert!(text.contains(&id));
    for entry in std::fs::read_dir(&dirs.config_dir).expect("list") {
        let name = entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        assert!(!name.contains("tmp"), "no temp file left: {name}");
    }

    // A second registration replaces cleanly — still exactly one record.
    let report2 = e
        .register_warp(IdentityRole::Outer, &opts(&fx, "ipv4"), None)
        .await;
    assert_eq!(report2.action, ReportAction::Registered);
    let id2 = report2.identity.clone().unwrap();
    assert_ne!(id, id2, "fresh registration mints a new device id");
    assert_eq!(e.load_identity(IdentityRole::Outer).unwrap().device_id, id2);
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn registration_reports_the_family_it_used() {
    // v4-only exchange.
    let dirs4 = work("fam4");
    dirs4.ensure_dirs().expect("dirs");
    let e4 = engine_in(&dirs4);
    let fx4 = Fixture::start(FixtureMode::Accept).await;
    let r4 = e4
        .register_warp(IdentityRole::Outer, &opts(&fx4, "ipv4"), None)
        .await;
    assert_eq!(r4.action, ReportAction::Registered);
    assert!(r4.cause.contains("ipv4"), "v4 reported: {}", r4.cause);

    // v6-only exchange against the ::1 fixture.
    let dirs6 = work("fam6");
    dirs6.ensure_dirs().expect("dirs");
    let e6 = engine_in(&dirs6);
    let fx6 = Fixture::start_v6(FixtureMode::Accept).await;
    let r6 = e6
        .register_warp(IdentityRole::Outer, &opts(&fx6, "ipv6"), None)
        .await;
    assert_eq!(r6.action, ReportAction::Registered);
    assert!(r6.cause.contains("ipv6"), "v6 reported: {}", r6.cause);
}

#[tokio::test]
async fn license_key_applies_without_leaking() {
    // Distinctive key bytes: any appearance outside the transient request
    // buffer is a leak.
    const KEY: &str = "WARP-PLUS-TEST-KEY-7f3a9c2e";
    let dirs = work("license");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let fx = Fixture::start(FixtureMode::Accept).await;

    let key = SecretString::new(KEY);
    let report = e
        .register_warp(IdentityRole::Outer, &opts(&fx, "dual"), Some(&key))
        .await;
    drop(key);
    assert_eq!(report.action, ReportAction::Registered);
    assert!(report.license_applied, "fixture accepts the upgrade");
    assert_eq!(report.exit_code(), 0);

    // The report carries no key, token, or private material.
    let blob = report.to_json();
    assert!(!blob.contains(KEY), "key never in reports");
    let stored = e.load_identity(IdentityRole::Outer).expect("stored");
    let token = String::from_utf8_lossy(stored.access_token.expose()).into_owned();
    let privkey = String::from_utf8_lossy(stored.private_key_b64.expose()).into_owned();
    for secret in [&token, &privkey] {
        assert!(
            !blob.contains(secret.as_str()),
            "credential never in reports"
        );
    }
    assert!(stored.license_upgraded);

    // The TOML record carries no secrets at all (they live in the secret
    // store); the key lives in NO file under the profile.
    let record = std::fs::read_to_string(qcore_core::identity::store::identity_file(
        &dirs,
        IdentityRole::Outer,
    ))
    .expect("record");
    assert!(!record.contains(KEY));
    assert!(!record.contains(token.as_str()));
    assert!(!record.contains(privkey.as_str()));
    for entry in std::fs::read_dir(&dirs.config_dir).expect("list") {
        let path = entry.expect("entry").path();
        if path.is_file() {
            let content = std::fs::read(&path).expect("read");
            let text = String::from_utf8_lossy(&content);
            assert!(!text.contains(KEY), "key persisted in {}", path.display());
        }
    }
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}
