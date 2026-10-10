//! US1 auto-registration (002 T010): connects with no stored identity
//! register inline and proceed; healthy identities are reused untouched;
//! GOOL-shaped specs provision the outer+inner pair; chains needing no
//! WARP material touch neither network nor disk.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::identity::register::ProviderOptions;
use qcore_core::identity::store::IdentityRole;
use tests_conformance::fixture::{Fixture, FixtureMode};
use tests_conformance::testutil::{closed_port, unique_dir};

fn work(name: &str) -> ProfileDirs {
    let dir = unique_dir(&format!("qcore-auto-{name}"));
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

#[tokio::test]
async fn connect_auto_registers_when_none_stored() {
    let dirs = work("fresh");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let fx = Fixture::start(FixtureMode::Accept).await;
    let specs = e.parse_chain("wireguard peer=warp").expect("parses");

    // No stored identity → registered inline as part of the connect path.
    let ensured = e
        .ensure_warp_for_specs(&specs, &opts(&fx), None)
        .await
        .expect("ensures");
    assert!(ensured.fresh);
    assert_eq!(ensured.roles, vec![IdentityRole::Outer]);
    assert!(ensured.notice.is_some(), "the user is told it happened");
    let first = e.load_identity(IdentityRole::Outer).unwrap().device_id;

    // Second pass reuses the healthy identity: no re-registration.
    let reused = e
        .ensure_warp_for_specs(&specs, &opts(&fx), None)
        .await
        .expect("reuses");
    assert!(!reused.fresh);
    assert_eq!(
        e.load_identity(IdentityRole::Outer).unwrap().device_id,
        first
    );
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn chains_needing_no_identity_skip_registration() {
    let dirs = work("mock");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    // No fixture at all: nothing may touch the network.
    let dead = closed_port();
    let dummy = ProviderOptions {
        provider_base: format!("http://{dead}/closed"),
        timeout_secs: 2,
        family: "dual".to_string(),
    };
    let specs = e.parse_chain("mock,relay").expect("parses");
    let ensured = e
        .ensure_warp_for_specs(&specs, &dummy, None)
        .await
        .expect("skips");
    assert!(!ensured.fresh);
    assert!(ensured.roles.is_empty());
    assert!(
        e.load_identity(IdentityRole::Outer).is_none(),
        "nothing stored"
    );
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn gool_specs_provision_outer_and_inner() {
    let dirs = work("gool");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let fx = Fixture::start(FixtureMode::Accept).await;
    let specs = e.parse_chain("gool").expect("parses");

    let ensured = e
        .ensure_warp_for_specs(&specs, &opts(&fx), None)
        .await
        .expect("ensures pair");
    assert!(ensured.fresh);
    assert_eq!(
        ensured.roles,
        vec![IdentityRole::Outer, IdentityRole::Inner]
    );
    let outer = e.load_identity(IdentityRole::Outer).expect("outer");
    let inner = e.load_identity(IdentityRole::Inner).expect("inner");
    assert_ne!(
        outer.device_id, inner.device_id,
        "separately registered identities (FR-009)"
    );
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}
