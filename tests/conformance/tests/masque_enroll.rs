//! US4 MASQUE enrollment (002 T029, T030): credential enrolls against the
//! fixture, rotates inside the window, confirms when healthy; h3 and h2
//! chains preflight through scanned endpoints (offline gating). The live
//! provider run is `#[ignore]`d nightly-only (constitution II).

use qcore_core::api::{Engine, EngineConfig, Preflight};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::config::secret::SecretString;
use qcore_core::identity::model::{now_ms, MasqueCredential, ProviderIdentity};
use qcore_core::identity::register::ProviderOptions;
use qcore_core::identity::renew::renew_role;
use qcore_core::identity::report::ReportAction;
use qcore_core::identity::store::IdentityRole;
use qcore_core::scan::seeds::{candidates_for, load_warp_profiles};
use qcore_core::scan::{ProbeKind, ScanProfile, ScanRequest, Scanner};
use std::net::SocketAddr;
use tests_conformance::fixture::{Fixture, FixtureMode};

fn work(name: &str) -> ProfileDirs {
    let dir = std::env::temp_dir().join(format!("qcore-masque-{name}-{}", std::process::id()));
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

async fn echo_listener() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn enrolls_against_fixture() {
    let dirs = work("enroll");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let fx = Fixture::start(FixtureMode::Accept).await;

    let reg = e.register_warp(IdentityRole::Outer, &opts(&fx), None).await;
    assert_eq!(reg.action, ReportAction::Registered);
    assert!(
        e.load_identity(IdentityRole::Outer)
            .unwrap()
            .masque
            .is_none(),
        "warp registration alone carries no credential"
    );

    let enrolled = renew_role(&dirs, IdentityRole::Outer, &opts(&fx), None, true).await;
    assert_eq!(enrolled.action, ReportAction::Rotated);
    assert!(enrolled.cause.contains("enrolled"), "{}", enrolled.cause);
    let stored = e.load_identity(IdentityRole::Outer).expect("stored");
    let cred = stored.masque.expect("credential stored");
    assert!(cred.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(
        now_ms().saturating_sub(cred.issued_at_ms) < 60_000,
        "freshly issued"
    );
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn rotation_window_triggers_rotate() {
    let dirs = work("window");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let fx = Fixture::start(FixtureMode::Accept).await;

    // Stored identity with a 360-day-old credential (inside the 7-day window
    // before the 365-day expiry, long past healthy).
    let (cert_pem, key_pem) = qcore_core::identity::masque::generate_credential().expect("cred");
    let day = 86_400_000u64;
    e.save_identity(
        IdentityRole::Outer,
        &ProviderIdentity {
            device_id: "dev-old".into(),
            access_token: SecretString::new("tok-old"),
            private_key_b64: SecretString::new("cHJpdmF0ZTE="),
            peer_key_b64: "cGVlcjE=".into(),
            interface_v4: "172.16.0.2".into(),
            interface_v6: "2606:4700:110::2".into(),
            masque: Some(MasqueCredential {
                cert_pem,
                key_pem,
                issued_at_ms: now_ms().saturating_sub(360 * day),
                lifetime_days: MasqueCredential::LIFETIME_DAYS,
                renew_before_days: MasqueCredential::RENEW_BEFORE_DAYS,
            }),
            refused: false,
            license_upgraded: false,
        },
    )
    .expect("saves");

    let rotated = renew_role(&dirs, IdentityRole::Outer, &opts(&fx), None, true).await;
    assert_eq!(rotated.action, ReportAction::Rotated);
    assert!(rotated.cause.contains("rotated"), "{}", rotated.cause);
    let stored = e.load_identity(IdentityRole::Outer).expect("stored");
    let cred = stored.masque.expect("credential");
    assert!(
        now_ms().saturating_sub(cred.issued_at_ms) < 60_000,
        "re-issued now"
    );

    // And now it is healthy: explicit confirmation, no churn.
    let healthy = renew_role(&dirs, IdentityRole::Outer, &opts(&fx), None, true).await;
    assert_eq!(healthy.action, ReportAction::Reused);
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

fn masque_warp_toml(dirs: &ProfileDirs, echo: SocketAddr) {
    let text = format!(
        "[warp]\nranges = []\nseeds = []\nports = [2408]\n\
         v6_ranges = []\nv6_seeds = []\n\
         [masque]\nranges = []\nseeds = [\"127.0.0.1\"]\nports = [{}]\n\
         v6_ranges = []\nv6_seeds = []\n\
         [defaults]\nscan_profile = \"balanced\"\n",
        echo.port()
    );
    std::fs::write(dirs.profile_dir.join("warp.toml"), text).unwrap();
}

fn test_profile() -> ScanProfile {
    ScanProfile {
        name: "masque-test".to_string(),
        concurrency: 8,
        rtt_budget_ms: 500,
        probe_kind: ProbeKind::DataPlane,
        family_order: vec!["ipv4".to_string(), "ipv6".to_string()],
        stealth: false,
    }
}

async fn scanned_masque_endpoint(dirs: &ProfileDirs) -> SocketAddr {
    let live = echo_listener().await;
    masque_warp_toml(dirs, live);
    let profiles = load_warp_profiles(dirs).expect("override loads");
    let report = Scanner::scan(ScanRequest {
        transport: "masque".into(),
        profile: test_profile(),
        family: "dual".into(),
        candidates: candidates_for(&profiles, "masque", "dual"),
    })
    .await
    .expect("scan runs");
    assert_eq!(report.ranked.len(), 1, "masque seed verifies");
    let winner = report.ranked[0].address;
    qcore_core::scan::cache::record_winner(
        dirs,
        "masque",
        qcore_core::scan::cache::TransportWinner {
            address: winner.to_string(),
            profile: "balanced".to_string(),
            verified_at_ms: now_ms(),
            family: "ipv4".to_string(),
        },
    )
    .expect("winner cached");
    winner
}

#[tokio::test]
async fn masque_h3_preflights_through_scanned_endpoint() {
    let dirs = work("h3");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let winner = scanned_masque_endpoint(&dirs).await;
    let specs = e
        .parse_chain(&format!("masque alpn=h3 endpoint={winner}"))
        .expect("parses");
    match e.preflight(specs) {
        Preflight::Ok { depth } => assert_eq!(depth, 1),
        Preflight::Rejected(err) => panic!("h3 rejected: {err}"),
    }
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

#[tokio::test]
async fn masque_h2_preflights_through_scanned_endpoint() {
    let dirs = work("h2");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let winner = scanned_masque_endpoint(&dirs).await;
    let specs = e
        .parse_chain(&format!("masque alpn=h2 endpoint={winner}"))
        .expect("parses");
    match e.preflight(specs) {
        Preflight::Ok { depth } => assert_eq!(depth, 1),
        Preflight::Rejected(err) => panic!("h2 rejected: {err}"),
    }
    let _ = std::fs::remove_dir_all(dirs.config_dir.parent().unwrap());
}

/// Nightly live run (SC-006 path): real registration + real MASQUE endpoint
/// discovery against the provider. Run with
/// `QCORE_LIVE=1 cargo test -- --ignored masque_live`. Tunnel bring-up stays
/// in the quickstart nightly run.
#[tokio::test]
#[ignore = "nightly: requires provider network + mints a real identity"]
async fn masque_live_register_and_scan() {
    if std::env::var("QCORE_LIVE").as_deref() != Ok("1") {
        panic!("nightly only: set QCORE_LIVE=1 with provider network reachable");
    }
    let dirs = work("live");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let opts = ProviderOptions::default();
    let report = e.register_warp(IdentityRole::Outer, &opts, None).await;
    assert_eq!(
        report.action,
        ReportAction::Registered,
        "live registration: {}",
        report.cause
    );
    let profiles = load_warp_profiles(&dirs).expect("shipped loads");
    let report = Scanner::scan(ScanRequest {
        transport: "masque".into(),
        profile: test_profile(),
        family: "dual".into(),
        candidates: candidates_for(&profiles, "masque", "dual"),
    })
    .await
    .expect("live scan runs");
    assert!(!report.ranked.is_empty(), "live scan finds an edge");
}
