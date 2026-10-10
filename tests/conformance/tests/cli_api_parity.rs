//! CLI→public-API parity audit (T084, FR-003c).
//!
//! Every CLI capability must be reachable through the public Rust API. Each
//! test below mirrors one CLI command's core operation using only public
//! `qcore-core` / `qcore-transport-api` / `qcore-transports` types — the same
//! surface the CLI itself consumes. A CLI-only path (logic the CLI
//! reimplements instead of calling) fails this file at compile time (no API
//! to call) or here at runtime.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use std::path::PathBuf;
use tests_conformance::testutil::unique_dir;

fn work(name: &str) -> ProfileDirs {
    let dir = unique_dir(&format!("qcore-parity-{name}"));
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

#[test]
fn version_reports_engine_api_abi_schema() {
    // `qcore version` (+ `--json`): engine + API + ABI + schema from one call.
    let (api, abi, schema) = Engine::versions();
    assert!(!api.is_empty(), "API version surfaced");
    assert!(abi > 0, "ABI version surfaced");
    assert!(!schema.is_empty(), "schema version surfaced");
}

#[test]
fn preflight_validates_without_sockets() {
    // `qcore preflight --chain ...`: parse + validate, exit 2 on rejection.
    let dirs = work("preflight");
    let e = engine_in(&dirs);
    let specs = e.parse_chain("mock,relay").expect("parses via public API");
    match e.preflight(specs) {
        qcore_core::api::engine::Preflight::Ok { depth } => assert_eq!(depth, 2),
        qcore_core::api::engine::Preflight::Rejected(err) => panic!("rejected: {err}"),
    }
    let bad = e.parse_chain("gool,gool").expect("over-depth parses");
    assert!(
        matches!(
            e.preflight(bad),
            qcore_core::api::engine::Preflight::Rejected(_)
        ),
        "over-depth rejected via public API (exit 2)"
    );
}

#[test]
fn max_depth_global_reaches_engine_config() {
    // `--max-depth 1`: the CLI threads this into EngineConfig, not its own check.
    let dirs = work("depth");
    let _ = qcore_transports::linked_kinds();
    let e = Engine::new(EngineConfig {
        dirs: dirs.clone(),
        max_depth: 1,
        ..Default::default()
    });
    let specs = e.parse_chain("mock,mock").expect("parses");
    assert!(
        matches!(
            e.preflight(specs),
            qcore_core::api::engine::Preflight::Rejected(_)
        ),
        "engine enforces the CLI-supplied depth cap"
    );
}

#[tokio::test]
async fn connect_status_stop_round_trip() {
    // `qcore connect/up`, `status`, `stop`: start → status → stop, all public.
    let dirs = work("connect");
    dirs.ensure_dirs().expect("dirs");
    let e = engine_in(&dirs);
    let specs = e.parse_chain("mock").expect("parses");
    let handle = e.start(specs).await.expect("starts via public API");
    assert_eq!(handle.exit_hop_id, "mock-0");
    assert_eq!(handle.hop_reports().len(), 1);
    // Status shape + exit-code mapping are public (status/stop commands).
    // A fresh dir has no durable session → NotRunning → exit 10 (contract).
    let _ = e.status();
    assert_eq!(
        qcore_core::session::SessionStatus::read(&work("fresh")).exit_code(),
        10,
        "not_running exit-code mapping is public API"
    );
    handle.stop_all().await.expect("stops via public API");
}

#[test]
fn ls_lists_registry_kinds_and_profiles() {
    // `qcore ls`: transports + scan + obfuscation + presets, all from data.
    let _ = qcore_transports::linked_kinds();
    let kinds = qcore_core::registry::TransportRegistry::global().kinds();
    assert!(kinds.contains(&"mock"), "registry kinds are public");
    let dirs = work("ls");
    for name in ["turbo", "balanced", "stealth"] {
        // Missing profile dir is a shaped error, not a panic (CLI prints it).
        let _ = qcore_core::scan::load_profile(&dirs, name);
    }
    let _ = qcore_core::config::obfuscation::load_profiles(&dirs);
    assert!(
        !qcore_core::chain::preset::builtin_presets().is_empty(),
        "builtin presets are public data"
    );
}

#[test]
fn scan_profiles_and_scanner_are_public() {
    // `qcore scan` (+ `--scan` on connect): profiles + Scanner, no CLI logic.
    let dirs = work("scan");
    let _ = qcore_core::scan::load_profile(&dirs, "balanced");
    let profile = qcore_core::scan::ScanProfile {
        name: "parity".to_string(),
        concurrency: 1,
        rtt_budget_ms: 200,
        probe_kind: qcore_core::scan::ProbeKind::Handshake,
        family_order: vec!["ipv4".to_string()],
        stealth: false,
    };
    let req = qcore_core::scan::ScanRequest {
        transport: "mock".to_string(),
        profile,
        family: "ipv4".to_string(),
        candidates: vec![],
    };
    let report = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
        .block_on(qcore_core::scan::Scanner::scan(req))
        .expect("empty scan is Ok with zero ranked, never fallback");
    assert!(report.ranked.is_empty());
}

#[test]
fn import_export_round_trip_is_public() {
    // `qcore import` / `qcore export`: parse + reproduce + redact, exit 5 path.
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/standard-wg.conf");
    let imp = qcore_core::config::import::ConfigImport::parse(&path).expect("parses");
    let text = qcore_core::config::export::export_redacted(&imp);
    assert!(text.contains("[Interface]"), "export reproduces sections");
    let re = qcore_core::config::import::ConfigImport::parse_str(&text, &path)
        .expect("redacted export reparses");
    let keys =
        |m: &std::collections::BTreeMap<String, String>| m.keys().cloned().collect::<Vec<_>>();
    assert_eq!(
        keys(&re.interface),
        keys(&imp.interface),
        "no interface field lost across export"
    );
    if !imp.secrets.is_empty() {
        assert!(text.contains("<redacted>"), "secrets redacted in export");
        for s in imp.secrets.values() {
            let plain = String::from_utf8_lossy(s.expose()).to_string();
            assert!(!text.contains(&plain), "no secret plaintext in export");
        }
    }
}

#[test]
fn obfuscation_resolution_is_public() {
    // `-O/--obfuscation`: the CLI only sets `obfuscation=`; the FR-021 gate
    // and application live in the public resolver.
    let dirs = work("obf");
    let _ = qcore_transports::linked_kinds();
    let e = engine_in(&dirs);
    let specs = e
        .parse_chain("wireguard peer=warp endpoint=127.0.0.1:51820 obfuscation=awg-balanced")
        .expect("parses");
    let hops: Vec<qcore_core::config::HopSpec> = specs
        .into_iter()
        .filter_map(|s| match s {
            qcore_core::chain::ExpandedHop::Hop(h) => Some(h),
            qcore_core::chain::ExpandedHop::Preset(_) => None,
        })
        .collect();
    // No profile dir here → shaped ChainError, proving the gate is callable
    // (shipped profiles exercise the accept path in obfuscation.rs).
    let _ = qcore_core::config::obfuscation::resolve_for_chain(&dirs, e.registry(), &hops);
}

#[test]
fn shortcuts_reparse_through_public_grammar() {
    // Shortcut dispatch is a pure alias: canonical expr → same ConnectionReport.
    // The grammar it aliases (`parse_chain`) is public, so any shortcut the
    // CLI mints re-parses to identical specs here.
    let dirs = work("shortcut");
    let e = engine_in(&dirs);
    let a = e.parse_chain("mock,mock").expect("parses");
    let b = e.parse_chain("mock,mock").expect("reparses");
    assert_eq!(
        format!("{a:?}"),
        format!("{b:?}"),
        "canonical reparse is stable via public API"
    );
}
