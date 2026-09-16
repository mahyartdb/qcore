//! Dynamic trace-level secret-capture test (T088, SC-006).
//!
//! The most verbose surfaces (full `ConnectionReport` text+JSON, every
//! NDJSON diag line, redacted exports, stored import records, durable
//! session files) must contain zero secret plaintext — including through
//! the fail-closed placeholder path, which emits metadata only.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::ChainBuilder;
use qcore_core::config::import::ConfigImport;
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::session::net::FamilyPolicy;
use qcore_core::session::Session;
use std::path::PathBuf;

fn work(name: &str) -> ProfileDirs {
    let dir = std::env::temp_dir().join(format!("qcore-hygiene-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// Every secret value from both fixture configs (private + preshared keys).
fn corpus_secrets() -> Vec<String> {
    let mut out = Vec::new();
    for name in ["standard-wg.conf", "awg.conf"] {
        let imp = ConfigImport::parse(&fixture(name)).expect("fixture parses");
        for s in imp.secrets.values() {
            out.push(String::from_utf8_lossy(s.expose()).to_string());
        }
    }
    assert!(!out.is_empty(), "corpus must contain secrets to hunt for");
    out
}

fn assert_clean(label: &str, text: &str, secrets: &[String]) {
    for s in secrets {
        assert!(!text.contains(s.as_str()), "{label} leaks a secret value");
    }
}

#[test]
fn exports_reports_and_stored_records_carry_no_secrets() {
    let secrets = corpus_secrets();
    let dirs = work("exports");
    dirs.ensure_dirs().expect("dirs");

    // Redacted export (CLI default) + stored import record.
    for name in ["standard-wg.conf", "awg.conf"] {
        let imp = ConfigImport::parse(&fixture(name)).expect("parses");
        let redacted = qcore_core::config::export::export_redacted(&imp);
        assert_clean(&format!("export {name}"), &redacted, &secrets);
        assert!(redacted.contains("<redacted>"), "redaction marker present");
        let stored_ref = qcore_core::config::import::store_import(&dirs, &imp).expect("stores");
        let stored_path =
            qcore_core::config::import::imports_dir(&dirs).join(format!("{stored_ref}.toml"));
        let stored_text = std::fs::read_to_string(&stored_path).expect("stored record");
        assert_clean(&format!("stored record {name}"), &stored_text, &secrets);
    }
}

#[tokio::test]
async fn trace_verbose_surfaces_carry_no_secrets() {
    let secrets = corpus_secrets();
    let dirs = work("trace");
    dirs.ensure_dirs().expect("dirs");
    let _ = qcore_transports::linked_kinds();
    let engine = Engine::new(EngineConfig {
        dirs: dirs.clone(),
        ..Default::default()
    });

    // A chain exercising import-adjacent + obfuscation-adjacent reporting.
    let specs = engine.parse_chain("mock,relay").expect("parses");
    let handle = engine.start(specs).await.expect("starts");
    let report = qcore_core::session::report::ConnectionReport::new(
        handle.hop_reports(),
        handle.exit_hop_id.clone(),
    );
    assert_clean(
        "report json",
        &qcore_core::session::report::to_json(&report),
        &secrets,
    );
    assert_clean(
        "report text",
        &qcore_core::session::report::to_text(&report),
        &secrets,
    );
    assert_clean(
        "report ndjson",
        &qcore_core::diag::to_ndjson(qcore_core::diag::DiagEvent::Report(&report)),
        &secrets,
    );
    // Every HopEvent variant at full detail.
    let mut events = engine.subscribe();
    handle.stop_all().await.expect("stops");
    while let Ok(ev) = events.try_recv() {
        assert_clean(
            "hop event ndjson",
            &qcore_core::diag::to_ndjson(qcore_core::diag::DiagEvent::Hop(&ev)),
            &secrets,
        );
    }

    // Durable session file shape carries hops but never secrets.
    let specs = engine.parse_chain("mock").expect("parses");
    let chain = ChainBuilder::new(engine.registry(), 3)
        .build(specs)
        .expect("builds");
    let session = Session::new(
        "sess-hygiene".to_string(),
        &chain,
        FamilyPolicy::parse("dual", "ipv4").expect("policy"),
        0,
    );
    session.save(&dirs).expect("saves");
    let session_text = std::fs::read_to_string(dirs.session_file()).expect("session file");
    assert_clean("session.json", &session_text, &secrets);
}

#[test]
fn fail_closed_placeholder_emits_metadata_only() {
    // A secret-like value under an innocuous key drops the record: the
    // placeholder names keys and counts, never values.
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("hop_id".to_string(), "mock-0".to_string());
    fields.insert(
        "mystery".to_string(),
        "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==".to_string(),
    );
    let dropped = qcore_core::diag::redact_record(&fields).unwrap_err();
    assert_eq!(dropped.field_count, 2);
    assert!(dropped.keys.contains(&"mystery".to_string()));

    // Same guarantee through the NDJSON stream.
    let r = qcore_transport_api::FailureReport::new(
        qcore_transport_api::FailureLayer::Transport,
        "mock-0",
        "mystery xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==",
        "weird",
    );
    let line = qcore_core::diag::to_ndjson(qcore_core::diag::DiagEvent::Failure(&r));
    assert!(line.contains("\"dropped\":true"));
    assert!(!line.contains("xT4vN7qW"));
}
