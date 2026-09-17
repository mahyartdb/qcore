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

// --- 002 T034: registration artifacts (SC-005) ------------------------------
// Identity records, RegistrationReports (register/renew/MASQUE), refusal
// causes, and the endpoint cache must carry zero secret plaintext: device
// keys, access tokens, MASQUE keys, and the per-operation license key.

use qcore_core::identity::register::ProviderOptions;
use qcore_core::identity::renew::renew_role;
use qcore_core::identity::report::ReportAction;
use qcore_core::identity::store::IdentityRole;
use tests_conformance::fixture::{Fixture, FixtureMode};

fn identity_opts(fx: &Fixture) -> ProviderOptions {
    ProviderOptions {
        provider_base: fx.base_url().to_string(),
        timeout_secs: 10,
        family: "dual".to_string(),
    }
}

#[tokio::test]
async fn registration_artifacts_carry_no_secrets() {
    const KEY: &str = "HYGIENE-PROBE-KEY-9d4c1a7e";
    let dirs = work("identity");
    dirs.ensure_dirs().expect("dirs");
    let _ = qcore_transports::linked_kinds();
    let engine = Engine::new(EngineConfig {
        dirs: dirs.clone(),
        ..Default::default()
    });
    let accept = Fixture::start(FixtureMode::Accept).await;

    // Register with a license key, then enroll MASQUE: every new secret
    // class exists from here on (device key, token, MASQUE key, license).
    let license = qcore_core::config::secret::SecretString::new(KEY);
    let reg = engine
        .register_warp(IdentityRole::Outer, &identity_opts(&accept), Some(&license))
        .await;
    assert_eq!(reg.action, ReportAction::Registered);
    drop(license);
    let enrolled = renew_role(
        &dirs,
        IdentityRole::Outer,
        &identity_opts(&accept),
        None,
        true,
    )
    .await;
    assert_eq!(enrolled.action, ReportAction::Rotated);

    let stored = engine.load_identity(IdentityRole::Outer).expect("stored");
    let mut secrets = vec![KEY.to_string()];
    secrets.push(String::from_utf8_lossy(stored.access_token.expose()).into_owned());
    secrets.push(String::from_utf8_lossy(stored.private_key_b64.expose()).into_owned());
    let masque = stored.masque.expect("credential");
    secrets.push(String::from_utf8_lossy(masque.key_pem.expose()).into_owned());
    assert!(secrets.iter().all(|s| !s.is_empty()));

    // Reports (JSON is the wire shape) carry none of them.
    assert_clean("register report", &reg.to_json(), &secrets);
    assert_clean("masque report", &enrolled.to_json(), &secrets);

    // The TOML record carries none either (secrets live in the secret
    // store, never beside the record).
    let record_path = qcore_core::identity::store::identity_file(&dirs, IdentityRole::Outer);
    let record = std::fs::read_to_string(&record_path).expect("record");
    assert_clean("identity record", &record, &secrets);

    // Refusal causes name the next step, never credentials: renew against
    // the refusing provider with a license key offered.
    let refuse = Fixture::start(FixtureMode::RefuseIdentity).await;
    let license2 = qcore_core::config::secret::SecretString::new(KEY);
    let renewed = renew_role(
        &dirs,
        IdentityRole::Outer,
        &identity_opts(&refuse),
        Some(&license2),
        false,
    )
    .await;
    drop(license2);
    assert_eq!(renewed.action, ReportAction::ReRegistered);
    // The fresh identity minted a new token: hunt for that one too.
    let fresh = engine.load_identity(IdentityRole::Outer).expect("fresh");
    secrets.push(String::from_utf8_lossy(fresh.access_token.expose()).into_owned());
    assert_clean("renew report", &renewed.to_json(), &secrets);
    let record2 = std::fs::read_to_string(&record_path).expect("record");
    assert_clean("renewed record", &record2, &secrets);

    // Record files are user-only on unix (0600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&record_path)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "identity record is 0600");
    }
}

// --- 003 T013: Wave-1 regression guards -------------------------------------
// Provider-echoed secret-like details must be masked in CLI-facing causes
// (identity RegistrationReport) and in text failure rendering (session
// report), while actionable prefixes survive.

#[test]
fn refusal_cause_with_provider_echoed_secret_is_masked() {
    use qcore_core::identity::register::RegisterError;
    const ECHO: &str = "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==";
    let r = qcore_core::identity::report::report_for_error(RegisterError::Refused(format!(
        "quota gone {ECHO}"
    )));
    let json = r.to_json();
    assert!(
        !json.contains("xT4vN7qW"),
        "refusal cause leaked provider echo"
    );
    assert!(
        json.contains("provider refused: "),
        "actionable prefix kept"
    );
    assert!(json.contains("<redacted>"));
}

#[test]
fn text_failure_path_masks_secret_like_cause() {
    const ECHO: &str = "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==";
    let r = qcore_transport_api::FailureReport::new(
        qcore_transport_api::FailureLayer::Transport,
        "wg-0",
        format!("boom {ECHO}"),
        "transport",
    );
    let report = qcore_core::session::report::ConnectionReport {
        failure: Some(r),
        ..qcore_core::session::report::ConnectionReport::new(vec![], "wg-0")
    };
    let text = qcore_core::session::report::to_text(&report);
    assert!(
        !text.contains("xT4vN7qW"),
        "text path leaked secret-like cause"
    );
    assert!(text.contains("cause=<redacted>"));
}
