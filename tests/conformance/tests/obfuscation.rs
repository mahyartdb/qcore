//! US5 obfuscation compatibility (T069): compatible profiles apply and are
//! reported; incompatible selections (awg-on-warp, noize-on-tor, unknown
//! profiles) fail closed with the reason (FR-021). Measured against the
//! loopback responders.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::ExpandedHop;
use qcore_core::config::import::{store_import, ConfigImport, ImportVerdict};
use qcore_core::config::profile_dir::ProfileDirs;
use transport_wireguard::test_support::{generate_keypair, WgResponder};

fn b64(data: &[u8]) -> String {
    qcore_core::config::import::b64_encode(data)
}

fn work(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("qcore-obf-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn engine_in(dir: &std::path::Path) -> Engine {
    let _ = qcore_transports::linked_kinds();
    Engine::new(EngineConfig {
        dirs: ProfileDirs::resolve(Some(dir.join("cfg")), Some(dir.join("prof"))),
        ..Default::default()
    })
}

fn dirs_of(dir: &std::path::Path) -> ProfileDirs {
    ProfileDirs::resolve(Some(dir.join("cfg")), Some(dir.join("prof")))
}

fn import_conf(dir: &std::path::Path, file: &str, body: &str) -> String {
    let path = dir.join(file);
    std::fs::write(&path, body).unwrap();
    let imp = ConfigImport::parse(&path).expect("conf parses");
    assert_eq!(
        imp.verdict,
        ImportVerdict::Accepted,
        "{file}: {:?}",
        imp.reasons
    );
    let dirs = dirs_of(dir);
    dirs.ensure_dirs().unwrap();
    store_import(&dirs, &imp).expect("stores")
}

fn conf_text(priv_b64: &str, pub_b64: &str, endpoint: &str, awg: bool) -> String {
    let mut s = format!("[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.9.0.2/32\n");
    if awg {
        s.push_str("Jc = 6\nJmin = 64\nJmax = 256\nS1 = 24\nH1 = 111\nH2 = 222\n");
    }
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n"
    ));
    s
}

fn hop(kind: &str, opts: &str, id: &str) -> ExpandedHop {
    let mut spec = Engine::parse_single_hop(kind, opts).expect("spec parses");
    spec.id = id.to_string();
    ExpandedHop::Hop(spec)
}

#[tokio::test]
async fn noize_on_wireguard_applies_and_reports() {
    let dir = work("wg");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = WgResponder::spawn("127.0.0.1".parse().unwrap(), s_sk, c_pk)
        .await
        .unwrap();
    let r = import_conf(
        &dir,
        "wg.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), &responder.addr.to_string(), false),
    );
    let engine = engine_in(&dir);
    let handle = engine
        .start(vec![hop(
            "wireguard",
            &format!("peer=imported import={r} obfuscation=masque-balanced"),
            "wg-0",
        )])
        .await
        .expect("noize wireguard establishes");
    let reports = handle.hop_reports();
    assert_eq!(
        reports[0].obfuscation.as_deref(),
        Some("masque-balanced"),
        "profile reported"
    );
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn noize_on_masque_h2_applies_and_reports() {
    let _ = (generate_keypair, WgResponder::spawn);
    let dir = work("h2");
    let responder =
        transport_masque::test_support::H2Responder::spawn("127.0.0.1".parse().unwrap())
            .await
            .unwrap();
    let engine = engine_in(&dir);
    let handle = engine
        .start(vec![hop(
            "masque",
            &format!(
                "alpn=h2 endpoint={} obfuscation=masque-balanced",
                responder.addr
            ),
            "mq-0",
        )])
        .await
        .expect("noize masque-h2 establishes");
    assert_eq!(
        handle.hop_reports()[0].obfuscation.as_deref(),
        Some("masque-balanced")
    );
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn awg_profile_on_awg_peer_applies_and_reports() {
    let dir = work("awg");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = WgResponder::spawn("127.0.0.1".parse().unwrap(), s_sk, c_pk)
        .await
        .unwrap();
    let r = import_conf(
        &dir,
        "awg.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), &responder.addr.to_string(), true),
    );
    let engine = engine_in(&dir);
    let handle = engine
        .start(vec![hop(
            "wireguard",
            &format!("peer=awg import={r} obfuscation=awg-balanced"),
            "awg-0",
        )])
        .await
        .expect("AWG with profile establishes (junk + plain handshake)");
    assert_eq!(
        handle.hop_reports()[0].obfuscation.as_deref(),
        Some("awg-balanced")
    );
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn awg_profile_on_warp_edge_is_rejected() {
    let dir = work("warp-edge");
    let engine = engine_in(&dir);
    // FR-021: AmneziaWG server-negotiated params must never reach a plain
    // WARP peer. Rejected at validation, before any key/handshake work.
    let err = engine
        .start(vec![hop(
            "wireguard",
            "peer=warp endpoint=127.0.0.1:51820 obfuscation=awg-balanced",
            "warp-0",
        )])
        .await
        .expect_err("awg-on-warp forbidden");
    assert_eq!(err.layer, qcore_transport_api::FailureLayer::Validation);
    assert!(
        err.cause.contains("awg-balanced"),
        "names profile: {}",
        err.cause
    );
}

#[test]
fn noize_on_tor_rejected_at_parse() {
    // Tor's typed config takes no `obfuscation` key: unknown keys fail
    // closed naming the field (T054 typed-options rule).
    let err = Engine::parse_single_hop("tor", "obfuscation=masque-balanced")
        .expect_err("tor takes no obfuscation");
    assert!(
        err.to_string().contains("obfuscation"),
        "names field: {err}"
    );
}

#[tokio::test]
async fn unknown_profile_is_rejected_by_name() {
    let dir = work("unknown");
    let engine = engine_in(&dir);
    let err = engine
        .start(vec![hop(
            "wireguard",
            "peer=warp endpoint=127.0.0.1:51820 obfuscation=no-such-profile",
            "w-0",
        )])
        .await
        .expect_err("unknown profile forbidden");
    assert_eq!(err.layer, qcore_transport_api::FailureLayer::Validation);
    assert!(
        err.cause.contains("no-such-profile"),
        "names profile: {}",
        err.cause
    );
}
