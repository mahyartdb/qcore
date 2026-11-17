//! US5 obfuscation compatibility (T069): compatible profiles apply and are
//! reported; incompatible selections (awg-on-warp, noize-on-tor, unknown
//! profiles) fail closed with the reason (FR-021). Measured against the
//! loopback responders.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::ExpandedHop;
use qcore_core::config::import::{store_import, ConfigImport, ImportVerdict};
use qcore_core::config::profile_dir::ProfileDirs;
use tests_conformance::awg_peer::AwgResponder;
use tests_conformance::testutil::unique_dir;
use transport_wireguard::awg::AwgParams;
use transport_wireguard::test_support::{generate_keypair, WgResponder};

/// AWG transforms pinned by the import `.conf`. Import material fills before
/// profile params (chain > import > profile), so every AWG test drives the
/// same wire shape regardless of the profile's S/H ranges.
const AWG_S: u32 = 24;
const AWG_H1: u32 = 111;
const AWG_H2: u32 = 222;
const AWG_H3: u32 = 333;
const AWG_H4: u32 = 444;

fn b64(data: &[u8]) -> String {
    qcore_core::config::import::b64_encode(data)
}

fn work(name: &str) -> std::path::PathBuf {
    let dir = unique_dir(&format!("qcore-obf-{name}"));
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
        s.push_str(&format!(
            "Jc = 6\nJmin = 64\nJmax = 256\n\
             S1 = {AWG_S}\nS2 = {AWG_S}\nS3 = {AWG_S}\nS4 = {AWG_S}\n\
             H1 = {AWG_H1}\nH2 = {AWG_H2}\nH3 = {AWG_H3}\nH4 = {AWG_H4}\n"
        ));
    }
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n"
    ));
    s
}

/// AWG params the responder must carry to complete a handshake with the hop
/// above. `random_trailers` follows the selected profile: a trailed handshake
/// datagram only parses on a peer that expects trailers, and vice versa.
fn awg_peer_params(random_trailers: bool) -> AwgParams {
    AwgParams {
        s1: AWG_S,
        s2: AWG_S,
        s3: AWG_S,
        s4: AWG_S,
        h1: AWG_H1,
        h2: AWG_H2,
        h3: AWG_H3,
        h4: AWG_H4,
        random_trailers,
        ..Default::default()
    }
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
    // A stock WireGuard responder cannot parse S1-prefixed, H1-typed
    // handshakes: completion here is the proof the transforms applied.
    let responder = AwgResponder::spawn(
        "127.0.0.1".parse().unwrap(),
        s_sk,
        c_pk,
        awg_peer_params(true),
    )
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
        .expect("AWG with profile establishes against an AWG peer");
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

#[tokio::test]
async fn awg_header_protection_without_key_fails_closed() {
    let dir = work("awg-hp-no-key");
    let prof = dir.join("prof");
    std::fs::create_dir_all(&prof).unwrap();
    // Profile params ride to the factory opaquely, so a profile can request
    // header protection — but it cannot supply the per-peer shared key
    // (profile data is not secret), and this conf declares no
    // `HeaderProtectionKey`. The build must refuse by name instead of
    // silently claiming the transform.
    std::fs::write(
        prof.join("obfuscation.toml"),
        "[\"awg-hp-no-key\"]\n\
         family = \"awg\"\n\
         compatible_modes = [{ kind = \"wireguard\", peer = \"awg\" }]\n\
         [\"awg-hp-no-key\".params]\n\
         header_protection = true\n",
    )
    .unwrap();
    let (c_sk, _c_pk) = generate_keypair();
    let (_s_sk, s_pk) = generate_keypair();
    let r = import_conf(
        &dir,
        "awg.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), "127.0.0.1:51820", true),
    );
    let engine = engine_in(&dir);
    let err = engine
        .start(vec![hop(
            "wireguard",
            &format!("peer=awg import={r} obfuscation=awg-hp-no-key"),
            "awg-hp-0",
        )])
        .await
        .expect_err("header protection without the key refuses at hop build");
    assert_eq!(err.layer, qcore_transport_api::FailureLayer::Config);
    assert!(
        err.cause.contains("awg_header_protection_key"),
        "names the missing key: {}",
        err.cause
    );
}

#[test]
fn imported_hp_key_with_wrong_length_is_rejected_naming_the_field() {
    // The CLI maps a rejected parse to exit 5; the parse layer must name the
    // field and the key-size rule, not merely treat the line as unknown.
    let dir = work("awg-hp-badlen");
    let (c_sk, _c_pk) = generate_keypair();
    let (_s_sk, s_pk) = generate_keypair();
    let short = [0x11u8; 16];
    let body = conf_text(&b64(&c_sk), &b64(&s_pk), "127.0.0.1:51820", true).replacen(
        "[Interface]\n",
        &format!("[Interface]\nHeaderProtectionKey = {}\n", b64(&short)),
        1,
    );
    let path = dir.join("short-hp.conf");
    std::fs::write(&path, body).unwrap();
    let imp = ConfigImport::parse(&path).expect("parse returns a verdict");
    assert_eq!(imp.verdict, ImportVerdict::Rejected);
    assert!(
        imp.reasons
            .iter()
            .any(|r| r.contains("HeaderProtectionKey") && r.contains("expected 32")),
        "rejects by key length naming the field (exit 5 at the CLI): {:?}",
        imp.reasons
    );
}

#[test]
fn hp_key_without_the_flag_fails_closed_naming_the_pair() {
    // The factory pair rule behind the import mapping: a materialized key is
    // always paired with `awg_header_protection=true`, so an orphan key can
    // only arrive through a hand-built factory config — and must be refused
    // naming both fields rather than silently disabling the transform.
    let mut cfg = qcore_transport_api::HopConfig::new("wireguard");
    cfg.fields
        .insert("awg_header_protection".into(), "false".into());
    cfg.fields
        .insert("awg_header_protection_key".into(), "ab".repeat(32));
    let err = transport_wireguard::awg::parse_fields(&cfg).expect_err("orphan key refuses");
    assert!(
        err.contains("awg_header_protection_key") && err.contains("awg_header_protection"),
        "names the pair: {err}"
    );
}

#[tokio::test]
async fn awg_profile_with_imported_hp_key_handshakes() {
    // End-to-end V2.2: the `.conf` carries `HeaderProtectionKey`, the import
    // store keeps it as a secret, materialize() pairs it with
    // `awg_header_protection=true`, and the hop completes a header-protected
    // handshake against a peer keyed with the same value. The profile ships
    // `header_protection = false`; import material wins.
    let dir = work("awg-hp-import");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let hp_key = [0x42u8; 32];
    let responder = AwgResponder::spawn("127.0.0.1".parse().unwrap(), s_sk, c_pk, {
        let mut p = awg_peer_params(true);
        p.header_protection = true;
        p.header_protection_key = Some(hp_key);
        p
    })
    .await
    .unwrap();
    let body = conf_text(&b64(&c_sk), &b64(&s_pk), &responder.addr.to_string(), true).replacen(
        "[Interface]\n",
        &format!("[Interface]\nHeaderProtectionKey = {}\n", b64(&hp_key)),
        1,
    );
    let r = import_conf(&dir, "awg-hp.conf", &body);
    let _ = qcore_transports::linked_kinds();
    let engine = Engine::new(EngineConfig {
        dirs: dirs_of(&dir),
        // A bounded handshake budget: an unplumbed key must fail the build,
        // not sit until the 30 s session default.
        timeout_secs: 5,
        ..Default::default()
    });
    let handle = engine
        .start(vec![hop(
            "wireguard",
            &format!("peer=awg import={r} obfuscation=awg-balanced"),
            "awg-hp-0",
        )])
        .await
        .expect("imported HeaderProtectionKey completes an hp handshake");
    assert_eq!(
        handle.hop_reports()[0].obfuscation.as_deref(),
        Some("awg-balanced")
    );
    handle.stop_all().await.expect("clean stop");
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

// --- T7 story 20: aggressive/off paths --------------------------------------
// Every shipped profile family needs an offline establishment proof, not
// just the balanced defaults.

#[tokio::test]
async fn masque_aggressive_on_h2_applies_and_reports() {
    let dir = work("h2-aggr");
    let responder =
        transport_masque::test_support::H2Responder::spawn("127.0.0.1".parse().unwrap())
            .await
            .unwrap();
    let engine = engine_in(&dir);
    let handle = engine
        .start(vec![hop(
            "masque",
            &format!(
                "alpn=h2 endpoint={} obfuscation=masque-aggressive",
                responder.addr
            ),
            "mq-aggr-0",
        )])
        .await
        .expect("aggressive masque-h2 establishes");
    assert_eq!(
        handle.hop_reports()[0].obfuscation.as_deref(),
        Some("masque-aggressive")
    );
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn awg_aggressive_on_awg_peer_applies_and_reports() {
    let dir = work("awg-aggr");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = AwgResponder::spawn(
        "127.0.0.1".parse().unwrap(),
        s_sk,
        c_pk,
        awg_peer_params(true),
    )
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
            &format!("peer=awg import={r} obfuscation=awg-aggressive"),
            "awg-aggr-0",
        )])
        .await
        .expect("AWG aggressive establishes");
    assert_eq!(
        handle.hop_reports()[0].obfuscation.as_deref(),
        Some("awg-aggressive")
    );
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn awg_off_on_awg_peer_applies_and_reports() {
    let dir = work("awg-off");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    // `awg-off` disables trailers and content padding, but import material
    // fills first, so the conf's S/H transforms (and Jc) still apply: the
    // responder must still speak AWG, with exact-size handshake datagrams.
    let responder = AwgResponder::spawn(
        "127.0.0.1".parse().unwrap(),
        s_sk,
        c_pk,
        awg_peer_params(false),
    )
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
            &format!("peer=awg import={r} obfuscation=awg-off"),
            "awg-off-0",
        )])
        .await
        .expect("AWG off establishes");
    assert_eq!(
        handle.hop_reports()[0].obfuscation.as_deref(),
        Some("awg-off")
    );
    handle.stop_all().await.expect("clean stop");
}
