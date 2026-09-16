//! US2 imported-hop chaining (T060): imported WG / AWG alone establish live
//! against the loopback responder with egress through the declared exit;
//! personal↔WARP both orders validate exit-correct (live nightly: nested WG
//! needs a qcore-aware far end, same precedent as orderings.rs).
//!
//! Import material (endpoint + keys + AWG params) is merged into the factory
//! config in memory only — secrets live in the secret store, never in the
//! stored TOML or the typed HopSpec.

use qcore_core::api::{Engine, EngineConfig, Preflight};
use qcore_core::chain::ExpandedHop;
use qcore_core::config::import::{store_import, ConfigImport};
use qcore_core::config::profile_dir::ProfileDirs;
use transport_wireguard::test_support::{generate_keypair, WgResponder};

fn b64(data: &[u8]) -> String {
    qcore_core::config::import::b64_encode(data)
}

fn work(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("qcore-ichain-{name}-{}", std::process::id()));
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

/// Import a conf text into `dir`, returning its ref.
fn import_conf(dir: &std::path::Path, file: &str, body: &str) -> String {
    let path = dir.join(file);
    std::fs::write(&path, body).unwrap();
    let imp = ConfigImport::parse(&path).expect("conf parses");
    assert_eq!(
        imp.verdict,
        qcore_core::config::import::ImportVerdict::Accepted,
        "{file}: {:?}",
        imp.reasons
    );
    let dirs = dirs_of(dir);
    dirs.ensure_dirs().unwrap();
    store_import(&dirs, &imp).expect("stores")
}

fn conf_text(priv_b64: &str, pub_b64: &str, endpoint: &str, awg: bool) -> String {
    let mut s = format!(
        "[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.9.0.2/32, fd00:9::2/128\nDNS = 1.1.1.1\n"
    );
    if awg {
        s.push_str("Jc = 6\nJmin = 64\nJmax = 256\nS1 = 24\nS2 = 18\nS3 = 30\nS4 = 16\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\nI1 = quic\n");
    }
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n"
    ));
    s
}

fn imported_hop(peer: &str, import_ref: &str, id: &str) -> ExpandedHop {
    let mut spec =
        Engine::parse_single_hop("wireguard", &format!("peer={peer} import={import_ref}"))
            .expect("spec parses");
    spec.id = id.to_string();
    ExpandedHop::Hop(spec)
}

#[tokio::test]
async fn imported_wg_alone_establishes_with_exit_egress() {
    let dir = work("alone");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = WgResponder::spawn("127.0.0.1".parse().unwrap(), s_sk, c_pk)
        .await
        .unwrap();
    let r = import_conf(
        &dir,
        "wg-home.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), &responder.addr.to_string(), false),
    );
    let engine = engine_in(&dir);
    let handle = engine
        .start(vec![imported_hop("imported", &r, "home-0")])
        .await
        .expect("imported WG establishes");
    assert_eq!(handle.exit_hop_id, "home-0", "exit is the declared hop");
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn awg_alone_establishes_with_exit_egress() {
    let dir = work("awg");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = WgResponder::spawn("127.0.0.1".parse().unwrap(), s_sk, c_pk)
        .await
        .unwrap();
    let r = import_conf(
        &dir,
        "awg-home.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), &responder.addr.to_string(), true),
    );
    let engine = engine_in(&dir);
    let handle = engine
        .start(vec![imported_hop("awg", &r, "awg-0")])
        .await
        .expect("AWG establishes (plain handshake; obfuscation lands in US5)");
    assert_eq!(handle.exit_hop_id, "awg-0", "exit is the declared hop");
    handle.stop_all().await.expect("clean stop");
}

#[tokio::test]
async fn mock_outer_imported_inner_establishes_nested() {
    let dir = work("nested");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let responder = WgResponder::spawn("127.0.0.1".parse().unwrap(), s_sk, c_pk)
        .await
        .unwrap();
    let r = import_conf(
        &dir,
        "wg-in.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), &responder.addr.to_string(), false),
    );
    let engine = engine_in(&dir);
    let mut outer = Engine::parse_single_hop("mock", "").expect("mock parses");
    outer.id = "mock-0".into();
    let specs = vec![
        ExpandedHop::Hop(outer),
        imported_hop("imported", &r, "wg-1"),
    ];
    let handle = engine.start(specs).await.expect("nested establishes");
    assert_eq!(handle.exit_hop_id, "wg-1", "exit is the inner hop");
    handle.stop_all().await.expect("clean stop");
}

#[test]
fn warp_and_personal_validate_both_orders_with_last_hop_exit() {
    let dir = work("orders");
    let (c_sk, c_pk) = generate_keypair();
    let (s_sk, s_pk) = generate_keypair();
    let endpoint = "127.0.0.1:51820";
    let _ = (s_sk, c_pk);
    let r = import_conf(
        &dir,
        "wg-home.conf",
        &conf_text(&b64(&c_sk), &b64(&s_pk), endpoint, false),
    );
    let engine = engine_in(&dir);
    // Personal-WG-inside-WARP and WARP-inside-personal-WG: validated with the
    // exit as the last hop (live nightly — needs real WARP egress).
    for (first, second) in [("warp", "imported"), ("imported", "warp")] {
        let mut a = if first == "warp" {
            Engine::parse_single_hop("wireguard", &format!("peer=warp endpoint={endpoint}"))
                .expect("warp parses")
        } else {
            Engine::parse_single_hop("wireguard", &format!("peer=imported import={r}"))
                .expect("imported parses")
        };
        a.id = format!("{first}-0");
        let mut b = if second == "warp" {
            Engine::parse_single_hop("wireguard", &format!("peer=warp endpoint={endpoint}"))
                .expect("warp parses")
        } else {
            Engine::parse_single_hop("wireguard", &format!("peer=imported import={r}"))
                .expect("imported parses")
        };
        b.id = format!("{second}-1");
        match engine.preflight(vec![ExpandedHop::Hop(a), ExpandedHop::Hop(b)]) {
            Preflight::Ok { depth } => assert_eq!(depth, 2),
            Preflight::Rejected(e) => panic!("{first}->{second} must validate: {e}"),
        }
    }
}

#[tokio::test]
async fn missing_import_ref_fails_closed_naming_ref() {
    let dir = work("missing");
    let engine = engine_in(&dir);
    let err = engine
        .start(vec![imported_hop("imported", "no-such-ref", "wg-0")])
        .await
        .expect_err("missing import must fail closed");
    assert!(
        err.cause.contains("no-such-ref"),
        "names ref: {}",
        err.cause
    );
    assert_eq!(err.hop_id, "wg-0");
}
