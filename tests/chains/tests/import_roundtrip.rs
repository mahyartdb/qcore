//! US2 config round-trip (T059): 100% field fidelity over the fixture corpus;
//! unknown/malformed fields rejected by name (FR-023).

use qcore_core::config::export::{export_plain, export_redacted};
use qcore_core::config::import::{ConfigImport, ImportVerdict, SourceFormat};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn write_temp(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qcore-import-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn standard_wg_imports_field_for_field() {
    let imp = ConfigImport::parse(&fixture("standard-wg.conf")).expect("parses");
    assert_eq!(imp.verdict, ImportVerdict::Accepted);
    assert_eq!(imp.source_format, SourceFormat::Wireguard);
    assert!(imp.awg.is_none(), "no AWG params on plain WG");
    assert!(imp.unknown_fields.is_empty());
    // Dual-stack values preserved exactly (Principle II).
    assert_eq!(
        imp.interface.get("address").map(String::as_str),
        Some("10.0.0.2/32, fd00::2/128")
    );
    assert_eq!(
        imp.interface.get("dns").map(String::as_str),
        Some("1.1.1.1")
    );
    assert_eq!(imp.peers.len(), 1);
    assert_eq!(
        imp.peers[0].get("allowed_ips").map(String::as_str),
        Some("0.0.0.0/0, ::/0")
    );
    assert_eq!(
        imp.peers[0].get("endpoint").map(String::as_str),
        Some("203.0.113.10:51820")
    );
    assert_eq!(
        imp.peers[0].get("persistent_keepalive").map(String::as_str),
        Some("25")
    );
    assert!(imp.secrets.contains_key("interface.private_key"));
}

#[test]
fn awg_import_detects_format_and_params() {
    let imp = ConfigImport::parse(&fixture("awg.conf")).expect("parses");
    assert_eq!(imp.verdict, ImportVerdict::Accepted);
    assert_eq!(imp.source_format, SourceFormat::Amneziawg);
    let awg = imp.awg.as_ref().expect("awg params present");
    assert_eq!((awg.jc, awg.jmin, awg.jmax), (6, 64, 256));
    assert_eq!([awg.s1, awg.s2, awg.s3, awg.s4], [24, 18, 30, 16]);
    assert_eq!(
        [awg.h1, awg.h2, awg.h3, awg.h4],
        [1234567, 2345678, 3456789, 4567890]
    );
    assert_eq!(awg.i1.as_deref(), Some("quic"));
    assert_eq!(
        imp.peers[0].get("endpoint").map(String::as_str),
        Some("203.0.113.20:51820")
    );
}

#[test]
fn export_reproduces_parsed_equivalently() {
    for name in ["standard-wg.conf", "awg.conf"] {
        let a = ConfigImport::parse(&fixture(name)).expect("parses");
        let text = export_plain(&a);
        let b = ConfigImport::parse_str(&text, std::path::Path::new(name)).expect("reparses");
        assert_eq!(b.verdict, ImportVerdict::Accepted, "{name}");
        assert_eq!(b.source_format, a.source_format, "{name}");
        assert_eq!(b.interface, a.interface, "{name}: interface");
        assert_eq!(b.peers, a.peers, "{name}: peers");
        assert_eq!(b.awg, a.awg, "{name}: awg");
    }
}

#[test]
fn export_redacts_secrets() {
    let a = ConfigImport::parse(&fixture("awg.conf")).expect("parses");
    let text = export_redacted(&a);
    assert!(!text.contains("BwcHBwcH"), "private key never plaintext");
    assert!(text.contains("<redacted>"), "placeholder present");
    // Non-secret values survive redaction.
    assert!(text.contains("203.0.113.20:51820"));
    assert!(text.contains("Jc = 6"));
}

#[test]
fn unknown_fields_rejected_by_name() {
    let path = write_temp(
        "bogus.conf",
        "[Interface]\nPrivateKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nAddress = 10.0.0.2/32\nBogusKey = 1\n\n[Peer]\nPublicKey = CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n",
    );
    let imp = ConfigImport::parse(&path).expect("parses to a verdict");
    assert_eq!(imp.verdict, ImportVerdict::Rejected);
    assert!(
        imp.unknown_fields.iter().any(|f| f == "BogusKey"),
        "names field: {:?}",
        imp.unknown_fields
    );
    assert!(
        imp.reasons.join(" ").contains("BogusKey"),
        "reason names field: {:?}",
        imp.reasons
    );
}

#[test]
fn malformed_endpoint_rejected_naming_field() {
    let path = write_temp(
        "badendpoint.conf",
        "[Interface]\nPrivateKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n\n[Peer]\nPublicKey = CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nEndpoint = not-a-socket-addr\n",
    );
    let imp = ConfigImport::parse(&path).expect("parses to a verdict");
    assert_eq!(imp.verdict, ImportVerdict::Rejected);
    assert!(
        imp.reasons.join(" ").contains("Endpoint"),
        "names field: {:?}",
        imp.reasons
    );
}

#[test]
fn overlapping_h_headers_rejected() {
    let path = write_temp(
        "overlap.conf",
        "[Interface]\nPrivateKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nJc = 6\nJmin = 64\nJmax = 256\nH1 = 111\nH2 = 111\n\n[Peer]\nPublicKey = CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nEndpoint = 203.0.113.10:51820\n",
    );
    let imp = ConfigImport::parse(&path).expect("parses to a verdict");
    assert_eq!(imp.verdict, ImportVerdict::Rejected);
    assert!(
        imp.reasons.join(" ").contains("H1"),
        "names field: {:?}",
        imp.reasons
    );
}
