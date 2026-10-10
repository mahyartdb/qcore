//! US2 seeded scanning (002 T017): `warp.toml` candidates feed the
//! scanner; only handshake+traffic verified endpoints rank, ordered by
//! measured RTT; per-family candidate selection (FR-006/007/013/014).
//!
//! Loopback only (offline gating): a TCP echo responder stands in for a
//! provider edge, and the candidate file is a test-profile override.

use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::scan::seeds::{candidates_for, load_warp_profiles};
use qcore_core::scan::{ProbeKind, ScanProfile, ScanRequest, Scanner};
use std::net::SocketAddr;
use tests_conformance::testutil::{closed_port, unique_dir};

fn work(name: &str) -> ProfileDirs {
    let dir = unique_dir(&format!("qcore-seed-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    let d = ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")));
    d.ensure_dirs().unwrap();
    d
}

/// warp.toml override pointing at one loopback echo port (+ one dead port
/// to prove discard). IPv6 section stays empty on purpose.
fn write_warp_toml(dirs: &ProfileDirs, echo_v4: SocketAddr, dead_port: u16) {
    let text = format!(
        "[warp]\nranges = []\nseeds = [\"127.0.0.1\"]\nports = [{}, {}]\n\
         v6_ranges = []\nv6_seeds = []\n\
         [masque]\nranges = []\nseeds = [\"127.0.0.1\"]\nports = [{}]\n\
         v6_ranges = []\nv6_seeds = []\n\
         [defaults]\nscan_profile = \"balanced\"\n",
        echo_v4.port(),
        dead_port,
        echo_v4.port()
    );
    std::fs::write(dirs.profile_dir.join("warp.toml"), text).unwrap();
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

fn test_profile() -> ScanProfile {
    ScanProfile {
        name: "seeded-test".to_string(),
        concurrency: 8,
        rtt_budget_ms: 500,
        probe_kind: ProbeKind::DataPlane,
        family_order: vec!["ipv4".to_string(), "ipv6".to_string()],
        stealth: false,
    }
}

#[tokio::test]
async fn seeded_scan_ranks_verified_by_rtt() {
    let d = work("rank");
    let live = echo_listener().await;
    let dead = closed_port();
    write_warp_toml(&d, live, dead.port());
    let profiles = load_warp_profiles(&d).expect("override loads");

    // Seeded candidates: live echo × its port + dead port; closed port dies.
    let cands = candidates_for(&profiles, "warp", "ipv4");
    assert!(cands.contains(&live), "seed × port expands: {cands:?}");
    assert!(cands.contains(&dead));

    let report = Scanner::scan(ScanRequest {
        transport: "warp".into(),
        profile: test_profile(),
        family: "dual".into(),
        candidates: cands,
    })
    .await
    .expect("scan runs");
    assert_eq!(report.ranked.len(), 1, "failed discarded, never reused");
    let top = &report.ranked[0];
    assert_eq!(top.address, live);
    assert_eq!(top.reachability, qcore_core::scan::Reachability::Passed);
    assert_eq!(top.confidence, qcore_core::scan::Confidence::Verified);
    assert!(top.latency_ms < 500, "measured RTT under budget");
    assert_eq!(report.failed, 1);
    let _ = std::fs::remove_dir_all(d.config_dir.parent().unwrap());
}

#[tokio::test]
async fn candidate_selection_covers_families_and_transports() {
    let d = work("families");
    let live = echo_listener().await;
    let dead = closed_port();
    write_warp_toml(&d, live, dead.port());
    let profiles = load_warp_profiles(&d).expect("override loads");

    // wireguard/gool resolve to the warp section; masque to its own.
    for t in ["warp", "wireguard", "gool"] {
        assert!(
            candidates_for(&profiles, t, "ipv4").contains(&live),
            "{t} serves warp seeds"
        );
    }
    assert!(
        candidates_for(&profiles, "masque", "ipv4").contains(&live),
        "masque serves masque seeds"
    );
    // No v6 seeds in the override → v6 selects nothing (explicit, not fallback).
    assert!(candidates_for(&profiles, "warp", "ipv6").is_empty());
    // Unknown transports get no candidates (sieve stays empty, never guessed).
    assert!(candidates_for(&profiles, "tor", "dual").is_empty());
    assert!(candidates_for(&profiles, "warp", "dual").contains(&live));

    // A v6-only scan over v4 candidates finds nothing (exit-4 shape downstream).
    let report = Scanner::scan(ScanRequest {
        transport: "warp".into(),
        profile: test_profile(),
        family: "ipv6".into(),
        candidates: candidates_for(&profiles, "warp", "dual"),
    })
    .await
    .expect("scan runs");
    assert!(report.ranked.is_empty(), "family filter holds");
    let _ = std::fs::remove_dir_all(d.config_dir.parent().unwrap());
}

#[test]
fn shipped_defaults_load_with_documented_shape() {
    // No override file → compiled-in shipped warp.toml (FR-014 out-of-box).
    let d = work("shipped");
    let profiles = load_warp_profiles(&d).expect("shipped loads");
    assert_eq!(profiles.default_scan_profile, "balanced");
    assert!(!profiles.warp.ranges.is_empty(), "warp ships ranges");
    assert!(!profiles.warp.seeds.is_empty(), "warp ships seeds");
    assert!(profiles.warp.ports.contains(&2408), "2408 tried first");
    assert_eq!(profiles.warp.ports[0], 2408);
    assert!(!profiles.masque.ranges.is_empty(), "masque ships ranges");
    assert!(profiles.masque.ports.contains(&443));
    // Bounded: sampling caps keep scans inside profile budgets.
    let cands = candidates_for(&profiles, "warp", "dual");
    assert!(
        cands.len() <= qcore_core::scan::seeds::MAX_SEEDED_CANDIDATES,
        "bounded candidate space: {}",
        cands.len()
    );
    let _ = std::fs::remove_dir_all(d.config_dir.parent().unwrap());
}

#[test]
fn malformed_override_fails_closed_naming_field() {
    let d = work("malformed");
    std::fs::write(
        dirs_profile(&d),
        "[warp]\nranges = []\nseeds = [\"not-an-ip\"]\nports = [2408]\n\
         v6_ranges = []\nv6_seeds = []\n\
         [masque]\nranges = []\nseeds = []\nports = [443]\n\
         v6_ranges = []\nv6_seeds = []\n\
         [defaults]\nscan_profile = \"balanced\"\n",
    )
    .unwrap();
    let err = load_warp_profiles(&d).unwrap_err();
    assert!(
        err.contains("warp") && err.contains("seeds"),
        "names file+field: {err}"
    );
    let _ = std::fs::remove_dir_all(d.config_dir.parent().unwrap());
}

fn dirs_profile(d: &ProfileDirs) -> std::path::PathBuf {
    d.profile_dir.join("warp.toml")
}
