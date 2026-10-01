//! US4 scan profiles (T065): each profile yields ranked candidates with
//! latency + reachability; handshake-only results are uncertain and never
//! promoted to last-known-good; empty scans exit 4 with no silent reuse;
//! a balanced scan finishes well inside the 30 s budget (SC-005).

use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::scan::{
    evict_stale_lkg, load_profile, persist_verified, ProbeKind, Reachability, ScanError,
    ScanRequest, Scanner,
};
use std::net::SocketAddr;
use std::time::Instant;

fn dirs(name: &str) -> ProfileDirs {
    let dir = std::env::temp_dir().join(format!("qcore-scan-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let d = ProfileDirs::resolve(Some(dir.join("cfg")), Some(dir.join("prof")));
    d.ensure_dirs().unwrap();
    // Seed the profile dir with the shipped scan.toml.
    let shipped =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../profiles/scan.toml");
    std::fs::copy(&shipped, dir.join("prof").join("scan.toml")).expect("ship scan.toml");
    d
}

/// TCP echo responder: data-plane probes validate against this.
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

fn closed_port() -> SocketAddr {
    "127.0.0.1:1".parse().unwrap()
}

#[test]
fn profiles_load_with_documented_defaults() {
    let d = dirs("profiles");
    for name in ["turbo", "balanced", "stealth"] {
        load_profile(&d, name).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let b = load_profile(&d, "balanced").unwrap();
    assert_eq!(b.concurrency, 32);
    assert_eq!(b.rtt_budget_ms, 400);
    assert_eq!(b.family_order, vec!["ipv4".to_string(), "ipv6".to_string()]);
    assert!(!b.stealth);
    assert!(
        load_profile(&d, "nope").is_err(),
        "unknown profile rejected"
    );
}

#[tokio::test]
async fn data_plane_scan_ranks_verified_first_and_discards_failed() {
    let d = dirs("rank");
    let live = echo_listener().await;
    let profile = load_profile(&d, "balanced").unwrap();
    assert_eq!(profile.probe_kind, ProbeKind::DataPlane);
    let report = Scanner::scan(ScanRequest {
        transport: "wireguard".into(),
        profile,
        family: "dual".into(),
        candidates: vec![closed_port(), live],
    })
    .await
    .expect("scan runs");
    assert_eq!(report.ranked.len(), 1, "failed discarded, never reused");
    let top = &report.ranked[0];
    assert_eq!(top.address, live);
    assert_eq!(top.reachability, Reachability::Passed);
    assert_eq!(top.confidence, qcore_core::scan::Confidence::Verified);
    assert!(top.latency_ms <= 400, "latency measured within budget");
    assert_eq!(report.failed, 1);
}

#[tokio::test]
async fn handshake_only_is_uncertain_and_never_promoted() {
    let d = dirs("uncertain");
    let live = echo_listener().await;
    let mut profile = load_profile(&d, "turbo").unwrap();
    profile.probe_kind = ProbeKind::Handshake;
    let report = Scanner::scan(ScanRequest {
        transport: "masque".into(),
        profile,
        family: "dual".into(),
        candidates: vec![live],
    })
    .await
    .expect("scan runs");
    assert_eq!(report.ranked.len(), 1);
    assert_eq!(
        report.ranked[0].confidence,
        qcore_core::scan::Confidence::Uncertain
    );
    // Uncertain results are never promoted to last-known-good.
    assert_eq!(persist_verified(&d, &report).expect("persist runs"), None);
    assert!(
        qcore_core::session::reconnect::last_known_good(&d).is_none(),
        "no silent LKG write"
    );
}

#[tokio::test]
async fn verified_scan_caches_last_known_good_for_reconnect() {
    let d = dirs("lkg");
    let live = echo_listener().await;
    let profile = load_profile(&d, "balanced").unwrap();
    let report = Scanner::scan(ScanRequest {
        transport: "wireguard".into(),
        profile,
        family: "dual".into(),
        candidates: vec![live],
    })
    .await
    .expect("scan runs");
    let cached = persist_verified(&d, &report).expect("persist runs");
    assert_eq!(cached, Some(live));
    // FR-017: reconnect prefers the cached verified endpoint.
    assert_eq!(
        qcore_core::session::reconnect::last_known_good(&d),
        Some(live)
    );
}

#[tokio::test]
async fn empty_scan_exits_4_with_no_silent_reuse() {
    let d = dirs("empty");
    // A stale LKG that no longer answers must be evicted, not reused.
    std::fs::write(
        d.endpoints_file(),
        serde_json::json!({"last_known_good": "127.0.0.1:1"}).to_string(),
    )
    .unwrap();
    let profile = load_profile(&d, "balanced").unwrap();
    let report = Scanner::scan(ScanRequest {
        transport: "wireguard".into(),
        profile,
        family: "dual".into(),
        candidates: vec![closed_port()],
    })
    .await
    .expect("scan runs");
    assert!(report.ranked.is_empty());
    assert_eq!(ScanError::for_report(&report), ScanError::Empty);
    assert_eq!(ScanError::Empty.exit_code(), 4);
    evict_stale_lkg(&d, "wireguard", &report).expect("evict runs");
    assert!(
        qcore_core::session::reconnect::last_known_good(&d).is_none(),
        "stale LKG evicted, not silently reused"
    );
}

#[tokio::test]
async fn balanced_scan_finishes_inside_budget() {
    let d = dirs("timing");
    let live = echo_listener().await;
    let mut candidates = vec![live];
    for _ in 0..7 {
        candidates.push(closed_port());
    }
    let profile = load_profile(&d, "balanced").unwrap();
    let t = Instant::now();
    let report = Scanner::scan(ScanRequest {
        transport: "wireguard".into(),
        profile,
        family: "dual".into(),
        candidates,
    })
    .await
    .expect("scan runs");
    // Millis, not truncated seconds: `as_secs() < 30` passes a 30.9 s run.
    assert!(t.elapsed().as_millis() < 30_000, "SC-005: balanced < 30 s");
    assert_eq!(report.ranked.len(), 1);
}

// --- 002 T018: per-transport winner cache (FR-008) -------------------------

use qcore_core::scan::cache::{read_winners, record_winner, verify_winner_first, TransportWinner};

fn winner_for(addr: SocketAddr) -> TransportWinner {
    TransportWinner {
        address: addr.to_string(),
        profile: "balanced".to_string(),
        verified_at_ms: qcore_core::identity::model::now_ms(),
        family: if addr.is_ipv4() {
            "ipv4".to_string()
        } else {
            "ipv6".to_string()
        },
    }
}

#[tokio::test]
async fn per_transport_winner_reverified_first() {
    let d = dirs("winner");
    let live = echo_listener().await;
    record_winner(&d, "warp", winner_for(live)).expect("records");

    // Healthy winner: fast-path hit, no full scan needed downstream.
    let hit = verify_winner_first(&d, "warp", "ipv4", std::time::Duration::from_secs(2)).await;
    let (addr, latency_ms) = hit.expect("winner re-verifies");
    assert_eq!(addr, live);
    assert!(latency_ms < 2000, "re-verify is the fast path");

    // Transports are independent namespaces.
    assert!(!read_winners(&d).contains_key("masque"));
    assert_eq!(
        read_winners(&d).get("warp").unwrap().address,
        live.to_string()
    );
}

#[tokio::test]
async fn dead_winner_evicts_instead_of_reuse() {
    let d = dirs("evict");
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    record_winner(&d, "warp", winner_for(dead)).expect("records");

    // Dead winner: miss + eviction, so the caller runs a full scan.
    let hit = verify_winner_first(&d, "warp", "ipv4", std::time::Duration::from_secs(2)).await;
    assert!(hit.is_none(), "dead winner is not reused");
    assert!(
        !read_winners(&d).contains_key("warp"),
        "dead winner evicted"
    );
}

#[tokio::test]
async fn winner_family_mismatch_keeps_entry() {
    let d = dirs("famkeep");
    let live = echo_listener().await;
    record_winner(&d, "warp", winner_for(live)).expect("records");

    // Wrong family for this scan: miss, but the entry survives for its own
    // family's next scan (no destruction on a non-applicable lookup).
    let hit = verify_winner_first(&d, "warp", "ipv6", std::time::Duration::from_secs(2)).await;
    assert!(hit.is_none());
    assert!(read_winners(&d).contains_key("warp"), "entry kept");
}
