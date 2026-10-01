//! `scan` (US4 T068): discover and traffic-validate endpoints per
//! transport+family (FR-014–017). Ranked latency+verdict output as
//! table|json|ndjson; empty scans are exit 4 with no silent reuse.
//! Verified results are cached as last-known-good, feeding the T048
//! reconnect sink.

use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::identity::model::now_ms;
use qcore_core::scan::{
    cache, discovery_seeds, evict_stale_lkg, load_profile, persist_verified,
    seeds::{candidates_for, load_warp_profiles},
    ScanReport, ScanRequest, Scanner,
};

use crate::exit;

/// Load a profile by name (default `balanced`) from the profile dir.
pub fn profile_named(
    dirs: &ProfileDirs,
    name: &str,
) -> Result<qcore_core::scan::ScanProfile, String> {
    load_profile(dirs, name)
}

/// Run one scan (002 FR-006/007/008/014).
///
/// - Per-transport winner re-verify (fast path — full scan skipped while
///   the cached winner answers);
/// - else full scan over legacy LKG + warp.toml seeds + scan.toml
///   discovery seeds; winners cached per transport (and legacy LKG).
///
/// Verified winners are cached; a fully-failed scan evicts stale state.
pub async fn run_scan_request(
    dirs: &ProfileDirs,
    transport: &str,
    profile: qcore_core::scan::ScanProfile,
    family: &str,
) -> Result<ScanReport, String> {
    let budget = std::time::Duration::from_millis(profile.rtt_budget_ms.clamp(1, 5000));
    if let Some((addr, latency_ms)) =
        cache::verify_winner_first(dirs, transport, family, budget).await
    {
        // Fast path: the recorded winner still answers. It was
        // traffic-verified when recorded; the re-verify confirms continued
        // reachability, so the Verified verdict stands without a rescan.
        return Ok(ScanReport {
            transport: transport.to_string(),
            profile: profile.name.clone(),
            ranked: vec![qcore_core::scan::EndpointCandidate {
                address: addr,
                family: if addr.is_ipv4() {
                    "ipv4".to_string()
                } else {
                    "ipv6".to_string()
                },
                latency_ms,
                reachability: qcore_core::scan::Reachability::Passed,
                confidence: qcore_core::scan::Confidence::Verified,
                last_known_good: true,
            }],
            failed: 0,
            elapsed_ms: latency_ms,
        });
    }
    let mut candidates = Vec::new();
    if let Some(lkg) = qcore_core::session::reconnect::last_known_good(dirs) {
        let ok = match family {
            "ipv4" => lkg.is_ipv4(),
            "ipv6" => lkg.is_ipv6(),
            _ => true,
        };
        if ok {
            candidates.push(lkg);
        }
    }
    // Seeded candidates (FR-014): malformed/empty warp data selects nothing
    // rather than failing the scan — discovery seeds still run.
    if let Ok(warp) = load_warp_profiles(dirs) {
        candidates.extend(candidates_for(&warp, transport, family));
    }
    candidates.extend(discovery_seeds(dirs, transport));
    candidates.sort();
    candidates.dedup();
    let report = Scanner::scan(ScanRequest {
        transport: transport.to_string(),
        profile,
        family: family.to_string(),
        candidates,
    })
    .await?;
    if report.ranked.is_empty() {
        evict_stale_lkg(dirs, &report)?;
    } else {
        persist_verified(dirs, &report)?;
        if let Some(top) = report.ranked.iter().find(|c| {
            c.confidence == qcore_core::scan::Confidence::Verified
                && c.reachability == qcore_core::scan::Reachability::Passed
        }) {
            let _ = cache::record_winner(
                dirs,
                transport,
                cache::TransportWinner {
                    address: top.address.to_string(),
                    profile: report.profile.clone(),
                    verified_at_ms: now_ms(),
                    family: top.family.clone(),
                },
            );
        }
    }
    Ok(report)
}

pub async fn run(
    transport: &str,
    profile: &str,
    family: &str,
    output: &str,
    json: bool,
    dirs: &ProfileDirs,
) -> i32 {
    // Global --json selects the JSON document unless --output says otherwise.
    // `--json` guarantees exactly one JSON document on stdout: an explicit
    // `--output ndjson` with `--json` is a conflict (usage error), never
    // multi-document output.
    let output = if json && output == "table" {
        "json"
    } else {
        output
    };
    if !["table", "json", "ndjson"].contains(&output) {
        eprintln!("qcore: --output must be table|json|ndjson (exit 6)");
        return exit::USAGE;
    }
    if json && output == "ndjson" {
        eprintln!(
            "qcore: --json with --output ndjson conflicts (single document required) (exit 6)"
        );
        return exit::USAGE;
    }
    let profile = match profile_named(dirs, profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("qcore: {e}");
            return exit::USAGE;
        }
    };
    if !["ipv4", "ipv6", "dual"].contains(&family) {
        eprintln!("qcore: --family must be ipv4|ipv6|dual (exit 6)");
        return exit::USAGE;
    }
    let report = match run_scan_request(dirs, transport, profile, family).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qcore: scan failed: {e}");
            return exit::HOP_FAILURE;
        }
    };
    if report.ranked.is_empty() {
        if json || output == "json" {
            println!(
                "{}",
                serde_json::json!({"ok": false, "transport": transport, "candidates": []})
            );
        } else {
            eprintln!("qcore: scan found nothing reachable (exit 4)");
        }
        return exit::SCAN_EMPTY;
    }
    match output {
        "json" => {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "transport": report.transport,
                    "profile": report.profile,
                    "candidates": report.ranked.iter().map(candidate_json).collect::<Vec<_>>(),
                    "failed": report.failed,
                    "elapsed_ms": report.elapsed_ms,
                })
            );
        }
        "ndjson" => {
            for c in &report.ranked {
                println!("{}", candidate_json(c));
            }
        }
        _ => {
            println!(
                "{:<22} {:<6} {:>10} {:<10} {:<9}",
                "ENDPOINT", "FAMILY", "LATENCY-MS", "REACH", "CONFIDENCE"
            );
            for c in &report.ranked {
                println!(
                    "{:<22} {:<6} {:>10} {:<10} {:<9}",
                    c.address.to_string(),
                    c.family,
                    c.latency_ms,
                    match c.reachability {
                        qcore_core::scan::Reachability::Passed => "passed",
                        qcore_core::scan::Reachability::Failed => "failed",
                    },
                    match c.confidence {
                        qcore_core::scan::Confidence::Verified => "verified",
                        qcore_core::scan::Confidence::Uncertain => "uncertain",
                    },
                );
            }
            if json {
                eprintln!("qcore: --json with table output ignored (use --output json)");
            }
        }
    }
    exit::SUCCESS
}

fn candidate_json(c: &qcore_core::scan::EndpointCandidate) -> serde_json::Value {
    serde_json::json!({
        "address": c.address.to_string(),
        "family": c.family,
        "latency_ms": c.latency_ms,
        "reachability": match c.reachability {
            qcore_core::scan::Reachability::Passed => "passed",
            qcore_core::scan::Reachability::Failed => "failed",
        },
        "confidence": match c.confidence {
            qcore_core::scan::Confidence::Verified => "verified",
            qcore_core::scan::Confidence::Uncertain => "uncertain",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_core::scan::{Confidence, ProbeKind};

    fn test_dirs(tag: &str) -> ProfileDirs {
        let dir = std::env::temp_dir().join(format!("qcore-cli-scan-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = ProfileDirs::resolve(Some(dir.join("cfg")), Some(dir.join("prof")));
        d.ensure_dirs().unwrap();
        std::fs::write(
            d.profile_dir.join("warp.toml"),
            "[warp]\nports = [2408]\nseeds = []\nranges = []\nv6_ranges = []\nv6_seeds = []\n[masque]\nports = [443]\nseeds = []\nranges = []\nv6_ranges = []\nv6_seeds = []\n[defaults]\nscan_profile = \"balanced\"\n",
        )
        .unwrap();
        d
    }

    #[tokio::test]
    async fn handshake_scan_never_records_winner() {
        let d = test_dirs("handshake-no-promote");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { while let Ok((_, _)) = listener.accept().await {} });
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            format!("[discovery.warp]\nseeds = [\"{addr}\"]\n"),
        )
        .unwrap();
        let profile = qcore_core::scan::ScanProfile {
            name: "turbo".to_string(),
            concurrency: 8,
            rtt_budget_ms: 400,
            probe_kind: ProbeKind::Handshake,
            family_order: vec!["ipv4".to_string()],
            stealth: false,
        };
        let report = run_scan_request(&d, "warp", profile, "ipv4")
            .await
            .expect("scan runs");
        assert_eq!(report.ranked.len(), 1);
        assert_eq!(report.ranked[0].confidence, Confidence::Uncertain);
        assert!(
            cache::read_winners(&d).is_empty(),
            "uncertain must not enter winner cache"
        );
        assert!(
            qcore_core::session::reconnect::last_known_good(&d).is_none(),
            "uncertain must not become LKG"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[tokio::test]
    async fn bogus_output_is_usage() {
        let d = test_dirs("bogus-output");
        assert_eq!(
            run("warp", "balanced", "dual", "yaml", false, &d).await,
            exit::USAGE
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[tokio::test]
    async fn json_plus_ndjson_is_usage_single_document() {
        let d = test_dirs("json-ndjson");
        assert_eq!(
            run("warp", "balanced", "dual", "ndjson", true, &d).await,
            exit::USAGE
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[tokio::test]
    async fn bad_family_is_usage() {
        let d = test_dirs("bad-family");
        assert_eq!(
            run("warp", "balanced", "bogus", "table", false, &d).await,
            exit::USAGE
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }
}
