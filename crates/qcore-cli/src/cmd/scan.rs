//! `scan` (US4 T068): discover and traffic-validate endpoints per
//! transport+family (FR-014–017). Ranked latency+verdict output as
//! table|json|ndjson; empty scans are exit 4 with no silent reuse.
//! Verified results are cached as last-known-good, feeding the T048
//! reconnect sink.

use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::scan::{
    discovery_seeds, evict_stale_lkg, load_profile, persist_verified, ScanReport, ScanRequest,
    Scanner,
};

use crate::exit;

/// Load a profile by name (default `balanced`) from the profile dir.
pub fn profile_named(
    dirs: &ProfileDirs,
    name: &str,
) -> Result<qcore_core::scan::ScanProfile, String> {
    load_profile(dirs, name)
}

/// Run one scan: LKG (family-matching) first, then discovery seeds.
/// Verified winners are cached; a fully-failed scan evicts stale LKG.
pub async fn run_scan_request(
    dirs: &ProfileDirs,
    transport: &str,
    profile: qcore_core::scan::ScanProfile,
    family: &str,
) -> Result<ScanReport, String> {
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
    candidates.extend(discovery_seeds(dirs, transport));
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
    let output = if json && output == "table" {
        "json"
    } else {
        output
    };
    let profile = match profile_named(dirs, profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("qcore: {e}");
            return exit::USAGE;
        }
    };
    if !["ipv4", "ipv6", "dual"].contains(&family) {
        eprintln!("qcore: --family must be ipv4|ipv6|dual");
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
