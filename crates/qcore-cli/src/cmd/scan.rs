//! `scan` (US4 T068): discover and traffic-validate endpoints per
//! transport+family (FR-014–017). Ranked latency+verdict output as
//! table|json|ndjson; empty scans are exit 4 with no silent reuse.
//! Verified results are cached as last-known-good, feeding the T048
//! reconnect sink.

use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::scan::{load_profile, ScanReport};

use crate::exit;

/// Load a profile by name (default `balanced`) from the profile dir.
pub fn profile_named(
    dirs: &ProfileDirs,
    name: &str,
) -> Result<qcore_core::scan::ScanProfile, String> {
    load_profile(dirs, name)
}

/// Run one scan (002 FR-006/007/008/014): shared core pipeline so CLI and
/// FFI populate/use the winner cache identically on same inputs.
pub async fn run_scan_request(
    dirs: &ProfileDirs,
    transport: &str,
    profile: qcore_core::scan::ScanProfile,
    family: &str,
) -> Result<ScanReport, String> {
    qcore_core::scan::run_scan_request(dirs, transport, profile, family).await
}

pub async fn run(
    transport: &str,
    profile: &str,
    family: &str,
    output: &str,
    json: bool,
    dirs: &ProfileDirs,
) -> i32 {
    // Transport must name a linked registry kind: a typo (`warrp`) would
    // otherwise produce a seeded-empty scan and exit 4 "nothing reachable",
    // which reads like a network verdict instead of the usage mistake it
    // is. `warp` is accepted beside `wireguard` (it is the established
    // scan/cache alias for the wireguard section of warp.toml).
    if let Err(e) = validate_transport(transport) {
        eprintln!("qcore: {e} (exit 6)");
        return exit::USAGE;
    }
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

/// Validate a scan transport against the linked registry kinds. `warp` is
/// the accepted alias for `wireguard` (warp.toml section + winner-cache key
/// all use it); everything else must be a registered kind. The error names
/// the valid kinds so the usage error is actionable.
pub fn validate_transport(transport: &str) -> Result<(), String> {
    if transport == "warp" {
        return Ok(());
    }
    let mut kinds = qcore_transports::linked_kinds();
    kinds.sort_unstable();
    if kinds.contains(&transport) {
        return Ok(());
    }
    Err(format!(
        "unknown transport `{transport}` (valid: {} or `warp` for wireguard)",
        kinds.join(", ")
    ))
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
    use qcore_core::scan::{cache, Confidence, ProbeKind};

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

    #[test]
    fn unknown_transport_is_usage_not_empty_scan() {
        // A typo must be a usage error naming valid kinds, never a seeded
        // empty scan that reports "nothing reachable" (exit 4).
        let _ = qcore_transports::linked_kinds();
        let err = validate_transport("warrp").unwrap_err();
        assert!(
            err.starts_with("unknown transport `warrp` (valid: "),
            "{err}"
        );
        assert!(err.contains("wireguard"), "error names wireguard: {err}");
        assert!(err.contains("`warp` for wireguard"), "{err}");
        assert!(validate_transport("").is_err());
    }

    #[test]
    fn linked_kinds_and_warp_alias_validate() {
        let _ = qcore_transports::linked_kinds();
        for kind in qcore_transports::linked_kinds() {
            assert!(validate_transport(kind).is_ok(), "registry kind `{kind}`");
        }
        assert!(validate_transport("warp").is_ok(), "warp alias");
    }

    #[tokio::test]
    async fn typo_transport_is_usage() {
        let d = test_dirs("typo-transport");
        assert_eq!(
            run("warrp", "balanced", "dual", "table", false, &d).await,
            exit::USAGE
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }
}
