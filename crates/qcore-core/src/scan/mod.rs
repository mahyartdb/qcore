//! Endpoint discovery types (data-model ScanProfile / EndpointCandidate).
//!
//! Full `Scanner::scan` implementation lands in US4 (T066); types live here so
//! the session reconnect sink (US1 T048) can consume candidates.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub mod cache;
pub mod seeds;

/// Upper bound for profile `concurrency`: discovery caps at 512 candidates
/// (`seeds::MAX_SEEDED_CANDIDATES`), so more permits buy no parallelism —
/// only in-flight sockets. 8x the shipped max (64).
pub const MAX_CONCURRENCY: u32 = 512;
/// Upper bound for profile `rtt_budget_ms`: 40x the shipped max (1500 ms),
/// 12x the CLI fast-path cap (5000 ms). A per-probe minute is the absurdity
/// ceiling, not a tuning choice.
pub const MAX_RTT_BUDGET_MS: u64 = 60_000;

/// Scan profile (data-model). Exactly `turbo`, `balanced` (default), `stealth`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub concurrency: u32,
    pub rtt_budget_ms: u64,
    pub probe_kind: ProbeKind,
    pub family_order: Vec<String>,
    pub stealth: bool,
}

/// Handshake-only vs data-plane validated probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeKind {
    Handshake,
    DataPlane,
}

/// Reachability verdict: data-traffic validated or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reachability {
    Passed,
    Failed,
}

/// Confidence: handshake-only results are `uncertain` and MUST NOT be promoted
/// to last-known-good (constitution Confidence reporting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Verified,
    Uncertain,
}

/// A discovered endpoint candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCandidate {
    pub address: SocketAddr,
    pub family: String,
    pub latency_ms: u64,
    pub reachability: Reachability,
    pub confidence: Confidence,
    /// Set only for `verified` candidates (FR-017).
    pub last_known_good: bool,
}

impl EndpointCandidate {
    /// Rank: verified+passed first, then by latency. Failed endpoints sort last
    /// and are discarded by the caller, never reused.
    pub fn rank_key(&self) -> (u8, u64) {
        let tier = match (self.confidence, self.reachability) {
            (Confidence::Verified, Reachability::Passed) => 0,
            (Confidence::Uncertain, Reachability::Passed) => 1,
            (_, Reachability::Failed) => 2,
        };
        (tier, self.latency_ms)
    }
}

/// Pure ranking helper shared by the scanner and tests.
pub fn rank(mut candidates: Vec<EndpointCandidate>) -> Vec<EndpointCandidate> {
    candidates.sort_by_key(|c| c.rank_key());
    candidates
}

/// Shipped `profiles/scan.toml` (US4 T067): profile-dir overrides replace it
/// wholesale per FR-028.
pub const SHIPPED_SCAN_TOML: &str = include_str!("../../../../profiles/scan.toml");

/// Load a named profile: profile-dir `scan.toml` override when present, else
/// the shipped data. Exactly `turbo`, `balanced`, `stealth` exist; anything
/// else is an error.
pub fn load_profile(
    dirs: &crate::config::profile_dir::ProfileDirs,
    name: &str,
) -> Result<ScanProfile, String> {
    let path = dirs.profile_dir.join("scan.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| SHIPPED_SCAN_TOML.to_string());
    parse_scan_toml(&text, name)
}

fn parse_scan_toml(text: &str, name: &str) -> Result<ScanProfile, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("scan.toml invalid: {e}"))?;
    let t = v
        .get(name)
        .and_then(|x| x.as_table())
        .ok_or_else(|| format!("unknown scan profile `{name}` (turbo|balanced|stealth)"))?;
    let get = |k: &str| {
        t.get(k)
            .ok_or_else(|| format!("scan profile `{name}` missing `{k}`"))
    };
    let probe_kind = match get("probe_kind")?.as_str() {
        Some("handshake") => ProbeKind::Handshake,
        Some("data-plane") => ProbeKind::DataPlane,
        Some(other) => {
            return Err(format!(
                "scan profile `{name}` probe_kind `{other}` (handshake|data-plane)"
            ))
        }
        None => return Err(format!("scan profile `{name}` probe_kind must be a string")),
    };
    let family_order = get("family_order")?
        .as_array()
        .ok_or_else(|| format!("scan profile `{name}` family_order must be a list"))?
        .iter()
        .map(|x| {
            x.as_str().map(str::to_string).ok_or_else(|| {
                format!("scan profile `{name}` family_order entries must be strings")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Bounds are validated here, not just clamped downstream: a negative
    // TOML integer would wrap on cast (unbounded scan budget / unbounded
    // semaphore permits), and a huge one would truncate (`as u32` wraps) or
    // hang (292M-year budget). Fail closed naming the field. Scanner::scan
    // additionally floors defensively: ScanProfile fields are pub and
    // directly constructible, bypassing this gate.
    let raw_concurrency = get("concurrency")?
        .as_integer()
        .ok_or_else(|| format!("scan profile `{name}` concurrency must be an integer"))?;
    if raw_concurrency < 1 {
        return Err(format!("scan profile `{name}` concurrency must be >= 1"));
    }
    if raw_concurrency > MAX_CONCURRENCY as i64 {
        return Err(format!(
            "scan profile `{name}` concurrency must be <= {MAX_CONCURRENCY}"
        ));
    }
    // Infallible after the bounds above; try_from (never `as`) documents it.
    let concurrency = u32::try_from(raw_concurrency)
        .map_err(|_| format!("scan profile `{name}` concurrency must be >= 1"))?;
    let raw_budget = get("rtt_budget_ms")?
        .as_integer()
        .ok_or_else(|| format!("scan profile `{name}` rtt_budget_ms must be an integer"))?;
    if raw_budget < 1 {
        return Err(format!("scan profile `{name}` rtt_budget_ms must be >= 1"));
    }
    if raw_budget > MAX_RTT_BUDGET_MS as i64 {
        return Err(format!(
            "scan profile `{name}` rtt_budget_ms must be <= {MAX_RTT_BUDGET_MS}"
        ));
    }
    let rtt_budget_ms = u64::try_from(raw_budget)
        .map_err(|_| format!("scan profile `{name}` rtt_budget_ms must be >= 1"))?;
    Ok(ScanProfile {
        name: name.to_string(),
        concurrency,
        rtt_budget_ms,
        probe_kind,
        family_order,
        stealth: get("stealth")?
            .as_bool()
            .ok_or_else(|| format!("scan profile `{name}` stealth must be a bool"))?,
    })
}

/// Discovery seeds for a transport from `scan.toml [discovery.<transport>]`
/// (data; empty by default — discovery providers plug in here).
pub fn discovery_seeds(
    dirs: &crate::config::profile_dir::ProfileDirs,
    transport: &str,
) -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string(dirs.profile_dir.join("scan.toml")) else {
        return Vec::new();
    };
    let Ok(v) = toml::from_str::<toml::Value>(&text) else {
        return Vec::new();
    };
    v.get("discovery")
        .and_then(|d| d.get(transport))
        .and_then(|t| t.get("seeds"))
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str()?.parse::<SocketAddr>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// One scan invocation: transport + profile + family + candidates.
/// Endpoints are property of transport+family, not chain (T068).
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub transport: String,
    pub profile: ScanProfile,
    pub family: String,
    pub candidates: Vec<SocketAddr>,
}

/// Ranked scan outcome: `ranked` holds passed candidates best-first; failed
/// endpoints are counted and discarded, never reused.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub transport: String,
    pub profile: String,
    pub ranked: Vec<EndpointCandidate>,
    pub failed: usize,
    pub elapsed_ms: u64,
}

/// Scan failure: empty means nothing reachable (exit 4, never silent reuse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    Empty,
}

impl ScanError {
    pub fn for_report(report: &ScanReport) -> Self {
        let _ = report;
        ScanError::Empty
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            ScanError::Empty => 4,
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Empty => write!(f, "scan found nothing reachable (exit 4)"),
        }
    }
}

/// The scanner: bounded-parallel TCP sieve with latency measurement (T066).
/// Candidates above `rtt_budget_ms` are discarded. Family filtering follows
/// `family`; probe order follows the profile `family_order`.
///
///   - `handshake` probes: TCP connect within budget → passed/uncertain.
///     Uncertain results are never promoted to last-known-good.
///   - `data-plane` probes: connect + nonce echo exchange within budget →
///     passed/verified. Anything less (refused/timeout/mismatch) is failed,
///     discarded, and never reused.
pub struct Scanner;

impl Scanner {
    pub async fn scan(req: ScanRequest) -> Result<ScanReport, String> {
        let t0 = std::time::Instant::now();
        let mut cands: Vec<SocketAddr> = req
            .candidates
            .into_iter()
            .filter(|a| family_matches(&req.family, *a))
            .collect();
        // Probe order follows family_order; unknown families last.
        cands.sort_by_key(|a| {
            req.profile
                .family_order
                .iter()
                .position(|f| *f == family_of(*a))
                .unwrap_or(usize::MAX)
        });
        let limit = req.profile.concurrency.max(1) as usize;
        let budget = std::time::Duration::from_millis(req.profile.rtt_budget_ms.max(1));
        let kind = req.profile.probe_kind;
        let stealth_gap = req.profile.stealth;
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(limit));
        // Pre-sized (#15): one join per candidate, at most one pass each —
        // no reason to grow these incrementally on large seeded scans.
        let mut joins = Vec::with_capacity(cands.len());
        for addr in cands {
            if stealth_gap {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| e.to_string())?;
            joins.push(tokio::spawn(async move {
                let _permit = permit;
                probe(addr, kind, budget).await
            }));
        }
        let mut passed = Vec::with_capacity(joins.len());
        let mut failed = 0usize;
        for j in joins {
            match j.await {
                Ok(Some(c)) => passed.push(c),
                _ => failed += 1,
            }
        }
        let ranked = rank(passed);
        Ok(ScanReport {
            transport: req.transport,
            profile: req.profile.name,
            ranked,
            failed,
            elapsed_ms: t0.elapsed().as_millis() as u64,
        })
    }
}

fn family_of(addr: SocketAddr) -> String {
    if addr.is_ipv4() {
        "ipv4".to_string()
    } else {
        "ipv6".to_string()
    }
}

fn family_matches(family: &str, addr: SocketAddr) -> bool {
    match family {
        "ipv4" => addr.is_ipv4(),
        "ipv6" => addr.is_ipv6(),
        _ => true,
    }
}

async fn probe(
    addr: SocketAddr,
    kind: ProbeKind,
    budget: std::time::Duration,
) -> Option<EndpointCandidate> {
    let t0 = std::time::Instant::now();
    let stream = tokio::time::timeout(budget, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    match kind {
        ProbeKind::Handshake => Some(EndpointCandidate {
            address: addr,
            family: family_of(addr),
            latency_ms: t0.elapsed().as_millis() as u64,
            reachability: Reachability::Passed,
            confidence: Confidence::Uncertain,
            last_known_good: false,
        }),
        ProbeKind::DataPlane => {
            let nonce: [u8; 8] = rand8();
            let mut stream = stream;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let remaining = budget.saturating_sub(t0.elapsed());
            let ok = tokio::time::timeout(remaining, async {
                stream.write_all(&nonce).await?;
                let mut back = [0u8; 8];
                stream.read_exact(&mut back).await?;
                if back == nonce {
                    Ok::<(), std::io::Error>(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "echo mismatch",
                    ))
                }
            })
            .await
            .ok()?
            .is_ok();
            if !ok {
                return None;
            }
            Some(EndpointCandidate {
                address: addr,
                family: family_of(addr),
                latency_ms: t0.elapsed().as_millis() as u64,
                reachability: Reachability::Passed,
                confidence: Confidence::Verified,
                last_known_good: true,
            })
        }
    }
}

fn rand8() -> [u8; 8] {
    // Cheap nonce: time + pid folded; unpredictability is not load-bearing
    // (it only pairs a probe with its echo).
    let t = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut out = [0u8; 8];
    let mut x = t ^ ((std::process::id() as u128) << 32);
    for b in out.iter_mut() {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *b = (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
    }
    out
}

/// Persist the top verified candidate as last-known-good (FR-017). Returns
/// the cached address, or `None` when nothing verified exists — uncertain
/// results are never promoted. Reader half is the T048 reconnect sink.
pub fn persist_verified(
    dirs: &crate::config::profile_dir::ProfileDirs,
    report: &ScanReport,
) -> Result<Option<SocketAddr>, String> {
    let top = report
        .ranked
        .iter()
        .find(|c| c.confidence == Confidence::Verified && c.reachability == Reachability::Passed);
    let Some(top) = top else {
        return Ok(None);
    };
    dirs.ensure_dirs().map_err(|e| e.to_string())?;
    // Locked RMW in `cache` (preserves sibling transports' winners — the old
    // whole-file rewrite wiped them on every scan).
    cache::persist_last_known_good(dirs, top.address)?;
    Ok(Some(top.address))
}

/// Drop a stale last-known-good after a scan that passed nothing (FR-016:
/// failed endpoints are discarded and not reused — no silent reuse).
pub fn evict_stale_lkg(
    dirs: &crate::config::profile_dir::ProfileDirs,
    report: &ScanReport,
) -> Result<(), String> {
    if !report.ranked.is_empty() {
        return Ok(());
    }
    let path = dirs.endpoints_file();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(latency: u64, conf: Confidence, reach: Reachability) -> EndpointCandidate {
        EndpointCandidate {
            address: "192.0.2.1:51820".parse().unwrap(),
            family: "ipv4".into(),
            latency_ms: latency,
            reachability: reach,
            confidence: conf,
            last_known_good: conf == Confidence::Verified && reach == Reachability::Passed,
        }
    }

    #[test]
    fn verified_passed_sorts_before_uncertain_and_failed() {
        let out = rank(vec![
            cand(10, Confidence::Uncertain, Reachability::Passed),
            cand(5, Confidence::Verified, Reachability::Failed),
            cand(50, Confidence::Verified, Reachability::Passed),
        ]);
        assert_eq!(out[0].latency_ms, 50);
        assert_eq!(out[1].latency_ms, 10);
        assert_eq!(out[2].latency_ms, 5);
    }

    #[test]
    fn last_known_good_only_for_verified() {
        assert!(cand(1, Confidence::Verified, Reachability::Passed).last_known_good);
        assert!(!cand(1, Confidence::Uncertain, Reachability::Passed).last_known_good);
    }

    #[test]
    fn negative_profile_bounds_rejected() {
        // Negative TOML integers would wrap to u64::MAX on cast
        // (unbounded budget / unbounded permits): fail closed instead.
        let base = |concurrency: &str, rtt: &str| {
            format!(
                "[p]\nconcurrency = {concurrency}\nrtt_budget_ms = {rtt}\nprobe_kind = \"handshake\"\nfamily_order = [\"ipv4\"]\nstealth = false\n"
            )
        };
        let err = parse_scan_toml(&base("-4", "500"), "p").unwrap_err();
        assert!(
            err.contains("concurrency") && err.contains(">= 1"),
            "got: {err}"
        );
        let err = parse_scan_toml(&base("4", "-1"), "p").unwrap_err();
        assert!(
            err.contains("rtt_budget_ms") && err.contains(">= 1"),
            "got: {err}"
        );
    }

    #[test]
    fn absurd_profile_bounds_rejected() {
        let base = |concurrency: &str, rtt: &str| {
            format!(
                "[p]\nconcurrency = {concurrency}\nrtt_budget_ms = {rtt}\nprobe_kind = \"handshake\"\nfamily_order = [\"ipv4\"]\nstealth = false\n"
            )
        };
        // 2^32 would truncate to 0 semaphore permits (hang) on a lossy cast.
        let err = parse_scan_toml(&base("4294967296", "500"), "p").unwrap_err();
        assert!(
            err.contains("concurrency") && err.contains("512"),
            "got: {err}"
        );
        // A ~292M-year per-probe budget is never a tuning choice.
        let err = parse_scan_toml(&base("4", "60001"), "p").unwrap_err();
        assert!(
            err.contains("rtt_budget_ms") && err.contains("60000"),
            "got: {err}"
        );
        // Boundary values still parse (inclusive).
        let ok = parse_scan_toml(&base("512", "60000"), "p").expect("bounds inclusive");
        assert_eq!(ok.concurrency, 512);
        assert_eq!(ok.rtt_budget_ms, 60_000);
    }
}
