//! Endpoint discovery types (data-model ScanProfile / EndpointCandidate).
//!
//! Full `Scanner::scan` implementation lands in US4 (T066); types live here so
//! the session reconnect sink (US1 T048) can consume candidates.
//!
//! Probe honesty: the data-plane probe is a TCP connect+echo exchange, so
//! data-plane verification covers TCP-probeable transports only (a
//! transport whose descriptor sets `Capabilities::accepts_tcp_carrier` —
//! its endpoint terminates a TCP stream). Endpoints of transports that ride
//! UDP only can never pass a TCP probe; they are verified by successful
//! session bring-up instead. The winner cache honors this: a cached winner
//! of a non-TCP-probeable transport misses WITHOUT eviction on the fast-path
//! re-verify (`cache::verify_winner_first`), so a TCP refusal can never
//! destroy a healthy UDP winner. Eviction on probe failure stays for
//! TCP-probeable transports.

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
/// Overall scan deadline (SC-005): no scan outlives this, however many
/// candidates or however small the concurrency. Per-probe budgets still apply
/// inside; leftovers count as failed.
pub const MAX_SCAN_OVERALL_MS: u64 = 30_000;

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
/// else is an error. A present-but-unreadable override (permissions,
/// directory, transient IO) fails closed — only `NotFound` (absent file)
/// falls back to shipped data (mirrors `config::obfuscation::load_profiles`).
pub fn load_profile(
    dirs: &crate::config::profile_dir::ProfileDirs,
    name: &str,
) -> Result<ScanProfile, String> {
    let path = dirs.profile_dir.join("scan.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SHIPPED_SCAN_TOML.to_string(),
        Err(e) => return Err(format!("scan.toml: cannot read {}: {e}", path.display())),
    };
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
/// (data; empty by default — discovery providers plug in here). Capped at
/// `seeds::MAX_SEEDED_CANDIDATES` (F4): an adversarial profile dir must not
/// turn one scan into unbounded sockets.
///
/// Fail-closed like [`load_profile`]: a present-but-unreadable file or
/// invalid TOML errors (naming `scan.toml`); only a missing file falls back
/// to the shipped default (which carries no seeds → empty). A present
/// `seeds` list with non-socket entries errors naming the entry, so a
/// typo'd/garbage seed list cannot silently disable discovery.
pub fn discovery_seeds(
    dirs: &crate::config::profile_dir::ProfileDirs,
    transport: &str,
) -> Result<Vec<SocketAddr>, String> {
    let path = dirs.profile_dir.join("scan.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SHIPPED_SCAN_TOML.to_string(),
        Err(e) => return Err(format!("scan.toml: cannot read {}: {e}", path.display())),
    };
    let v: toml::Value = toml::from_str(&text).map_err(|e| format!("scan.toml invalid: {e}"))?;
    let Some(discovery) = v.get("discovery") else {
        return Ok(Vec::new());
    };
    let discovery = discovery
        .as_table()
        .ok_or_else(|| "scan.toml [discovery] must be a table".to_string())?;
    let Some(entry) = discovery.get(transport) else {
        return Ok(Vec::new());
    };
    let entry = entry
        .as_table()
        .ok_or_else(|| format!("scan.toml [discovery.{transport}] must be a table"))?;
    let Some(seeds) = entry.get("seeds") else {
        return Ok(Vec::new());
    };
    let seeds = seeds
        .as_array()
        .ok_or_else(|| format!("scan.toml [discovery.{transport}] `seeds` must be a list"))?;
    seeds
        .iter()
        .take(seeds::MAX_SEEDED_CANDIDATES)
        .map(|x| {
            let s = x.as_str().ok_or_else(|| {
                format!("scan.toml [discovery.{transport}] `seeds` entries must be strings")
            })?;
            s.parse::<SocketAddr>().map_err(|_| {
                format!(
                    "scan.toml [discovery.{transport}] `seeds` entry `{s}` is not a socket address"
                )
            })
        })
        .collect()
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
/// endpoints are counted and discarded, never reused. `family` is the
/// family the scan was scoped to (never `"dual"` after validation): cache
/// eviction decisions are family-aware because a family-scoped empty scan
/// must not destroy sibling-family winners it never probed.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub transport: String,
    pub profile: String,
    pub family: String,
    pub ranked: Vec<EndpointCandidate>,
    pub failed: usize,
    pub elapsed_ms: u64,
}

/// Scan failure: empty means nothing reachable (exit 4, never silent reuse).
/// `NonEmpty` reports a caller bug (asking for an error on a passing scan) —
/// it names the discrepancy instead of lying with `Empty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    Empty,
    NonEmpty,
}

impl ScanError {
    /// Honest classification of a report: only a verified-empty report is
    /// `Empty` (exit 4); anything else is a caller-contract violation
    /// (`NonEmpty`) — the error never ignores its input.
    pub fn for_report(report: &ScanReport) -> Self {
        if report.ranked.is_empty() {
            ScanError::Empty
        } else {
            ScanError::NonEmpty
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            ScanError::Empty => 4,
            ScanError::NonEmpty => 6,
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Empty => write!(f, "scan found nothing reachable (exit 4)"),
            ScanError::NonEmpty => {
                write!(f, "scan error requested for a non-empty report (exit 6)")
            }
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
        // F4: cap candidates — 10k inputs must not become 10k spawns.
        // Reuses the seeded-scan bound (512) as the scan-wide ceiling.
        cands.truncate(seeds::MAX_SEEDED_CANDIDATES);
        // F4: clamp defensively — ScanProfile fields are pub and directly
        // constructible, bypassing the TOML gate (u32::MAX permits would
        // otherwise mean unbounded in-flight sockets; 0 permits would hang).
        let limit = req.profile.concurrency.clamp(1, MAX_CONCURRENCY) as usize;
        let budget =
            std::time::Duration::from_millis(req.profile.rtt_budget_ms.clamp(1, MAX_RTT_BUDGET_MS));
        // F4: overall deadline — per-probe budgets bound each socket, this
        // bounds the scan. Batches * budget + slack, floored so tiny scans
        // are never starved, capped at SC-005's 30 s.
        let batches = cands.len().div_ceil(limit.max(1)) as u64;
        let overall_ms = (budget.as_millis() as u64)
            .saturating_mul(batches)
            .saturating_add(2_000)
            .clamp(5_000, MAX_SCAN_OVERALL_MS);
        let deadline = t0 + std::time::Duration::from_millis(overall_ms);
        let kind = req.profile.probe_kind;
        let stealth = req.profile.stealth;
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(limit));
        // Pre-sized (#15): one join per candidate, at most one pass each —
        // no reason to grow these incrementally on large seeded scans.
        // Post-truncate len <= 512, so spawns are bounded (F4).
        //
        // Stealth stagger lives inside the spawned tasks (`i * 50 ms`), not
        // as a serial pre-spawn sleep: the spawn loop itself never awaits,
        // so all probes are scheduled immediately and their staggers count
        // down concurrently; the semaphore still bounds in-flight sockets.
        // A serial pre-spawn sleep adds 50 ms per candidate (25 s at the
        // 512 cap) plus re-sleeps after every permit wait under contention,
        // pushing large stealth scans into the overall deadline.
        let mut joins = Vec::with_capacity(cands.len());
        for (i, addr) in cands.into_iter().enumerate() {
            let sem = sem.clone();
            joins.push(tokio::spawn(async move {
                if stealth {
                    let stagger_ms = (i as u64).saturating_mul(50);
                    tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;
                }
                let _permit = sem.acquire_owned().await.ok()?;
                probe(addr, kind, budget).await
            }));
        }
        // Drain under the overall deadline: expired remainder aborts and
        // counts as failed (never silently retried). `&mut` join keeps
        // ownership so the timeout branch can abort instead of detaching.
        let mut passed = Vec::with_capacity(joins.len());
        let mut failed = 0usize;
        for mut j in joins {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                j.abort();
                failed += 1;
                continue;
            }
            tokio::select! {
                res = &mut j => {
                    match res {
                        Ok(Some(c)) => passed.push(c),
                        _ => failed += 1,
                    }
                }
                _ = tokio::time::sleep(remaining) => {
                    j.abort();
                    failed += 1;
                }
            }
        }
        let ranked = rank(passed);
        Ok(ScanReport {
            transport: req.transport,
            profile: req.profile.name,
            family: req.family,
            ranked,
            failed,
            elapsed_ms: t0.elapsed().as_millis() as u64,
        })
    }
}

/// Canonical scan family: exactly `ipv4`, `ipv6`, `dual`.
pub const SCAN_FAMILIES: &[&str] = &["ipv4", "ipv6", "dual"];

fn family_of(addr: SocketAddr) -> String {
    if addr.is_ipv4() {
        "ipv4".to_string()
    } else {
        "ipv6".to_string()
    }
}

fn family_matches(family: &str, addr: SocketAddr) -> bool {
    if family == "dual" {
        return true;
    }
    match family {
        "ipv4" => addr.is_ipv4(),
        "ipv6" => addr.is_ipv6(),
        // Unknown strings filter everything (fail closed): callers validate
        // against SCAN_FAMILIES first, so reaching here means a caller
        // bypassed validation and the sieve must select nothing rather than
        // silently scan "everything" for a typo'd family.
        _ => false,
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

/// Shared scan-request pipeline (T6): winner fast-path, seed expansion,
/// verify, persist/evict — called by both CLI `scan` and FFI `qcore_scan`
/// so identical inputs give identical results and cache effects.
///
/// - Per-transport winner re-verify (fast path — full scan skipped while
///   the cached winner answers);
/// - else full scan over legacy LKG + warp.toml seeds + scan.toml
///   discovery seeds; winners cached per transport (and legacy LKG).
///
/// Verified winners are cached; a fully-failed scan evicts stale state
/// (family-aware: a family-scoped empty scan never evicts a sibling-family
/// winner it never probed). Profile loading stays with the caller via
/// [`load_profile`] (T3 owns the fallback semantics) — this takes an
/// already-loaded profile. `family` must be exactly one of
/// [`SCAN_FAMILIES`]; unknown values are rejected naming the field so a
/// typo'd family cannot silently scan "everything" (`family_matches` stays
/// fail-closed too, so both layers reject).
pub async fn run_scan_request(
    dirs: &crate::config::profile_dir::ProfileDirs,
    transport: &str,
    profile: ScanProfile,
    family: &str,
) -> Result<ScanReport, String> {
    if !SCAN_FAMILIES.contains(&family) {
        return Err(format!(
            "scan family `{family}` is unknown: family must be one of ipv4|ipv6|dual"
        ));
    }
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
            family: family.to_string(),
            ranked: vec![EndpointCandidate {
                address: addr,
                family: if addr.is_ipv4() {
                    "ipv4".to_string()
                } else {
                    "ipv6".to_string()
                },
                latency_ms,
                reachability: Reachability::Passed,
                confidence: Confidence::Verified,
                last_known_good: true,
            }],
            failed: 0,
            elapsed_ms: latency_ms,
        });
    }
    let mut candidates = Vec::new();
    if let Some(lkg) = crate::session::reconnect::last_known_good(dirs) {
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
    // rather than failing the scan — discovery seeds still run. A
    // present-but-broken override fails closed (naming warp.toml): silently
    // disabling warp seeding on a corrupt file is not "empty data", it is a
    // broken source (same fail-closed semantics as discovery_seeds below).
    let warp = seeds::load_warp_profiles(dirs)?;
    candidates.extend(seeds::candidates_for(&warp, transport, family));
    candidates.extend(discovery_seeds(dirs, transport)?);
    candidates.sort();
    candidates.dedup();
    // F4: scan-wide ceiling (reuses the seeded bound) — the scanner truncates
    // again defensively, this keeps the pre-scan sort/dedup bounded too.
    candidates.truncate(seeds::MAX_SEEDED_CANDIDATES);
    let report = Scanner::scan(ScanRequest {
        transport: transport.to_string(),
        profile,
        family: family.to_string(),
        candidates,
    })
    .await?;
    if report.ranked.is_empty() {
        // F1: per-transport eviction — a dead transport must not wipe
        // siblings' winners.
        evict_stale_lkg_async(dirs, transport, &report).await?;
    } else {
        persist_verified_async(dirs, &report).await?;
        if let Some(top) = report.ranked.iter().find(|c| {
            c.confidence == Confidence::Verified && c.reachability == Reachability::Passed
        }) {
            let _ = cache::record_winner_async(
                dirs,
                transport,
                cache::TransportWinner {
                    address: top.address.to_string(),
                    profile: report.profile.clone(),
                    verified_at_ms: crate::identity::model::now_ms(),
                    family: top.family.clone(),
                },
            )
            .await;
        }
    }
    Ok(report)
}

/// Persist the top verified candidate as last-known-good (FR-017). Returns
/// the cached address, or `None` when nothing verified exists — uncertain
/// results are never promoted. Reader half is the T048 reconnect sink.
/// Blocking; async callers use [`persist_verified_async`].
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

/// Async spelling of [`persist_verified`]: the locked RMW + fs write runs
/// on the blocking pool (never on the calling executor thread).
pub async fn persist_verified_async(
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
    cache::persist_last_known_good_async(dirs, top.address).await?;
    Ok(Some(top.address))
}

/// Drop a stale last-known-good after a scan that passed nothing (FR-016:
/// failed endpoints are discarded and not reused — no silent reuse).
/// Per-transport (F1): only `transport`'s winner is dropped; siblings survive.
/// Family-aware: a family-scoped empty scan never probed the sibling family
/// (`Scanner::scan` filters candidates and the winner fast-path misses
/// without probing on family mismatch), so a stored winner of a different
/// family is kept — only `"dual"` scans (which probe both families) may
/// evict across families. Blocking; async callers use
/// [`evict_stale_lkg_async`].
pub fn evict_stale_lkg(
    dirs: &crate::config::profile_dir::ProfileDirs,
    transport: &str,
    report: &ScanReport,
) -> Result<(), String> {
    if !report.ranked.is_empty() {
        return Ok(());
    }
    cache::evict_stale_transport(dirs, transport, &report.family)
}

/// Async spelling of [`evict_stale_lkg`]: the locked RMW + fs write runs on
/// the blocking pool (never on the calling executor thread).
pub async fn evict_stale_lkg_async(
    dirs: &crate::config::profile_dir::ProfileDirs,
    transport: &str,
    report: &ScanReport,
) -> Result<(), String> {
    if !report.ranked.is_empty() {
        return Ok(());
    }
    cache::evict_stale_transport_async(dirs, transport, &report.family).await
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

    fn evict_dirs(tag: &str) -> crate::config::profile_dir::ProfileDirs {
        let dir = std::env::temp_dir().join(format!("qcore-evict-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = crate::config::profile_dir::ProfileDirs::resolve(
            Some(dir.join("cfg")),
            Some(dir.join("prof")),
        );
        d.ensure_dirs().unwrap();
        d
    }

    fn evict_winner(addr: &str) -> cache::TransportWinner {
        cache::TransportWinner {
            address: addr.to_string(),
            profile: "balanced".to_string(),
            verified_at_ms: crate::identity::model::now_ms(),
            family: "ipv4".to_string(),
        }
    }

    fn empty_report(transport: &str) -> ScanReport {
        empty_report_family(transport, "dual")
    }

    fn empty_report_family(transport: &str, family: &str) -> ScanReport {
        ScanReport {
            transport: transport.to_string(),
            profile: "balanced".to_string(),
            family: family.to_string(),
            ranked: Vec::new(),
            failed: 1,
            elapsed_ms: 0,
        }
    }

    /// F1: an empty warp scan evicts only warp — masque survives with a live
    /// legacy LKG, and the file is deleted only when fully empty.
    #[test]
    fn evict_stale_lkg_is_per_transport() {
        let d = evict_dirs("per-transport");
        cache::record_winner(&d, "warp", evict_winner("127.0.0.1:2408")).unwrap();
        cache::record_winner(&d, "masque", evict_winner("127.0.0.1:443")).unwrap();
        evict_stale_lkg(&d, "warp", &empty_report("warp")).expect("evict runs");
        let map = cache::read_winners(&d);
        assert!(
            !map.contains_key("warp"),
            "empty transport evicted: {map:?}"
        );
        assert_eq!(
            map.get("masque").map(|w| w.address.as_str()),
            Some("127.0.0.1:443"),
            "sibling winner preserved: {map:?}"
        );
        assert!(
            d.endpoints_file().exists(),
            "file survives while a sibling winner remains"
        );
        assert_eq!(
            crate::session::reconnect::last_known_good(&d),
            Some("127.0.0.1:443".parse().unwrap()),
            "legacy LKG follows the surviving winner, never the dead one"
        );
        // Evicting the last transport clears the file (legacy-only stale
        // files included — no silent reuse).
        evict_stale_lkg(&d, "masque", &empty_report("masque")).expect("evict runs");
        assert!(cache::read_winners(&d).is_empty());
        assert_eq!(crate::session::reconnect::last_known_good(&d), None);
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// F1: a non-empty report never evicts, even for another transport.
    #[test]
    fn evict_stale_lkg_keeps_cache_on_success() {
        let d = evict_dirs("keeps-on-success");
        cache::record_winner(&d, "warp", evict_winner("127.0.0.1:2408")).unwrap();
        let mut report = empty_report("warp");
        report
            .ranked
            .push(cand(10, Confidence::Verified, Reachability::Passed));
        evict_stale_lkg(&d, "warp", &report).expect("evict runs");
        assert!(cache::read_winners(&d).contains_key("warp"));
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// F1: a family-scoped empty scan never evicts a sibling-family winner —
    /// the ipv4 winner was never probed by an `--family ipv6` scan (family
    /// filtering happens before probing), so its death is unproven.
    #[test]
    fn family_scoped_empty_scan_keeps_sibling_family_winner() {
        let d = evict_dirs("family-scoped");
        cache::record_winner(&d, "warp", evict_winner("127.0.0.1:2408")).unwrap();
        evict_stale_lkg(&d, "warp", &empty_report_family("warp", "ipv6")).expect("evict runs");
        let map = cache::read_winners(&d);
        assert_eq!(
            map.get("warp").map(|w| w.address.as_str()),
            Some("127.0.0.1:2408"),
            "ipv4 winner survives an empty ipv6-family scan: {map:?}"
        );
        // A dual-family scan probed both families: eviction applies.
        evict_stale_lkg(&d, "warp", &empty_report("warp")).expect("evict runs");
        assert!(
            !cache::read_winners(&d).contains_key("warp"),
            "dual scan evicts the probed winner"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// FIX 9: `for_report` is honest — an empty report is `Empty`, a
    /// non-empty report is never misclassified (the old impl ignored its
    /// argument and always returned `Empty`).
    #[test]
    fn for_report_is_honest_about_emptiness() {
        assert_eq!(
            ScanError::for_report(&empty_report("warp")),
            ScanError::Empty
        );
        let mut report = empty_report("warp");
        report
            .ranked
            .push(cand(10, Confidence::Verified, Reachability::Passed));
        assert_eq!(
            ScanError::for_report(&report),
            ScanError::NonEmpty,
            "non-empty report must not claim Empty"
        );
        assert_eq!(ScanError::Empty.exit_code(), 4);
        assert_eq!(ScanError::NonEmpty.exit_code(), 6);
    }

    /// F4: 10k candidates are capped at `MAX_SEEDED_CANDIDATES` (512) — not
    /// 10k spawns. Closed ports fail fast, so this stays quick.
    #[tokio::test]
    async fn scan_caps_ten_k_candidates() {
        let closed: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let profile = ScanProfile {
            name: "balanced".to_string(),
            concurrency: 32,
            rtt_budget_ms: 50,
            probe_kind: ProbeKind::Handshake,
            family_order: vec!["ipv4".to_string()],
            stealth: false,
        };
        let report = Scanner::scan(ScanRequest {
            transport: "warp".into(),
            profile,
            family: "ipv4".into(),
            candidates: vec![closed; 10_000],
        })
        .await
        .expect("scan runs");
        assert!(report.ranked.is_empty());
        assert_eq!(
            report.failed,
            seeds::MAX_SEEDED_CANDIDATES,
            "10k inputs capped to {} spawns, got {}",
            seeds::MAX_SEEDED_CANDIDATES,
            report.failed
        );
        assert!(
            report.elapsed_ms < MAX_SCAN_OVERALL_MS,
            "overall deadline holds: {} ms",
            report.elapsed_ms
        );
    }

    /// F4: a directly-constructed absurd concurrency (bypassing the TOML gate)
    /// is clamped to `MAX_CONCURRENCY`, never unbounded permits.
    #[tokio::test]
    async fn scan_clamps_absurd_concurrency() {
        let closed: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let profile = ScanProfile {
            name: "balanced".to_string(),
            concurrency: u32::MAX,
            rtt_budget_ms: 50,
            probe_kind: ProbeKind::Handshake,
            family_order: vec!["ipv4".to_string()],
            stealth: false,
        };
        let report = Scanner::scan(ScanRequest {
            transport: "warp".into(),
            profile,
            family: "ipv4".into(),
            candidates: vec![closed; 100],
        })
        .await
        .expect("scan runs");
        assert_eq!(report.failed, 100);
    }

    /// F4: `discovery_seeds` caps an adversarial `scan.toml` at the same bound.
    #[test]
    fn discovery_seeds_capped() {
        let d = evict_dirs("seeds-cap");
        let mut seeds = String::from("[discovery.warp]\nseeds = [");
        for i in 0..2000 {
            if i > 0 {
                seeds.push_str(", ");
            }
            seeds.push_str(&format!("\"127.0.0.1:{}\"", 1000 + (i % 50000)));
        }
        seeds.push_str("]\n");
        std::fs::write(d.profile_dir.join("scan.toml"), seeds).unwrap();
        let got = discovery_seeds(&d, "warp").expect("seeds load");
        assert!(
            got.len() <= seeds::MAX_SEEDED_CANDIDATES,
            "discovery capped to {}, got {}",
            seeds::MAX_SEEDED_CANDIDATES,
            got.len()
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// FIX 4: `family_matches` is fail-closed for unknown strings — the old
    /// wildcard (`_ => true`) made "ip4"/"IPv4" scan *everything*. `dual`
    /// still matches both families; validated callers never reach the
    /// unknown arm, and if one does, the sieve selects nothing.
    #[test]
    fn family_matches_fail_closed_on_unknown_strings() {
        let v4: std::net::SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let v6: std::net::SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert!(family_matches("dual", v4) && family_matches("dual", v6));
        assert!(family_matches("ipv4", v4) && !family_matches("ipv4", v6));
        assert!(family_matches("ipv6", v6) && !family_matches("ipv6", v4));
        for typo in ["ip4", "IPv4", "IPV6", "", "bogus"] {
            assert!(
                !family_matches(typo, v4) && !family_matches(typo, v6),
                "unknown family `{typo}` must filter, not match-all"
            );
        }
    }

    /// FIX 4: `run_scan_request` rejects unknown families naming the field,
    /// before any probe or cache mutation.
    #[tokio::test]
    async fn unknown_family_rejected_naming_field() {
        let d = evict_dirs("family-unknown");
        cache::record_winner(&d, "warp", evict_winner("127.0.0.1:2408")).unwrap();
        let profile = load_profile(&d, "balanced").expect("profile loads");
        for family in ["ip4", "IPv4", "bogus", ""] {
            let err = run_scan_request(&d, "warp", profile.clone(), family)
                .await
                .expect_err("unknown family rejected");
            assert!(
                err.contains("family") && err.contains("ipv4|ipv6|dual"),
                "error names the field: {err}"
            );
        }
        // Rejection happens before any cache mutation: the winner survives.
        assert!(
            cache::read_winners(&d).contains_key("warp"),
            "family validation precedes cache writes"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// FIX 3: a corrupt warp.toml override fails the scan closed (naming
    /// warp.toml) instead of silently disabling warp seeding — the old
    /// `if let Ok(warp)` swallow turned a broken source into "empty data".
    #[tokio::test]
    async fn corrupt_warp_override_fails_closed() {
        let d = evict_dirs("warp-corrupt");
        std::fs::write(d.profile_dir.join("warp.toml"), "[[[not toml").unwrap();
        let profile = load_profile(&d, "balanced").expect("profile loads");
        let err = run_scan_request(&d, "warp", profile, "dual")
            .await
            .expect_err("corrupt warp.toml fails closed");
        assert!(err.contains("warp.toml"), "error names warp.toml: {err}");
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// T3: `load_profile` fails closed on corrupt/unreadable overrides
    /// (naming `scan.toml`); only a missing file falls back to shipped data
    /// (mirrors `config::obfuscation` loader semantics).
    #[test]
    fn load_profile_fail_closed_only_not_found_falls_back() {
        // Absent file falls back to the shipped default.
        let d = evict_dirs("profile-missing");
        let b = load_profile(&d, "balanced").expect("missing falls back");
        assert_eq!(b.concurrency, 32);
        // Corrupt TOML fails closed naming the file.
        let d = evict_dirs("profile-corrupt");
        std::fs::write(d.profile_dir.join("scan.toml"), "[[[not toml").unwrap();
        let err = load_profile(&d, "balanced").unwrap_err();
        assert!(
            err.contains("scan.toml"),
            "corrupt override names the file: {err}"
        );
        // Present-but-unreadable (a directory at the file path) fails closed
        // instead of silently using shipped data.
        let d = evict_dirs("profile-unreadable");
        std::fs::create_dir_all(d.profile_dir.join("scan.toml")).unwrap();
        let err = load_profile(&d, "balanced").unwrap_err();
        assert!(
            err.contains("cannot read") && err.contains("scan.toml"),
            "unreadable override fails closed: {err}"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// T3: `discovery_seeds` is explicit — missing file (shipped default
    /// carries no seeds) is `Ok(empty)`, while corrupt/unreadable files and
    /// malformed `seeds` lists error naming the field, so an adversarial
    /// profile dir cannot silently disable discovery.
    #[test]
    fn discovery_seeds_fail_closed_only_not_found_falls_back() {
        // Missing file → shipped default → no seeds, still Ok.
        let d = evict_dirs("seeds-missing");
        assert!(discovery_seeds(&d, "warp")
            .expect("missing → empty")
            .is_empty());
        // Valid seeds parse.
        let d = evict_dirs("seeds-valid");
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            "[discovery.warp]\nseeds = [\"127.0.0.1:2408\"]\n",
        )
        .unwrap();
        let got = discovery_seeds(&d, "warp").expect("valid seeds load");
        assert_eq!(got, vec!["127.0.0.1:2408".parse().unwrap()]);
        // Corrupt TOML fails closed naming the file.
        let d = evict_dirs("seeds-corrupt");
        std::fs::write(d.profile_dir.join("scan.toml"), "[[[not toml").unwrap();
        let err = discovery_seeds(&d, "warp").unwrap_err();
        assert!(
            err.contains("scan.toml"),
            "corrupt file names scan.toml: {err}"
        );
        // Present-but-unreadable fails closed, no silent empty.
        let d = evict_dirs("seeds-unreadable");
        std::fs::create_dir_all(d.profile_dir.join("scan.toml")).unwrap();
        let err = discovery_seeds(&d, "warp").unwrap_err();
        assert!(
            err.contains("cannot read") && err.contains("scan.toml"),
            "unreadable file fails closed: {err}"
        );
        // A present `seeds` list with a garbage entry errors naming `seeds`
        // instead of silently dropping the entry (or the whole list).
        let d = evict_dirs("seeds-bad-entry");
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            "[discovery.warp]\nseeds = [\"127.0.0.1:2408\", \"not-an-addr\"]\n",
        )
        .unwrap();
        let err = discovery_seeds(&d, "warp").unwrap_err();
        assert!(err.contains("seeds"), "bad entry names the field: {err}");
        // `seeds` of the wrong shape errors too.
        let d = evict_dirs("seeds-not-a-list");
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            "[discovery.warp]\nseeds = \"127.0.0.1:2408\"\n",
        )
        .unwrap();
        let err = discovery_seeds(&d, "warp").unwrap_err();
        assert!(
            err.contains("seeds"),
            "non-list seeds names the field: {err}"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// T3: a 100-candidate stealth scan staggers inside the spawned tasks, so
    /// it completes well under the overall deadline. The stagger is
    /// preserved (elapsed reflects the ~5 s tail), just no longer serialized
    /// through the spawn loop.
    #[tokio::test]
    async fn stealth_hundred_candidates_fits_deadline() {
        let closed: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let profile = ScanProfile {
            name: "stealth".to_string(),
            concurrency: 8,
            rtt_budget_ms: 200,
            probe_kind: ProbeKind::Handshake,
            family_order: vec!["ipv4".to_string()],
            stealth: true,
        };
        let t0 = std::time::Instant::now();
        let report = Scanner::scan(ScanRequest {
            transport: "warp".into(),
            profile,
            family: "ipv4".into(),
            candidates: vec![closed; 100],
        })
        .await
        .expect("scan runs");
        assert_eq!(report.failed, 100);
        // Stagger preserved: the last task sleeps 99 * 50 ms before probing.
        assert!(
            report.elapsed_ms >= 4_500,
            "stealth stagger preserved, got {} ms",
            report.elapsed_ms
        );
        // …but the scan fits well inside the 30 s overall deadline.
        assert!(
            report.elapsed_ms < MAX_SCAN_OVERALL_MS,
            "overall deadline holds: {} ms",
            report.elapsed_ms
        );
        assert!(
            t0.elapsed().as_millis() < 20_000,
            "100-candidate stealth scan completes well under deadline"
        );
    }
}
