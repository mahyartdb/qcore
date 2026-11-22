//! Endpoint discovery types (data-model ScanProfile / EndpointCandidate).
//!
//! Full `Scanner::scan` implementation lands in US4 (T066); types live here so
//! the session reconnect sink (US1 T048) can consume candidates.
//!
//! Probe honesty (review wave C1): a transport declares what protocol its
//! *endpoint address* speaks via `HopFactory::endpoint_probe`
//! (`qcore_transport_api::EndpointProbe`, default `None`). Only a declared
//! contract opens endpoint sockets: `TcpEcho` runs the connect+nonce-echo
//! data-plane probe; `None` means the scanner has no valid assumption about
//! the endpoint's protocol, so the pipeline skips data-plane probing
//! entirely and reports candidates in the honest `uncertain` tier (never
//! `Verified`, never promoted to last-known-good; see `run_scan_request`).
//! The old derivation from `Capabilities::accepts_tcp_carrier` was wrong:
//! that is a nesting property (hop data plane rides TCP), not an endpoint
//! property — WireGuard declares a TCP carrier while its endpoints speak
//! UDP only, so probing them over TCP always failed (empty exit-4 scans
//! and winner-cache eviction of healthy endpoints). A `None`-contract
//! endpoint is verified by successful session bring-up instead. The winner
//! cache honors the same contract: a cached winner of a non-probeable
//! transport skips the fast path entirely (no probe attempt, no eviction —
//! `cache::verify_winner_first`); eviction on probe failure stays for
//! `TcpEcho` transports.
//!
//! `Scanner::scan` itself stays protocol-agnostic (it runs whatever sieve
//! its request asks for; loopback conformance doubles drive it directly);
//! the endpoint-contract gate lives in [`run_scan_request`], the shared
//! CLI/FFI pipeline.

use crate::registry::TransportRegistry;
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
///
/// `warnings` carries best-effort cache-IO skip notices (persist/evict
/// failures that never fail the scan). Core never writes CLI-framed stderr;
/// the CLI renders each as `qcore: {warning}` on stderr unless `--quiet`.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub transport: String,
    pub profile: String,
    pub family: String,
    pub ranked: Vec<EndpointCandidate>,
    pub failed: usize,
    pub elapsed_ms: u64,
    pub warnings: Vec<String>,
}

impl ScanReport {
    /// A report with `warnings` empty: every construction site starts clean
    /// and pushes only on an observed cache-IO skip.
    pub fn new(
        transport: String,
        profile: String,
        family: String,
        ranked: Vec<EndpointCandidate>,
        failed: usize,
        elapsed_ms: u64,
    ) -> Self {
        ScanReport {
            transport,
            profile,
            family,
            ranked,
            failed,
            elapsed_ms,
            warnings: Vec::new(),
        }
    }
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
        // Reuses the seeded-scan bound (512) as the scan-wide ceiling,
        // family-aware so a v4-heavy list cannot crowd IPv6 out entirely.
        let cands = cap_candidates(cands, seeds::MAX_SEEDED_CANDIDATES);
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
        Ok(ScanReport::new(
            req.transport,
            req.profile.name,
            req.family,
            ranked,
            failed,
            t0.elapsed().as_millis() as u64,
        ))
    }
}

/// Canonical scan family: exactly `ipv4`, `ipv6`, `dual`.
pub const SCAN_FAMILIES: &[&str] = &["ipv4", "ipv6", "dual"];

/// The endpoint-probe contract `transport` declares (review wave C1).
/// Unregistered kinds have no contract (`None`): fail closed, like every
/// other registry lookup in the scan path.
fn endpoint_probe_contract(transport: &str) -> qcore_transport_api::EndpointProbe {
    match TransportRegistry::global().factory(transport) {
        Some(f) => f.endpoint_probe(),
        None => qcore_transport_api::EndpointProbe::None,
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

/// Cap `candidates` at `cap` while keeping both address families
/// represented. `SocketAddr` orders every V4 before every V6, so a plain
/// sort+truncate lets a v4-heavy source starve a dual scan's IPv6 half to
/// zero. The IPv6 side is reserved up to half the cap; IPv4 fills the
/// remainder, and an IPv4 shortfall returns to IPv6. Input order is
/// preserved, so probe order and seed-before-range priority survive.
pub(crate) fn cap_candidates(candidates: Vec<SocketAddr>, cap: usize) -> Vec<SocketAddr> {
    if candidates.len() <= cap {
        return candidates;
    }
    let v4_len = candidates.iter().filter(|a| a.is_ipv4()).count();
    let v6_len = candidates.len() - v4_len;
    if v4_len == 0 || v6_len == 0 {
        return candidates.into_iter().take(cap).collect();
    }
    let v6_keep = v6_len.min(cap / 2);
    let v4_keep = v4_len.min(cap - v6_keep);
    let v6_keep = v6_len.min(cap - v4_keep);
    let (mut kept_v4, mut kept_v6) = (0usize, 0usize);
    candidates
        .into_iter()
        .filter(|a| {
            if a.is_ipv4() {
                if kept_v4 == v4_keep {
                    return false;
                }
                kept_v4 += 1;
            } else {
                if kept_v6 == v6_keep {
                    return false;
                }
                kept_v6 += 1;
            }
            true
        })
        .collect()
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
/// - Endpoint-probe contract first (review wave C1): only a transport whose
///   factory declares `EndpointProbe::TcpEcho` gets endpoint sockets probed;
///   any other transport (including the `warp` alias when unregistered, and
///   every undeclared real transport) yields the honest unverified tier —
///   candidates reported Uncertain without any probe socket, no cache
///   eviction, no legacy-LKG write — because a TCP refusal at an endpoint
///   whose protocol is undeclared proves nothing.
/// - Per-transport winner re-verify (fast path — full scan skipped while
///   the cached winner answers; skipped entirely for non-probeable kinds);
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
    let t0 = std::time::Instant::now();
    // Endpoint-probe contract (review wave C1): only a transport that
    // declares an endpoint protocol may have endpoint sockets opened. An
    // undeclared contract means no valid probe exists for those addresses —
    // probing them anyway (the old behavior, keyed off the nesting
    // capability `accepts_tcp_carrier`) reported honest-looking verdicts
    // that no real endpoint could ever pass.
    let probe_contract = endpoint_probe_contract(transport);
    let budget = std::time::Duration::from_millis(profile.rtt_budget_ms.clamp(1, 5000));
    if let Some((addr, latency_ms)) =
        cache::verify_winner_first(dirs, transport, family, budget).await
    {
        // Fast path: the recorded winner still answers. It was
        // traffic-verified when recorded; the re-verify confirms continued
        // reachability, so the Verified verdict stands without a rescan.
        return Ok(ScanReport::new(
            transport.to_string(),
            profile.name.clone(),
            family.to_string(),
            vec![EndpointCandidate {
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
            0,
            latency_ms,
        ));
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
    // The family filter runs BEFORE the cap: capping the merged dual list
    // family-blind would spend half the 512 budget on the unrequested family
    // (a `family=ipv4` scan over >512 dual candidates would probe at most
    // 256 v4 endpoints). Seeded candidates are already family-filtered at
    // their sources; re-filtering the merged list is idempotent and keeps
    // the seed-first priority (input order preserved by `cap_candidates`).
    let candidates: Vec<SocketAddr> = candidates
        .into_iter()
        .filter(|a| family_matches(family, *a))
        .collect();
    let candidates = cap_candidates(candidates, seeds::MAX_SEEDED_CANDIDATES);
    // No declared endpoint contract (review wave C1): the sieve has no
    // protocol it may speak to those endpoints, so nothing here may be
    // Verified and no socket may be opened. The honest outcome is the
    // unverified tier: every candidate reported as Uncertain with no
    // latency measurement (`latency_ms: 0`), zero probe sockets, zero
    // failures — and no cache mutation, because nothing was tested (a
    // connect-refusal at an endpoint whose protocol is undeclared proves
    // nothing, so winners and the legacy field keep their state). The
    // reachability field has no `Unknown` variant (CLI/FFI shape), so the
    // unverified tier reuses the handshake spelling: Passed + Uncertain
    // reads "listed, not traffic-validated". Such endpoints are verified by
    // successful session bring-up instead.
    if probe_contract != qcore_transport_api::EndpointProbe::TcpEcho {
        let ranked = candidates
            .into_iter()
            .map(|addr| EndpointCandidate {
                address: addr,
                family: family_of(addr),
                latency_ms: 0,
                reachability: Reachability::Passed,
                confidence: Confidence::Uncertain,
                last_known_good: false,
            })
            .collect();
        return Ok(ScanReport::new(
            transport.to_string(),
            profile.name,
            family.to_string(),
            ranked,
            0,
            t0.elapsed().as_millis() as u64,
        ));
    }
    let mut report = Scanner::scan(ScanRequest {
        transport: transport.to_string(),
        profile,
        family: family.to_string(),
        candidates,
    })
    .await?;
    if report.ranked.is_empty() {
        // F1: per-transport eviction — a dead transport must not wipe
        // siblings' winners. Cache IO stays best-effort (the sibling
        // `record_winner_async` below is too): the honest empty verdict is
        // the scan's result, and a read-only/full cache dir must not turn
        // exit 4 into a hard failure.
        if let Err(e) = evict_stale_lkg_async(dirs, transport, &report).await {
            report
                .warnings
                .push(format!("scan cache eviction skipped: {e}"));
        }
    } else {
        if let Err(e) = persist_verified_async(dirs, &report).await {
            report
                .warnings
                .push(format!("scan cache persist skipped: {e}"));
        }
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
/// The legacy top-level field serves wireguard-family readers (reconnect,
/// import materialize, discovery gate), so a non-wireguard-family scan's
/// verified endpoint is only reported, never written into it (review wave
/// C1: a masque address in the legacy field poisons every wireguard
/// reader). Blocking; async callers use [`persist_verified_async`].
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
    // whole-file rewrite wiped them on every scan). Legacy-field scoping:
    // only wireguard-family transports feed it.
    if cache::feeds_legacy_lkg(&report.transport) {
        cache::persist_last_known_good(dirs, top.address)?;
    }
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
    if cache::feeds_legacy_lkg(&report.transport) {
        cache::persist_last_known_good_async(dirs, top.address).await?;
    }
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
        ScanReport::new(
            transport.to_string(),
            "balanced".to_string(),
            family.to_string(),
            Vec::new(),
            1,
            0,
        )
    }

    /// F1: an empty warp scan evicts only warp — masque survives, and the
    /// file is deleted only when fully empty. Wave C1: the surviving masque
    /// winner does not feed the legacy field (the dead warp address is
    /// cleared from it — never silently reused, never replaced by a
    /// non-wireguard winner).
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
        assert_ne!(
            crate::session::reconnect::last_known_good(&d),
            Some("127.0.0.1:2408".parse().unwrap()),
            "legacy LKG never keeps the dead warp address"
        );
        assert!(
            !std::fs::read_to_string(d.endpoints_file())
                .unwrap()
                .contains("\"last_known_good\":\"127.0.0.1:443\""),
            "surviving masque winner never feeds the legacy field (wave C1)"
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

    /// FIX 1 (review wave C1): a non-probeable transport gets the honest
    /// unverified tier from the shared pipeline — candidates reported
    /// Uncertain without any probe socket, no eviction. A TCP echo listener
    /// is running at the seeded endpoint, yet it must not be probed, and
    /// nothing may reach Verified, because no real endpoint of this
    /// transport speaks the probe's language.
    #[tokio::test]
    async fn undeclared_endpoint_contract_scans_nothing_without_probing() {
        let d = evict_dirs("contract-none");
        // `wireguard` is a registered kind with no declared endpoint
        // contract (its endpoints are UDP): the pipeline must not open a
        // TCP socket at its endpoints even when one would answer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        std::fs::write(
            d.profile_dir.join("warp.toml"),
            format!(
                "[warp]\nranges = []\nseeds = [\"127.0.0.1\"]\nports = [{}]\nv6_ranges = []\nv6_seeds = []\n[masque]\nranges = []\nseeds = []\nports = [443]\nv6_ranges = []\nv6_seeds = []\n[defaults]\nscan_profile = \"balanced\"\n",
                echo.port()
            ),
        )
        .unwrap();
        // A stale wireguard winner: the skipped fast path must not evict it
        // (evicting here would destroy a healthy UDP endpoint on the
        // strength of a proof-less TCP refusal).
        cache::record_winner(&d, "wireguard", evict_winner("127.0.0.1:2408")).unwrap();
        let profile = load_profile(&d, "balanced").expect("profile loads");
        let report = run_scan_request(&d, "wireguard", profile, "dual")
            .await
            .expect("pipeline runs");
        // Two candidates: the seeded loopback echo + the legacy LKG seed
        // (both listed Uncertain without any probe).
        assert_eq!(report.ranked.len(), 2, "candidates are listed, not probed");
        assert!(
            report
                .ranked
                .iter()
                .all(|c| c.confidence == Confidence::Uncertain),
            "unverified tier: no candidate is Verified without a declared contract"
        );
        assert!(
            report.ranked.iter().all(|c| c.latency_ms == 0),
            "no probe, no measurement"
        );
        assert!(
            report.ranked.iter().all(|c| !c.last_known_good),
            "uncertain is never promoted"
        );
        assert_eq!(
            report.failed, 0,
            "zero probe sockets: nothing was attempted, nothing failed"
        );
        assert_eq!(
            cache::read_winners(&d)["wireguard"].address,
            "127.0.0.1:2408",
            "healthy winner survives a contract-less scan"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// Test-only transport declaring the `TcpEcho` endpoint contract, so the
    /// pipeline's contract gate can be exercised with a live echo endpoint
    /// inside the qcore-core unit-test binary (which links no real transport
    /// plugins — the registry here only sees test submissions like this one
    /// and registry.rs's). Mirrors registry.rs's registration pattern.
    struct EchoTestFactory;
    static ECHO_TEST_FACTORY: EchoTestFactory = EchoTestFactory;

    static ECHO_TEST_DESCRIPTOR: qcore_transport_api::TransportDescriptor =
        qcore_transport_api::TransportDescriptor {
            kind: "echo-test",
            capabilities: qcore_transport_api::Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: true,
            },
            obfuscation_families: &[],
            config_schema: "echo-test/v1",
            needs_sidecar: false,
        };

    #[async_trait::async_trait]
    impl qcore_transport_api::HopFactory for EchoTestFactory {
        fn descriptor(&self) -> &'static qcore_transport_api::TransportDescriptor {
            &ECHO_TEST_DESCRIPTOR
        }

        fn endpoint_probe(&self) -> qcore_transport_api::EndpointProbe {
            qcore_transport_api::EndpointProbe::TcpEcho
        }

        async fn build(
            &self,
            _cfg: qcore_transport_api::HopConfig,
            _carrier: std::sync::Arc<dyn qcore_transport_api::Dialer>,
        ) -> Result<
            std::sync::Arc<dyn qcore_transport_api::RunningHop>,
            qcore_transport_api::HopError,
        > {
            Err(qcore_transport_api::HopError::validation("test-only"))
        }
    }

    qcore_transport_api::register_plugin!(&ECHO_TEST_FACTORY);

    /// FIX 1 (review wave C1): the `TcpEcho` contract keeps the old
    /// honest-confidence tiers — a live echo endpoint Verifies (and wins the
    /// cache), a closed endpoint fails (probeable eviction applies).
    /// `echo-test` declares the contract; an undeclared transport behaves
    /// oppositely (see `undeclared_endpoint_contract_scans_nothing_without_probing`).
    #[tokio::test]
    async fn tcp_echo_contract_pipeline_verifies_and_caches() {
        let d = evict_dirs("contract-tcp-echo");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            format!(
                "{}\n[discovery.echo-test]\nseeds = [\"{echo}\"]\n",
                SHIPPED_SCAN_TOML
            ),
        )
        .unwrap();
        let profile = load_profile(&d, "balanced").expect("profile loads");
        let report = run_scan_request(&d, "echo-test", profile, "dual")
            .await
            .expect("pipeline runs");
        assert_eq!(report.ranked.len(), 1, "echo endpoint verified");
        assert_eq!(report.ranked[0].address, echo);
        assert_eq!(
            report.ranked[0].confidence,
            Confidence::Verified,
            "declared TcpEcho contract keeps the Verified tier"
        );
        assert_eq!(
            cache::read_winners(&d)["echo-test"].address,
            echo.to_string(),
            "verified winner cached under the echo-test key"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// FIX 2 (review wave C1): the pipeline's legacy LKG write is scoped to
    /// the wireguard family — a verified masque scan reports the winner but
    /// never overwrites the legacy field the wireguard readers consume.
    #[tokio::test]
    async fn masque_verified_scan_does_not_poison_legacy_lkg() {
        let d = evict_dirs("masque-lkg");
        cache::record_winner(&d, "warp", evict_winner("127.0.0.1:2408")).unwrap();
        let mut report = empty_report_family("masque", "dual");
        report
            .ranked
            .push(cand(10, Confidence::Verified, Reachability::Passed));
        let cached = persist_verified_async(&d, &report).await.expect("persist");
        assert!(cached.is_some(), "verified candidate reported");
        assert_eq!(
            cache::read_winners(&d)["warp"].address,
            "127.0.0.1:2408",
            "warp winner untouched"
        );
        let raw = std::fs::read_to_string(d.endpoints_file()).unwrap();
        assert!(
            !raw.contains("192.0.2.1"),
            "masque winner never enters the legacy field: {raw}"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    /// F3: a cache write failure must not discard an honest verified report
    /// (the CLI would map the `Err` to a failed exit, throwing the ranked
    /// list away). A file where the config dir belongs makes every cache
    /// write fail while the scan itself is healthy.
    #[tokio::test]
    async fn cache_write_failure_keeps_verified_report() {
        let base = std::env::temp_dir().join(format!("qcore-cache-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let prof = base.join("prof");
        std::fs::create_dir_all(&prof).expect("profile dir");
        let d =
            crate::config::profile_dir::ProfileDirs::resolve(Some(base.join("cfg")), Some(prof));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo");
        let echo = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            format!(
                "{}\n[discovery.echo-test]\nseeds = [\"{echo}\"]\n",
                SHIPPED_SCAN_TOML
            ),
        )
        .expect("scan.toml");
        // A file where the config dir belongs: `ensure_dirs` fails, so the
        // winner/LKG write fails after an otherwise successful scan.
        std::fs::write(base.join("cfg"), b"not a directory").expect("blocking file");
        let profile = load_profile(&d, "balanced").expect("profile loads");
        let report = run_scan_request(&d, "echo-test", profile, "ipv4")
            .await
            .expect("cache write failure must not discard the report");
        assert_eq!(report.ranked.len(), 1, "verified candidate kept");
        assert_eq!(report.ranked[0].address, echo);
        assert_eq!(report.ranked[0].confidence, Confidence::Verified);
        // Observability: the skip was attempted and actually failed — the
        // report carries the warning and no cache file was written.
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("scan cache persist skipped")),
            "persist skip is reported on the report: {:?}",
            report.warnings
        );
        assert!(
            !d.endpoints_file().exists(),
            "blocked cache dir: the write was attempted and failed, no endpoints.json exists"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// F3: a failed cache eviction must not discard the honest empty verdict
    /// (exit 4) either. An `endpoints.json` directory makes `remove_file`
    /// fail; the scan still returns its (empty) report.
    #[tokio::test]
    async fn cache_eviction_failure_keeps_empty_verdict() {
        let d = evict_dirs("evict-write-fail");
        std::fs::create_dir_all(d.endpoints_file()).expect("blocking dir");
        std::fs::write(
            d.profile_dir.join("scan.toml"),
            format!(
                "{}\n[discovery.echo-test]\nseeds = [\"127.0.0.1:1\"]\n",
                SHIPPED_SCAN_TOML
            ),
        )
        .expect("scan.toml");
        let profile = load_profile(&d, "balanced").expect("profile loads");
        let report = run_scan_request(&d, "echo-test", profile, "ipv4")
            .await
            .expect("cache eviction failure must not discard the empty verdict");
        assert!(report.ranked.is_empty(), "nothing reachable");
        assert_eq!(
            report.failed, 1,
            "the closed candidate was probed and failed"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("scan cache eviction skipped")),
            "eviction skip is reported on the report: {:?}",
            report.warnings
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

    /// The 512 budget must be spent inside the requested family: the merged
    /// candidate list is capped by `run_scan_request` BEFORE `Scanner::scan`
    /// applies the family filter, so with >512 dual candidates and
    /// `family=ipv4` the family-blind cap spends half the budget on the
    /// unrequested family — at most 256 of the 512 probed candidates are
    /// IPv4. The fix applies the filter to the merged list before capping;
    /// the observable is the unverified tier's `ranked` list (the capped
    /// merged list is reported verbatim for a non-probeable transport).
    #[tokio::test]
    async fn family_scoped_scan_spends_full_cap_inside_the_requested_family() {
        // `warp` declares no endpoint contract in the qcore-core test binary,
        // so the pipeline takes the honest unverified tier: `ranked` IS the
        // capped merged candidate list, address-level observable, zero probes.
        let d = evict_dirs("cap-after-filter");
        // warp.toml: 300 distinct IPv4 seeds x 2 ports = 600 v4 candidates.
        let mut warp_toml = String::from("[warp]\nports = [2408, 500]\nseeds = [");
        for i in 1..=300u32 {
            let ip = std::net::Ipv4Addr::new(198, 51, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8);
            warp_toml.push_str(&format!("\"{ip}\", "));
        }
        warp_toml.push_str("]\nranges = []\nv6_ranges = []\nv6_seeds = []\n");
        warp_toml.push_str("[masque]\nports = [443]\nseeds = []\nranges = []\nv6_ranges = []\nv6_seeds = []\n[defaults]\nscan_profile = \"balanced\"\n");
        std::fs::write(d.profile_dir.join("warp.toml"), warp_toml).unwrap();
        // scan.toml [discovery.warp]: 512 distinct IPv6 entries (at the
        // discovery gate's own 512 take) — merged list is ~1112 dual.
        let mut scan_toml = format!("{}\n[discovery.warp]\nseeds = [", SHIPPED_SCAN_TOML);
        for i in 1..=512u32 {
            scan_toml.push_str(&format!("\"[2001:db8::{i:x}]:443\", "));
        }
        scan_toml.push_str("]\n");
        std::fs::write(d.profile_dir.join("scan.toml"), scan_toml).unwrap();
        let profile = load_profile(&d, "balanced").expect("profile loads");
        let report = run_scan_request(&d, "warp", profile, "ipv4")
            .await
            .expect("scan runs");
        // Post-fix: the family filter runs before the cap, so the full 512
        // budget is spent on IPv4 candidates (600 available v4 seeds).
        let v4 = report.ranked.iter().filter(|c| c.family == "ipv4").count();
        let v6 = report.ranked.iter().filter(|c| c.family == "ipv6").count();
        assert_eq!(
            v4, 512,
            "the full 512 budget is spent on IPv4 (600 available), got {v4}"
        );
        assert_eq!(
            v6, 0,
            "no unrequested-family candidate consumes the ipv4 scan's budget"
        );
        // Seed-first priority: the first v4 seed (198.51.0.1 on both ports)
        // must survive the cap.
        assert!(
            report
                .ranked
                .iter()
                .any(|c| c.address.to_string() == "198.51.0.1:2408")
                && report
                    .ranked
                    .iter()
                    .any(|c| c.address.to_string() == "198.51.0.1:500"),
            "seed candidates are tried in full within the requested family"
        );
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }
}
