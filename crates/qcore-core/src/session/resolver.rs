//! Tunnel-routed DNS resolver (FR-013c realization).
//!
//! The SOCKS5 proxy accepts ATYP=domain targets. Resolving them through the
//! OS resolver would leak every visited domain name in plaintext to the
//! local network — on a censored network that alone exposes the user. This
//! module resolves through the tunnel's own data plane instead: a DNS query
//! is encoded by hand (RFC 1035, no new dependency), sent as a UDP datagram
//! through the exit hop's [`Dialer::dial_udp`] to a resolver address
//! reachable *inside* the tunnel (WARP exits can reach 1.1.1.1), and the
//! answer is decoded and cached. The domain name never touches the OS
//! resolver. Borrow-note: technique only — clean-room implementation in
//! qcore's own style.
//!
//! Family strategy (deliberately serial, not raced): single-stack modes
//! query exactly their family; `dual` queries A first (the default `prefer`)
//! and falls back to AAAA only on NODATA (rcode 0, no A record). A negative
//! answer (NXDOMAIN/ServFail) is terminal — retrying the other family
//! cannot fix a name the resolver does not know.
//!
//! Config: `EngineConfig::dns_resolver` (engine-owned, not a chain-grammar
//! field — the per-hop `dns=` plumb-through was disproportionate against
//! keeping the single `allowed_fields` table and chain-file schema
//! untouched). The engine builds a [`TunnelResolver`] when the exit hop's
//! dialer reports `dials_udp`; without it, domain targets keep refusing
//! (fail closed) exactly as before.

use super::net::{FamilyMode, FamilyPolicy};
use qcore_transport_api::{Dialer, HopError};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default resolver address for the warp/wireguard exit family: the WARP
/// resolver, reachable from inside the tunnel (documented provider fact).
pub const DEFAULT_DNS_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// Per-attempt timeout (a stub query is one round trip; 2 s is generous).
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// One retry for a silent/timing-out resolver, then give up.
const QUERY_ATTEMPTS: u32 = 2;
/// Hard ceiling on a resolve call (attempts + scheduling slack).
const RESOLVE_BUDGET: Duration = Duration::from_secs(5);
/// Cache entry lifetime (coarse session-scale TTL; per-record TTLs vary).
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Cache bound: insertion-order eviction (oldest out when full).
const CACHE_MAX: usize = 256;
/// UDP datagram budget for a response.
const DNS_BUF: usize = 4096;

/// QTYPE A (RFC 1035 §3.2.2).
const QTYPE_A: u16 = 1;
/// QTYPE AAAA (RFC 3596 §2.1).
const QTYPE_AAAA: u16 = 28;

/// Why a resolve failed. Every variant names the RFC fact that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverError {
    /// Caller-side input problem: label count/length limits, empty name.
    BadName(String),
    /// The response's ID did not match the query's (RFC 1035 §7.3).
    IdMismatch,
    /// The TC bit was set: the datagram answer was truncated (a stub retry
    /// would need TCP EDNS0 fallback; refuse rather than half-parse).
    Truncated,
    /// The RCODE field carried an error (NXDOMAIN, ServFail, ...).
    Rcode(&'static str),
    /// RCODE 0 but no record of the requested type (NODATA).
    NoAnswer,
    /// The query never completed inside the attempt timeout / budget.
    Timeout,
    /// The exit dialer could not produce a UDP flow (transport cannot UDP).
    NoUdpEgress(String),
    /// Datagram IO failed or the response was malformed.
    Io(String),
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolverError::BadName(m) => write!(f, "dns: bad name: {m}"),
            ResolverError::IdMismatch => write!(f, "dns: response ID does not match query ID"),
            ResolverError::Truncated => write!(f, "dns: response truncated (TC bit set)"),
            ResolverError::Rcode(name) => write!(f, "dns: resolver returned {name}"),
            ResolverError::NoAnswer => write!(f, "dns: no record of the requested type"),
            ResolverError::Timeout => write!(f, "dns: query timed out through the tunnel"),
            ResolverError::NoUdpEgress(m) => write!(f, "dns: no UDP egress via tunnel: {m}"),
            ResolverError::Io(m) => write!(f, "dns: {m}"),
        }
    }
}

impl std::error::Error for ResolverError {}

/// One cached address with its cache time.
#[derive(Debug, Clone)]
struct CacheEntry {
    addr: IpAddr,
    cached_at: Instant,
}

/// Session-scoped resolver: encodes A/AAAA queries, sends them through the
/// exit hop's UDP egress, and caches answers (bounded, TTL'd).
pub struct TunnelResolver {
    dialer: Arc<dyn Dialer>,
    server: SocketAddr,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Insertion order for bounded eviction (`HashMap` iteration order is
    /// unspecified, so the order is tracked separately).
    order: Mutex<Vec<String>>,
}

impl std::fmt::Debug for TunnelResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The dialer is a trait object: never Debug-print transport internals.
        f.debug_struct("TunnelResolver")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl TunnelResolver {
    pub fn new(dialer: Arc<dyn Dialer>, server: IpAddr) -> Self {
        TunnelResolver::with_server(dialer, SocketAddr::new(server, 53))
    }

    /// Explicit resolver endpoint (tests / non-standard resolver ports).
    pub fn with_server(dialer: Arc<dyn Dialer>, server: SocketAddr) -> Self {
        TunnelResolver {
            dialer,
            server,
            cache: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
        }
    }

    /// The upstream DNS endpoint this resolver queries. Read only by the
    /// watchdog swap-consistency test (that test lives in
    /// `session::watchdog`), so the lib build flags it dead unless
    /// silenced — deliberate, with the consumer named.
    #[allow(dead_code)]
    pub(crate) fn server(&self) -> SocketAddr {
        self.server
    }

    /// Resolve `host` to one address under the session's family policy:
    /// single-stack modes query their family only; `dual` prefers A and
    /// falls back to AAAA on NODATA. Results are cached 300 s, bounded at
    /// 256 entries with insertion-order eviction.
    pub async fn resolve(
        &self,
        host: &str,
        policy: &FamilyPolicy,
    ) -> Result<IpAddr, ResolverError> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(ResolverError::BadName("empty name".into()));
        }
        if host.len() > 253 {
            return Err(ResolverError::BadName(format!(
                "name longer than 253 octets ({} octets)",
                host.len()
            )));
        }
        let (first, fallback) = match policy.mode {
            FamilyMode::Ipv4 => (QTYPE_A, None),
            FamilyMode::Ipv6 => (QTYPE_AAAA, None),
            // The wildcard keeps exhaustiveness and defaults an unreachable
            // `dual` to the A-first behavior (same convention as
            // `FamilyPolicy::order`).
            _ => match policy.prefer {
                FamilyMode::Ipv6 => (QTYPE_AAAA, Some(QTYPE_A)),
                _ => (QTYPE_A, Some(QTYPE_AAAA)),
            },
        };
        if let Some(addr) = self.cache_hit(&host, policy.mode) {
            return Ok(addr);
        }
        let deadline = Instant::now() + RESOLVE_BUDGET;
        match self.query_with_retries(&host, first, deadline).await {
            // NODATA on the preferred family: try the other one (dual only).
            Err(ResolverError::NoAnswer) if fallback.is_some() => {
                let alt = fallback.expect("checked above");
                self.query_with_retries(&host, alt, deadline).await
            }
            other => other,
        }
        .inspect(|addr| self.cache_insert(host, *addr, Instant::now()))
    }

    /// A cached answer, when fresh and valid under the family mode.
    fn cache_hit(&self, host: &str, mode: FamilyMode) -> Option<IpAddr> {
        let now = Instant::now();
        let cache = self.cache.lock().ok()?;
        let e = cache.get(host)?;
        if now.duration_since(e.cached_at) >= CACHE_TTL {
            return None;
        }
        let ok = match mode {
            FamilyMode::Ipv4 => e.addr.is_ipv4(),
            FamilyMode::Ipv6 => e.addr.is_ipv6(),
            FamilyMode::Dual => true,
        };
        ok.then_some(e.addr)
    }

    fn cache_insert(&self, host: String, addr: IpAddr, now: Instant) {
        let mut cache = match self.cache.lock() {
            Ok(c) => c,
            // Poisoned cache: resolve keeps working uncached; the cache is
            // an optimization, never state.
            Err(_) => return,
        };
        // Refresh path: existing keys update in place (insertion order kept).
        if let std::collections::hash_map::Entry::Occupied(mut e) = cache.entry(host.clone()) {
            e.insert(CacheEntry {
                addr,
                cached_at: now,
            });
            return;
        }
        if cache.len() >= CACHE_MAX {
            let mut order = self.order.lock().unwrap_or_else(|e| e.into_inner());
            while cache.len() >= CACHE_MAX {
                if let Some(oldest) = order.first().cloned() {
                    order.remove(0);
                    cache.remove(&oldest);
                } else {
                    break;
                }
            }
        }
        cache.insert(
            host.clone(),
            CacheEntry {
                addr,
                cached_at: now,
            },
        );
        // Poisoned order tracker: treat like the cache-poison case (drop the
        // new entry rather than desyncing the two structures).
        if let Ok(mut order) = self.order.lock() {
            order.push(host);
        } else {
            cache.remove(&host);
        }
    }

    async fn query_with_retries(
        &self,
        host: &str,
        qtype: u16,
        deadline: Instant,
    ) -> Result<IpAddr, ResolverError> {
        let mut last_err = None;
        for _ in 0..QUERY_ATTEMPTS {
            if Instant::now() >= deadline {
                break;
            }
            match self.query_once(host, qtype, deadline).await {
                Ok(addr) => return Ok(addr),
                // A negative resolver answer (NXDOMAIN etc.) is terminal for
                // this name: retrying cannot change it. A capability refusal
                // (no UDP egress) must surface immediately for the SOCKS
                // 0x08 mapping, not burn the retry budget.
                Err(
                    e @ (ResolverError::Rcode(_)
                    | ResolverError::NoAnswer
                    | ResolverError::BadName(_)
                    | ResolverError::IdMismatch
                    | ResolverError::Truncated
                    | ResolverError::NoUdpEgress(_)),
                ) => return Err(e),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(ResolverError::Timeout))
    }

    async fn query_once(
        &self,
        host: &str,
        qtype: u16,
        deadline: Instant,
    ) -> Result<IpAddr, ResolverError> {
        let flow = self
            .dialer
            .dial_udp(self.server)
            .await
            .map_err(|e: HopError| ResolverError::NoUdpEgress(e.message))?;
        let mut id = [0u8; 2];
        getrandom::fill(&mut id)
            .map_err(|e| ResolverError::Io(format!("query ID randomness: {e}")))?;
        let q = encode_query(u16::from_be_bytes(id), host, qtype)?;
        flow.send_to(&q, self.server)
            .await
            .map_err(|e| ResolverError::Io(format!("send failed: {}", e.message)))?;
        let mut buf = vec![0u8; DNS_BUF];
        loop {
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(QUERY_TIMEOUT);
            if wait.is_zero() {
                return Err(ResolverError::Timeout);
            }
            let recv = tokio::time::timeout(wait, flow.recv_from(&mut buf)).await;
            let (n, _from) = match recv {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Err(ResolverError::Io(format!("recv failed: {}", e.message))),
                Err(_) => return Err(ResolverError::Timeout),
            };
            match parse_response(&q, &buf[..n], qtype) {
                // A mismatched ID may be a late reply to the previous
                // attempt: keep listening, never parse it.
                Err(ResolverError::IdMismatch) => continue,
                other => return other,
            }
        }
    }
}

/// Build one DNS query datagram: header (QD=1, RD=1), QNAME labels, then the
/// question. RFC 1035 §4.1.
fn encode_query(id: u16, host: &str, qtype: u16) -> Result<Vec<u8>, ResolverError> {
    let mut q = Vec::with_capacity(17 + host.len());
    q.extend_from_slice(&id.to_be_bytes());
    // Flags: RD (recursion desired) only — we are a stub, not a server.
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    let mut labels = 0usize;
    for label in host.split('.') {
        if label.is_empty() {
            return Err(ResolverError::BadName(format!(
                "empty label in `{host}` (doubled or leading dot)"
            )));
        }
        if label.len() > 63 {
            return Err(ResolverError::BadName(format!(
                "label longer than 63 octets in `{host}`"
            )));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
        labels += 1;
        if labels > 127 {
            return Err(ResolverError::BadName(format!(
                "more than 127 labels in `{host}`"
            )));
        }
    }
    q.push(0); // root label: end of QNAME
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    Ok(q)
}

/// Parse a response datagram: header sanity (ID, QR, TC, RCODE), skip the
/// question section, then scan answer records for the first one of the
/// requested type (CNAME chains are not followed: the first matching record
/// wins, matching what a stub needs).
fn parse_response(query: &[u8], buf: &[u8], qtype: u16) -> Result<IpAddr, ResolverError> {
    if buf.len() < 12 {
        return Err(ResolverError::Io(format!(
            "malformed response: {} octets is shorter than the 12-octet header",
            buf.len()
        )));
    }
    if buf[0..2] != query[0..2] {
        return Err(ResolverError::IdMismatch);
    }
    // QR=1 (a response), never TC (no TCP retry for a UDP stub here).
    if buf[2] & 0x80 == 0 {
        return Err(ResolverError::Io("not a response (QR bit clear)".into()));
    }
    if buf[2] & 0x02 != 0 {
        return Err(ResolverError::Truncated);
    }
    match buf[3] & 0x0F {
        0 => {}
        1 => return Err(ResolverError::Rcode("FormatErr")),
        2 => return Err(ResolverError::Rcode("ServFail")),
        3 => return Err(ResolverError::Rcode("NameError (NXDOMAIN)")),
        4 => return Err(ResolverError::Rcode("NotImp")),
        5 => return Err(ResolverError::Rcode("Refused")),
        r => return Err(ResolverError::Io(format!("reserved rcode {r}"))),
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut off = 12;
    for _ in 0..qdcount {
        off = skip_name(buf, off)?;
        if off + 4 > buf.len() {
            return Err(ResolverError::Io(
                "malformed response: QTYPE/QCLASS runs past the datagram".into(),
            ));
        }
        off += 4;
    }
    for _ in 0..ancount {
        off = skip_name(buf, off)?;
        if off + 10 > buf.len() {
            return Err(ResolverError::Io(
                "malformed response: RR fixed fields run past the datagram".into(),
            ));
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        if off + rdlen > buf.len() {
            return Err(ResolverError::Io(
                "malformed response: RDATA runs past the datagram".into(),
            ));
        }
        let rdata = &buf[off..off + rdlen];
        if rtype == qtype && rtype == QTYPE_A && rdlen == 4 {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )));
        }
        if rtype == qtype && rtype == QTYPE_AAAA && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            return Ok(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        off += rdlen;
    }
    Err(ResolverError::NoAnswer)
}

/// Skip one (possibly compressed) owner name; returns the offset after it —
/// in the ORIGINAL stream (a pointer consumes 2 bytes there, so the RR's
/// fixed fields begin right after it, never inside the jump target).
fn skip_name(buf: &[u8], mut cursor: usize) -> Result<usize, ResolverError> {
    let mut hops = 0usize;
    // Furthest offset consumed in the original stream: a pointer jump reads
    // earlier bytes, and parsing must resume after the pointer itself.
    let mut furthest = cursor;
    loop {
        if cursor >= buf.len() {
            return Err(ResolverError::Io(
                "malformed response: owner name runs past the datagram".into(),
            ));
        }
        match buf[cursor] {
            0 => {
                cursor += 1;
                furthest = furthest.max(cursor);
                return Ok(furthest);
            }
            n if n & 0xC0 == 0xC0 => {
                if cursor + 2 > buf.len() {
                    return Err(ResolverError::Io(
                        "malformed response: compression pointer runs past the datagram".into(),
                    ));
                }
                let target = (u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) & 0x3FFF) as usize;
                if target >= cursor {
                    return Err(ResolverError::Io(
                        "malformed response: compression pointer does not point backwards".into(),
                    ));
                }
                cursor += 2;
                furthest = furthest.max(cursor);
                cursor = target;
                hops += 1;
                if hops > 64 {
                    return Err(ResolverError::Io(
                        "malformed response: compression pointer loop".into(),
                    ));
                }
            }
            n => {
                cursor += 1 + n as usize;
                furthest = furthest.max(cursor);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_transport_api::{ByteStream, Capabilities, UdpFlow};

    fn policy(mode: FamilyMode) -> FamilyPolicy {
        FamilyPolicy {
            mode,
            ..FamilyPolicy::default()
        }
    }

    fn name_wire(host: &str) -> Vec<u8> {
        let mut w = Vec::new();
        for label in host.split('.') {
            w.push(label.len() as u8);
            w.extend_from_slice(label.as_bytes());
        }
        w.push(0);
        w
    }

    /// Build a well-formed response with one answer record.
    fn response(id: u16, qtype: u16, rcode: u8, answers: &[(u16, Vec<u8>)], tc: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.push(0x80); // QR=1
        b.push(rcode); // rcode (no TC unless asked)
        b[2] |= if tc { 0x02 } else { 0x00 };
        b.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        b.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        b.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        b.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        b.extend_from_slice(&name_wire("example.test"));
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&[0x00, 0x01]); // IN
        for (t, rdata) in answers {
            // Owner name as a compression pointer to the question name.
            b.extend_from_slice(&[0xC0, 0x0C]);
            b.extend_from_slice(&t.to_be_bytes());
            b.extend_from_slice(&[0x00, 0x01]); // IN
            b.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
            b.extend_from_slice(&[0x00, rdata.len() as u8]); // RDLENGTH (test rdata stays < 256)
            b.extend_from_slice(rdata);
        }
        b
    }

    #[test]
    fn query_encodes_rfc1035_shape() {
        let q = encode_query(0x1234, "example.test", QTYPE_A).expect("encodes");
        assert_eq!(&q[0..2], &[0x12, 0x34], "query ID");
        assert_eq!(&q[2..4], &[0x01, 0x00], "RD set, QR clear");
        assert_eq!(&q[4..6], &[0x00, 0x01], "one question");
        assert_eq!(
            &q[12..25],
            &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't'],
            "QNAME labels"
        );
        assert_eq!(&q[25], &0, "root label ends QNAME");
        assert_eq!(&q[26..28], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&q[28..30], &[0x00, 0x01], "QCLASS IN");
    }

    #[test]
    fn bad_names_fail_closed_naming_the_problem() {
        for (name, why) in [
            ("", "empty"),
            (".", "empty label"),
            ("a..b", "empty label"),
            ("a.", "trailing dot is trimmed, not an error"),
            (&format!("{}b", "a".repeat(253)), "253 octets"),
        ] {
            match (name, why) {
                ("a.", _) => {}
                (_, "empty") => {
                    let e = encode_query(1, name, QTYPE_A).unwrap_err();
                    assert!(matches!(e, ResolverError::BadName(_)), "{name}");
                }
                (_, "253 octets") => {
                    // >253 is rejected by resolve() before encoding; encode
                    // itself only rejects label-level faults.
                    let _ = name;
                }
                _ => {
                    let e = encode_query(1, name, QTYPE_A).unwrap_err();
                    assert!(
                        matches!(e, ResolverError::BadName(ref m) if m.contains("empty label")),
                        "{name}: {e}"
                    );
                }
            }
        }
        let long = format!("{}.test", "a".repeat(64));
        let e = encode_query(1, &long, QTYPE_A).unwrap_err();
        assert!(
            matches!(e, ResolverError::BadName(ref m) if m.contains("63 octets")),
            "long label: {e}"
        );
    }

    #[test]
    fn response_round_trip_parses_a_record() {
        let q = encode_query(0xBEEF, "example.test", QTYPE_A).expect("encodes");
        let r = response(
            0xBEEF,
            QTYPE_A,
            0,
            &[(QTYPE_A, vec![203, 0, 113, 9])],
            false,
        );
        let ip = parse_response(&q, &r, QTYPE_A).expect("parses");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    }

    #[test]
    fn response_round_trip_parses_aaaa_record() {
        let q = encode_query(0x0007, "example.test", QTYPE_AAAA).expect("encodes");
        let aaaa: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let r = response(0x0007, QTYPE_AAAA, 0, &[(QTYPE_AAAA, aaaa.to_vec())], false);
        let ip = parse_response(&q, &r, QTYPE_AAAA).expect("parses");
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::from(aaaa)));
    }

    #[test]
    fn compression_pointer_answer_parses_and_loops_are_caught() {
        // The `response` fixture already answers via a C0 0C pointer; verify
        // skip_name resolves it (the answer was found, not skipped past).
        let q = encode_query(9, "example.test", QTYPE_A).unwrap();
        let r = response(9, QTYPE_A, 0, &[(QTYPE_A, vec![192, 0, 2, 1])], false);
        assert!(
            parse_response(&q, &r, QTYPE_A).is_ok(),
            "pointer owner parses"
        );
        // Forward/self-pointing pointer in the answer owner: rejected, never
        // looped (the owner sits at offset 30 in this fixture; pointing it at
        // itself must trip the backwards check).
        let mut evil = response(9, QTYPE_A, 0, &[(QTYPE_A, vec![192, 0, 2, 1])], false);
        let owner = evil.len() - 16;
        assert_eq!(owner, 30, "fixture shape: answer owner at 30");
        evil[owner] = 0xC0;
        evil[owner + 1] = owner as u8; // pointer target = the owner itself
        let e = parse_response(&q, &evil, QTYPE_A).unwrap_err();
        assert!(
            matches!(e, ResolverError::Io(ref m) if m.contains("backwards")),
            "self-pointer rejected: {e}"
        );
    }

    #[test]
    fn nxdomain_and_servfail_map_to_rcode_errors() {
        let q = encode_query(3, "missing.test", QTYPE_A).unwrap();
        for (rcode, want) in [(3u8, "NameError (NXDOMAIN)"), (2, "ServFail")] {
            let r = response(3, QTYPE_A, rcode, &[], false);
            let e = parse_response(&q, &r, QTYPE_A).unwrap_err();
            assert!(
                matches!(e, ResolverError::Rcode(name) if name == want),
                "rcode {rcode}: {e}"
            );
        }
    }

    #[test]
    fn mismatched_id_is_an_error_never_parsed() {
        let q = encode_query(1, "example.test", QTYPE_A).unwrap();
        let r = response(2, QTYPE_A, 0, &[(QTYPE_A, vec![192, 0, 2, 1])], false);
        let e = parse_response(&q, &r, QTYPE_A).unwrap_err();
        assert!(matches!(e, ResolverError::IdMismatch), "{e}");
    }

    #[test]
    fn truncated_response_is_rejected() {
        let q = encode_query(4, "example.test", QTYPE_A).unwrap();
        let r = response(4, QTYPE_A, 0, &[(QTYPE_A, vec![192, 0, 2, 1])], true);
        let e = parse_response(&q, &r, QTYPE_A).unwrap_err();
        assert!(matches!(e, ResolverError::Truncated), "{e}");
    }

    #[test]
    fn answers_of_other_types_are_skipped() {
        // A CNAME before the A record: the A still wins.
        let q = encode_query(5, "example.test", QTYPE_A).unwrap();
        let cname = vec![0xC0, 0x0C]; // RDATA = pointer (owner) — shape only
        let r = response(
            5,
            QTYPE_A,
            0,
            &[(5, cname), (QTYPE_A, vec![198, 51, 100, 7])],
            false,
        );
        let ip = parse_response(&q, &r, QTYPE_A).expect("parses");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
    }

    #[test]
    fn wrong_rdata_length_is_not_an_answer() {
        let q = encode_query(6, "example.test", QTYPE_A).unwrap();
        let r = response(6, QTYPE_A, 0, &[(QTYPE_A, vec![1, 2, 3])], false);
        let e = parse_response(&q, &r, QTYPE_A).unwrap_err();
        assert!(matches!(e, ResolverError::NoAnswer), "3-byte A: {e}");
    }

    /// Test dialer: UDP dials land on a real OS socket (the fake DNS server
    /// listens there); TCP dials reach loopback targets directly.
    struct TestDialer;

    #[async_trait::async_trait]
    impl Dialer for TestDialer {
        async fn dial_tcp(&self, dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            let s = tokio::net::TcpStream::connect(dst)
                .await
                .map_err(HopError::from)?;
            Ok(Box::new(super::super::net::TcpByteStream::new(s)))
        }

        async fn dial_udp(&self, dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            // Infallible unspecified bind (never parse constant literals).
            let bind = qcore_transport_api::unspecified_bind(&dst);
            let socket = tokio::net::UdpSocket::bind(bind)
                .await
                .map_err(HopError::from)?;
            socket.connect(dst).await.map_err(HopError::from)?;
            Ok(Box::new(super::super::net::SocketUdpFlow::new(socket)))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: true,
            }
        }
    }

    /// Test dialer whose UDP egress is a capability refusal.
    struct NoUdpDialer;

    #[async_trait::async_trait]
    impl Dialer for NoUdpDialer {
        async fn dial_tcp(&self, _dst: SocketAddr) -> Result<Box<dyn ByteStream>, HopError> {
            Err(HopError::transport("test", "tcp only"))
        }

        async fn dial_udp(&self, _dst: SocketAddr) -> Result<Box<dyn UdpFlow>, HopError> {
            Err(HopError::transport("test", "transport cannot dial UDP"))
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities {
                accepts_tcp_carrier: true,
                accepts_udp_carrier: true,
                dials_tcp: true,
                dials_udp: false,
            }
        }
    }

    /// Spawn a fake DNS server on a loopback UDP port: answers A questions
    /// for `name` with `answer`; behavior hooks drive the negative tests.
    /// The handle carries only the endpoint + query counter (tuning lives in
    /// the server task's closure).
    struct FakeDns {
        addr: SocketAddr,
        /// Track that queries arrive (assertion aid).
        received: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl FakeDns {
        async fn spawn(name: &'static str, answer: IpAddr) -> Self {
            Self::spawn_with(name, answer, |_, _| {}).await
        }

        async fn spawn_with(
            name: &'static str,
            answer: IpAddr,
            tune: impl FnOnce(&str, &mut FakeDnsTuning),
        ) -> Self {
            let mut t = FakeDnsTuning::default();
            tune(name, &mut t);
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let received = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let recv = received.clone();
            let name = name.to_string();
            let fixed_answer = answer;
            tokio::spawn(async move {
                let mut buf = vec![0u8; DNS_BUF];
                loop {
                    let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                        break;
                    };
                    recv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if t.silent {
                        continue;
                    }
                    let Some(reply) = fake_answer(&buf[..n], &name, fixed_answer, &t) else {
                        continue;
                    };
                    let _ = socket.send_to(&reply, from).await;
                }
            });
            // Yield once so the server task is polling before the first query
            // goes out (a query answered before the spawn loop wakes would be
            // lost by the OS only if the socket did not exist yet — it does —
            // but this keeps the `received` counter deterministic).
            tokio::task::yield_now().await;
            FakeDns { addr, received }
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct FakeDnsTuning {
        silent: bool,
        truncate: bool,
        wrong_id: bool,
        rcode: u8,
    }

    /// Build the canned reply for a query (None = do not answer).
    fn fake_answer(query: &[u8], name: &str, answer: IpAddr, t: &FakeDnsTuning) -> Option<Vec<u8>> {
        if query.len() < 17 {
            return None;
        }
        let id = u16::from_be_bytes([query[0], query[1]]);
        let reply_id = if t.wrong_id { id.wrapping_add(1) } else { id };
        let qname = &query[12..];
        let host = parse_qname(qname)?;
        if host != name {
            // Name the server does not know: NXDOMAIN.
            return Some(build_reply(id, 3, name, None, &FakeDnsTuning::default()));
        }
        Some(build_reply(reply_id, t.rcode, name, Some(answer), t))
    }

    /// Parse the question name back out of a query datagram.
    fn parse_qname(mut q: &[u8]) -> Option<String> {
        let mut labels = Vec::new();
        loop {
            let len = *q.first()?;
            if len == 0 {
                break;
            }
            if len & 0xC0 != 0 {
                return None;
            }
            let label = q.get(1..1 + len as usize)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            q = &q[1 + len as usize..];
        }
        Some(labels.join("."))
    }

    fn build_reply(
        id: u16,
        rcode: u8,
        name: &str,
        answer: Option<IpAddr>,
        t: &FakeDnsTuning,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        // Byte 2: QR + TC (opcode/AA zero); byte 3: RCODE (RA/Z zero).
        b.push(0x80 | if t.truncate { 0x02 } else { 0x00 });
        b.push(rcode & 0x0F);
        b.extend_from_slice(&[0x00, 0x01]);
        let answers = usize::from(answer.is_some());
        b.extend_from_slice(&(answers as u16).to_be_bytes());
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        b.extend_from_slice(&name_wire(name));
        b.extend_from_slice(&QTYPE_A.to_be_bytes());
        b.extend_from_slice(&[0x00, 0x01]);
        if let Some(ip) = answer {
            b.extend_from_slice(&[0xC0, 0x0C]);
            b.extend_from_slice(&QTYPE_A.to_be_bytes());
            b.extend_from_slice(&[0x00, 0x01]);
            b.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
            b.extend_from_slice(&[0x00, 0x04]); // RDLENGTH: 4-byte A
            match ip {
                IpAddr::V4(v4) => b.extend_from_slice(&v4.octets()),
                IpAddr::V6(_) => unreachable!("fake server answers v4 only"),
            }
        }
        b
    }

    #[tokio::test]
    async fn resolve_returns_the_canned_answer_through_udp() {
        let server =
            FakeDns::spawn("example.internal", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let ip = resolver
            .resolve("example.internal", &policy(FamilyMode::Dual))
            .await
            .expect("resolves through the dialer");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(
            server.received.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the fake server saw the query"
        );
    }

    #[tokio::test]
    async fn resolve_caches_within_ttl() {
        let server =
            FakeDns::spawn("cached.test", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))).await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let pol = policy(FamilyMode::Dual);
        let first = resolver.resolve("cached.test", &pol).await.expect("first");
        let second = resolver
            .resolve("cached.test", &pol)
            .await
            .expect("second (cached)");
        assert_eq!(first, second);
        assert_eq!(
            server.received.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "second resolve served from the cache, not the wire"
        );
    }

    #[tokio::test]
    async fn nxdomain_surfaces_as_rcode_error() {
        let server = FakeDns::spawn("known.test", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let e = resolver
            .resolve("unknown.test", &policy(FamilyMode::Dual))
            .await
            .expect_err("NXDOMAIN is terminal");
        assert!(
            matches!(e, ResolverError::Rcode(name) if name.contains("NXDOMAIN")),
            "{e}"
        );
    }

    #[tokio::test]
    async fn silent_server_times_out_inside_the_budget() {
        let server = FakeDns::spawn_with("quiet.test", IpAddr::V4(Ipv4Addr::LOCALHOST), |_, t| {
            t.silent = true;
        })
        .await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let e = resolver
            .resolve("quiet.test", &policy(FamilyMode::Dual))
            .await
            .expect_err("silent server times out");
        assert!(matches!(e, ResolverError::Timeout), "{e}");
    }

    #[tokio::test]
    async fn wrong_id_never_satisfies_the_query() {
        let server =
            FakeDns::spawn_with("mismatch.test", IpAddr::V4(Ipv4Addr::LOCALHOST), |_, t| {
                t.wrong_id = true;
            })
            .await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let e = resolver
            .resolve("mismatch.test", &policy(FamilyMode::Dual))
            .await
            .expect_err("mismatched ID is not an answer");
        assert!(
            matches!(e, ResolverError::Timeout),
            "waits out the budget: {e}"
        );
    }

    #[tokio::test]
    async fn truncated_reply_is_terminal() {
        let server = FakeDns::spawn_with("big.test", IpAddr::V4(Ipv4Addr::LOCALHOST), |_, t| {
            t.truncate = true;
        })
        .await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let e = resolver
            .resolve("big.test", &policy(FamilyMode::Dual))
            .await
            .expect_err("TC reply refuses");
        assert!(matches!(e, ResolverError::Truncated), "{e}");
    }

    #[tokio::test]
    async fn no_udp_egress_refuses_with_capability_error() {
        // No server at all: the dialer must refuse before any datagram.
        let server = FakeDns::spawn("never.test", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let resolver = TunnelResolver::with_server(Arc::new(NoUdpDialer), server.addr);
        let e = resolver
            .resolve("never.test", &policy(FamilyMode::Dual))
            .await
            .expect_err("no UDP egress");
        assert!(
            matches!(e, ResolverError::NoUdpEgress(ref m) if m.contains("cannot dial UDP")),
            "{e}"
        );
    }

    #[tokio::test]
    async fn single_stack_modes_query_only_their_family() {
        // An ipv6-mode resolver must not accept a cached/wire v4 answer. The
        // fake server only answers A with v4: an ipv6-mode resolve cannot
        // get that answer — it must end in NoAnswer (AAAA question, no AAAA
        // in the reply), never the v4 literal.
        let server = FakeDns::spawn("v4only.test", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))).await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let e = resolver
            .resolve("v4only.test", &policy(FamilyMode::Ipv6))
            .await
            .expect_err("ipv6 mode cannot take the v4 answer");
        assert!(matches!(e, ResolverError::NoAnswer), "{e}");
        // And ipv4 mode gets it through the same wire.
        let ip = resolver
            .resolve("v4only.test", &policy(FamilyMode::Ipv4))
            .await
            .expect("ipv4 mode takes the A answer");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
    }

    #[tokio::test]
    async fn cache_respects_family_mode() {
        let server =
            FakeDns::spawn("famcache.test", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33))).await;
        let resolver = TunnelResolver::with_server(Arc::new(TestDialer), server.addr);
        let ip = resolver
            .resolve("famcache.test", &policy(FamilyMode::Dual))
            .await
            .expect("dual caches the v4");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33)));
        // Same name, ipv6 mode: the fresh v4 cache entry is not valid there
        // and the AAAA question finds no AAAA record.
        let e = resolver
            .resolve("famcache.test", &policy(FamilyMode::Ipv6))
            .await
            .expect_err("ipv6 mode never takes the cached v4");
        assert!(matches!(e, ResolverError::NoAnswer), "{e}");
    }

    #[test]
    fn oversized_names_fail_before_any_query() {
        let long = format!("{}.test", "a".repeat(300));
        let server_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let resolver = TunnelResolver::new(Arc::new(NoUdpDialer), server_addr);
        // No runtime needed: the name is rejected before any await/IO.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let e = rt
            .block_on(resolver.resolve(&long, &policy(FamilyMode::Dual)))
            .unwrap_err();
        assert!(
            matches!(e, ResolverError::BadName(ref m) if m.contains("253")),
            "{e}"
        );
    }
}
