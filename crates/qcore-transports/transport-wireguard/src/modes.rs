//! Peer-mode resolution: WARP, imported, AmneziaWG (FR-004, FR-009).
//!
//! - `peer=warp`: Cloudflare WARP peer; endpoint + keys from fields (identity
//!   registration in a later milestone; loopback/tests pass explicit keys).
//! - `peer=imported`: user-imported config via `import_ref` (US2 import store).
//! - `peer=awg`: AmneziaWG mode against a supporting peer (US2 modes + US5
//!   obfuscation decorator).

use crate::WgParams;
use qcore_transport_api::HopConfig;
use std::net::SocketAddr;
use std::time::Duration;

/// Timeout for the DNS resolution of a hostname endpoint (fails closed; same
/// policy as transport-masque's `ENDPOINT_RESOLVE_TIMEOUT`).
const ENDPOINT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse `xx:xx:...:xx` hex into 32 bytes.
pub fn parse_key_hex(s: &str) -> Result<[u8; 32], String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("key must be 64 hex chars".to_string());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Endpoint address family policy (`family=dual|ipv4|ipv6`). Unknown values
/// fail closed naming the field: a typo (`v4`, `IPv6`, `any`) must not be
/// silently treated as `dual` — that silently connects over the stack the
/// operator ruled out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Dual,
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "dual" => Ok(Family::Dual),
            "ipv4" => Ok(Family::Ipv4),
            "ipv6" => Ok(Family::Ipv6),
            other => Err(format!("bad `family` value `{other}` (dual|ipv4|ipv6)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Family::Dual => "dual",
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }

    fn accepts(self, addr: &SocketAddr) -> bool {
        match self {
            Family::Dual => true,
            Family::Ipv4 => addr.is_ipv4(),
            Family::Ipv6 => addr.is_ipv6(),
        }
    }
}

/// Resolve `host:port` where host is an IP literal, `[v6]`, or DNS name into
/// **every** address the name has (a literal is a one-element list). Callers
/// try the addresses in order: "localhost" resolves to both `::1` and
/// `127.0.0.1` and which one comes first is platform-ordered, so returning
/// only the first silently broke one stack (masque fixed the same bug).
/// `family` filters resolved addresses; a filter that leaves nothing fails
/// closed naming the field. IP literals parse synchronously (their family is
/// the operator's explicit choice); names go through the async resolver with
/// a bounded timeout. Standard `.conf` files routinely carry hostnames —
/// failing them at build with `bad endpoint` after import accepted them was
/// late and confusing.
pub async fn resolve_endpoint(hostport: &str, family: Family) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = hostport.parse::<SocketAddr>() {
        if addr.port() == 0 {
            return Err("bad endpoint: port `0` is not connectable".to_string());
        }
        // The literal arm returns before any filtering: explicit `ipv4` with
        // a v6 literal (or the reverse) must fail closed naming the field,
        // not silently connect over the stack the operator ruled out.
        if !family.accepts(&addr) {
            return Err(format!(
                "bad endpoint: no {} address for `{hostport}` (family={})",
                family.as_str(),
                family.as_str()
            ));
        }
        return Ok(vec![addr]);
    }
    // Bracketed v6 that failed to parse above is malformed, not a name.
    if hostport.starts_with('[') {
        return Err(format!("bad endpoint: `{hostport}` is not `[ipv6]:port`"));
    }
    // Unbracketed multi-colon input is ambiguous (see import `check_endpoint`
    // which rejects it there too): do not guess.
    let (host, port_str) = hostport
        .rsplit_once(':')
        .ok_or_else(|| format!("bad endpoint: `{hostport}` is not host:port"))?;
    if host.is_empty() || host.contains(':') {
        return Err(format!("bad endpoint: `{hostport}` is not host:port"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("bad endpoint: port `{port_str}` is not numeric"))?;
    if port == 0 {
        return Err("bad endpoint: port `0` is not connectable".to_string());
    }
    let mut addrs = bounded_lookup(host, ENDPOINT_RESOLVE_TIMEOUT, async {
        tokio::net::lookup_host((host, port))
            .await
            .map(|addrs| addrs.collect::<Vec<SocketAddr>>())
    })
    .await?;
    addrs.retain(|a| family.accepts(a));
    if addrs.is_empty() {
        return Err(format!(
            "bad endpoint: no {} address for `{host}` (family={})",
            family.as_str(),
            family.as_str()
        ));
    }
    Ok(addrs)
}

/// Resolve through `lookup`, bounded by `budget`. A resolver that never
/// answers must fail closed with the field-named error rather than park the
/// build forever (the seam also makes the guard testable: the system resolver
/// cannot be made to hang on demand).
async fn bounded_lookup<F>(
    host: &str,
    budget: Duration,
    lookup: F,
) -> Result<Vec<SocketAddr>, String>
where
    F: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    let lookup = tokio::time::timeout(budget, lookup)
        .await
        .map_err(|_| format!("bad endpoint: resolve `{host}` timed out"))?;
    lookup.map_err(|e| format!("bad endpoint: resolve `{host}`: {e}"))
}

/// Resolve factory fields into peer parameters. Async because a hostname
/// `endpoint` goes through the resolver here; literals never await.
pub async fn resolve(cfg: &HopConfig) -> Result<WgParams, String> {
    let peer = cfg.get("peer").unwrap_or("warp");
    match peer {
        "warp" | "imported" | "awg" => {
            // FR-021: server-negotiated AWG params only against a supporting
            // peer — never on plain wireguard/WARP.
            if peer != "awg" {
                if let Some(k) = cfg.fields.keys().find(|k| k.starts_with("awg_")) {
                    return Err(format!(
                        "field `{k}` is AmneziaWG-only and needs `peer=awg` (supporting peer required)"
                    ));
                }
            }
            resolve_fields(cfg, peer).await
        }
        other => Err(format!(
            "unknown wireguard peer mode `{other}` (warp|imported|awg)"
        )),
    }
}

async fn resolve_fields(cfg: &HopConfig, peer: &str) -> Result<WgParams, String> {
    let has_import = cfg
        .get("import")
        .or_else(|| cfg.get("import_ref"))
        .is_some();
    if peer == "imported" && !has_import {
        return Err("peer=imported requires import=<ref> (see `qcore import`)".to_string());
    }
    // Import-backed hops get endpoint/keys merged by the engine (US2 import
    // store); without merged material the hop cannot build.
    if (peer == "imported" || peer == "awg") && has_import {
        let missing = ["endpoint", "private_key", "peer_public_key"]
            .iter()
            .find(|k| cfg.get(k).is_none());
        if let Some(k) = missing {
            return Err(format!(
                "peer={peer} import has no `{k}` merged (re-import the .conf)"
            ));
        }
    }
    if peer == "awg" && cfg.get("awg_params").is_none() && cfg.get("import").is_none() {
        // Loopback/tests may pass raw keys; real AWG peers need params (US5).
    }
    let family = Family::parse(cfg.get("family").unwrap_or("dual"))?;
    let endpoint = cfg
        .get("endpoint")
        .ok_or_else(|| "wireguard hop requires endpoint=<ip:port>".to_string())?;
    // Resolves every address the name has (a literal is a one-element list)
    // and rejects port 0 and family mismatches naming the field.
    let peer_endpoints = resolve_endpoint(endpoint, family).await?;
    let private_key = cfg
        .get("private_key")
        .ok_or_else(|| {
            "wireguard hop requires private_key=<64 hex> (identity store milestone)".to_string()
        })
        .and_then(parse_key_hex)?;
    let peer_public_key = cfg
        .get("peer_public_key")
        .ok_or_else(|| "wireguard hop requires peer_public_key=<64 hex>".to_string())
        .and_then(parse_key_hex)?;
    let preshared_key = cfg
        .get("preshared_key")
        .map(|s| parse_key_hex(s).map_err(|e| format!("invalid preshared_key: {e}")))
        .transpose()?;
    let keepalive = cfg
        .get("keepalive")
        .map(|s| {
            s.parse::<u16>()
                .map_err(|e| format!("invalid keepalive: {e}"))
        })
        .transpose()?;
    let awg = if peer == "awg" {
        Some(crate::awg::parse_fields(cfg)?)
    } else {
        None
    };
    let noize = qcore_transport_api::obfuscate::NoizeParams::try_from_fields(&cfg.fields)
        .map_err(|e| format!("wireguard hop: {e}"))?;
    Ok(WgParams {
        peer_endpoints,
        private_key,
        peer_public_key,
        preshared_key,
        keepalive,
        awg,
        noize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_hex_rejected() {
        assert!(parse_key_hex("zz").is_err());
        assert!(parse_key_hex(&"ab".repeat(31)).is_err());
        assert!(parse_key_hex(&"ab".repeat(32)).is_ok());
    }

    fn cfg(pairs: &[(&str, &str)]) -> HopConfig {
        let mut c = HopConfig::new("wireguard");
        for (k, v) in pairs {
            c.fields.insert(k.to_string(), v.to_string());
        }
        c
    }

    fn keys() -> [(&'static str, String); 3] {
        let k = "ab".repeat(32);
        [
            ("endpoint", "127.0.0.1:51820".to_string()),
            ("private_key", k.clone()),
            ("peer_public_key", k),
        ]
    }

    #[tokio::test]
    async fn awg_fields_forbidden_on_plain_modes() {
        for peer in ["warp", "imported"] {
            let owned = keys();
            let mut pairs = vec![("peer", peer), ("import", "x"), ("awg_jc", "6")];
            pairs.extend(owned.iter().map(|(k, v)| (*k, v.as_str())));
            let err = resolve(&cfg(&pairs)).await.expect_err("FR-021");
            assert!(err.contains("awg_jc"), "names field: {err}");
            assert!(err.contains("peer=awg"), "names remedy: {err}");
        }
    }

    #[tokio::test]
    async fn imported_requires_ref() {
        let owned = keys();
        let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        // Default peer is warp; force imported without ref.
        let mut v = vec![("peer", "imported")];
        v.extend(pairs);
        let err = resolve(&cfg(&v)).await.expect_err("import required");
        assert!(err.contains("import=<ref>"), "{err}");
    }

    #[tokio::test]
    async fn imported_with_material_resolves() {
        let k = "ab".repeat(32);
        let p = resolve(&cfg(&[
            ("peer", "imported"),
            ("import", "wg-home"),
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
        ]))
        .await
        .expect("material resolves");
        assert!(p.awg.is_none());
    }

    #[tokio::test]
    async fn awg_carries_params() {
        let k = "ab".repeat(32);
        let p = resolve(&cfg(&[
            ("peer", "awg"),
            ("import", "awg-home"),
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
            ("awg_jc", "6"),
            ("awg_h1", "123"),
        ]))
        .await
        .expect("awg resolves");
        let a = p.awg.expect("params carried");
        assert_eq!((a.jc, a.h1), (6, 123));
    }

    #[tokio::test]
    async fn bad_awg_value_names_field() {
        let k = "ab".repeat(32);
        let err = resolve(&cfg(&[
            ("peer", "awg"),
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
            ("awg_jc", "many"),
        ]))
        .await
        .expect_err("bad awg value");
        assert!(err.contains("awg_jc"), "{err}");
    }

    #[tokio::test]
    async fn bad_keepalive_names_field() {
        let k = "ab".repeat(32);
        let err = resolve(&cfg(&[
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
            ("keepalive", "abc"),
        ]))
        .await
        .expect_err("bad keepalive");
        assert!(err.contains("invalid keepalive"), "{err}");
        // The contract: the message STARTS WITH the field-named prefix and a
        // cause follows it — the field name deliberately precedes the raw
        // parse error, so grep-for-field wins over the raw cause text.
        let cause = err
            .strip_prefix("invalid keepalive: ")
            .expect("field-named prefix must lead the message");
        assert!(!cause.is_empty(), "cause rides after the field name: {err}");
    }

    #[tokio::test]
    async fn bad_preshared_key_names_field() {
        let k = "ab".repeat(32);
        let err = resolve(&cfg(&[
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
            ("preshared_key", "zz"),
        ]))
        .await
        .expect_err("bad preshared_key");
        assert!(err.contains("invalid preshared_key"), "{err}");
    }

    #[tokio::test]
    async fn literal_endpoint_port_zero_rejected_naming_field() {
        // Both the literal and hostname paths share `resolve_endpoint`'s
        // port gate now; the literal arm used to accept port 0.
        let k = "ab".repeat(32);
        let err = resolve(&cfg(&[
            ("endpoint", "127.0.0.1:0"),
            ("private_key", &k),
            ("peer_public_key", &k),
        ]))
        .await
        .expect_err("port-0 literal endpoint must fail closed");
        assert!(err.contains("endpoint"), "names the field: {err}");
        assert!(err.contains("port `0`"), "names the port: {err}");
    }

    /// Finding 5: `family` is honoured on every endpoint path, including the
    /// literal one where no resolver filter runs. An unknown value must not
    /// silently behave as `dual`.
    #[tokio::test]
    async fn unknown_family_fails_closed_on_the_literal_path() {
        let k = "ab".repeat(32);
        let err = resolve(&cfg(&[
            ("endpoint", "127.0.0.1:51820"),
            ("family", "v4"),
            ("private_key", &k),
            ("peer_public_key", &k),
        ]))
        .await
        .expect_err("family=`v4` must not behave as dual");
        assert!(err.contains("family"), "names the field: {err}");
    }

    #[tokio::test]
    async fn endpoint_hostnames_resolve() {
        // `localhost` exercises the resolver path offline (hosts file, no
        // DNS); literals never touch the resolver.
        let lit = resolve_endpoint("127.0.0.1:51820", Family::Dual)
            .await
            .expect("literal");
        assert_eq!(lit, vec!["127.0.0.1:51820".parse().unwrap()]);
        let via_dns = resolve_endpoint("localhost:51820", Family::Dual)
            .await
            .expect("localhost");
        assert!(!via_dns.is_empty(), "localhost has an address");
        assert!(via_dns.iter().all(|a| a.ip().is_loopback()), "{via_dns:?}");
        assert!(resolve_endpoint("no-such-host.invalid:51820", Family::Dual)
            .await
            .is_err());
        assert!(
            resolve_endpoint("::1", Family::Dual).await.is_err(),
            "unbracketed v6"
        );
        assert!(
            resolve_endpoint("1.2.3.4:0", Family::Dual).await.is_err(),
            "port 0"
        );
        // Family filtering applies to literals too: an explicit stack that
        // contradicts the literal fails closed instead of connecting anyway.
        let err = resolve_endpoint("127.0.0.1:51820", Family::Ipv6)
            .await
            .expect_err("v4 literal under family=ipv6");
        assert!(err.contains("family=ipv6"), "names value: {err}");
        let err = resolve_endpoint("[::1]:51820", Family::Ipv4)
            .await
            .expect_err("v6 literal under family=ipv4");
        assert!(err.contains("family=ipv4"), "names value: {err}");
    }

    /// Finding 6: pre-fix `lookup_host` had no timeout, so a resolver that
    /// never answers parked the build forever. The system resolver cannot be
    /// made to hang on demand, so the guard is exercised through the same
    /// seam the production path uses; the outer timeout keeps a regression
    /// failing fast instead of hanging the suite.
    #[tokio::test]
    async fn stalled_dns_lookup_times_out_instead_of_parking_the_build() {
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            bounded_lookup(
                "stalled.invalid",
                Duration::from_millis(20),
                std::future::pending(),
            ),
        )
        .await
        .expect("the resolver guard must return, not park the build");
        let err = result.expect_err("a resolver that never answers must fail closed");
        assert!(err.contains("resolve `stalled.invalid` timed out"), "{err}");
    }
}
