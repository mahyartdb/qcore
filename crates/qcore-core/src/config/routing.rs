//! Routing rules as data (`routing.toml`, per profile dir).
//!
//! A rule is `action` plus a `match` table; every present `match` field must
//! agree (AND). Rules evaluate in file order and the first match decides.
//! Nothing matching means "proxy through the tunnel", the historic behavior,
//! so an absent or empty file changes nothing.
//!
//! Parsing fails closed naming the rule index and the offending field, the
//! same discipline as `obfuscation.toml`: a typo must not silently turn a
//! block rule into a no-op (the operator would believe traffic is refused
//! while it leaks through the tunnel).

use std::net::IpAddr;
use std::path::Path;

/// File name inside the profile dir.
pub const ROUTING_FILE: &str = "routing.toml";

/// What a matching rule does with the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    /// Tunnel egress (the default when no rule matches).
    Proxy,
    /// Host-network egress, bypassing the tunnel.
    Direct,
    /// Refuse before any egress.
    Block,
}

/// One authored rule: optional domain / CIDR / port constraints, ANDed.
///
/// `domain` and `cidr` are mutually exclusive: a target is either a name or
/// an address, so a rule combining both could never match and would silently
/// shadow later rules.
#[derive(Debug, Clone)]
pub struct RoutingRule {
    /// Lowercased DNS suffix, matched on label boundaries.
    pub domain: Option<String>,
    /// Literal or tunnel-resolved address constraint.
    pub cidr: Option<Cidr>,
    /// Target port; alone it matches any host.
    pub port: Option<u16>,
    pub action: RoutingAction,
}

/// IPv4/IPv6 prefix. No `ipnet` dependency: matching is one masked compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr/prefix`. Host bits are accepted and masked away
    /// (`10.0.0.1/8` means `10.0.0.0/8`, as with most routing tools);
    /// everything shape-invalid is an error naming the field.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr, len) = text
            .split_once('/')
            .ok_or_else(|| format!("`{text}` is not CIDR (expected addr/prefix)"))?;
        let network: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an IP address"))?;
        let prefix: u8 = len
            .parse()
            .map_err(|_| format!("`{len}` is not a prefix length"))?;
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("prefix /{prefix} exceeds /{max} for {network}"));
        }
        Ok(Cidr { network, prefix })
    }

    pub fn contains(&self, other: &IpAddr) -> bool {
        match (self.network, other) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}

/// Read and parse a routing file the caller named explicitly. A missing or
/// unreadable file is an error: only the profile-dir default may be absent.
pub fn load(path: &Path) -> Result<Vec<RoutingRule>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: cannot read: {e}", path.display()))?;
    parse_routing_toml(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse routing TOML. The accepted shape:
///
/// ```toml
/// [[rules]]
/// match = { domain = "example.com", port = 443 }
/// action = "direct"
/// ```
pub fn parse_routing_toml(text: &str) -> Result<Vec<RoutingRule>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("invalid TOML: {e}"))?;
    let t = v.as_table().ok_or_else(|| "must be a table".to_string())?;
    for k in t.keys() {
        if k != "rules" {
            return Err(format!("unknown key `{k}` (only `rules` is accepted)"));
        }
    }
    let Some(rules) = t.get("rules") else {
        return Ok(Vec::new());
    };
    let rules = rules
        .as_array()
        .ok_or_else(|| "`rules` must be an array of tables ([[rules]])".to_string())?;
    let mut out = Vec::with_capacity(rules.len());
    for (i, raw) in rules.iter().enumerate() {
        out.push(parse_rule(i + 1, raw)?);
    }
    Ok(out)
}

fn parse_rule(idx: usize, v: &toml::Value) -> Result<RoutingRule, String> {
    let t = v
        .as_table()
        .ok_or_else(|| format!("rule {idx} must be a table"))?;
    for k in t.keys() {
        if k != "match" && k != "action" {
            return Err(format!("rule {idx} has unknown key `{k}`"));
        }
    }
    let action = match t.get("action").and_then(|a| a.as_str()) {
        Some("proxy") => RoutingAction::Proxy,
        Some("direct") => RoutingAction::Direct,
        Some("block") => RoutingAction::Block,
        Some(other) => {
            return Err(format!(
                "rule {idx} action `{other}` (expected proxy|direct|block)"
            ))
        }
        None => return Err(format!("rule {idx} missing `action`")),
    };
    let m = t
        .get("match")
        .ok_or_else(|| format!("rule {idx} missing `match`"))?;
    let m = m
        .as_table()
        .ok_or_else(|| format!("rule {idx} `match` must be a table"))?;
    for k in m.keys() {
        if k != "domain" && k != "cidr" && k != "port" {
            return Err(format!("rule {idx} match has unknown key `{k}`"));
        }
    }
    let domain = match m.get("domain") {
        Some(d) => {
            let raw = d
                .as_str()
                .ok_or_else(|| format!("rule {idx} match.domain must be a string"))?;
            Some(parse_domain(idx, raw)?)
        }
        None => None,
    };
    let cidr = match m.get("cidr") {
        Some(c) => {
            let raw = c
                .as_str()
                .ok_or_else(|| format!("rule {idx} match.cidr must be a string"))?;
            Some(Cidr::parse(raw).map_err(|e| format!("rule {idx} match.cidr {e}"))?)
        }
        None => None,
    };
    let port = match m.get("port") {
        Some(p) => {
            let n = p
                .as_integer()
                .ok_or_else(|| format!("rule {idx} match.port must be an integer"))?;
            let port = u16::try_from(n)
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("rule {idx} match.port {n} is not 1..=65535"))?;
            Some(port)
        }
        None => None,
    };
    if domain.is_none() && cidr.is_none() && port.is_none() {
        return Err(format!(
            "rule {idx} match is empty (needs `domain`, `cidr` or `port`)"
        ));
    }
    if domain.is_some() && cidr.is_some() {
        return Err(format!(
            "rule {idx} match combines `domain` and `cidr`; a target is one or the other"
        ));
    }
    Ok(RoutingRule {
        domain,
        cidr,
        port,
        action,
    })
}

/// Normalize a suffix: lowercase (RFC 4343), one trailing dot dropped (FQDN
/// spelling), no wildcard/scheme syntax — those would never match and the
/// operator would only see traffic keep flowing.
fn parse_domain(idx: usize, raw: &str) -> Result<String, String> {
    let host = raw.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("rule {idx} match.domain is empty"));
    }
    if host.contains('*') {
        return Err(format!(
            "rule {idx} match.domain `{raw}`: wildcards are not supported (a bare suffix matches subdomains)"
        ));
    }
    if host.contains('/') || host.contains(':') {
        return Err(format!(
            "rule {idx} match.domain `{raw}` must be a bare host suffix"
        ));
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_combined_domain_and_port_rule() {
        let rules = parse_routing_toml(
            r#"
            [[rules]]
            match = { domain = "Example.COM.", port = 443 }
            action = "direct"
            "#,
        )
        .expect("valid");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].domain.as_deref(), Some("example.com"));
        assert_eq!(rules[0].port, Some(443));
        assert_eq!(rules[0].action, RoutingAction::Direct);
    }

    #[test]
    fn empty_file_and_empty_rules_mean_no_rules() {
        assert!(parse_routing_toml("").expect("empty").is_empty());
        assert!(parse_routing_toml("rules = []")
            .expect("empty rules")
            .is_empty());
    }

    #[test]
    fn unknown_keys_fail_closed_naming_the_key() {
        let err = parse_routing_toml("default = \"direct\"").expect_err("unknown top-level key");
        assert!(err.contains("unknown key `default`"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { doman = "example.com" }
            action = "block"
            "#,
        )
        .expect_err("typo in match");
        assert!(err.contains("unknown key `doman`"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { port = 443 }
            action = "block"
            retries = 2
            "#,
        )
        .expect_err("typo in rule");
        assert!(err.contains("unknown key `retries`"), "{err}");
    }

    #[test]
    fn malformed_fields_fail_closed_naming_the_rule_and_field() {
        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { port = 443 }
            action = "drop"
            "#,
        )
        .expect_err("bad action");
        assert!(err.contains("rule 1 action `drop`"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { cidr = "10.0.0.0" }
            action = "block"
            "#,
        )
        .expect_err("cidr without prefix");
        assert!(err.contains("rule 1 match.cidr"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { cidr = "10.0.0.0/33" }
            action = "block"
            "#,
        )
        .expect_err("prefix too long");
        assert!(err.contains("/33 exceeds /32"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { port = 0 }
            action = "block"
            "#,
        )
        .expect_err("port zero");
        assert!(err.contains("not 1..=65535"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = { domain = "example.com", cidr = "10.0.0.0/8" }
            action = "block"
            "#,
        )
        .expect_err("domain+cidr");
        assert!(err.contains("combines `domain` and `cidr`"), "{err}");

        let err = parse_routing_toml(
            r#"
            [[rules]]
            match = {}
            action = "block"
            "#,
        )
        .expect_err("empty match");
        assert!(err.contains("match is empty"), "{err}");
    }

    #[test]
    fn cidr_masks_host_bits_and_never_crosses_families() {
        let cidr = Cidr::parse("10.1.2.3/8").expect("cidr");
        assert!(cidr.contains(&"10.255.0.1".parse().unwrap()));
        assert!(!cidr.contains(&"11.0.0.1".parse().unwrap()));
        assert!(!cidr.contains(&"::ffff:10.0.0.1".parse().unwrap()));

        let v6 = Cidr::parse("2001:db8::/32").expect("v6 cidr");
        assert!(v6.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains(&"2001:db9::1".parse().unwrap()));
        assert!(!v6.contains(&"10.0.0.1".parse().unwrap()));

        let all = Cidr::parse("0.0.0.0/0").expect("default route");
        assert!(all.contains(&"203.0.113.9".parse().unwrap()));
    }
}
