//! Routing rules for proxy targets (first match wins).
//!
//! Semantics, also documented in `contracts/cli.md` §4 and
//! `profiles/README.md`:
//!
//! - Rules evaluate in file order. The first rule whose present `match`
//!   fields all agree decides; no match means [`Action::Proxy`] through the
//!   tunnel, so an absent or empty `routing.toml` is the historic behavior.
//! - `domain` matches the CONNECT target hostname as a DNS suffix on label
//!   boundaries (`example.com` covers `example.com` and `a.example.com`,
//!   never `notexample.com`), case-insensitively. The proxy never sniffs
//!   TLS/HTTP: only the CONNECT target is consulted.
//! - `cidr` matches a literal target IP. Evaluation is order-independent:
//!   when ANY CIDR rule could match the target port ([`Router::cidr_relevant`]),
//!   a domain target is resolved BEFORE any verdict, through the tunnel
//!   resolver (never the OS resolver), and the table is then applied once
//!   with both the name and the address. Without a resolver such a target
//!   fails closed instead of guessing (or leaking the name locally). When no
//!   CIDR rule could match the port, domain and port-only rules decide on the
//!   name alone, with no resolution. A hostname-capable exit
//!   ([`Dialer::dial_host`](qcore_transport_api::Dialer::dial_host)'s
//!   remote resolution) is bypassed for such targets because the rule needs
//!   the address on this side.
//! - First match still wins among rules that were evaluated with the same
//!   information (a `domain` rule before a CIDR rule can still win when the
//!   resolved address does not match the CIDR) — with ONE exception: a CIDR
//!   `block` rule is unorderable. When the resolved address matches a
//!   port-matching CIDR block, `block` wins over any earlier rule, so file
//!   order can never ship a denied address to the host stack.
//! - `direct` dials from the host's own network stack: it BYPASSES the
//!   tunnel. That is the point of the rule, and the leak trade-off (the
//!   destination sees the host IP; a hostname is resolved locally) is
//!   documented in `contracts/cli.md`.
//! - `block` refuses before any dial (SOCKS 0x02, HTTP 403).
//! - `port` alone matches any host.

use crate::config::profile_dir::ProfileDirs;
use crate::config::routing::{self, RoutingAction, RoutingRule, ROUTING_FILE};
use std::net::IpAddr;
use std::path::Path;

/// The decision vocabulary re-exported at the session layer.
pub use crate::config::routing::RoutingAction as Action;

/// Compiled routing table. `rules` is private so construction stays parse-
/// checked (fail-closed) and `Default` is the all-proxy table.
#[derive(Debug, Clone, Default)]
pub struct Router {
    rules: Vec<RoutingRule>,
}

impl Router {
    pub fn new(rules: Vec<RoutingRule>) -> Self {
        Self { rules }
    }

    /// No rules: every target proxies through the tunnel.
    pub fn all_proxy() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Load a file the caller named explicitly; a missing/unreadable file is
    /// an error (only the profile-dir default may be absent).
    pub fn load(path: &Path) -> Result<Self, String> {
        Ok(Self::new(routing::load(path)?))
    }

    /// Load `<profile_dir>/routing.toml`; absent means all-proxy.
    pub fn load_optional(dirs: &ProfileDirs) -> Result<Self, String> {
        let path = dirs.profile_dir.join(ROUTING_FILE);
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => Self::load(&path),
            Ok(_) => Err(format!("{}: not a file", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::all_proxy()),
            Err(e) => Err(format!("{}: cannot stat: {e}", path.display())),
        }
    }

    /// Decision over the rules whose present `match` fields all agree, with
    /// one order-independence guarantee: a CIDR `block` rule whose port
    /// matches is evaluated against the resolved address BEFORE first-match,
    /// so file order can never let a target slip past a deny rule (QA#1 —
    /// `direct` before `block` previously shipped the blocked address to the
    /// host stack). Everything else keeps first-match semantics.
    ///
    /// Callers must not decide a domain target with `addr = None` while
    /// [`Self::cidr_relevant`] reports the port: a CIDR rule placed before a
    /// domain rule would silently miss the resolved address and the domain
    /// rule would win on incomplete information (order-dependent routing,
    /// QA#2). Resolve first, then make ONE call with both.
    pub fn decide(&self, host: Option<&str>, addr: Option<&IpAddr>, port: u16) -> Action {
        // Blocks are unorderable: any CIDR block rule that matches the
        // resolved address (and, when constrained, the port) wins over an
        // earlier non-block rule. Without `addr` (a domain not yet resolved)
        // a CIDR rule cannot match, so the first-match scan proceeds — the
        // callers resolve first whenever [`Self::cidr_relevant`] says the
        // port could be CIDR-governed.
        if let Some(ip) = addr {
            let blocked = self.rules.iter().any(|rule| {
                rule.action == RoutingAction::Block
                    && rule.cidr.is_some()
                    && rule_matches(rule, host, Some(ip), port)
            });
            if blocked {
                return RoutingAction::Block;
            }
        }
        self.rules
            .iter()
            .find(|rule| rule_matches(rule, host, addr, port))
            .map_or(RoutingAction::Proxy, |rule| rule.action)
    }

    /// True when some CIDR rule in the table could match `port`
    /// (unconstrained or the same port). A domain target at such a port must
    /// be resolved through the tunnel before any verdict, so a CIDR block
    /// placed before (or after) a domain rule applies to the same address.
    pub fn cidr_relevant(&self, port: u16) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.cidr.is_some() && rule.port.is_none_or(|p| p == port))
    }
}

fn rule_matches(rule: &RoutingRule, host: Option<&str>, addr: Option<&IpAddr>, port: u16) -> bool {
    let host_ok = rule
        .domain
        .as_deref()
        .is_none_or(|suffix| host.is_some_and(|h| domain_matches(h, suffix)));
    let addr_ok = rule
        .cidr
        .is_none_or(|cidr| addr.is_some_and(|a| cidr.contains(a)));
    let port_ok = rule.port.is_none_or(|p| p == port);
    host_ok && addr_ok && port_ok
}

/// Suffix match on DNS label boundaries: equal to the suffix, or ending in
/// `.<suffix>`. Case-insensitive; one trailing dot (FQDN form) is ignored.
fn domain_matches(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::routing::parse_routing_toml;

    fn router(toml: &str) -> Router {
        Router::new(parse_routing_toml(toml).expect("test routing table parses"))
    }

    #[test]
    fn suffix_matches_on_label_boundaries_only() {
        let r = router(
            r#"
            [[rules]]
            match = { domain = "example.com" }
            action = "block"
            "#,
        );
        assert_eq!(r.decide(Some("example.com"), None, 443), Action::Block);
        assert_eq!(r.decide(Some("a.example.com"), None, 443), Action::Block);
        assert_eq!(r.decide(Some("A.Example.COM."), None, 443), Action::Block);
        assert_eq!(
            r.decide(Some("notexample.com"), None, 443),
            Action::Proxy,
            "the suffix must end on a dot boundary"
        );
        assert_eq!(r.decide(Some("example.com.evil"), None, 443), Action::Proxy);
        assert_eq!(
            r.decide(None, Some(&"10.0.0.1".parse().unwrap()), 443),
            Action::Proxy
        );
    }

    #[test]
    fn first_match_wins_in_file_order() {
        let r = router(
            r#"
            [[rules]]
            match = { domain = "example.com", port = 443 }
            action = "direct"

            [[rules]]
            match = { domain = "example.com" }
            action = "block"
            "#,
        );
        assert_eq!(r.decide(Some("example.com"), None, 443), Action::Direct);
        assert_eq!(r.decide(Some("example.com"), None, 80), Action::Block);
    }

    #[test]
    fn port_only_matches_any_host_and_needs_no_resolution() {
        let r = router(
            r#"
            [[rules]]
            match = { port = 25 }
            action = "block"
            "#,
        );
        assert_eq!(r.decide(Some("mail.example"), None, 25), Action::Block);
        assert_eq!(
            r.decide(None, Some(&"192.0.2.7".parse().unwrap()), 25),
            Action::Block
        );
        assert_eq!(r.decide(Some("mail.example"), None, 587), Action::Proxy);
        assert!(!r.cidr_relevant(25));
    }

    #[test]
    fn no_rules_is_all_proxy() {
        let r = Router::all_proxy();
        assert_eq!(r.decide(Some("example.com"), None, 443), Action::Proxy);
        assert_eq!(
            r.decide(None, Some(&"10.0.0.1".parse().unwrap()), 443),
            Action::Proxy
        );
        assert!(!r.cidr_relevant(443));
    }

    #[test]
    fn cidr_decides_only_once_an_address_is_known() {
        let r = router(
            r#"
            [[rules]]
            match = { cidr = "10.0.0.0/8" }
            action = "block"
            "#,
        );
        assert_eq!(r.decide(Some("intranet.example"), None, 443), Action::Proxy);
        assert!(r.cidr_relevant(443));
        assert_eq!(
            r.decide(
                Some("intranet.example"),
                Some(&"10.1.2.3".parse().unwrap()),
                443
            ),
            Action::Block
        );
        assert_eq!(
            r.decide(
                Some("public.example"),
                Some(&"203.0.113.1".parse().unwrap()),
                443
            ),
            Action::Proxy
        );
    }

    #[test]
    fn cidr_resolution_is_skipped_for_ports_no_cidr_rule_covers() {
        let r = router(
            r#"
            [[rules]]
            match = { cidr = "10.0.0.0/8", port = 445 }
            action = "block"
            "#,
        );
        assert!(!r.cidr_relevant(443));
        assert!(r.cidr_relevant(445));
    }

    #[test]
    fn cidr_relevance_scans_rules_behind_a_domain_rule() {
        // QA#2: the CIDR rule sits AFTER a domain rule, so a name-first
        // decision would short-circuit on `direct` and never see the
        // address. The scan must look at the whole table.
        let r = router(
            r#"
            [[rules]]
            match = { domain = "corp.internal" }
            action = "direct"

            [[rules]]
            match = { cidr = "10.0.0.0/8", port = 445 }
            action = "block"
            "#,
        );
        assert!(r.cidr_relevant(445));
        assert!(!r.cidr_relevant(443));
    }

    #[test]
    fn cidr_block_is_unorderable_direct_before_block_still_blocks() {
        // QA#1 mirror order: with first-match alone, the earlier `direct`
        // rule would ship 10.x:445 to the host stack and the deny rule would
        // never fire. `block` must win regardless of file order once the
        // resolved address is known.
        let r = router(
            r#"
            [[rules]]
            match = { domain = "corp.internal" }
            action = "direct"

            [[rules]]
            match = { cidr = "10.0.0.0/8", port = 445 }
            action = "block"
            "#,
        );
        assert_eq!(
            r.decide(
                Some("corp.internal"),
                Some(&"10.1.2.3".parse().unwrap()),
                445
            ),
            Action::Block,
            "a CIDR deny rule applies even after an earlier direct rule"
        );
        // And the resolved address NOT matching the CIDR keeps first-match:
        // the domain rule wins, direct.
        assert_eq!(
            r.decide(
                Some("corp.internal"),
                Some(&"192.0.2.9".parse().unwrap()),
                445
            ),
            Action::Direct
        );
        // A port-only earlier rule is likewise overridden by a later block.
        let r2 = router(
            r#"
            [[rules]]
            match = { port = 445 }
            action = "direct"

            [[rules]]
            match = { cidr = "10.0.0.0/8" }
            action = "block"
            "#,
        );
        assert_eq!(
            r2.decide(
                Some("anything.example"),
                Some(&"10.9.9.9".parse().unwrap()),
                445
            ),
            Action::Block
        );
    }

    #[test]
    fn cidr_block_respects_its_own_port_constraint() {
        // Unorderable does not mean over-broad: a block scoped to port 445
        // must not eat port 443 traffic to the same address.
        let r = router(
            r#"
            [[rules]]
            match = { domain = "corp.internal" }
            action = "direct"

            [[rules]]
            match = { cidr = "10.0.0.0/8", port = 445 }
            action = "block"
            "#,
        );
        assert_eq!(
            r.decide(
                Some("corp.internal"),
                Some(&"10.1.2.3".parse().unwrap()),
                443
            ),
            Action::Direct
        );
    }

    fn scratch_dirs(tag: &str) -> (ProfileDirs, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("qcore-routing-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("profiles")).expect("scratch profile dir");
        (
            ProfileDirs::resolve(Some(root.join("config")), Some(root.join("profiles"))),
            root,
        )
    }

    #[test]
    fn absent_profile_file_is_all_proxy() {
        let (dirs, root) = scratch_dirs("absent");
        let r = Router::load_optional(&dirs).expect("absent file is not an error");
        assert!(
            r.is_empty(),
            "no routing.toml = the historic all-proxy path"
        );
        assert_eq!(r.decide(Some("example.com"), None, 443), Action::Proxy);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_missing_file_is_an_error_naming_the_path() {
        let (dirs, root) = scratch_dirs("missing");
        let path = dirs.profile_dir.join("chosen.toml");
        let err = Router::load(&path).expect_err("an explicit path must exist");
        assert!(
            err.contains("chosen.toml"),
            "the error names the file: {err}"
        );
        assert!(err.contains("cannot read"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
