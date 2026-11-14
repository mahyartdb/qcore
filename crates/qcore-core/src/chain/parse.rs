//! Chain grammar (US3 T054, contracts/cli.md).
//!
//! ```text
//! chain := hop ( "," hop )*
//! hop   := name ( ws key "=" value )* [ "@" label ]
//! ```
//! Hops are comma-separated, left to right; the last hop is the exit
//! (FR-011). A bare `name` that matches a registered transport kind is a
//! single-hop chain, otherwise it is a preset reference. Options are typed
//! per transport: an unknown key fails closed naming the field. Values
//! containing `,`, whitespace, `=` or quotes MUST be quoted (single or
//! double); unquoted `=`/quotes in a value are rejected. A trailing
//! `@label` becomes the hop id (else `{kind}-{n}`).

use crate::chain::preset::CompositionPreset;
use crate::chain::{ChainError, ExpandedHop};
use crate::config::*;
use crate::registry::TransportRegistry;

/// Strip one layer of matching single/double quotes.
pub(crate) fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        unescape(&v[1..v.len() - 1])
    } else {
        v.to_string()
    }
}

/// Resolve `\"` → `"` and `\\` → `\` inside quoted spans (canonical-expr
/// quoting emits these; a lone trailing `\` stays literal).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n @ ('"' | '\\')) => out.push(n),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split on top-level commas (quote-aware). Empty segments are errors.
fn split_hops(expr: &str) -> Result<Vec<String>, ChainError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in expr.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    escaped = false;
                    cur.push(c);
                }
                ',' => {
                    if cur.trim().is_empty() {
                        return Err(ChainError::new(
                            None,
                            None,
                            "empty hop in chain expression".to_string(),
                            Some("remove the stray comma".to_string()),
                        ));
                    }
                    out.push(cur.trim().to_string());
                    cur.clear();
                }
                _ => cur.push(c),
            },
        }
    }
    if quote.is_some() {
        return Err(ChainError::new(
            None,
            None,
            "unterminated quote in chain expression".to_string(),
            None,
        ));
    }
    if cur.trim().is_empty() {
        return Err(ChainError::new(
            None,
            None,
            "empty hop in chain expression".to_string(),
            Some("remove the stray comma".to_string()),
        ));
    }
    out.push(cur.trim().to_string());
    Ok(out)
}

/// Whitespace-split a hop, quote-aware. Returns (token, was_quoted).
fn tokenize(hop: &str) -> Result<Vec<(String, bool)>, ChainError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut token_quoted = false;
    let mut in_token = false;
    let mut escaped = false;
    for c in hop.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    escaped = false;
                    token_quoted = true;
                    in_token = true;
                    cur.push(c);
                }
                _ if c.is_whitespace() => {
                    if in_token {
                        out.push((cur.clone(), token_quoted));
                        cur.clear();
                        token_quoted = false;
                        in_token = false;
                    }
                }
                _ => {
                    in_token = true;
                    cur.push(c);
                }
            },
        }
    }
    if quote.is_some() {
        return Err(ChainError::new(
            None,
            None,
            format!("unterminated quote in hop `{hop}`"),
            None,
        ));
    }
    if in_token {
        out.push((cur, token_quoted));
    }
    Ok(out)
}

/// Parse a full chain expression into authored hops/preset references.
pub fn parse_chain(
    expr: &str,
    registry: &TransportRegistry,
    presets: &[CompositionPreset],
) -> Result<Vec<ExpandedHop>, ChainError> {
    let mut n = 0u32;
    parse_chain_with_counter(expr, registry, presets, &mut n)
}

/// Same as [`parse_chain`] but sharing the auto-id counter across calls
/// (repeatable `--hop` accumulates in argv order).
pub fn parse_chain_with_counter(
    expr: &str,
    registry: &TransportRegistry,
    presets: &[CompositionPreset],
    n: &mut u32,
) -> Result<Vec<ExpandedHop>, ChainError> {
    if expr.trim().is_empty() {
        return Err(ChainError::new(
            None,
            None,
            "empty --chain expression".to_string(),
            None,
        ));
    }
    let mut out = Vec::new();
    for (i, hop_str) in split_hops(expr)?.iter().enumerate() {
        out.push(parse_hop(hop_str, i, n, registry, presets)?);
    }
    Ok(out)
}

fn parse_hop(
    hop_str: &str,
    index: usize,
    n: &mut u32,
    registry: &TransportRegistry,
    presets: &[CompositionPreset],
) -> Result<ExpandedHop, ChainError> {
    let err = |reason: String| ChainError::new(Some(index), None, reason, None);
    let tokens = tokenize(hop_str)?;
    if tokens.is_empty() {
        return Err(err("empty hop in chain expression".to_string()));
    }
    let (name, _) = &tokens[0];
    if name.starts_with('@') || name.contains('@') {
        return Err(err(format!(
            "bad hop name `{name}` (labels go last: `... @{}`)",
            name.trim_start_matches('@')
        )));
    }
    // Trailing @label becomes the hop id.
    let mut label: Option<String> = None;
    let mut rest = &tokens[1..];
    if let Some((last, _)) = rest.last() {
        if let Some(l) = last.strip_prefix('@') {
            if l.is_empty() {
                return Err(err("empty @label".to_string()));
            }
            label = Some(l.to_string());
            rest = &rest[..rest.len() - 1];
        }
    }
    // Bare token: registered kind wins, else preset reference.
    if rest.is_empty() && label.is_none() {
        if registry.get(name).is_some() {
            let spec = bare_hop(name, &format!("{name}-{n}"), registry)?;
            *n += 1;
            return Ok(ExpandedHop::Hop(spec));
        }
        if presets.iter().any(|p| &p.name == name) {
            return Ok(ExpandedHop::Preset(name.clone()));
        }
        return Err(err(format!(
            "unknown transport or preset `{name}` (run `qcore ls`)"
        )));
    }
    // Options form requires a registered kind (presets take no options).
    if registry.get(name).is_none() {
        if presets.iter().any(|p| &p.name == name) {
            return Err(err(format!(
                "preset `{name}` takes no options (flatten it into hops)"
            )));
        }
        return Err(err(format!(
            "unknown transport or preset `{name}` (run `qcore ls`)"
        )));
    }
    let mut pairs = std::collections::BTreeMap::new();
    for (tok, quoted) in rest {
        let (k, v) = tok
            .split_once('=')
            .ok_or_else(|| err(format!("bad option `{tok}` (expected key=value)")))?;
        if k.is_empty() || k.starts_with('@') {
            return Err(err(format!("bad option `{tok}` (expected key=value)")));
        }
        if !quoted && v.chars().any(|c| c == '=' || c == '"' || c == '\'') {
            return Err(err(format!(
                "value for `{k}` must be quoted (contains `=`, quote or space)"
            )));
        }
        // Duplicate keys never last-win: fail closed naming the field.
        if pairs.contains_key(k) {
            return Err(err(format!(
                "duplicate option `{k}` for transport `{name}`"
            )));
        }
        pairs.insert(k.to_string(), unquote(v));
    }
    // Plugin kinds (SC-002c): registered (checked above) but untyped —
    // every pair rides opaquely; the factory validates at build time.
    let spec = build_hop(name, &pairs, index, registry)?;
    let mut spec = spec;
    // Labeled hops reserve their counter slot too: `mock @mock-0` followed
    // by auto `mock` yields `mock-0,mock-1`, not a duplicate `mock-0`.
    if let Some(l) = label {
        *n += 1;
        spec.id = l;
    } else {
        let id = format!("{name}-{n}");
        *n += 1;
        spec.id = id;
    }
    Ok(ExpandedHop::Hop(spec))
}

/// A bare kind with defaults (family dual; wireguard peer warp; masque h3).
fn bare_hop(kind: &str, id: &str, registry: &TransportRegistry) -> Result<HopSpec, ChainError> {
    build_hop(kind, &std::collections::BTreeMap::new(), 0, registry).map(|mut spec| {
        spec.id = id.to_string();
        spec
    })
}

fn get(pairs: &std::collections::BTreeMap<String, String>, k: &str, default: &str) -> String {
    pairs.get(k).cloned().unwrap_or_else(|| default.to_string())
}

fn build_hop(
    kind: &str,
    pairs: &std::collections::BTreeMap<String, String>,
    index: usize,
    registry: &TransportRegistry,
) -> Result<HopSpec, ChainError> {
    let err = |reason: String| ChainError::new(Some(index), None, reason, None);
    // Plugin kinds (SC-002c): registered but untyped — every pair rides
    // opaquely; the factory validates at build time. Unregistered kinds
    // fail closed naming the kind. The CALLER's registry decides (never the
    // global): a kind present in the passed registry but absent from the
    // linked set parses here instead of dying one gate later.
    if crate::config::allowed_fields(kind).is_none() {
        if registry.get(kind).is_none() {
            return Err(err(format!("unknown transport `{kind}` (run `qcore ls`)")));
        }
        return Ok(HopSpec {
            id: format!("{kind}-{index}"),
            config: HopConfig::plugin(kind, pairs),
        });
    }
    let allowed = crate::config::allowed_fields(kind)
        .ok_or_else(|| err(format!("transport `{kind}` has no field list")))?;
    for k in pairs.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(err(format!("unknown option `{k}` for transport `{kind}`")));
        }
    }
    let family = get(pairs, "family", "dual");
    // Explicit endpoints validate at the parse gate: a malformed
    // `endpoint=` (bad host, non-numeric port) must die here naming the
    // field, not mid-connect inside the transport. Same rules as the
    // import parser's Endpoint check.
    if let Some(ep) = pairs.get("endpoint") {
        if let Err(e) = crate::config::import::validate_explicit_endpoint(ep) {
            return Err(err(format!("invalid endpoint for transport `{kind}`: {e}")));
        }
    }
    let config = match kind {
        "wireguard" => HopConfig::Wireguard(WireguardConfig {
            peer: get(pairs, "peer", "warp"),
            import_ref: crate::config::resolve_import_ref(
                pairs.get("import").cloned(),
                pairs.get("import_ref").cloned(),
                &format!("chain: transport `{kind}`"),
            )
            .map_err(err)?,
            obfuscation: pairs.get("obfuscation").cloned(),
            family,
            endpoint: pairs.get("endpoint").cloned(),
        }),
        "masque" => HopConfig::Masque(MasqueConfig {
            alpn: get(pairs, "alpn", "h3"),
            obfuscation: pairs.get("obfuscation").cloned(),
            family,
            endpoint: pairs.get("endpoint").cloned(),
        }),
        "tor" => HopConfig::Tor(TorConfig { family }),
        "psiphon" => HopConfig::Psiphon(PsiphonConfig {
            sidecar_path: get(pairs, "sidecar_path", ""),
            family,
        }),
        "relay" => HopConfig::Relay(RelayConfig { family }),
        "mock" => HopConfig::Mock(MockConfig { family }),
        // Table hit without an arm is programmer drift, not user input:
        // fail closed like the gate above, never panic.
        _ => return Err(err(format!("transport `{kind}` has no hop builder"))),
    };
    Ok(HopSpec {
        id: format!("{kind}-{index}"),
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_respects_quotes() {
        let parts = split_hops(r#"a x="1,2",b y='p q'"#).unwrap();
        assert_eq!(parts, vec![r#"a x="1,2""#, "b y='p q'"]);
    }

    #[test]
    fn empty_segments_rejected() {
        assert!(split_hops("mock,,mock").is_err());
        assert!(split_hops(",").is_err());
        assert!(split_hops("mock,").is_err());
    }

    #[test]
    fn unterminated_quote_rejected() {
        assert!(split_hops("mock endpoint=\"127.0.0.1:1").is_err());
        assert!(tokenize("mock endpoint=\"abc").is_err());
    }

    #[test]
    fn tokenize_marks_quoted() {
        let toks = tokenize(r#"wireguard peer=warp endpoint="10.0.0.1:51820""#).unwrap();
        assert_eq!(toks[0], ("wireguard".to_string(), false));
        assert_eq!(toks[2], ("endpoint=\"10.0.0.1:51820\"".to_string(), true));
    }

    #[test]
    fn unquote_strips_one_layer() {
        assert_eq!(unquote("\"a b\""), "a b");
        assert_eq!(unquote("'a'"), "a");
        assert_eq!(unquote("plain"), "plain");
    }

    #[test]
    fn quoted_escapes_round_trip() {
        // Canonical-expr quoting emits \" and \\ inside double quotes.
        assert_eq!(unquote("\"a\\\"b\""), "a\"b");
        assert_eq!(unquote("\"a\\\\b\""), "a\\b");
        assert_eq!(
            unquote("\"C:\\\\Program Files\\\\app.exe\""),
            "C:\\Program Files\\app.exe"
        );
        // An escaped quote does not close the span: the comma stays inside.
        let hops = split_hops("mock note=\"a\\\",b\"").unwrap();
        assert_eq!(hops.len(), 1);
        // Unterminated escape-quote still errors.
        assert!(split_hops("mock endpoint=\"abc").is_err());
        assert!(tokenize("mock endpoint=\"abc").is_err());
    }

    #[test]
    fn empty_expression_rejected() {
        let reg = crate::registry::TransportRegistry::global();
        let presets = crate::chain::preset::builtin_presets();
        let err = parse_chain("   ", &reg, &presets).unwrap_err();
        assert!(err.reason.contains("empty"));
    }

    #[test]
    fn duplicate_option_rejected_naming_field() {
        // `registry-test` is the inventory plugin registered in
        // `registry::tests` (same test binary): a plugin kind exercises the
        // duplicate gate without needing an out-of-crate transport link.
        let reg = crate::registry::TransportRegistry::global();
        let presets = crate::chain::preset::builtin_presets();
        let err = parse_chain("registry-test x=1 x=1", &reg, &presets).unwrap_err();
        assert!(
            err.reason.contains("duplicate") && err.reason.contains("x"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn single_hop_duplicate_option_rejected() {
        let err = crate::chain::parse_single_hop("mock", "family=ipv4 family=dual").unwrap_err();
        assert!(
            err.reason.contains("duplicate") && err.reason.contains("family"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn invalid_explicit_endpoint_rejected_at_parse() {
        // `999.999.999.999` parses as a hostname-shaped token but the
        // endpoint gate rejects the non-numeric port; both malformed
        // shapes die at parse time naming the field, never mid-connect.
        // `build_hop` directly: the test binary links no wireguard
        // transport, so the registry-backed `parse_chain` path is
        // unavailable here (chain-file gate coverage lives in chain_file).
        let reg = crate::registry::TransportRegistry::global();
        let pairs =
            |v: &str| std::collections::BTreeMap::from([("endpoint".to_string(), v.to_string())]);
        for bad in [
            "999.999.999.999:notaport",
            "1.2.3.4:0",
            "[::1:51820",
            "10.0.0.1:notaport",
        ] {
            let err = build_hop("wireguard", &pairs(bad), 0, &reg).unwrap_err();
            assert!(
                err.reason.contains("endpoint"),
                "{bad}: names field: {}",
                err.reason
            );
            let err = build_hop("masque", &pairs(bad), 0, &reg).unwrap_err();
            assert!(
                err.reason.contains("endpoint"),
                "masque {bad}: names field: {}",
                err.reason
            );
        }
        // Well-formed explicit endpoints still build (bracketed IPv6 too).
        build_hop("wireguard", &pairs("10.0.0.1:51820"), 0, &reg).expect("valid endpoint builds");
        build_hop("masque", &pairs("[2001:db8::1]:443"), 0, &reg).expect("bracketed IPv6 builds");
    }
}
