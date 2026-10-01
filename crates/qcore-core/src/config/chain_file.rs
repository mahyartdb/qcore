//! Chain TOML declaration parsing (US3 T055).
//!
//! Backs `--chain-file` and the positional `chain.toml` operand:
//! ```toml
//! [chain]
//! max_depth = 4
//! [[chain.hop]]
//! kind = "wireguard"
//! id = "warp-0"
//! peer = "warp"
//! family = "dual"
//! ```
//! Last hop is the exit (FR-011). Unknown fields fail closed naming the
//! field; `max_depth` above the hard limit 5 is rejected.

use crate::chain::{ChainError, ExpandedHop};
use crate::config::*;

/// Hard depth limit (FR-010a): chain files may not exceed it.
pub const HARD_MAX_DEPTH: u32 = 5;

/// A parsed chain file: authored hops plus optional depth override.
#[derive(Debug)]
pub struct ChainFile {
    pub max_depth: Option<u32>,
    pub hops: Vec<ExpandedHop>,
}

/// Parse chain TOML text. Errors name the offending field.
pub fn parse_chain_file_str(s: &str) -> Result<ChainFile, ChainError> {
    parse_chain_file_str_in(s, &crate::registry::TransportRegistry::global())
}

/// [`parse_chain_file_str`] against an explicit registry (see
/// [`load_chain_file_in`]).
pub fn parse_chain_file_str_in(
    s: &str,
    registry: &crate::registry::TransportRegistry,
) -> Result<ChainFile, ChainError> {
    let v: toml::Value = toml::from_str(s)
        .map_err(|e| ChainError::new(None, None, format!("chain file: invalid TOML: {e}"), None))?;
    let chain = v.get("chain").ok_or_else(|| {
        ChainError::new(
            None,
            None,
            "chain file: missing `[chain]` section".to_string(),
            None,
        )
    })?;
    for k in chain.as_table().map(|t| t.keys()).into_iter().flatten() {
        if k != "max_depth" && k != "hop" {
            return Err(ChainError::new(
                None,
                None,
                format!("chain file: unknown field `[chain].{k}`"),
                None,
            ));
        }
    }
    let max_depth = match chain.get("max_depth") {
        None => None,
        Some(d) => {
            let n = d.as_integer().ok_or_else(|| {
                ChainError::new(
                    None,
                    None,
                    "chain file: `max_depth` must be an integer".to_string(),
                    None,
                )
            })?;
            if n < 1 || n > HARD_MAX_DEPTH as i64 {
                return Err(ChainError::new(
                    None,
                    None,
                    format!("chain file: `max_depth` {n} outside 1..={HARD_MAX_DEPTH}"),
                    None,
                ));
            }
            Some(n as u32)
        }
    };
    let hops = chain.get("hop").and_then(|h| h.as_array()).ok_or_else(|| {
        ChainError::new(
            None,
            None,
            "chain file: missing `[[chain.hop]]` entries".to_string(),
            None,
        )
    })?;
    let mut out = Vec::new();
    for (i, h) in hops.iter().enumerate() {
        out.push(ExpandedHop::Hop(parse_file_hop(i, h, registry)?));
    }
    Ok(ChainFile {
        max_depth,
        hops: out,
    })
}

fn field(hop: &toml::Value, i: usize, id: &str, key: &str) -> Result<Option<String>, ChainError> {
    match hop.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                ChainError::new(
                    Some(i),
                    Some(id.to_string()),
                    format!("chain file: hop `{id}` field `{key}` must be a string"),
                    None,
                )
            })
            .map(Some),
    }
}

fn parse_file_hop(
    i: usize,
    hop: &toml::Value,
    registry: &crate::registry::TransportRegistry,
) -> Result<HopSpec, ChainError> {
    let err = |reason: String| ChainError::new(Some(i), None, reason, None);
    let t = hop
        .as_table()
        .ok_or_else(|| err("chain file: hop must be a table".to_string()))?;
    let kind = t
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("chain file: hop without `kind`".to_string()))?;
    // `id` first: error paths below name the hop.
    let id = match t.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => format!("{kind}-{i}"),
    };
    // Plugin kinds (SC-002c) skip the per-kind field table: every string
    // field rides opaquely; the factory validates at build time. The
    // caller's registry decides (see `load_chain_file_in`).
    if allowed_fields(kind).is_none() {
        if registry.get(kind).is_none() {
            return Err(err(format!("chain file: unknown transport `{kind}`")));
        }
        let mut pairs = std::collections::BTreeMap::new();
        for (k, v) in t {
            if k == "kind" || k == "id" {
                continue;
            }
            let s = v.as_str().ok_or_else(|| {
                err(format!(
                    "chain file: hop `{id}` field `{k}` must be a string"
                ))
            })?;
            pairs.insert(k.clone(), s.to_string());
        }
        // `family` defaults inside plugin().
        return Ok(HopSpec {
            id,
            config: HopConfig::plugin(kind, &pairs),
        });
    }
    // Plugin kinds returned above. A miss here means the field table
    // drifted from the builtin arms below: fail closed, never panic on
    // user input (the table-coverage test pins the table in CI).
    let allowed = allowed_fields(kind)
        .ok_or_else(|| err(format!("chain file: transport `{kind}` has no field list")))?;
    for k in t.keys() {
        if k != "kind" && k != "id" && !allowed.contains(&k.as_str()) {
            return Err(err(format!(
                "chain file: unknown field `{k}` for transport `{kind}`"
            )));
        }
    }
    let family = field(hop, i, &id, "family")?.unwrap_or_else(|| "dual".into());
    let config = match kind {
        "wireguard" => HopConfig::Wireguard(WireguardConfig {
            peer: field(hop, i, &id, "peer")?.unwrap_or_else(|| "warp".into()),
            import_ref: resolve_import_ref(
                field(hop, i, &id, "import")?,
                field(hop, i, &id, "import_ref")?,
                &format!("chain file hop `{id}`"),
            )
            .map_err(err)?,
            obfuscation: field(hop, i, &id, "obfuscation")?,
            family,
            endpoint: field(hop, i, &id, "endpoint")?,
        }),
        "masque" => HopConfig::Masque(MasqueConfig {
            alpn: field(hop, i, &id, "alpn")?.unwrap_or_else(|| "h3".into()),
            obfuscation: field(hop, i, &id, "obfuscation")?,
            family,
            endpoint: field(hop, i, &id, "endpoint")?,
        }),
        "tor" => HopConfig::Tor(TorConfig { family }),
        "psiphon" => HopConfig::Psiphon(PsiphonConfig {
            sidecar_path: field(hop, i, &id, "sidecar_path")?.unwrap_or_default(),
            family,
        }),
        "relay" => HopConfig::Relay(RelayConfig { family }),
        "mock" => HopConfig::Mock(MockConfig { family }),
        // Table hit without an arm is programmer drift, not user input:
        // fail closed like the gate above, never panic.
        _ => return Err(err(format!("transport `{kind}` has no hop builder"))),
    };
    Ok(HopSpec { id, config })
}

/// Load a chain file from disk.
pub fn load_chain_file(path: &std::path::Path) -> Result<ChainFile, ChainError> {
    load_chain_file_in(path, &crate::registry::TransportRegistry::global())
}

/// [`load_chain_file`] against an explicit registry: plugin kinds resolve
/// via the caller's registry instead of the linked global set.
pub fn load_chain_file_in(
    path: &std::path::Path,
    registry: &crate::registry::TransportRegistry,
) -> Result<ChainFile, ChainError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        ChainError::new(
            None,
            None,
            format!("cannot read {}: {e}", path.display()),
            None,
        )
    })?;
    parse_chain_file_str_in(&raw, registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hops_with_exit_last() {
        let f = parse_chain_file_str(
            r#"
[chain]
max_depth = 4
[[chain.hop]]
kind = "tor"
id = "tor-0"
[[chain.hop]]
kind = "relay"
id = "relay-0"
[[chain.hop]]
kind = "wireguard"
id = "warp-0"
peer = "warp"
family = "dual"
"#,
        )
        .unwrap();
        assert_eq!(f.max_depth, Some(4));
        assert_eq!(f.hops.len(), 3);
    }

    #[test]
    fn unknown_field_names_field() {
        let err = parse_chain_file_str(
            r#"
[chain]
[[chain.hop]]
kind = "tor"
bogus = "1"
"#,
        )
        .unwrap_err();
        assert!(err.reason.contains("bogus"), "names field: {}", err.reason);
    }

    #[test]
    fn depth_over_hard_limit_rejected() {
        let err = parse_chain_file_str(
            r#"
[chain]
max_depth = 9
[[chain.hop]]
kind = "mock"
"#,
        )
        .unwrap_err();
        assert!(err.reason.contains("max_depth"), "{}", err.reason);
    }

    #[test]
    fn missing_section_rejected() {
        assert!(parse_chain_file_str("foo = 1").is_err());
    }
}
