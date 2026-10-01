//! Chain abstraction: builder, presets, validation, grammar.
//!
//! Chains are validated data. Depth is owned solely by the validator, which
//! counts the expanded hop list (FR-010a).

pub mod parse;
pub mod preset;
pub mod validate;

use crate::config::HopSpec;
use crate::registry::TransportRegistry;
use std::fmt;

/// A validated chain: ordered hop specs, index 0 = outermost carrier,
/// last = exit (FR-011).
#[derive(Debug, Clone)]
pub struct Chain {
    pub hops: Vec<HopSpec>,
    pub max_depth: u32,
}

impl Chain {
    pub fn depth(&self) -> usize {
        self.hops.len()
    }

    pub fn exit(&self) -> Option<&HopSpec> {
        self.hops.last()
    }
}

/// Chain-level errors. Each names the offending hop and reason; validation
/// opens zero sockets and starts zero hops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainError {
    pub hop_index: Option<usize>,
    pub hop_id: Option<String>,
    pub reason: String,
    pub fix: Option<String>,
}

impl ChainError {
    pub fn new(
        hop_index: Option<usize>,
        hop_id: Option<String>,
        reason: impl Into<String>,
        fix: Option<String>,
    ) -> Self {
        ChainError {
            hop_index,
            hop_id,
            reason: reason.into(),
            fix,
        }
    }
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match (self.hop_index, &self.hop_id) {
            (Some(i), Some(id)) => write!(f, "hop {i} `{id}`: {}", self.reason)?,
            _ => write!(f, "chain: {}", self.reason)?,
        }
        if let Some(fix) = &self.fix {
            write!(f, " (fix: {fix})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ChainError {}

/// Builds validated chains: expands presets, then validates.
pub struct ChainBuilder<'a> {
    registry: &'a TransportRegistry,
    max_depth: u32,
}

impl<'a> ChainBuilder<'a> {
    pub fn new(registry: &'a TransportRegistry, max_depth: u32) -> Self {
        ChainBuilder {
            registry,
            max_depth,
        }
    }

    /// Expand presets, validate depth/cycles/ports/carrier compatibility from
    /// descriptors. Returns `Result<Chain, ChainError>` before any start
    /// (FR-009/010/010a).
    pub fn build(&self, specs: Vec<ExpandedHop>) -> Result<Chain, ChainError> {
        self.build_with(specs, &preset::builtin_presets())
    }

    /// Same, with an explicit preset set (profile-dir override via T053).
    pub fn build_with(
        &self,
        specs: Vec<ExpandedHop>,
        presets: &[preset::CompositionPreset],
    ) -> Result<Chain, ChainError> {
        let hops = preset::expand(specs, presets)?;
        validate::validate(&hops, self.max_depth, self.registry)?;
        Ok(Chain {
            hops,
            max_depth: self.max_depth,
        })
    }
}

/// One hop as authored (preset name or concrete spec).
#[derive(Debug, Clone)]
pub enum ExpandedHop {
    Preset(String),
    Hop(HopSpec),
}

/// Minimal single-hop parser (CLI form; full comma grammar in US3 parse.rs).
///
/// Input like `wireguard peer=warp family=dual`: first token is the kind or a
/// preset name, rest are space-separated `key=value` pairs.
pub fn parse_single_hop(kind: &str, opts: &str) -> Result<HopSpec, ChainError> {
    use crate::config::*;
    let mut pairs = std::collections::BTreeMap::new();
    for tok in opts.split_whitespace() {
        let (k, v) = tok.split_once('=').ok_or_else(|| {
            ChainError::new(
                None,
                None,
                format!("bad option `{tok}` (expected key=value)"),
                None,
            )
        })?;
        // Duplicate keys never last-win: fail closed naming the field.
        if pairs.contains_key(k) {
            return Err(ChainError::new(
                None,
                None,
                format!("duplicate option `{k}` for transport `{kind}`"),
                None,
            ));
        }
        pairs.insert(k.to_string(), parse::unquote(v));
    }
    let get = |k: &str, default: &str| pairs.get(k).cloned().unwrap_or_else(|| default.to_string());
    // Plugin kinds (SC-002c): registered but untyped — carry opaquely.
    if crate::config::allowed_fields(kind).is_none() {
        if crate::registry::TransportRegistry::global()
            .get(kind)
            .is_none()
        {
            return Err(ChainError::new(
                None,
                None,
                format!("unknown transport `{kind}`"),
                Some("run `qcore ls` for registered transports".to_string()),
            ));
        }
        return Ok(HopSpec {
            id: format!("{kind}-0"),
            config: HopConfig::plugin(kind, &pairs),
        });
    }
    // Unknown keys fail closed, naming the field (typed per transport).
    // Plugin kinds returned above. A miss here means the field table
    // drifted from the builtin arms below: fail closed, never panic on
    // user input (the table-coverage test pins the table in CI).
    let known: &[&str] = crate::config::allowed_fields(kind).ok_or_else(|| {
        ChainError::new(
            None,
            None,
            format!("transport `{kind}` has no field list"),
            None,
        )
    })?;
    for k in pairs.keys() {
        if !known.contains(&k.as_str()) {
            return Err(ChainError::new(
                None,
                None,
                format!("unknown option `{k}` for transport `{kind}`"),
                None,
            ));
        }
    }
    let family = get("family", "dual");
    let config = match kind {
        "wireguard" => HopConfig::Wireguard(WireguardConfig {
            peer: get("peer", "warp"),
            import_ref: resolve_import_ref(
                pairs.get("import").cloned(),
                pairs.get("import_ref").cloned(),
                &format!("chain: transport `{kind}`"),
            )
            .map_err(|e| ChainError::new(None, None, e, None))?,
            obfuscation: pairs.get("obfuscation").cloned(),
            family,
            endpoint: pairs.get("endpoint").cloned(),
        }),
        "masque" => HopConfig::Masque(MasqueConfig {
            alpn: get("alpn", "h3"),
            obfuscation: pairs.get("obfuscation").cloned(),
            family,
            endpoint: pairs.get("endpoint").cloned(),
        }),
        "tor" => HopConfig::Tor(TorConfig { family }),
        "psiphon" => HopConfig::Psiphon(PsiphonConfig {
            sidecar_path: get("sidecar_path", ""),
            family,
        }),
        "relay" => HopConfig::Relay(RelayConfig { family }),
        "mock" => HopConfig::Mock(MockConfig { family }),
        // Table hit without an arm is programmer drift, not user input:
        // fail closed like the gate above, never panic.
        _ => {
            return Err(ChainError::new(
                None,
                None,
                format!("transport `{kind}` has no hop builder"),
                None,
            ))
        }
    };
    Ok(HopSpec {
        id: format!("{kind}-0"),
        config,
    })
}
