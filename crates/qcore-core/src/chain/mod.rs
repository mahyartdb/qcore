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

/// Text sinks render this directly (CLI stderr, `FailureReport` causes), so
/// the hop id and the reason are masked like every other diagnostic field;
/// benign ids and prose pass through unchanged.
impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let reason = crate::diag::masked_value("reason", &self.reason);
        match (self.hop_index, &self.hop_id) {
            (Some(i), Some(id)) => write!(
                f,
                "hop {i} `{}`: {}",
                crate::diag::masked_value("hop_id", id),
                reason
            )?,
            _ => write!(f, "chain: {reason}")?,
        }
        if let Some(fix) = &self.fix {
            write!(f, " (fix: {fix})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ChainError {}

/// Family values a typed hop accepts. An unknown value used to reach the
/// transport, whose unknown-family arm treats it as `dual` — silently
/// widening the connect family — so every parse gate rejects it up front.
/// Plugin kinds never reach this gate: their factory owns the contract.
const CHAIN_FAMILIES: &[&str] = &["ipv4", "ipv6", "dual"];

/// Validate a typed hop's `family`, naming the field (single source for the
/// grammar, chain-file and preset gates).
pub(crate) fn validate_family(family: &str) -> Result<(), String> {
    if CHAIN_FAMILIES.contains(&family) {
        return Ok(());
    }
    Err(format!(
        "family `{family}` is unknown: expected one of ipv4|ipv6|dual"
    ))
}

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
    parse_single_hop_in(kind, opts, &crate::registry::TransportRegistry::global())
}

/// [`parse_single_hop`] against an explicit registry: embedder-filtered
/// registries are honored for plugin kinds instead of the linked global set.
pub fn parse_single_hop_in(
    kind: &str,
    opts: &str,
    registry: &crate::registry::TransportRegistry,
) -> Result<HopSpec, ChainError> {
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
    // The caller's registry decides (see `parse_single_hop_in`).
    if crate::config::allowed_fields(kind).is_none() {
        if registry.get(kind).is_none() {
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
    if let Err(e) = validate_family(&family) {
        return Err(ChainError::new(
            None,
            None,
            format!("transport `{kind}`: {e}"),
            None,
        ));
    }
    // Explicit endpoints validate at the parse gate (same rules as the
    // import parser's Endpoint check): a malformed `endpoint=` dies here
    // naming the field, not mid-connect inside the transport.
    if let Some(ep) = pairs.get("endpoint") {
        if let Err(e) = crate::config::import::validate_explicit_endpoint(ep) {
            return Err(ChainError::new(
                None,
                None,
                format!("invalid endpoint for transport `{kind}`: {e}"),
                None,
            ));
        }
    }
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
        "masque" => {
            let server_name = pairs.get("server_name").cloned();
            if let Some(sn) = &server_name {
                crate::config::hop::validate_server_name(sn).map_err(|e| {
                    ChainError::new(None, None, format!("transport `{kind}`: {e}"), None)
                })?;
            }
            let insecure_skip_verify = pairs
                .get("insecure_skip_verify")
                .map(|raw| crate::config::hop::parse_bool_field(raw, "insecure_skip_verify"))
                .transpose()
                .map_err(|e| {
                    ChainError::new(None, None, format!("transport `{kind}`: {e}"), None)
                })?;
            HopConfig::Masque(MasqueConfig {
                alpn: get("alpn", "h3"),
                obfuscation: pairs.get("obfuscation").cloned(),
                family,
                endpoint: pairs.get("endpoint").cloned(),
                server_name,
                insecure_skip_verify,
            })
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// F1: an unknown `family` must fail closed at the single-hop gate
    /// naming the field. WireGuard treats an unknown value as `dual`, so
    /// `family=ip4` would silently widen the connect family.
    #[test]
    fn single_hop_rejects_unknown_family_naming_field() {
        for bad in ["ip4", "IPv4", "ipv6,ipv4", ""] {
            let err = parse_single_hop("mock", &format!("family={bad}"))
                .expect_err("unknown family rejected");
            assert!(
                err.reason.contains("family") && err.reason.contains("ipv4|ipv6|dual"),
                "`{bad}` names the field and the accepted set: {}",
                err.reason
            );
        }
        for ok in ["ipv4", "ipv6", "dual"] {
            let spec =
                parse_single_hop("mock", &format!("family={ok}")).expect("valid family parses");
            assert_eq!(spec.config.family(), ok);
        }
    }

    /// `Display` is itself a text sink (CLI diagnostics, `FailureReport`
    /// causes, embedder logs): a secret-shaped hop id must not survive it.
    #[test]
    fn display_masks_secret_shaped_hop_id_and_keeps_benign_ones_readable() {
        let secret = "deadbeefdeadbeefdeadbeefdeadbeef";
        let err = ChainError::new(
            Some(0),
            Some(secret.to_string()),
            "chain depth 4 exceeds max depth 3",
            None,
        );
        let text = err.to_string();
        assert!(
            !text.contains(secret),
            "raw hop id reaches the diagnostic: {text}"
        );
        assert!(
            text.contains("hop 0 `<redacted>`:"),
            "masked in place with the index kept: {text}"
        );

        let err = ChainError::new(Some(1), Some("exit".to_string()), "boom", None);
        assert_eq!(err.to_string(), "hop 1 `exit`: boom");
    }

    /// The reason is free text built by many producers that embed raw hop
    /// ids (config/chain_file.rs, chain/preset.rs, chain/parse.rs): a
    /// secret-shaped id anywhere inside the reason must not survive
    /// Display either; a benign reason stays byte-identical.
    #[test]
    fn display_masks_secret_shaped_reason_and_keeps_benign_ones_readable() {
        // Space-delimited 32-hex id inside long low-entropy prose: the
        // token scan masks in place, the context survives.
        let secret = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
        let err = ChainError::new(
            Some(0),
            Some("exit".to_string()),
            format!(
                "{} {secret} must be a string",
                "chain file: hop field note ".repeat(10)
            ),
            None,
        );
        let text = err.to_string();
        assert!(
            !text.contains(secret),
            "raw id inside the reason reaches the diagnostic: {text}"
        );
        assert!(
            text.contains("<redacted>") && text.contains("must be a string"),
            "masked in place with surrounding context kept: {text}"
        );

        // A short reason with a backticked high-entropy id: whole-value
        // entropy is a single-token rule, so the prose is token-scanned and
        // the id body is masked in place — backticks and context survive.
        let err = ChainError::new(
            Some(1),
            Some("hop-a".to_string()),
            format!("chain file: hop `{secret}` unknown"),
            None,
        );
        let text = err.to_string();
        assert!(
            !text.contains(secret),
            "raw id reaches the diagnostic: {text}"
        );
        assert!(
            text.contains("hop 1 `hop-a`: chain file: hop `<redacted>` unknown"),
            "id masked in place with context kept: {text}"
        );

        let benign = ChainError::new(
            Some(1),
            Some("gool-1".to_string()),
            "chain depth 4 exceeds max depth 3",
            Some("reduce to at most 3 hops".to_string()),
        );
        assert_eq!(
            benign.to_string(),
            "hop 1 `gool-1`: chain depth 4 exceeds max depth 3 (fix: reduce to at most 3 hops)"
        );

        let benign_no_hop = ChainError::new(
            None,
            None,
            "unknown transport `frobnicate`",
            Some("run `qcore ls` for registered transports".to_string()),
        );
        assert_eq!(
            benign_no_hop.to_string(),
            "chain: unknown transport `frobnicate` (fix: run `qcore ls` for registered transports)"
        );
    }

    /// F7: the CLI single-hop gate must map masque `server_name` /
    /// `insecure_skip_verify` into the typed config; a field table hit with
    /// no mapping would drop them silently.
    #[test]
    fn single_hop_masque_server_name_reaches_the_typed_config() {
        let spec = parse_single_hop(
            "masque",
            "alpn=h3 endpoint=127.0.0.1:443 server_name=masque.test insecure_skip_verify=true",
        )
        .expect("server_name is a masque option");
        let crate::config::HopConfig::Masque(cfg) = &spec.config else {
            panic!("kind=masque must parse to the masque variant");
        };
        assert_eq!(cfg.server_name.as_deref(), Some("masque.test"));
        assert_eq!(cfg.insecure_skip_verify, Some(true));
        let factory = spec.config.to_factory_config();
        assert_eq!(factory.get("server_name"), Some("masque.test"));
        assert_eq!(factory.get("insecure_skip_verify"), Some("true"));

        let err = parse_single_hop("masque", "insecure_skip_verify=yes").unwrap_err();
        assert!(
            err.reason.contains("insecure_skip_verify"),
            "names field: {}",
            err.reason
        );
    }
}
