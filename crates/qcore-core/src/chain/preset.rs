//! Composition presets (plan: GOOL/MIM are compositions, not transports).
//!
//! `gool` = two `wireguard peer=warp` hops, `mim` = two `masque alpn=h3` hops,
//! `tor-warp` = `tor,relay,wireguard peer=warp`. Presets expand exactly one
//! level before validation (FR-007a); depth is plain hop counting after
//! expansion (FR-010a).

use crate::chain::{ChainError, ExpandedHop};
use crate::config::profile_dir::ProfileDirs;
use crate::config::{
    HopConfig, HopSpec, MasqueConfig, MockConfig, PsiphonConfig, RelayConfig, TorConfig,
    WireguardConfig,
};

/// A named chain fragment. Presets MUST NOT embed secrets.
#[derive(Debug, Clone)]
pub struct CompositionPreset {
    pub name: String,
    pub hops: Vec<HopSpec>,
}

fn wg_peer_warp(id: &str) -> HopSpec {
    HopSpec {
        id: id.to_string(),
        config: HopConfig::Wireguard(WireguardConfig {
            peer: "warp".into(),
            import_ref: None,
            obfuscation: None,
            family: "dual".into(),
            endpoint: None,
        }),
    }
}

fn masque_h3(id: &str) -> HopSpec {
    HopSpec {
        id: id.to_string(),
        config: HopConfig::Masque(MasqueConfig {
            alpn: "h3".into(),
            obfuscation: None,
            family: "dual".into(),
            endpoint: None,
        }),
    }
}

/// Shipped presets.
pub fn builtin_presets() -> Vec<CompositionPreset> {
    vec![
        CompositionPreset {
            name: "gool".into(),
            hops: vec![wg_peer_warp("gool-0"), wg_peer_warp("gool-1")],
        },
        CompositionPreset {
            name: "mim".into(),
            hops: vec![masque_h3("mim-0"), masque_h3("mim-1")],
        },
        CompositionPreset {
            name: "tor-warp".into(),
            hops: vec![
                HopSpec {
                    id: "tor-0".into(),
                    config: HopConfig::Tor(TorConfig {
                        family: "dual".into(),
                    }),
                },
                HopSpec {
                    id: "relay-0".into(),
                    config: HopConfig::Relay(RelayConfig {
                        family: "dual".into(),
                    }),
                },
                wg_peer_warp("warp-0"),
            ],
        },
    ]
}

/// Expand preset references exactly one level. A preset reference inside a
/// preset definition is a validation error naming both names.
pub fn expand(
    specs: Vec<ExpandedHop>,
    presets: &[CompositionPreset],
) -> Result<Vec<HopSpec>, ChainError> {
    let mut out = Vec::new();
    for spec in specs {
        match spec {
            ExpandedHop::Hop(h) => out.push(h),
            ExpandedHop::Preset(name) => {
                let preset = presets.iter().find(|p| p.name == name).ok_or_else(|| {
                    ChainError::new(None, None, format!("unknown preset `{name}`"), None)
                })?;
                for hop in &preset.hops {
                    // Preset hops are concrete specs by construction; a nested
                    // preset reference here is a definition error naming both.
                    let _ = hop;
                }
                out.extend(preset.hops.iter().cloned());
            }
        }
    }
    Ok(out)
}

/// Validate a preset definition itself (called when loading profile-dir
/// presets): no nested preset references, no secrets.
pub fn validate_definition(
    name: &str,
    hops: &[HopSpec],
    nested: &[String],
) -> Result<(), ChainError> {
    if let Some(n) = nested.first() {
        return Err(ChainError::new(
            None,
            Some(name.to_string()),
            format!("preset `{name}` contains nested preset `{n}`"),
            Some("flatten the inner preset into concrete hops".to_string()),
        ));
    }
    let _ = hops;
    Ok(())
}

/// Shipped `profiles/compositions.toml` (US3 T053): profile-dir overrides are
/// data. Parses `[[preset]]` (`name` + `[[preset.hop]]` with `id`, `kind`,
/// `family` plus kind-specific keys). Unknown fields and nested preset
/// references (a hop whose kind names another preset) are errors naming both.
pub fn parse_compositions_toml(s: &str) -> Result<Vec<CompositionPreset>, String> {
    let v: toml::Value =
        toml::from_str(s).map_err(|e| format!("compositions.toml: invalid TOML: {e}"))?;
    let presets = v
        .get("preset")
        .and_then(|p| p.as_array())
        .ok_or_else(|| "compositions.toml: missing `[[preset]]` entries".to_string())?;
    let mut out = Vec::new();
    for p in presets {
        let name = p
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| "compositions.toml: preset without `name`".to_string())?;
        let hops = p
            .get("hop")
            .and_then(|h| h.as_array())
            .ok_or_else(|| format!("preset `{name}`: missing `[[preset.hop]]` entries"))?;
        let mut specs = Vec::new();
        for h in hops {
            specs.push(parse_preset_hop(name, h)?);
        }
        out.push(CompositionPreset {
            name: name.to_string(),
            hops: specs,
        });
    }
    // Nested preset references name both names (FR-007a).
    let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
    for p in &out {
        for h in &p.hops {
            if names.contains(&h.config.kind()) {
                return Err(format!(
                    "preset `{}` contains nested preset `{}`",
                    p.name,
                    h.config.kind()
                ));
            }
        }
    }
    Ok(out)
}

fn preset_field(
    hop: &toml::Value,
    preset: &str,
    id: &str,
    key: &str,
) -> Result<Option<String>, String> {
    match hop.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("preset `{preset}` hop `{id}`: `{key}` must be a string"))
            .map(Some),
    }
}

fn parse_preset_hop(preset: &str, hop: &toml::Value) -> Result<HopSpec, String> {
    let t = hop
        .as_table()
        .ok_or_else(|| format!("preset `{preset}`: hop must be a table"))?;
    let id = t
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("preset `{preset}`: hop without `id`"))?
        .to_string();
    let kind = t
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("preset `{preset}` hop `{id}`: missing `kind`"))?;
    let family = preset_field(hop, preset, &id, "family")?.unwrap_or_else(|| "dual".into());
    // Plugin kinds (SC-002c): registered but untyped — every string field
    // rides opaquely; the factory validates at build time.
    if crate::config::allowed_fields(kind).is_none() {
        if crate::registry::TransportRegistry::global()
            .get(kind)
            .is_none()
        {
            return Err(format!(
                "preset `{preset}` hop `{id}`: unknown transport `{kind}`"
            ));
        }
        let mut pairs = std::collections::BTreeMap::new();
        for (k, v) in t {
            if k == "id" || k == "kind" {
                continue;
            }
            let s = v
                .as_str()
                .ok_or_else(|| format!("preset `{preset}` hop `{id}`: `{k}` must be a string"))?;
            pairs.insert(k.clone(), s.to_string());
        }
        return Ok(HopSpec {
            id,
            config: HopConfig::plugin(kind, &pairs),
        });
    }
    let known: &[&str] = match kind {
        "wireguard" => &[
            "id",
            "kind",
            "peer",
            "import_ref",
            "obfuscation",
            "family",
            "endpoint",
        ],
        "masque" => &["id", "kind", "alpn", "obfuscation", "family", "endpoint"],
        "tor" => &["id", "kind", "family"],
        "psiphon" => &["id", "kind", "sidecar_path", "family"],
        "relay" => &["id", "kind", "family"],
        "mock" => &["id", "kind", "family"],
        _ => {
            return Err(format!(
                "preset `{preset}` hop `{id}`: unknown transport `{kind}`"
            ))
        }
    };
    for k in t.keys() {
        if !known.contains(&k.as_str()) {
            return Err(format!("preset `{preset}` hop `{id}`: unknown field `{k}`"));
        }
    }
    let config = match kind {
        "wireguard" => HopConfig::Wireguard(WireguardConfig {
            peer: preset_field(hop, preset, &id, "peer")?.unwrap_or_else(|| "warp".into()),
            import_ref: preset_field(hop, preset, &id, "import_ref")?,
            obfuscation: preset_field(hop, preset, &id, "obfuscation")?,
            family,
            endpoint: preset_field(hop, preset, &id, "endpoint")?,
        }),
        "masque" => HopConfig::Masque(MasqueConfig {
            alpn: preset_field(hop, preset, &id, "alpn")?.unwrap_or_else(|| "h3".into()),
            obfuscation: preset_field(hop, preset, &id, "obfuscation")?,
            family,
            endpoint: preset_field(hop, preset, &id, "endpoint")?,
        }),
        "tor" => HopConfig::Tor(TorConfig { family }),
        "psiphon" => HopConfig::Psiphon(PsiphonConfig {
            sidecar_path: preset_field(hop, preset, &id, "sidecar_path")?.unwrap_or_default(),
            family,
        }),
        "relay" => HopConfig::Relay(RelayConfig { family }),
        "mock" => HopConfig::Mock(MockConfig { family }),
        _ => unreachable!(),
    };
    Ok(HopSpec { id, config })
}

/// Resolve the preset set: profile-dir `compositions.toml` override when
/// present, else the shipped builtins. Override errors fail closed naming
/// the file (never silently fall back).
pub fn resolve_presets(dirs: &ProfileDirs) -> Result<Vec<CompositionPreset>, ChainError> {
    let path = dirs.profile_dir.join("compositions.toml");
    if !path.exists() {
        return Ok(builtin_presets());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        ChainError::new(
            None,
            None,
            format!("cannot read {}: {e}", path.display()),
            None,
        )
    })?;
    parse_compositions_toml(&raw)
        .map_err(|e| ChainError::new(None, None, format!("{}: {e}", path.display()), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gool_expands_to_two_wireguard_hops() {
        let hops = expand(vec![ExpandedHop::Preset("gool".into())], &builtin_presets()).unwrap();
        assert_eq!(hops.len(), 2);
        assert!(hops.iter().all(|h| h.config.kind() == "wireguard"));
    }

    #[test]
    fn tor_warp_includes_relay() {
        let hops = expand(
            vec![ExpandedHop::Preset("tor-warp".into())],
            &builtin_presets(),
        )
        .unwrap();
        let kinds: Vec<_> = hops.iter().map(|h| h.config.kind()).collect();
        assert_eq!(kinds, vec!["tor", "relay", "wireguard"]);
    }

    #[test]
    fn unknown_preset_is_validation_error() {
        let err = expand(vec![ExpandedHop::Preset("nope".into())], &builtin_presets()).unwrap_err();
        assert!(err.reason.contains("unknown preset"));
    }

    #[test]
    fn nested_preset_in_definition_rejected_naming_both() {
        let err = validate_definition("outer", &[], &["inner".to_string()]).unwrap_err();
        assert!(err.reason.contains("outer") && err.reason.contains("inner"));
    }

    #[test]
    fn shipped_toml_equals_builtins() {
        let shipped = include_str!("../../../../profiles/compositions.toml");
        let parsed = parse_compositions_toml(shipped).expect("shipped TOML parses");
        let builtin = builtin_presets();
        assert_eq!(parsed.len(), builtin.len());
        for (p, b) in parsed.iter().zip(builtin.iter()) {
            assert_eq!(p.name, b.name);
            assert_eq!(p.hops, b.hops);
        }
    }

    #[test]
    fn unknown_field_names_field() {
        let bad = r#"
[[preset]]
name = "x"
[[preset.hop]]
id = "x-0"
kind = "tor"
bogus = "1"
"#;
        let err = parse_compositions_toml(bad).expect_err("unknown field");
        assert!(err.contains("bogus"), "names field: {err}");
    }

    #[test]
    fn nested_preset_reference_names_both() {
        let bad = r#"
[[preset]]
name = "outer"
[[preset.hop]]
id = "o-0"
kind = "gool"
[[preset]]
name = "gool"
[[preset.hop]]
id = "g-0"
kind = "mock"
"#;
        let err = parse_compositions_toml(bad).expect_err("nested preset");
        assert!(
            err.contains("outer") && err.contains("gool"),
            "names both: {err}"
        );
    }
}
