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
                // Preset hops are concrete `HopSpec`s by construction, so a
                // nested preset reference is unrepresentable here by type;
                // file-loaded definitions are checked in
                // `parse_compositions_toml` via `validate_definition`.
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
    // Presets must not embed secrets. Preset fields are never key material
    // by construction (peer/family/endpoint/obfuscation/sidecar_path are
    // names and locators), so the gate checks typed anchors only — pasted
    // key blocks (denylist) or values under secret-named keys. No entropy
    // heuristic: it false-positives on benign identifiers while missing
    // short secrets, and a validator must be precise (a bogus high-entropy
    // profile name already fails downstream as unknown). Enforcement lives
    // at this file boundary — every in-repo preset source is validated-file
    // or builtin constants; programmatic presets are the constructor's
    // trust domain, like HopConfig values.
    for h in hops {
        let cfg = h.config.to_factory_config();
        for (k, v) in &cfg.fields {
            if crate::diag::redact::has_secret_anchor(k, v) {
                return Err(ChainError::new(
                    None,
                    Some(name.to_string()),
                    format!(
                        "preset `{name}` hop `{}` embeds a secret-like value in field `{k}`",
                        h.id
                    ),
                    Some(
                        "presets must not embed secrets; reference them by import or identity"
                            .to_string(),
                    ),
                ));
            }
        }
    }
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
    let mut seen = std::collections::HashSet::new();
    for p in presets {
        let t = p
            .as_table()
            .ok_or_else(|| "compositions.toml: preset must be a table".to_string())?;
        for k in t.keys() {
            if k != "name" && k != "hop" {
                return Err(format!(
                    "compositions.toml: unknown field `{k}` in preset table"
                ));
            }
        }
        let name = p
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| "compositions.toml: preset without `name`".to_string())?;
        // Duplicate preset names never last-win: fail closed naming the preset.
        if !seen.insert(name.to_string()) {
            return Err(format!("compositions.toml: duplicate preset `{name}`"));
        }
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
    // Definition validation (FR-007a): nested preset references name both
    // names; pasted key material is rejected (presets must not embed
    // secrets). One gate for both, via `validate_definition`.
    let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
    for p in &out {
        // Only names that cannot be concrete transports are even candidates
        // for a preset reference: builtin and registered kinds always parse
        // as transport hops (and anything else fails earlier as an unknown
        // transport), so a hop kind matching a preset name is otherwise a
        // legitimate hop, never a nesting.
        let registry = crate::registry::TransportRegistry::global();
        let nested: Vec<String> = p
            .hops
            .iter()
            .map(|h| h.config.kind().to_string())
            .filter(|k| {
                names.contains(&k.as_str())
                    && crate::config::allowed_fields(k).is_none()
                    && registry.get(k).is_none()
            })
            .collect();
        validate_definition(&p.name, &p.hops, &nested).map_err(|e| e.to_string())?;
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
    // Unknown fields fail closed naming the field. `allowed_fields` is the
    // single source (same table the TOML/grammar gates use); `id`/`kind`
    // ride alongside HopSpec, not the transport config. Plugin kinds
    // returned above. A miss here means the field table drifted from the
    // builtin arms below: fail closed, never panic on user input (the
    // table-coverage test pins the table in CI).
    let allowed = crate::config::allowed_fields(kind)
        .ok_or_else(|| format!("preset `{preset}`: transport `{kind}` has no field list"))?;
    for k in t.keys() {
        if k != "id" && k != "kind" && !allowed.contains(&k.as_str()) {
            return Err(format!("preset `{preset}` hop `{id}`: unknown field `{k}`"));
        }
    }
    let config = match kind {
        "wireguard" => HopConfig::Wireguard(WireguardConfig {
            peer: preset_field(hop, preset, &id, "peer")?.unwrap_or_else(|| "warp".into()),
            // `import` is the documented alias the grammar accepts (mod.rs);
            // the preset gate drifted by rejecting it — accept and map it.
            import_ref: crate::config::resolve_import_ref(
                preset_field(hop, preset, &id, "import")?,
                preset_field(hop, preset, &id, "import_ref")?,
                &format!("preset `{preset}` hop `{id}`"),
            )?,
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
        // Table hit without an arm is programmer drift, not user input:
        // fail closed like the gate above, never panic.
        _ => {
            return Err(format!(
                "preset `{preset}` hop `{id}`: transport `{kind}` has no hop builder"
            ))
        }
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
    fn non_transport_preset_kind_fails_closed_naming_both() {
        // A hop kind naming a preset that is no transport cannot parse as
        // a hop at all: it fails closed as an unknown transport (naming
        // preset and name) before nesting validation is even reached.
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

    #[test]
    fn pasted_key_block_in_preset_rejected_naming_preset_hop_field() {
        let bad = r#"
[[preset]]
name = "sneaky"
[[preset.hop]]
id = "s-0"
kind = "wireguard"
peer = "warp"
endpoint = "xx BEGIN PRIVATE KEY----- yy"
"#;
        let err = parse_compositions_toml(bad).expect_err("key block in preset");
        assert!(
            err.contains("sneaky") && err.contains("endpoint"),
            "names preset and field: {err}"
        );
    }

    #[test]
    fn benign_high_entropy_preset_value_accepted() {
        // The gate is typed-anchors-only (no entropy heuristic): a
        // random-looking but non-secret identifier must not fail the
        // definition (it fails downstream as an unknown profile instead).
        let toml = r#"
[[preset]]
name = "ok"
[[preset.hop]]
id = "o-0"
kind = "wireguard"
peer = "warp"
obfuscation = "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2=="
"#;
        parse_compositions_toml(toml).expect("benign identifier parses");
    }

    #[test]
    fn transport_kind_hop_is_not_a_nested_preset() {
        // A hop whose kind is a concrete transport is never a preset
        // reference — even when a preset shares the name. Only names that
        // cannot be transports reach the nesting check (and those fail
        // earlier as unknown transports).
        let toml = r#"
[[preset]]
name = "tor"
[[preset.hop]]
id = "t-0"
kind = "tor"
[[preset]]
name = "other"
[[preset.hop]]
id = "o-0"
kind = "tor"
"#;
        parse_compositions_toml(toml).expect("transport hops are not refs");
    }

    #[test]
    fn wireguard_import_alias_maps_to_import_ref() {
        let toml = r#"
[[preset]]
name = "imp"
[[preset.hop]]
id = "w-0"
kind = "wireguard"
peer = "imported"
import = "home"
"#;
        let parsed = parse_compositions_toml(toml).expect("import alias parses");
        match &parsed[0].hops[0].config {
            HopConfig::Wireguard(c) => assert_eq!(c.import_ref.as_deref(), Some("home")),
            other => panic!("expected wireguard, got {}", other.kind()),
        }
    }

    #[test]
    fn duplicate_preset_names_rejected() {
        let toml = r#"
[[preset]]
name = "dup"
[[preset.hop]]
id = "d-0"
kind = "mock"
[[preset]]
name = "dup"
[[preset.hop]]
id = "d-1"
kind = "mock"
"#;
        let err = parse_compositions_toml(toml).expect_err("duplicate preset");
        assert!(
            err.contains("duplicate") && err.contains("dup"),
            "names preset: {err}"
        );
    }

    #[test]
    fn unknown_preset_table_key_rejected_naming_field() {
        // Anything but name/hop in a preset table would be silently dropped
        // (a typo'd operator key becomes a silent default): rejected naming
        // the field, like the hop-level unknown-field gate.
        let bad = r#"
[[preset]]
name = "x"
priority = "high"
[[preset.hop]]
id = "x-0"
kind = "mock"
"#;
        let err = parse_compositions_toml(bad).expect_err("unknown preset key");
        assert!(
            err.contains("unknown field") && err.contains("priority"),
            "names field: {err}"
        );
    }
}
