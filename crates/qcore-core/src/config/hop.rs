//! Typed hop configuration (constitution IV: no untyped options map).
//!
//! Builtin transports get typed variants below. Any *other registered*
//! transport (see [`crate::registry`]) is carried opaquely as
//! [`HopConfig::Plugin`]: `family` plus all supplied pairs, validated
//! field-by-field by its own factory at build time (fail-closed). Adding a
//! transport therefore touches only its own crate plus one feature line —
//! never this schema, the chain grammar, the validator, or the CLI
//! (SC-002c). Unknown-field rejection stays strict for builtin kinds.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One chain entry: typed config plus chain-unique id used in reports/errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopSpec {
    /// Unique in chain; used in reports/errors.
    pub id: String,
    #[serde(flatten)]
    pub config: HopConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopConfig {
    Wireguard(WireguardConfig),
    Masque(MasqueConfig),
    Tor(TorConfig),
    Psiphon(PsiphonConfig),
    Relay(RelayConfig),
    Mock(MockConfig),
    /// Plugin-defined transport: opaque pass-through. `fields` carries every
    /// supplied pair except `kind`/`family`/`id`; the factory validates names
    /// and values at build time and fails closed naming the field.
    Plugin(PluginHopConfig),
}

/// Opaque config for a plugin-defined transport kind (SC-002c).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHopConfig {
    pub kind: String,
    pub family: String,
    pub fields: BTreeMap<String, String>,
}

/// Allowed fields per kind (excluding the `kind` tag itself).
/// Shared by strict TOML parsing, the chain grammar (T054) and preset data
/// (T053) so "unknown field" means the same everywhere.
pub fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
    ALLOWED_FIELDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, f)| *f)
}

const ALLOWED_FIELDS: &[(&str, &[&str])] = &[
    (
        "wireguard",
        &[
            "peer",
            "import_ref",
            "import",
            "obfuscation",
            "family",
            "endpoint",
        ],
    ),
    ("masque", &["alpn", "obfuscation", "family", "endpoint"]),
    ("tor", &["family"]),
    ("psiphon", &["sidecar_path", "family"]),
    ("relay", &["family"]),
    ("mock", &["family"]),
];

/// Strict TOML parse: unknown fields are deserialization errors naming the
/// field (Principle IV). The explicit key check below is the enforcement
/// point for builtin kinds. A *registered* non-builtin kind parses opaquely
/// into [`HopConfig::Plugin`] (scalar fields only — tables/arrays are
/// rejected naming the field); unregistered kinds are rejected naming the
/// kind. All file-loaded hop config MUST go through here.
pub fn parse_toml_strict(s: &str) -> Result<HopConfig, String> {
    let v: toml::Value = toml::from_str(s).map_err(|e| e.to_string())?;
    let table = v
        .as_table()
        .ok_or_else(|| "hop config must be a TOML table".to_string())?;
    let kind = table
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| "hop config is missing `kind`".to_string())?;
    let Some(allowed) = ALLOWED_FIELDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, f)| *f)
    else {
        // Plugin kind (SC-002c): registry decides, schema stays untouched.
        if crate::registry::TransportRegistry::global()
            .get(kind)
            .is_none()
        {
            return Err(format!("unknown transport kind `{kind}`"));
        }
        let mut pairs = BTreeMap::new();
        for (k, val) in table {
            if k == "kind" || k == "id" {
                continue;
            }
            let s = val
                .as_str()
                .ok_or_else(|| format!("non-string field `{k}` for transport `{kind}`"))?;
            pairs.insert(k.clone(), s.to_string());
        }
        return Ok(HopConfig::plugin(kind, &pairs));
    };
    for key in table.keys() {
        if key != "kind" && !allowed.contains(&key.as_str()) {
            return Err(format!("unknown field `{key}` for transport `{kind}`"));
        }
    }
    toml::Value::Table(table.clone())
        .try_into()
        .map_err(|e: toml::de::Error| e.to_string())
}

impl HopConfig {
    pub fn kind(&self) -> &str {
        match self {
            HopConfig::Wireguard(_) => "wireguard",
            HopConfig::Masque(_) => "masque",
            HopConfig::Tor(_) => "tor",
            HopConfig::Psiphon(_) => "psiphon",
            HopConfig::Relay(_) => "relay",
            HopConfig::Mock(_) => "mock",
            HopConfig::Plugin(c) => c.kind.as_str(),
        }
    }

    pub fn family(&self) -> &str {
        match self {
            HopConfig::Wireguard(c) => &c.family,
            HopConfig::Masque(c) => &c.family,
            HopConfig::Tor(c) => &c.family,
            HopConfig::Psiphon(c) => &c.family,
            HopConfig::Relay(c) => &c.family,
            HopConfig::Mock(c) => &c.family,
            HopConfig::Plugin(c) => &c.family,
        }
    }

    /// Data-driven constructor for plugin kinds (SC-002c): `family` (default
    /// `dual`) plus every other supplied pair, carried opaquely. Callers must
    /// have confirmed `kind` is registered; unregistered kinds are rejected
    /// at the grammar/preset/file gates, never here.
    pub fn plugin(kind: &str, pairs: &BTreeMap<String, String>) -> Self {
        let mut fields = pairs.clone();
        let family = fields
            .remove("family")
            .unwrap_or_else(|| "dual".to_string());
        HopConfig::Plugin(PluginHopConfig {
            kind: kind.to_string(),
            family,
            fields,
        })
    }

    /// Convert to the untyped factory view (keys only; secrets never here —
    /// secrets travel via [`crate::config::secret`](super::secret)).
    pub fn to_factory_config(&self) -> qcore_transport_api::HopConfig {
        let mut cfg = qcore_transport_api::HopConfig::new(self.kind());
        let mut put = |k: &str, v: &str| {
            cfg.fields.insert(k.to_string(), v.to_string());
        };
        match self {
            HopConfig::Wireguard(c) => {
                put("peer", &c.peer);
                if let Some(r) = &c.import_ref {
                    put("import_ref", r);
                }
                put("family", &c.family);
                if let Some(e) = &c.endpoint {
                    put("endpoint", e);
                }
                if let Some(o) = &c.obfuscation {
                    put("obfuscation", o);
                }
            }
            HopConfig::Masque(c) => {
                put("alpn", &c.alpn);
                put("family", &c.family);
                if let Some(e) = &c.endpoint {
                    put("endpoint", e);
                }
                if let Some(o) = &c.obfuscation {
                    put("obfuscation", o);
                }
            }
            HopConfig::Tor(c) => {
                put("family", &c.family);
            }
            HopConfig::Psiphon(c) => {
                put("sidecar_path", &c.sidecar_path);
                put("family", &c.family);
            }
            HopConfig::Relay(c) => {
                put("family", &c.family);
            }
            HopConfig::Mock(c) => {
                put("family", &c.family);
            }
            HopConfig::Plugin(c) => {
                put("family", &c.family);
                for (k, v) in &c.fields {
                    put(k, v);
                }
            }
        }
        cfg
    }
}

/// `{"kind", ...fields}` wire shape, identical to the former
/// `#[serde(tag = "kind")]` derive (tag first), extended to plugin kinds.
/// Hand-written because the tag is data (the registered kind), not a
/// fixed variant name (SC-002c).
impl Serialize for HopConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        fn inner(v: serde_json::Value) -> BTreeMap<String, serde_json::Value> {
            match v {
                serde_json::Value::Object(o) => o.into_iter().collect(),
                _ => BTreeMap::new(),
            }
        }
        let kind = self.kind().to_string();
        let fields: BTreeMap<String, serde_json::Value> = match self {
            HopConfig::Wireguard(c) => {
                inner(serde_json::to_value(c).map_err(serde::ser::Error::custom)?)
            }
            HopConfig::Masque(c) => {
                inner(serde_json::to_value(c).map_err(serde::ser::Error::custom)?)
            }
            HopConfig::Tor(c) => inner(serde_json::to_value(c).map_err(serde::ser::Error::custom)?),
            HopConfig::Psiphon(c) => {
                inner(serde_json::to_value(c).map_err(serde::ser::Error::custom)?)
            }
            HopConfig::Relay(c) => {
                inner(serde_json::to_value(c).map_err(serde::ser::Error::custom)?)
            }
            HopConfig::Mock(c) => {
                inner(serde_json::to_value(c).map_err(serde::ser::Error::custom)?)
            }
            HopConfig::Plugin(c) => {
                let mut m = BTreeMap::new();
                m.insert(
                    "family".to_string(),
                    serde_json::Value::String(c.family.clone()),
                );
                for (k, v) in &c.fields {
                    m.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
                m
            }
        };
        let mut map = serializer.serialize_map(Some(fields.len() + 1))?;
        map.serialize_entry("kind", &kind)?;
        for (k, v) in &fields {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

fn scalar_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl<'de> Deserialize<'de> for HopConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let mut map = BTreeMap::<String, serde_json::Value>::deserialize(deserializer)?;
        let kind = map
            .remove("kind")
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or_else(|| D::Error::missing_field("kind"))?
            .to_string();
        // `id` rides alongside under `HopSpec`'s flatten; builtin structs
        // ignore it exactly as before (they declare no deny list).
        let value = serde_json::Value::Object(map.clone().into_iter().collect());
        let builtin = |t: serde_json::Value,
                       allow: &'static [&'static str]|
         -> Result<serde_json::Value, D::Error> {
            for k in t.as_object().map(|o| o.keys()).into_iter().flatten() {
                if k != "id" && !allow.contains(&k.as_str()) {
                    return Err(D::Error::unknown_field(k.as_str(), allow));
                }
            }
            Ok(t)
        };
        Ok(match kind.as_str() {
            "wireguard" => HopConfig::Wireguard(
                serde_json::from_value(builtin(
                    value,
                    &[
                        "peer",
                        "import_ref",
                        "import",
                        "obfuscation",
                        "family",
                        "endpoint",
                    ],
                )?)
                .map_err(D::Error::custom)?,
            ),
            "masque" => HopConfig::Masque(
                serde_json::from_value(builtin(
                    value,
                    &["alpn", "obfuscation", "family", "endpoint"],
                )?)
                .map_err(D::Error::custom)?,
            ),
            "tor" => HopConfig::Tor(
                serde_json::from_value(builtin(value, &["family"])?).map_err(D::Error::custom)?,
            ),
            "psiphon" => HopConfig::Psiphon(
                serde_json::from_value(builtin(value, &["sidecar_path", "family"])?)
                    .map_err(D::Error::custom)?,
            ),
            "relay" => HopConfig::Relay(
                serde_json::from_value(builtin(value, &["family"])?).map_err(D::Error::custom)?,
            ),
            "mock" => HopConfig::Mock(
                serde_json::from_value(builtin(value, &["family"])?).map_err(D::Error::custom)?,
            ),
            other => {
                map.remove("id");
                let family = map
                    .remove("family")
                    .map(|v| scalar_string(&v))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "dual".to_string());
                let fields = map
                    .into_iter()
                    .map(|(k, v)| (k, scalar_string(&v)))
                    .collect();
                HopConfig::Plugin(PluginHopConfig {
                    kind: other.to_string(),
                    family,
                    fields,
                })
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardConfig {
    /// warp | imported | awg
    pub peer: String,
    pub import_ref: Option<String>,
    pub obfuscation: Option<String>,
    pub family: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasqueConfig {
    /// h3 | h2
    pub alpn: String,
    pub obfuscation: Option<String>,
    pub family: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorConfig {
    pub family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsiphonConfig {
    pub sidecar_path: String,
    pub family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    pub family: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockConfig {
    pub family: String,
}

/// Unknown-field probe used by tests: deny_unknown_fields everywhere.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fields_are_deserialization_errors() {
        let toml = r#"
kind = "tor"
family = "dual"
bogus_key = "nope"
"#;
        let err = super::parse_toml_strict(toml).unwrap_err();
        assert!(err.contains("bogus_key"), "got: {err}");
    }

    #[test]
    fn tor_round_trip() {
        let spec = HopSpec {
            id: "tor0".into(),
            config: HopConfig::Tor(TorConfig {
                family: "dual".into(),
            }),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: HopSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
        assert_eq!(back.config.kind(), "tor");
    }
}
