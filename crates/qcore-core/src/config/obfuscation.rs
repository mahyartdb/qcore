//! Obfuscation profiles as data (US5 T072/T073).
//!
//! Profiles resolve per hop: the profile must exist, its family must be in
//! the transport descriptor's `obfuscation_families` (the compatibility
//! source of truth), and its `compatible_modes` must include the hop mode.
//! Anything else fails closed naming the profile and the hop (FR-021).
//! Resolution yields factory fields merged after import material (chain >
//! import > profile) so transports stay file-IO-free.

use crate::chain::ChainError;
use crate::config::profile_dir::ProfileDirs;
use crate::registry::TransportRegistry;
use std::collections::{BTreeMap, HashMap};

/// Shipped `profiles/obfuscation.toml`: profile-dir overrides replace it
/// wholesale per FR-028.
pub const SHIPPED_OBFUSCATION_TOML: &str = include_str!("../../../../profiles/obfuscation.toml");

/// Profile family: noize (wireguard + masque) or awg (`peer=awg` only).
///
/// Version window (map #7): this enum parallels the transport API's
/// `ObfuscationFamily` (the compatibility source of truth) on purpose.
/// Unifying the two types — or typing the stringly `family: String` fields
/// on hop configs — is a breaking change and lands only in a major version
/// window with migration notes. Until then: keep the variants in sync via
/// the `From` impls below plus the parity test, and match on variants,
/// never on `Debug`/display strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfFamily {
    Noize,
    Awg,
}

impl ObfFamily {
    /// Canonical profile-file spelling (`family = "..."`).
    pub fn as_str(self) -> &'static str {
        match self {
            ObfFamily::Noize => "noize",
            ObfFamily::Awg => "awg",
        }
    }

    /// Parse a profile-file spelling; `None` means unknown (callers fail
    /// closed naming the profile and the bad value).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "noize" => Some(ObfFamily::Noize),
            "awg" => Some(ObfFamily::Awg),
            _ => None,
        }
    }
}

impl From<ObfFamily> for qcore_transport_api::ObfuscationFamily {
    fn from(f: ObfFamily) -> Self {
        match f {
            ObfFamily::Noize => qcore_transport_api::ObfuscationFamily::Noize,
            ObfFamily::Awg => qcore_transport_api::ObfuscationFamily::Awg,
        }
    }
}

impl From<qcore_transport_api::ObfuscationFamily> for ObfFamily {
    fn from(f: qcore_transport_api::ObfuscationFamily) -> Self {
        match f {
            qcore_transport_api::ObfuscationFamily::Noize => ObfFamily::Noize,
            qcore_transport_api::ObfuscationFamily::Awg => ObfFamily::Awg,
        }
    }
}

/// One compatible mode entry: kind plus optional peer/alpn qualifier.
#[derive(Debug, Clone)]
pub struct ModeMatch {
    pub kind: String,
    pub peer: Option<String>,
    pub alpn: Option<String>,
}

/// A param value: int, [min, max] range (midpoint), bool, or string.
#[derive(Debug, Clone)]
pub enum ParamVal {
    Int(i64),
    Range(i64, i64),
    Bool(bool),
    Str(String),
}

impl ParamVal {
    fn from_toml(v: &toml::Value) -> Result<Self, String> {
        match v {
            toml::Value::Integer(i) => Ok(ParamVal::Int(*i)),
            toml::Value::Boolean(b) => Ok(ParamVal::Bool(*b)),
            toml::Value::String(s) => Ok(ParamVal::Str(s.clone())),
            toml::Value::Array(a) if a.len() == 2 => {
                let lo = a[0]
                    .as_integer()
                    .ok_or_else(|| "range bounds must be ints".to_string())?;
                let hi = a[1]
                    .as_integer()
                    .ok_or_else(|| "range bounds must be ints".to_string())?;
                if lo > hi {
                    return Err(format!("range [{lo}, {hi}] is inverted"));
                }
                Ok(ParamVal::Range(lo, hi))
            }
            other => Err(format!(
                "unsupported param value `{other}` (int|[lo,hi]|bool|string)"
            )),
        }
    }

    /// Deterministic scalar: ints/bools/strings as-is, ranges at midpoint
    /// (`midpoint` cannot overflow, unlike `(lo + hi) / 2` on extremes —
    /// profile files are untrusted input).
    pub fn scalar(&self) -> String {
        match self {
            ParamVal::Int(i) => i.to_string(),
            ParamVal::Range(lo, hi) => lo.midpoint(*hi).to_string(),
            ParamVal::Bool(b) => b.to_string(),
            ParamVal::Str(s) => s.clone(),
        }
    }
}

/// A named obfuscation profile.
#[derive(Debug, Clone)]
pub struct ObfuscationProfile {
    pub name: String,
    pub family: ObfFamily,
    pub compatible_modes: Vec<ModeMatch>,
    pub params: BTreeMap<String, ParamVal>,
}

/// Resolved application for one hop: profile name plus factory fields.
#[derive(Debug, Clone, Default)]
pub struct ObfApplication {
    pub profile: String,
    pub fields: Vec<(String, String)>,
}

/// Load all profiles: profile-dir override when present, else shipped data.
/// A present-but-unreadable override (permissions, directory, transient IO)
/// fails closed — only `NotFound` (absent file) falls back to shipped data.
pub fn load_profiles(dirs: &ProfileDirs) -> Result<BTreeMap<String, ObfuscationProfile>, String> {
    let path = dirs.profile_dir.join("obfuscation.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SHIPPED_OBFUSCATION_TOML.to_string(),
        Err(e) => {
            return Err(format!(
                "obfuscation.toml: cannot read {}: {e}",
                path.display()
            ))
        }
    };
    parse_profiles_toml(&text)
}

fn parse_profiles_toml(text: &str) -> Result<BTreeMap<String, ObfuscationProfile>, String> {
    let v: toml::Value =
        toml::from_str(text).map_err(|e| format!("obfuscation.toml invalid: {e}"))?;
    let t = v
        .as_table()
        .ok_or_else(|| "obfuscation.toml must be a table".to_string())?;
    let mut out = BTreeMap::new();
    for (name, prof) in t {
        let pt = prof
            .as_table()
            .ok_or_else(|| format!("profile `{name}` must be a table"))?;
        // Profile-level typos (`familiy = …`) previously loaded silently
        // while the operator believed tuning applied (params ride opaquely
        // to factories, so a typo becomes a no-op field). Fail closed naming
        // the key, same standard as mode keys below. `params` contents stay
        // opaque by design (plugin extensibility lives there).
        for k in pt.keys() {
            if k != "family" && k != "compatible_modes" && k != "params" {
                return Err(format!("profile `{name}` has unknown key `{k}`"));
            }
        }
        let family = match pt.get("family").and_then(|x| x.as_str()) {
            Some(s) => ObfFamily::parse(s)
                .ok_or_else(|| format!("profile `{name}` family `{s}` (noize|awg)"))?,
            None => return Err(format!("profile `{name}` missing `family`")),
        };
        let modes = pt
            .get("compatible_modes")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("profile `{name}` missing `compatible_modes`"))?;
        let mut compatible_modes = Vec::new();
        for m in modes {
            let mt = m
                .as_table()
                .ok_or_else(|| format!("profile `{name}` mode must be a table"))?;
            for k in mt.keys() {
                if k != "kind" && k != "peer" && k != "alpn" {
                    return Err(format!("profile `{name}` mode has unknown key `{k}`"));
                }
            }
            compatible_modes.push(ModeMatch {
                kind: mt
                    .get("kind")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| format!("profile `{name}` mode without `kind`"))?
                    .to_string(),
                peer: mt.get("peer").and_then(|x| x.as_str()).map(str::to_string),
                alpn: mt.get("alpn").and_then(|x| x.as_str()).map(str::to_string),
            });
        }
        let mut params = BTreeMap::new();
        if let Some(p) = pt.get("params") {
            let ptab = p
                .as_table()
                .ok_or_else(|| format!("profile `{name}` params must be a table"))?;
            for (k, val) in ptab {
                params.insert(
                    k.clone(),
                    ParamVal::from_toml(val)
                        .map_err(|e| format!("profile `{name}` param `{k}`: {e}"))?,
                );
            }
        }
        out.insert(
            name.clone(),
            ObfuscationProfile {
                name: name.clone(),
                family,
                compatible_modes,
                params,
            },
        );
    }
    Ok(out)
}

/// Hop mode for compatibility: (kind, peer-or-default, alpn-or-default).
fn hop_mode(hop: &crate::config::HopSpec) -> (String, String, String) {
    match &hop.config {
        crate::config::HopConfig::Wireguard(c) => (
            "wireguard".to_string(),
            if c.peer.is_empty() {
                "warp".to_string()
            } else {
                c.peer.clone()
            },
            String::new(),
        ),
        crate::config::HopConfig::Masque(c) => (
            "masque".to_string(),
            String::new(),
            if c.alpn.is_empty() {
                "h3".to_string()
            } else {
                c.alpn.clone()
            },
        ),
        other => (other.kind().to_string(), String::new(), String::new()),
    }
}

fn mode_matches(entry: &ModeMatch, kind: &str, peer: &str, alpn: &str) -> bool {
    if entry.kind != kind {
        return false;
    }
    if let Some(p) = &entry.peer {
        if p != peer {
            return false;
        }
    }
    if let Some(a) = &entry.alpn {
        if a != alpn {
            return false;
        }
    }
    true
}

/// Resolve obfuscation for every hop that selects a profile (FR-021 gate).
/// Returns per-hop-id applications; hops without `obfuscation=` are absent.
pub fn resolve_for_chain(
    dirs: &ProfileDirs,
    registry: &TransportRegistry,
    hops: &[crate::config::HopSpec],
) -> Result<HashMap<String, ObfApplication>, ChainError> {
    let profiles = load_profiles(dirs).map_err(|e| ChainError::new(None, None, e, None))?;
    let mut out = HashMap::new();
    for hop in hops {
        let selected = match &hop.config {
            crate::config::HopConfig::Wireguard(c) => c.obfuscation.clone(),
            crate::config::HopConfig::Masque(c) => c.obfuscation.clone(),
            // Plugin hops (SC-002c) carry `obfuscation=` opaquely in fields.
            crate::config::HopConfig::Plugin(c) => c.fields.get("obfuscation").cloned(),
            _ => None,
        };
        let Some(name) = selected else { continue };
        let err = |reason: String| ChainError::new(None, Some(hop.id.clone()), reason, None);
        let profile = profiles
            .get(&name)
            .ok_or_else(|| err(format!("unknown obfuscation profile `{name}`")))?;
        let (kind, peer, alpn) = hop_mode(hop);
        // Family must be in the transport descriptor (source of truth).
        // Matched on variants via the `From` bridge, not Debug strings: a
        // renamed variant fails to compile here instead of silently
        // passing at runtime.
        let want = qcore_transport_api::ObfuscationFamily::from(profile.family);
        let descriptor_ok = registry
            .factory(&kind)
            .map(|f| f.descriptor().obfuscation_families.contains(&want))
            .unwrap_or(false);
        if !descriptor_ok {
            return Err(err(format!(
                "obfuscation profile `{name}` (family {}) incompatible with transport `{kind}`",
                profile.family.as_str()
            )));
        }
        if !profile
            .compatible_modes
            .iter()
            .any(|m| mode_matches(m, &kind, &peer, &alpn))
        {
            return Err(err(format!(
                "obfuscation profile `{name}` excludes mode `{}` (FR-021)",
                if peer.is_empty() && alpn.is_empty() {
                    kind.clone()
                } else if !peer.is_empty() {
                    format!("{kind} peer={peer}")
                } else {
                    format!("{kind} alpn={alpn}")
                }
            )));
        }
        out.insert(
            hop.id.clone(),
            ObfApplication {
                profile: name,
                fields: profile_fields(profile),
            },
        );
    }
    Ok(out)
}

/// Factory fields for a profile (noize_* / awg_* namespaces; import material
/// wins via or_insert precedence in lifecycle).
fn profile_fields(profile: &ObfuscationProfile) -> Vec<(String, String)> {
    let prefix = match profile.family {
        ObfFamily::Noize => "noize_",
        ObfFamily::Awg => "awg_",
    };
    let mut fields = Vec::new();
    for (k, v) in &profile.params {
        match v {
            ParamVal::Range(lo, hi) if prefix == "noize_" && k == "junk_size" => {
                fields.push(("noize_junk_min".into(), lo.to_string()));
                fields.push(("noize_junk_max".into(), hi.to_string()));
            }
            ParamVal::Range(lo, hi) if prefix == "awg_" && k == "content_padding" => {
                fields.push(("awg_content_padding_min".into(), lo.to_string()));
                fields.push(("awg_content_padding_max".into(), hi.to_string()));
            }
            ParamVal::Range(lo, hi) => {
                // Other ranges (s1..s4): deterministic midpoint scalar.
                fields.push((format!("{prefix}{k}"), lo.midpoint(*hi).to_string()));
            }
            _ => fields.push((format!("{prefix}{k}"), v.scalar())),
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_profiles_parse() {
        let profiles = parse_profiles_toml(SHIPPED_OBFUSCATION_TOML).expect("shipped parses");
        for name in [
            "masque-balanced",
            "masque-aggressive",
            "awg-balanced",
            "awg-aggressive",
            "awg-off",
        ] {
            assert!(profiles.contains_key(name), "ships {name}");
        }
        assert_eq!(profiles["awg-balanced"].params["jc"].scalar(), "6");
    }

    #[test]
    fn unknown_profile_key_fails_closed() {
        // `familiy` (typo) must not load silently while the operator believes
        // tuning applied; `params` contents stay opaque (plugin namespace).
        let bad = "[myprof]\nfamily = \"noize\"\nfamiliy = \"noize\"\ncompatible_modes = [{kind = \"masque\"}]\n";
        let err = parse_profiles_toml(bad).unwrap_err();
        assert!(err.contains("familiy"), "names the key: {err}");
        let ok = "[myprof]\nfamily = \"noize\"\ncompatible_modes = [{kind = \"masque\"}]\n[myprof.params]\njunk_size = [1, 10]\n";
        assert!(parse_profiles_toml(ok).is_ok());
    }

    #[test]
    fn obf_family_parity_with_transport_api() {
        // Version-window guard (map #7): the parallel enums must spell and
        // convert identically. Adding a variant to either side breaks this
        // test until the `From` impls (and the window plan) are updated.
        for (core, api) in [
            (
                ObfFamily::Noize,
                qcore_transport_api::ObfuscationFamily::Noize,
            ),
            (ObfFamily::Awg, qcore_transport_api::ObfuscationFamily::Awg),
        ] {
            assert_eq!(core.as_str(), api.as_str());
            assert_eq!(ObfFamily::parse(core.as_str()), Some(core));
            assert_eq!(
                qcore_transport_api::ObfuscationFamily::parse(api.as_str()),
                Some(api)
            );
            assert_eq!(qcore_transport_api::ObfuscationFamily::from(core), api);
            assert_eq!(ObfFamily::from(api), core);
        }
        assert_eq!(ObfFamily::parse("nope"), None);
        assert_eq!(qcore_transport_api::ObfuscationFamily::parse("nope"), None);
    }

    #[test]
    fn extreme_range_midpoint_cannot_overflow() {
        // (lo + hi) / 2 would overflow here; midpoint is exact.
        let r = ParamVal::Range(i64::MAX - 1, i64::MAX);
        let expected = (((i64::MAX - 1) as i128 + i64::MAX as i128) / 2).to_string();
        assert_eq!(r.scalar(), expected);
        assert_eq!(ParamVal::Range(4, 9).scalar(), "6");
    }

    #[test]
    fn unreadable_override_fails_closed_only_not_found_falls_back() {
        // Absent override falls back to shipped data.
        let base = std::env::temp_dir().join(format!("qcore-obf-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dirs = ProfileDirs::resolve(None, Some(base.join("prof")));
        let profiles = load_profiles(&dirs).expect("missing falls back");
        assert!(profiles.contains_key("masque-balanced"));
        // Present-but-unreadable (a directory at the file path: `IsADirectory`,
        // not `NotFound`) fails closed instead of silently using shipped data.
        let base2 = std::env::temp_dir().join(format!("qcore-obf-unread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base2);
        let prof = base2.join("prof");
        std::fs::create_dir_all(prof.join("obfuscation.toml")).unwrap();
        let dirs2 = ProfileDirs::resolve(None, Some(prof));
        let err = load_profiles(&dirs2).unwrap_err();
        assert!(
            err.contains("cannot read") && err.contains("obfuscation.toml"),
            "fail closed: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&base2);
    }
}
