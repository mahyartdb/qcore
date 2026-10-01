//! Bring-up injection (002 last mile): merge stored provider identities and
//! cached endpoints into hop factory configs, in memory only.
//!
//! Precedence at merge time (lifecycle.rs): explicit chain values win;
//! identity material fills `endpoint` + keys for WARP hops and `endpoint`
//! for MASQUE hops. Everything fails closed naming the hop and the fix
//! (`register`, `renew`, `scan`, or an explicit `endpoint=`).

use crate::config::profile_dir::ProfileDirs;
use crate::config::{HopConfig, HopSpec};
use crate::identity::store::{load, role_name, IdentityRole};
use crate::scan::cache::read_winners;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Factory fields injected for one hop (mirrors `ImportMaterial` shape).
/// Key values are `Zeroizing`: the map drops after bring-up and the hex
/// copies of 32-byte secrets wipe instead of lingering as plain `String`s
/// (the one plain copy that must exist lives in the factory config the
/// transport consumes, same as any authored `private_key=` value).
pub struct IdentityMaterial {
    pub fields: Vec<(String, Zeroizing<String>)>,
}

/// Resolve identity material for every hop that needs it. Returns hop-id →
/// fields, or the first `(hop_id, actionable message)` failure.
pub fn materials_for_chain(
    dirs: &ProfileDirs,
    hops: &[HopSpec],
) -> Result<HashMap<String, IdentityMaterial>, (String, String)> {
    let mut out = HashMap::new();
    let mut warp_seen = 0u32;
    for hop in hops {
        match &hop.config {
            HopConfig::Wireguard(c) if c.peer == "warp" && c.import_ref.is_none() => {
                let role = match warp_seen {
                    0 => IdentityRole::Outer,
                    1 => IdentityRole::Inner,
                    _ => {
                        return Err((
                            hop.id.clone(),
                            "more than two warp hops need identities (outer+inner only)"
                                .to_string(),
                        ))
                    }
                };
                warp_seen += 1;
                let name = role_name(role);
                let id = match load(dirs, role) {
                    Some(id) if !id.refused => id,
                    Some(_) => {
                        return Err((
                            hop.id.clone(),
                            format!(
                            "stored {name} identity was refused — run `qcore renew` to replace it"
                        ),
                        ))
                    }
                    None => {
                        return Err((
                            hop.id.clone(),
                            format!("no stored {name} identity — run `qcore register` first"),
                        ))
                    }
                };
                let endpoint = c
                    .endpoint
                    .clone()
                    .or_else(|| winner_endpoint(dirs, &["wireguard", "warp", "gool"], &c.family));
                let Some(endpoint) = endpoint else {
                    return Err((
                        hop.id.clone(),
                        "no endpoint for this hop — run `qcore scan --transport warp` or add endpoint=<ip:port>".to_string(),
                    ));
                };
                // Keys cross the boundary as hex (transport shape); the
                // base64 originals stay in the secret store. Decoded and
                // re-encoded byte-for-byte here, never logged.
                let private_hex = b64_to_hex(id.private_key_b64.expose(), &hop.id, name)?;
                let peer_hex = b64_to_hex(id.peer_key_b64.as_bytes(), &hop.id, name)?;
                out.insert(
                    hop.id.clone(),
                    IdentityMaterial {
                        fields: vec![
                            ("endpoint".to_string(), Zeroizing::new(endpoint)),
                            ("private_key".to_string(), private_hex),
                            ("peer_public_key".to_string(), peer_hex),
                        ],
                    },
                );
            }
            HopConfig::Masque(c) if c.endpoint.is_none() => {
                let endpoint = winner_endpoint(dirs, &["masque"], &c.family);
                let Some(endpoint) = endpoint else {
                    return Err((
                        hop.id.clone(),
                        "no endpoint for this hop — run `qcore scan --transport masque` or add endpoint=<ip:port>".to_string(),
                    ));
                };
                out.insert(
                    hop.id.clone(),
                    IdentityMaterial {
                        fields: vec![("endpoint".to_string(), Zeroizing::new(endpoint))],
                    },
                );
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Newest verified winner across the transport keys, honoring the hop
/// family (`dual` accepts either; otherwise exact match).
fn winner_endpoint(dirs: &ProfileDirs, keys: &[&str], family: &str) -> Option<String> {
    let winners = read_winners(dirs);
    keys.iter()
        .filter_map(|k| winners.get(*k))
        .filter(|w| family == "dual" || w.family == family)
        .max_by_key(|w| w.verified_at_ms)
        .and_then(|w| w.socket_addr())
        .map(|a| a.to_string())
}

/// Base64 key material → lowercase hex. Corrupt material fails toward
/// re-registration, never toward a half-built tunnel. Shares the 32-byte
/// validation with the import gate (`b64_decode_32`) instead of re-owning it.
/// `Zeroizing` so the transient hex wipes with the material map.
fn b64_to_hex(b64: &[u8], hop_id: &str, role: &str) -> Result<Zeroizing<String>, (String, String)> {
    let corrupt = || {
        (
            hop_id.to_string(),
            format!("stored {role} identity is corrupt — run `qcore register` to replace it"),
        )
    };
    let s = std::str::from_utf8(b64).map_err(|_| corrupt())?;
    let raw = crate::config::import::b64_decode_32(s).map_err(|_| corrupt())?;
    Ok(Zeroizing::new(crate::config::import::hex_encode(&raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::secret::SecretString;
    use crate::config::{HopConfig, MasqueConfig, WireguardConfig};
    use crate::identity::model::ProviderIdentity;
    use crate::scan::cache::{record_winner, TransportWinner};

    fn dirs(tag: &str) -> ProfileDirs {
        let dir = std::env::temp_dir().join(format!(
            "qcore-inject-{tag}-{}-{}",
            std::process::id(),
            crate::identity::model::now_ms()
        ));
        ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")))
    }

    fn warp_hop(id: &str, endpoint: Option<&str>) -> HopSpec {
        HopSpec {
            id: id.to_string(),
            config: HopConfig::Wireguard(WireguardConfig {
                peer: "warp".to_string(),
                import_ref: None,
                obfuscation: None,
                family: "dual".to_string(),
                endpoint: endpoint.map(str::to_string),
            }),
        }
    }

    fn save_identity(dirs: &ProfileDirs, role: IdentityRole, device: &str) {
        save_identity_with_base(dirs, role, device, 1u8);
    }

    fn save_identity_with_base(dirs: &ProfileDirs, role: IdentityRole, device: &str, base: u8) {
        // 32 key bytes from `base` (valid, deterministic, distinct per role).
        use base64::Engine as _;
        let bytes: Vec<u8> = (0u8..32).map(|i| base.wrapping_add(i)).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        crate::identity::store::save(
            dirs,
            role,
            &ProviderIdentity {
                device_id: device.to_string(),
                access_token: SecretString::new("tok"),
                private_key_b64: SecretString::new(b64.clone()),
                peer_key_b64: b64,
                interface_v4: "172.16.0.2".to_string(),
                interface_v6: "2606:4700:110::2".to_string(),
                masque: None,
                refused: false,
                license_upgraded: false,
            },
        )
        .expect("saves");
    }

    // (matched, not expect/unwrap_err: neither the Ok map — it carries key
    // hex — nor the Err tuple implements Debug, on purpose.)
    fn resolve(
        dirs: &ProfileDirs,
        hops: &[HopSpec],
    ) -> std::collections::HashMap<String, IdentityMaterial> {
        match materials_for_chain(dirs, hops) {
            Ok(m) => m,
            Err((hop, msg)) => panic!("resolve failed for {hop}: {msg}"),
        }
    }

    fn resolve_err(dirs: &ProfileDirs, hops: &[HopSpec]) -> (String, String) {
        match materials_for_chain(dirs, hops) {
            Ok(_) => panic!("expected failure, but it resolved"),
            Err(e) => e,
        }
    }

    fn cache_winner(dirs: &ProfileDirs, transport: &str, addr: &str) {
        record_winner(
            dirs,
            transport,
            TransportWinner {
                address: addr.to_string(),
                profile: "balanced".to_string(),
                verified_at_ms: crate::identity::model::now_ms(),
                family: "ipv4".to_string(),
            },
        )
        .expect("records");
    }

    #[test]
    fn warp_hop_gets_endpoint_and_hex_keys() {
        let d = dirs("warp");
        save_identity(&d, IdentityRole::Outer, "dev-1");
        cache_winner(&d, "wireguard", "162.159.192.1:2408");
        let map = resolve(&d, &[warp_hop("wireguard-0", None)]);
        let fields: std::collections::BTreeMap<_, _> =
            map["wireguard-0"].fields.iter().cloned().collect();
        assert_eq!(fields["endpoint"].as_str(), "162.159.192.1:2408");
        // bytes 0x01..0x20 as 64 lowercase hex chars.
        let expect: String = (1u8..=32).map(|b| format!("{b:02x}")).collect();
        assert_eq!(fields["private_key"].as_str(), expect);
        assert_eq!(fields["peer_public_key"].as_str(), expect);
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn explicit_endpoint_wins_over_cache() {
        let d = dirs("explicit");
        save_identity(&d, IdentityRole::Outer, "dev-1");
        cache_winner(&d, "warp", "162.159.192.1:2408");
        let map = resolve(&d, &[warp_hop("wireguard-0", Some("1.2.3.4:2408"))]);
        let fields: std::collections::BTreeMap<_, _> =
            map["wireguard-0"].fields.iter().cloned().collect();
        assert_eq!(fields["endpoint"].as_str(), "1.2.3.4:2408");
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn pair_assigns_outer_then_inner() {
        let d = dirs("pair");
        save_identity_with_base(&d, IdentityRole::Outer, "dev-outer", 1u8);
        save_identity_with_base(&d, IdentityRole::Inner, "dev-inner", 0xA0u8);
        cache_winner(&d, "warp", "162.159.192.1:2408");
        let map = resolve(
            &d,
            &[warp_hop("wireguard-0", None), warp_hop("wireguard-1", None)],
        );
        let outer: std::collections::BTreeMap<_, _> =
            map["wireguard-0"].fields.iter().cloned().collect();
        let inner: std::collections::BTreeMap<_, _> =
            map["wireguard-1"].fields.iter().cloned().collect();
        // Separately registered identities: distinct key material per hop.
        assert_ne!(outer["private_key"].as_str(), inner["private_key"].as_str());
        assert!(outer["private_key"].as_str().starts_with("01"));
        assert!(inner["private_key"].as_str().starts_with("a0"));
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn failures_name_the_fix() {
        let d = dirs("fail");
        // No identity at all.
        let (hop, msg) = resolve_err(&d, &[warp_hop("wireguard-0", None)]);
        assert_eq!(hop, "wireguard-0");
        assert!(msg.contains("register"), "{msg}");
        // Identity but no endpoint anywhere.
        save_identity(&d, IdentityRole::Outer, "dev-1");
        let (_, msg) = resolve_err(&d, &[warp_hop("wireguard-0", None)]);
        assert!(msg.contains("scan"), "{msg}");
        // Masque without endpoint or winner.
        let masque = HopSpec {
            id: "masque-0".to_string(),
            config: HopConfig::Masque(MasqueConfig {
                alpn: "h3".to_string(),
                obfuscation: None,
                family: "dual".to_string(),
                endpoint: None,
            }),
        };
        let (_, msg) = resolve_err(&d, &[masque]);
        assert!(msg.contains("masque"), "{msg}");
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }

    #[test]
    fn masque_uses_cached_winner() {
        let d = dirs("masque");
        cache_winner(&d, "masque", "162.159.192.1:443");
        let masque = HopSpec {
            id: "masque-0".to_string(),
            config: HopConfig::Masque(MasqueConfig {
                alpn: "h2".to_string(),
                obfuscation: None,
                family: "dual".to_string(),
                endpoint: None,
            }),
        };
        let map = resolve(&d, &[masque]);
        let fields: std::collections::BTreeMap<_, _> =
            map["masque-0"].fields.iter().cloned().collect();
        assert_eq!(fields["endpoint"].as_str(), "162.159.192.1:443");
        assert_eq!(fields.len(), 1, "endpoint only — no keys for masque");
        let _ = std::fs::remove_dir_all(&d.config_dir);
    }
}
