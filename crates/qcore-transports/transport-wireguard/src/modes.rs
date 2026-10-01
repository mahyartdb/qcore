//! Peer-mode resolution: WARP, imported, AmneziaWG (FR-004, FR-009).
//!
//! - `peer=warp`: Cloudflare WARP peer; endpoint + keys from fields (identity
//!   registration in a later milestone; loopback/tests pass explicit keys).
//! - `peer=imported`: user-imported config via `import_ref` (US2 import store).
//! - `peer=awg`: AmneziaWG mode against a supporting peer (US2 modes + US5
//!   obfuscation decorator).

use crate::WgParams;
use qcore_transport_api::HopConfig;
use std::net::SocketAddr;

/// Parse `xx:xx:...:xx` hex into 32 bytes.
pub fn parse_key_hex(s: &str) -> Result<[u8; 32], String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("key must be 64 hex chars".to_string());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Resolve factory fields into peer parameters.
pub fn resolve(cfg: &HopConfig) -> Result<WgParams, String> {
    let peer = cfg.get("peer").unwrap_or("warp");
    match peer {
        "warp" | "imported" | "awg" => {
            // FR-021: server-negotiated AWG params only against a supporting
            // peer — never on plain wireguard/WARP.
            if peer != "awg" {
                if let Some(k) = cfg.fields.keys().find(|k| k.starts_with("awg_")) {
                    return Err(format!(
                        "field `{k}` is AmneziaWG-only and needs `peer=awg` (supporting peer required)"
                    ));
                }
            }
            resolve_fields(cfg, peer)
        }
        other => Err(format!(
            "unknown wireguard peer mode `{other}` (warp|imported|awg)"
        )),
    }
}

fn resolve_fields(cfg: &HopConfig, peer: &str) -> Result<WgParams, String> {
    let has_import = cfg
        .get("import")
        .or_else(|| cfg.get("import_ref"))
        .is_some();
    if peer == "imported" && !has_import {
        return Err("peer=imported requires import=<ref> (see `qcore import`)".to_string());
    }
    // Import-backed hops get endpoint/keys merged by the engine (US2 import
    // store); without merged material the hop cannot build.
    if (peer == "imported" || peer == "awg") && has_import {
        let missing = ["endpoint", "private_key", "peer_public_key"]
            .iter()
            .find(|k| cfg.get(k).is_none());
        if let Some(k) = missing {
            return Err(format!(
                "peer={peer} import has no `{k}` merged (re-import the .conf)"
            ));
        }
    }
    if peer == "awg" && cfg.get("awg_params").is_none() && cfg.get("import").is_none() {
        // Loopback/tests may pass raw keys; real AWG peers need params (US5).
    }
    let endpoint: SocketAddr = cfg
        .get("endpoint")
        .ok_or_else(|| "wireguard hop requires endpoint=<ip:port>".to_string())?
        .parse()
        .map_err(|e: std::net::AddrParseError| format!("bad endpoint: {e}"))?;
    let private_key = cfg
        .get("private_key")
        .ok_or_else(|| {
            "wireguard hop requires private_key=<64 hex> (identity store milestone)".to_string()
        })
        .and_then(parse_key_hex)?;
    let peer_public_key = cfg
        .get("peer_public_key")
        .ok_or_else(|| "wireguard hop requires peer_public_key=<64 hex>".to_string())
        .and_then(parse_key_hex)?;
    let preshared_key = cfg.get("preshared_key").map(parse_key_hex).transpose()?;
    let keepalive = cfg
        .get("keepalive")
        .map(|s| s.parse::<u16>().map_err(|e| e.to_string()))
        .transpose()?;
    let awg = if peer == "awg" {
        Some(crate::awg::parse_fields(cfg)?)
    } else {
        None
    };
    let noize = qcore_transport_api::obfuscate::NoizeParams::try_from_fields(&cfg.fields)
        .map_err(|e| format!("wireguard hop: {e}"))?;
    Ok(WgParams {
        peer_endpoint: endpoint,
        private_key,
        peer_public_key,
        preshared_key,
        keepalive,
        awg,
        noize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_hex_rejected() {
        assert!(parse_key_hex("zz").is_err());
        assert!(parse_key_hex(&"ab".repeat(31)).is_err());
        assert!(parse_key_hex(&"ab".repeat(32)).is_ok());
    }

    fn cfg(pairs: &[(&str, &str)]) -> HopConfig {
        let mut c = HopConfig::new("wireguard");
        for (k, v) in pairs {
            c.fields.insert(k.to_string(), v.to_string());
        }
        c
    }

    fn keys() -> [(&'static str, String); 3] {
        let k = "ab".repeat(32);
        [
            ("endpoint", "127.0.0.1:51820".to_string()),
            ("private_key", k.clone()),
            ("peer_public_key", k),
        ]
    }

    #[test]
    fn awg_fields_forbidden_on_plain_modes() {
        for peer in ["warp", "imported"] {
            let owned = keys();
            let mut pairs = vec![("peer", peer), ("import", "x"), ("awg_jc", "6")];
            pairs.extend(owned.iter().map(|(k, v)| (*k, v.as_str())));
            let err = resolve(&cfg(&pairs)).expect_err("FR-021");
            assert!(err.contains("awg_jc"), "names field: {err}");
            assert!(err.contains("peer=awg"), "names remedy: {err}");
        }
    }

    #[test]
    fn imported_requires_ref() {
        let owned = keys();
        let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        // Default peer is warp; force imported without ref.
        let mut v = vec![("peer", "imported")];
        v.extend(pairs);
        let err = resolve(&cfg(&v)).expect_err("import required");
        assert!(err.contains("import=<ref>"), "{err}");
    }

    #[test]
    fn imported_with_material_resolves() {
        let k = "ab".repeat(32);
        let p = resolve(&cfg(&[
            ("peer", "imported"),
            ("import", "wg-home"),
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
        ]))
        .expect("material resolves");
        assert!(p.awg.is_none());
    }

    #[test]
    fn awg_carries_params() {
        let k = "ab".repeat(32);
        let p = resolve(&cfg(&[
            ("peer", "awg"),
            ("import", "awg-home"),
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
            ("awg_jc", "6"),
            ("awg_h1", "123"),
        ]))
        .expect("awg resolves");
        let a = p.awg.expect("params carried");
        assert_eq!((a.jc, a.h1), (6, 123));
    }

    #[test]
    fn bad_awg_value_names_field() {
        let k = "ab".repeat(32);
        let err = resolve(&cfg(&[
            ("peer", "awg"),
            ("endpoint", "127.0.0.1:51820"),
            ("private_key", &k),
            ("peer_public_key", &k),
            ("awg_jc", "many"),
        ]))
        .expect_err("bad awg value");
        assert!(err.contains("awg_jc"), "{err}");
    }
}
