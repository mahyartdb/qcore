//! WireGuard-family config export (US2 T062).
//!
//! Export MUST reproduce the parsed import equivalently (FR-024, SC-004):
//! every non-secret value round-trips byte-for-byte. Private keys and
//! preshared secrets are never emitted in plaintext (FR-026) — the redacted
//! form (the CLI default) substitutes `<redacted>`.

use crate::config::import::{AwgParams, ConfigImport};
use std::collections::BTreeMap;

/// Full-fidelity export using the in-memory secrets. `parse(export_plain(a))`
/// reproduces `a` (see the T059 round-trip test).
pub fn export_plain(imp: &ConfigImport) -> String {
    export_with(imp, &|key| {
        imp.secrets
            .get(key)
            .map(|s| String::from_utf8_lossy(s.expose()).into_owned())
            .unwrap_or_else(|| "<missing>".to_string())
    })
}

/// CLI export: values reproduced, secrets replaced with `<redacted>`.
pub fn export_redacted(imp: &ConfigImport) -> String {
    export_with(imp, &|_| "<redacted>".to_string())
}

fn export_with(imp: &ConfigImport, secret: &dyn Fn(&str) -> String) -> String {
    let mut s = String::new();
    s.push_str("[Interface]\n");
    // PrivateKey first (canonical WG order), then the rest alphabetically.
    s.push_str(&format!(
        "PrivateKey = {}\n",
        secret("interface.private_key")
    ));
    let mut keys: Vec<&String> = imp.interface.keys().collect();
    keys.sort();
    for k in keys {
        s.push_str(&format!("{} = {}\n", pretty(k), imp.interface[k]));
    }
    if let Some(a) = &imp.awg {
        s.push_str(&awg_block(a));
    }
    for (i, peer) in imp.peers.iter().enumerate() {
        s.push_str("\n[Peer]\n");
        if let Some(pk) = peer.get("public_key") {
            s.push_str(&format!("PublicKey = {pk}\n"));
        }
        if imp.secrets.contains_key(&format!("peer{i}.preshared_key")) {
            s.push_str(&format!(
                "PresharedKey = {}\n",
                secret(&format!("peer{i}.preshared_key"))
            ));
        }
        let mut keys: Vec<&String> = peer
            .keys()
            .filter(|k| *k != "public_key" && *k != "preshared_key")
            .collect();
        keys.sort();
        for k in keys {
            s.push_str(&format!("{} = {}\n", pretty(k), peer[k.as_str()]));
        }
    }
    s
}

fn awg_block(a: &AwgParams) -> String {
    let mut s = String::new();
    for (k, v) in [
        ("Jc", a.jc.to_string()),
        ("Jmin", a.jmin.to_string()),
        ("Jmax", a.jmax.to_string()),
        ("S1", a.s1.to_string()),
        ("S2", a.s2.to_string()),
        ("S3", a.s3.to_string()),
        ("S4", a.s4.to_string()),
        ("H1", a.h1.to_string()),
        ("H2", a.h2.to_string()),
        ("H3", a.h3.to_string()),
        ("H4", a.h4.to_string()),
    ] {
        s.push_str(&format!("{k} = {v}\n"));
    }
    for (k, v) in [
        ("I1", &a.i1),
        ("I2", &a.i2),
        ("I3", &a.i3),
        ("I4", &a.i4),
        ("I5", &a.i5),
    ] {
        if let Some(v) = v {
            s.push_str(&format!("{k} = {v}\n"));
        }
    }
    s
}

/// Canonical snake_case key back to WG spelling.
fn pretty(k: &str) -> String {
    match k {
        "private_key" => "PrivateKey".into(),
        "public_key" => "PublicKey".into(),
        "preshared_key" => "PresharedKey".into(),
        "allowed_ips" => "AllowedIPs".into(),
        "persistent_keepalive" => "PersistentKeepalive".into(),
        "endpoint" => "Endpoint".into(),
        "address" => "Address".into(),
        "dns" => "DNS".into(),
        "mtu" => "MTU".into(),
        other => {
            let mut c = other.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        }
    }
}

/// Rebuild a [`ConfigImport`] from a stored record plus caller-held secrets
/// (used by `export <ref>`: secrets come from the secret store, values from
/// the stored TOML — the pair replays exactly what was imported).
pub fn from_stored(
    stored: &crate::config::import::StoredImport,
    secrets: BTreeMap<String, crate::config::secret::SecretString>,
    origin: &std::path::Path,
) -> ConfigImport {
    ConfigImport {
        source_format: stored.source_format,
        path: origin.to_path_buf(),
        ref_name: stored.ref_name.clone(),
        interface: stored.interface.clone(),
        peers: stored.peers.clone(),
        awg: stored.awg.clone(),
        secrets,
        unknown_fields: Vec::new(),
        verdict: crate::config::import::ImportVerdict::Accepted,
        reasons: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::import::ImportVerdict;

    fn sample() -> ConfigImport {
        let text = "[Interface]\nPrivateKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n";
        ConfigImport::parse_str(text, std::path::Path::new("sample.conf")).unwrap()
    }

    #[test]
    fn plain_round_trips() {
        let a = sample();
        assert_eq!(a.verdict, ImportVerdict::Accepted);
        let b = ConfigImport::parse_str(&export_plain(&a), std::path::Path::new("x.conf")).unwrap();
        assert_eq!(b.interface, a.interface);
        assert_eq!(b.peers, a.peers);
    }

    #[test]
    fn redacted_hides_keys() {
        let text = export_redacted(&sample());
        assert!(!text.contains("cB6V3Xk8"));
        assert!(text.contains("PrivateKey = <redacted>"));
    }
}
