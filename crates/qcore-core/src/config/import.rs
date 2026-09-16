//! WireGuard-family config import (US2 T061).
//!
//! Standard INI (`[Interface]` / `[Peer]`). Import preserves every recognized
//! field field-for-field — including dual-stack `Address` and `AllowedIPs`
//! exactly — and rejects unknown fields by name (FR-023). Absent AWG keys
//! mean standard WireGuard behavior. Secrets (`PrivateKey`, `PresharedKey`)
//! are parsed at the boundary into [`SecretString`] and never persist in the
//! stored TOML; [`store_import`] puts them in the [`SecretStore`] (keyring
//! with 0600 file fallback) under `import/<ref>/<field>` accounts.
//!
//! Validation (all failures are `Rejected` verdicts naming the field):
//! - `H1..H4` must be pairwise distinct (non-overlapping).
//! - `Jmax` must be below the MTU (`MTU` key or 1420 default).
//! - `Endpoint` must be `host:port` with a numeric port.
//! - Keys must decode from base64 to 32 bytes.
//! - `HeaderProtectionKey` and the `S*`/`H*` params only against a supporting
//!   peer (`peer=awg` enforced in the wireguard modes, FR-021).

use crate::chain::ChainError;
use crate::config::profile_dir::ProfileDirs;
use crate::config::secret::{SecretStore, SecretString};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Detected source format: any `J*`/`S*`/`H*`/`I*` key means AmneziaWG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Wireguard,
    Amneziawg,
}

/// Import verdict: accepted, or rejected with named reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportVerdict {
    Accepted,
    Rejected,
}

/// AmneziaWG parameters (present for amneziawg only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwgParams {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s1: u32,
    pub s2: u32,
    pub s3: u32,
    pub s4: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
}

/// A parsed import: non-secret fields plus in-memory secrets.
#[derive(Debug)]
pub struct ConfigImport {
    pub source_format: SourceFormat,
    /// Filesystem path it was parsed from (informational only).
    pub path: PathBuf,
    /// Sanitized file stem, the default `import=<ref>`.
    pub ref_name: String,
    /// Recognized `[Interface]` non-secret fields, lowercased keys, raw values.
    pub interface: BTreeMap<String, String>,
    /// Recognized `[Peer]` non-secret fields per peer section.
    pub peers: Vec<BTreeMap<String, String>>,
    pub awg: Option<AwgParams>,
    /// In-memory secrets: `interface.private_key`, `peer<N>.preshared_key`.
    pub secrets: BTreeMap<String, SecretString>,
    pub unknown_fields: Vec<String>,
    pub verdict: ImportVerdict,
    pub reasons: Vec<String>,
}

/// In-memory material merged into the factory config at build time (T063).
/// Secrets are hex-encoded here; this map never touches disk.
#[derive(Debug, Clone, Default)]
pub struct ImportMaterial {
    pub fields: Vec<(String, String)>,
}

/// Recognized `[Interface]` keys (canonical snake_case). Secrets marked `*`.
const IFACE_KEYS: &[&str] = &[
    "private_key",
    "address",
    "dns",
    "mtu",
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
];

/// Recognized `[Peer]` keys (canonical snake_case).
const PEER_KEYS: &[&str] = &[
    "public_key",
    "allowed_ips",
    "endpoint",
    "persistent_keepalive",
    "preshared_key",
];

/// Lowercase INI spelling to canonical snake_case (`AllowedIPs` →
/// `allowed_ips`). Unknown spellings pass through for the unknown-field error.
fn canonical_key(lower: &str) -> String {
    match lower {
        "privatekey" => "private_key".into(),
        "publickey" => "public_key".into(),
        "presharedkey" => "preshared_key".into(),
        "allowedips" => "allowed_ips".into(),
        "persistentkeepalive" => "persistent_keepalive".into(),
        other => other.to_string(),
    }
}

const AWG_KEYS: &[&str] = &[
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4",
    "i5",
];

impl ConfigImport {
    /// Parse a config file. `Err` is IO only; content problems are `Rejected`.
    pub fn parse(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse_str(&raw, path)
    }

    /// Parse config text with `origin` used for the path/ref derivation.
    pub fn parse_str(raw: &str, origin: &Path) -> Result<Self, String> {
        let origin = origin.to_path_buf();
        let ref_name = sanitize_ref(
            origin
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("import"),
        );
        let mut imp = ConfigImport {
            source_format: SourceFormat::Wireguard,
            path: origin,
            ref_name,
            interface: BTreeMap::new(),
            peers: Vec::new(),
            awg: None,
            secrets: BTreeMap::new(),
            unknown_fields: Vec::new(),
            verdict: ImportVerdict::Accepted,
            reasons: Vec::new(),
        };
        let mut section = String::new();
        let mut peer_index = 0usize;
        let mut seen_iface = false;
        let mut raw_awg: BTreeMap<String, String> = BTreeMap::new();
        for (lineno, line) in raw.lines().enumerate() {
            let line = line.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_lowercase();
                if section == "peer" {
                    imp.peers.push(BTreeMap::new());
                    peer_index = imp.peers.len() - 1;
                } else if section == "interface" {
                    seen_iface = true;
                } else {
                    imp.reject(format!("line {}: unknown section `{line}`", lineno + 1));
                }
                continue;
            }
            let (k, v) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    imp.reject(format!("line {}: expected `Key = Value`", lineno + 1));
                    continue;
                }
            };
            if k.is_empty() || v.is_empty() {
                imp.reject(format!("line {}: empty key or value", lineno + 1));
                continue;
            }
            let key = canonical_key(&k.to_lowercase());
            match section.as_str() {
                "interface" => {
                    if !IFACE_KEYS.contains(&key.as_str()) {
                        imp.unknown_fields.push(k.to_string());
                        imp.reject(format!("unknown field `{k}` in [Interface]"));
                        continue;
                    }
                    if AWG_KEYS.contains(&key.as_str()) {
                        // AWG params live only in `awg` (export prints one
                        // block); never duplicated into `interface`.
                        raw_awg.insert(key, v.to_string());
                        continue;
                    }
                    match key.as_str() {
                        "private_key" => match b64_decode_32(v) {
                            Ok(_) => {
                                imp.secrets
                                    .insert("interface.private_key".into(), SecretString::new(v));
                            }
                            Err(e) => imp.reject(format!("`PrivateKey`: {e}")),
                        },
                        _ => {
                            imp.interface.insert(key, v.to_string());
                        }
                    }
                }
                "peer" => {
                    if imp.peers.is_empty() {
                        imp.reject(format!("line {}: key outside any [Peer]", lineno + 1));
                        continue;
                    }
                    if !PEER_KEYS.contains(&key.as_str()) {
                        imp.unknown_fields.push(k.to_string());
                        imp.reject(format!("unknown field `{k}` in [Peer]"));
                        continue;
                    }
                    match key.as_str() {
                        "preshared_key" => match b64_decode_32(v) {
                            Ok(_) => {
                                imp.secrets.insert(
                                    format!("peer{peer_index}.preshared_key"),
                                    SecretString::new(v),
                                );
                            }
                            Err(e) => imp.reject(format!("`PresharedKey`: {e}")),
                        },
                        "public_key" => match b64_decode_32(v) {
                            Ok(_) => {
                                imp.peers[peer_index].insert(key, v.to_string());
                            }
                            Err(e) => imp.reject(format!("`PublicKey`: {e}")),
                        },
                        _ => {
                            imp.peers[peer_index].insert(key, v.to_string());
                        }
                    }
                }
                _ => imp.reject(format!("line {}: key outside any section", lineno + 1)),
            }
        }
        if !seen_iface {
            imp.reject("missing [Interface] section".to_string());
        }
        if imp.peers.is_empty() && imp.verdict == ImportVerdict::Accepted {
            imp.reject("missing [Peer] section".to_string());
        }
        if !imp.secrets.contains_key("interface.private_key")
            && imp.verdict == ImportVerdict::Accepted
        {
            imp.reject("missing `PrivateKey` in [Interface]".to_string());
        }
        // Field-level validation (cloned first: reject() mutates).
        for (i, peer) in imp.peers.clone().iter().enumerate() {
            if let Some(ep) = peer.get("endpoint") {
                if let Err(e) = check_endpoint(ep) {
                    imp.reject(format!("peer {i} `Endpoint`: {e}"));
                }
            }
            if let Some(aips) = peer.get("allowed_ips") {
                for part in aips.split(',').map(str::trim) {
                    if !part.contains('/') {
                        imp.reject(format!("peer {i} `AllowedIPs` entry `{part}` is not CIDR"));
                    }
                }
            }
        }
        if let Some(addr) = imp.interface.get("address").cloned() {
            for part in addr.split(',').map(str::trim) {
                if !part.contains('/') {
                    imp.reject(format!("`Address` entry `{part}` is not CIDR"));
                }
            }
        }
        if !raw_awg.is_empty() {
            imp.source_format = SourceFormat::Amneziawg;
            match parse_awg(&raw_awg, &imp.interface) {
                Ok(awg) => imp.awg = Some(awg),
                Err(e) => imp.reject(e),
            }
        }
        Ok(imp)
    }

    fn reject(&mut self, reason: String) {
        self.verdict = ImportVerdict::Rejected;
        self.reasons.push(reason);
    }
}

fn check_endpoint(ep: &str) -> Result<(), String> {
    let (_, port) = ep
        .rsplit_once(':')
        .ok_or_else(|| format!("`{ep}` is not host:port"))?;
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| format!("port `{port}` is not numeric"))?;
    Ok(())
}

fn parse_awg(
    raw: &BTreeMap<String, String>,
    iface: &BTreeMap<String, String>,
) -> Result<AwgParams, String> {
    let num = |k: &str| -> Result<u32, String> {
        raw.get(k)
            .map(|v| {
                v.parse::<u32>()
                    .map_err(|_| format!("`{k}` value `{v}` is not a non-negative integer"))
            })
            .transpose()
            .map(|o| o.unwrap_or(0))
    };
    let jc = num("jc")?;
    let jmin = num("jmin")?;
    let jmax = num("jmax")?;
    let mtu: u32 = iface
        .get("mtu")
        .map(|v| {
            v.parse::<u32>()
                .map_err(|_| format!("`MTU` value `{v}` is not a non-negative integer"))
        })
        .transpose()?
        .unwrap_or(1420);
    if jmax != 0 && jmax >= mtu {
        return Err(format!("`Jmax` {jmax} must be below MTU {mtu}"));
    }
    let h = |k: &str| num(k);
    let (h1, h2, h3, h4) = (h("h1")?, h("h2")?, h("h3")?, h("h4")?);
    let hs = [h1, h2, h3, h4];
    let present: Vec<u32> = hs.into_iter().filter(|v| *v != 0).collect();
    let mut sorted = present.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != present.len() {
        return Err("`H1..H4` must be non-overlapping (pairwise distinct)".to_string());
    }
    Ok(AwgParams {
        jc,
        jmin,
        jmax,
        s1: num("s1")?,
        s2: num("s2")?,
        s3: num("s3")?,
        s4: num("s4")?,
        h1,
        h2,
        h3,
        h4,
        i1: raw.get("i1").cloned(),
        i2: raw.get("i2").cloned(),
        i3: raw.get("i3").cloned(),
        i4: raw.get("i4").cloned(),
        i5: raw.get("i5").cloned(),
    })
}

fn sanitize_ref(stem: &str) -> String {
    let mut s: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if s.is_empty() {
        s = "import".to_string();
    }
    s
}

/// Import store layout: `<config_dir>/imports/<ref>.toml` (non-secret fields
/// only) + secrets in the [`SecretStore`] under `import/<ref>/<field>`.
pub fn imports_dir(dirs: &ProfileDirs) -> PathBuf {
    dirs.config_dir.join("imports")
}

fn secret_store(dirs: &ProfileDirs) -> SecretStore {
    SecretStore::new("qcore-imports", dirs.config_dir.join("secrets"))
}

/// Persist a parsed + accepted import. Returns the stored ref (suffixed on
/// collision: `<ref>-2`, …). Rejected imports are never stored.
pub fn store_import(dirs: &ProfileDirs, imp: &ConfigImport) -> Result<String, String> {
    if imp.verdict != ImportVerdict::Accepted {
        return Err(format!(
            "refusing to store rejected import: {}",
            imp.reasons.join("; ")
        ));
    }
    if imp.peers.is_empty() {
        return Err("import has no [Peer]".to_string());
    }
    dirs.ensure_dirs().map_err(|e| e.to_string())?;
    let dir = imports_dir(dirs);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut name = imp.ref_name.clone();
    let mut n = 2u32;
    while dir.join(format!("{name}.toml")).exists() {
        name = format!("{}-{n}", imp.ref_name);
        n += 1;
    }
    let stored = StoredImport::from_import(imp, name.clone());
    std::fs::write(dir.join(format!("{name}.toml")), stored.to_toml())
        .map_err(|e| e.to_string())?;
    let store = secret_store(dirs);
    for (field, secret) in &imp.secrets {
        store
            .put(&format!("import/{name}/{field}"), secret)
            .map_err(|e| format!("secret store: {e}"))?;
    }
    Ok(name)
}

/// Stored (non-secret) import record.
#[derive(Debug, Clone)]
pub struct StoredImport {
    pub ref_name: String,
    pub source_format: SourceFormat,
    pub interface: BTreeMap<String, String>,
    pub peers: Vec<BTreeMap<String, String>>,
    pub awg: Option<AwgParams>,
}

impl StoredImport {
    fn from_import(imp: &ConfigImport, ref_name: String) -> Self {
        StoredImport {
            ref_name,
            source_format: imp.source_format,
            interface: imp.interface.clone(),
            peers: imp.peers.clone(),
            awg: imp.awg.clone(),
        }
    }

    fn to_toml(&self) -> String {
        let mut s =
            String::from("# qcore import record: secrets live in the secret store, never here.\n");
        s.push_str(&format!(
            "ref_name = \"{}\"\nsource_format = \"{}\"\n",
            self.ref_name,
            match self.source_format {
                SourceFormat::Wireguard => "wireguard",
                SourceFormat::Amneziawg => "amneziawg",
            }
        ));
        s.push_str("\n[interface]\n");
        for (k, v) in &self.interface {
            s.push_str(&format!("{k} = \"{}\"\n", toml_escape(v)));
        }
        for (i, peer) in self.peers.iter().enumerate() {
            s.push_str(&format!("\n[[peers]]\nindex = {i}\n"));
            for (k, v) in peer {
                s.push_str(&format!("{k} = \"{}\"\n", toml_escape(v)));
            }
        }
        if let Some(a) = &self.awg {
            s.push_str("\n[awg]\n");
            for (k, v) in [
                ("jc", a.jc.to_string()),
                ("jmin", a.jmin.to_string()),
                ("jmax", a.jmax.to_string()),
                ("s1", a.s1.to_string()),
                ("s2", a.s2.to_string()),
                ("s3", a.s3.to_string()),
                ("s4", a.s4.to_string()),
                ("h1", a.h1.to_string()),
                ("h2", a.h2.to_string()),
                ("h3", a.h3.to_string()),
                ("h4", a.h4.to_string()),
            ] {
                s.push_str(&format!("{k} = \"{v}\"\n"));
            }
            for (k, v) in [
                ("i1", &a.i1),
                ("i2", &a.i2),
                ("i3", &a.i3),
                ("i4", &a.i4),
                ("i5", &a.i5),
            ] {
                if let Some(v) = v {
                    s.push_str(&format!("{k} = \"{}\"\n", toml_escape(v)));
                }
            }
        }
        s
    }

    fn from_toml(text: &str) -> Result<Self, String> {
        let v: toml::Value = toml::from_str(text).map_err(|e| format!("import record: {e}"))?;
        let get = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .ok_or_else(|| format!("import record missing `{k}`"))
        };
        let source_format = match get("source_format")? {
            "wireguard" => SourceFormat::Wireguard,
            "amneziawg" => SourceFormat::Amneziawg,
            other => return Err(format!("import record: unknown format `{other}`")),
        };
        let table_to_map = |t: &toml::map::Map<String, toml::Value>| {
            t.iter()
                .filter(|(k, _)| *k != "index")
                .map(|(k, x)| {
                    x.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                        .ok_or_else(|| format!("import record: field `{k}` is not a string"))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
        };
        let interface = v
            .get("interface")
            .and_then(|x| x.as_table())
            .map(table_to_map)
            .transpose()?
            .unwrap_or_default();
        let mut peers = Vec::new();
        if let Some(arr) = v.get("peers").and_then(|x| x.as_array()) {
            for p in arr {
                let t = p
                    .as_table()
                    .ok_or_else(|| "import record: peer is not a table".to_string())?;
                peers.push(table_to_map(t)?);
            }
        }
        let awg = match v.get("awg") {
            None => None,
            Some(a) => {
                let t = a
                    .as_table()
                    .ok_or_else(|| "import record: awg is not a table".to_string())?;
                let num = |k: &str| {
                    t.get(k)
                        .and_then(|x| x.as_str())
                        .unwrap_or("0")
                        .parse::<u32>()
                        .map_err(|_| format!("import record: awg `{k}` not a uint"))
                };
                let opt = |k: &str| t.get(k).and_then(|x| x.as_str()).map(str::to_string);
                Some(AwgParams {
                    jc: num("jc")?,
                    jmin: num("jmin")?,
                    jmax: num("jmax")?,
                    s1: num("s1")?,
                    s2: num("s2")?,
                    s3: num("s3")?,
                    s4: num("s4")?,
                    h1: num("h1")?,
                    h2: num("h2")?,
                    h3: num("h3")?,
                    h4: num("h4")?,
                    i1: opt("i1"),
                    i2: opt("i2"),
                    i3: opt("i3"),
                    i4: opt("i4"),
                    i5: opt("i5"),
                })
            }
        };
        Ok(StoredImport {
            ref_name: get("ref_name")?.to_string(),
            source_format,
            interface,
            peers,
            awg,
        })
    }
}

fn toml_escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Load a stored import plus its secrets (in memory only).
pub fn load_import(
    dirs: &ProfileDirs,
    import_ref: &str,
) -> Result<(StoredImport, BTreeMap<String, SecretString>), String> {
    let path = imports_dir(dirs).join(format!("{import_ref}.toml"));
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("unknown import `{import_ref}` (see `qcore import`)"))?;
    let stored = StoredImport::from_toml(&text)?;
    let store = secret_store(dirs);
    let mut secrets = BTreeMap::new();
    // PrivateKey is always required for a usable import.
    match store.get(&format!("import/{import_ref}/interface.private_key")) {
        Ok(s) => {
            secrets.insert("interface.private_key".to_string(), s);
        }
        Err(e) => {
            return Err(format!(
                "import `{import_ref}` secret `interface.private_key` unavailable: {e}"
            ))
        }
    }
    // PresharedKey presence is known only via the secret store: probe per peer.
    for i in 0..stored.peers.len() {
        let field = format!("peer{i}.preshared_key");
        if let Ok(s) = store.get(&format!("import/{import_ref}/{field}")) {
            secrets.insert(field, s);
        }
    }
    Ok((stored, secrets))
}

/// Preflight check (T063 wiring): every wireguard `import=<ref>` in the
/// expanded chain must resolve. File reads only — zero sockets.
pub fn check_refs(dirs: &ProfileDirs, hops: &[crate::config::HopSpec]) -> Result<(), ChainError> {
    for hop in hops {
        if let crate::config::HopConfig::Wireguard(c) = &hop.config {
            if let Some(import_ref) = c.import_ref.as_deref() {
                let path = imports_dir(dirs).join(format!("{import_ref}.toml"));
                if !path.exists() {
                    return Err(ChainError::new(
                        None,
                        Some(hop.id.clone()),
                        format!("unknown import `{import_ref}` (see `qcore import`)"),
                        Some("import the .conf first".to_string()),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Materialize per-hop factory fields from stored imports (T063 wiring),
/// with last-known-good endpoint fallback (US4 T068).
/// Endpoint precedence: explicit chain `endpoint=` > import's `Endpoint` >
/// cached verified endpoint (family-compatible). Secrets are hex-encoded in
/// memory only and never touch disk.
pub fn materialize(
    dirs: &ProfileDirs,
    hops: &[crate::config::HopSpec],
) -> Result<HashMap<String, ImportMaterial>, ChainError> {
    let mut out = HashMap::new();
    for hop in hops {
        let crate::config::HopConfig::Wireguard(c) = &hop.config else {
            continue;
        };
        let mut fields: Vec<(String, String)> = Vec::new();
        // Endpoint: explicit chain value first.
        if let Some(ep) = c.endpoint.clone() {
            fields.push(("endpoint".into(), ep));
        }
        let Some(import_ref) = c.import_ref.clone() else {
            // No import: fall back to the cached verified endpoint.
            if fields.is_empty() {
                if let Some(lkg) = crate::session::reconnect::last_known_good(dirs) {
                    let compatible = match c.family.as_str() {
                        "ipv4" => lkg.is_ipv4(),
                        "ipv6" => lkg.is_ipv6(),
                        _ => true,
                    };
                    if compatible {
                        fields.push(("endpoint".into(), lkg.to_string()));
                    }
                }
            }
            if !fields.is_empty() {
                out.insert(hop.id.clone(), ImportMaterial { fields });
            }
            continue;
        };
        let (stored, secrets) = load_import(dirs, &import_ref).map_err(|e| {
            ChainError::new(
                None,
                Some(hop.id.clone()),
                e,
                Some("import the .conf first".to_string()),
            )
        })?;
        if stored.peers.is_empty() {
            return Err(ChainError::new(
                None,
                Some(hop.id.clone()),
                format!("import `{import_ref}` has no [Peer]"),
                None,
            ));
        }
        let peer = &stored.peers[0];
        // Endpoint: explicit chain value wins over the import.
        if fields.is_empty() {
            if let Some(ep) = peer.get("endpoint") {
                fields.push(("endpoint".into(), ep.clone()));
            }
        }
        let priv_b64 = String::from_utf8_lossy(
            secrets
                .get("interface.private_key")
                .map(|s| s.expose())
                .unwrap_or_default(),
        )
        .into_owned();
        let priv_raw = b64_decode_32(priv_b64.trim()).map_err(|e| {
            ChainError::new(
                None,
                Some(hop.id.clone()),
                format!("import `{import_ref}` PrivateKey: {e}"),
                None,
            )
        })?;
        fields.push(("private_key".into(), hex_encode(&priv_raw)));
        let pub_b64 = peer.get("public_key").ok_or_else(|| {
            ChainError::new(
                None,
                Some(hop.id.clone()),
                format!("import `{import_ref}` peer has no PublicKey"),
                None,
            )
        })?;
        let pub_raw = b64_decode_32(pub_b64.trim()).map_err(|e| {
            ChainError::new(
                None,
                Some(hop.id.clone()),
                format!("import `{import_ref}` PublicKey: {e}"),
                None,
            )
        })?;
        fields.push(("peer_public_key".into(), hex_encode(&pub_raw)));
        if let Some(psk) = secrets.get("peer0.preshared_key") {
            let psk_str = String::from_utf8_lossy(psk.expose()).into_owned();
            let psk_raw = b64_decode_32(psk_str.trim()).map_err(|e| {
                ChainError::new(
                    None,
                    Some(hop.id.clone()),
                    format!("import `{import_ref}` PresharedKey: {e}"),
                    None,
                )
            })?;
            fields.push(("preshared_key".into(), hex_encode(&psk_raw)));
        }
        if let Some(ka) = peer.get("persistent_keepalive") {
            fields.push(("keepalive".into(), ka.clone()));
        }
        if let Some(a) = &stored.awg {
            for (k, v) in [
                ("awg_jc", a.jc.to_string()),
                ("awg_jmin", a.jmin.to_string()),
                ("awg_jmax", a.jmax.to_string()),
                ("awg_s1", a.s1.to_string()),
                ("awg_s2", a.s2.to_string()),
                ("awg_s3", a.s3.to_string()),
                ("awg_s4", a.s4.to_string()),
                ("awg_h1", a.h1.to_string()),
                ("awg_h2", a.h2.to_string()),
                ("awg_h3", a.h3.to_string()),
                ("awg_h4", a.h4.to_string()),
            ] {
                fields.push((k.into(), v));
            }
            for (k, v) in [
                ("awg_i1", &a.i1),
                ("awg_i2", &a.i2),
                ("awg_i3", &a.i3),
                ("awg_i4", &a.i4),
                ("awg_i5", &a.i5),
            ] {
                if let Some(v) = v {
                    fields.push((k.into(), v.clone()));
                }
            }
        }
        out.insert(hop.id.clone(), ImportMaterial { fields });
    }
    Ok(out)
}

/// Standard-base64 decode demanding exactly 32 bytes (WG key format).
pub fn b64_decode_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = b64_decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("key is {} bytes, expected 32", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Minimal standard-base64 decoder (no external crate; WG keys canonical).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of 4".to_string());
    }
    let val = |c: char| -> Result<u8, String> {
        match c {
            'A'..='Z' => Ok(c as u8 - b'A'),
            'a'..='z' => Ok(c as u8 - b'a' + 26),
            '0'..='9' => Ok(c as u8 - b'0' + 52),
            '+' => Ok(62),
            '/' => Ok(63),
            _ => Err(format!("bad base64 char `{c}`")),
        }
    };
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let mut sext = [0u8; 4];
        let mut pad = 0;
        for j in 0..4 {
            let c = b[i + j] as char;
            if c == '=' {
                pad += 1;
            } else {
                if pad > 0 {
                    return Err("base64 padding in the middle".to_string());
                }
                sext[j] = val(c)?;
            }
        }
        if pad > 2 {
            return Err("bad base64 padding".to_string());
        }
        // Mask before shifting: sextets are 6 bits, u8 shifts overflow.
        out.push(sext[0] << 2 | sext[1] >> 4);
        if pad < 2 {
            out.push((sext[1] & 0x0f) << 4 | sext[2] >> 2);
        }
        if pad < 1 {
            out.push((sext[2] & 0x03) << 6 | sext[3]);
        }
        i += 4;
    }
    Ok(out)
}

/// Standard-base64 encode (tests + tooling; canonical WG alphabet).
pub fn b64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in data.chunks(3) {
        let mut n = [0u8; 3];
        n[..chunk.len()].copy_from_slice(chunk);
        s.push(ALPHA[(n[0] >> 2) as usize] as char);
        s.push(ALPHA[(((n[0] & 3) << 4) | (n[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            s.push(ALPHA[(((n[1] & 15) << 2) | (n[2] >> 6)) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(ALPHA[(n[2] & 63) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

pub fn hex_encode(data: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip() {
        let raw: Vec<u8> = (0..32u8).collect();
        assert_eq!(b64_decode(&b64_encode(&raw)).unwrap(), raw);
        assert_eq!(
            b64_encode(&[0x63, 0xb6, 0x15]),
            "Y7YV",
            "padding-free vector"
        );
    }

    #[test]
    fn known_key_decodes() {
        // 32-byte keys are 44 base64 chars with single `=` padding.
        let k = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
        let raw = b64_decode_32(k).unwrap();
        assert_eq!(raw, [7u8; 32]);
        assert_eq!(b64_encode(&raw), k);
    }

    #[test]
    fn bad_key_rejected() {
        assert!(b64_decode_32("zz").is_err());
        assert!(b64_decode_32(&b64_encode(&[1u8; 31])).is_err());
    }
}
