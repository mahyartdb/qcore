//! WireGuard-family config import (US2 T061).
//!
//! Standard INI (`[Interface]` / `[Peer]`). Import preserves every recognized
//! field, field-for-field — including dual-stack `Address` and `AllowedIPs`
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
use crate::config::secret::{namespace_hash, namespace_input, SecretStore, SecretString};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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
        // Duplicate INI keys fail closed (never last-wins): canonical keys
        // seen per section instance.
        let mut seen_iface_keys = std::collections::HashSet::new();
        let mut seen_peer_keys: Vec<std::collections::HashSet<String>> = Vec::new();
        for (lineno, raw_line) in raw.lines().enumerate() {
            let line = raw_line.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_lowercase();
                if section == "peer" {
                    imp.peers.push(BTreeMap::new());
                    seen_peer_keys.push(std::collections::HashSet::new());
                    peer_index = imp.peers.len() - 1;
                } else if section == "interface" {
                    // A second [Interface] with disjoint keys would silently
                    // merge (only cross-block duplicate keys trip the guard):
                    // reject, symmetric with the multi-[Peer] gate below.
                    if seen_iface {
                        imp.reject(format!(
                            "line {}: duplicate [Interface] section",
                            lineno + 1
                        ));
                    }
                    seen_iface = true;
                } else {
                    imp.reject(format!("line {}: unknown section `{line}`", lineno + 1));
                }
                continue;
            }
            // Free-form AWG keys (`I1..I5`) keep everything after `=`: their
            // values may legitimately contain `#`/`;`, and line-level
            // stripping silently truncates them (then the export bakes the
            // loss in). All other keys strip inline comments as before.
            let raw_key = raw_line
                .split_once('=')
                .map(|(k, _)| k.trim().to_lowercase());
            let free_form = matches!(
                raw_key.as_deref(),
                Some("i1") | Some("i2") | Some("i3") | Some("i4") | Some("i5")
            );
            let (k, v) = if free_form {
                match raw_line.split_once('=') {
                    Some((k, v)) => (k.trim(), v.trim()),
                    None => {
                        imp.reject(format!("line {}: expected `Key = Value`", lineno + 1));
                        continue;
                    }
                }
            } else {
                match line.split_once('=') {
                    Some((k, v)) => (k.trim(), v.trim()),
                    None => {
                        imp.reject(format!("line {}: expected `Key = Value`", lineno + 1));
                        continue;
                    }
                }
            };
            if k.is_empty() || v.is_empty() {
                imp.reject(format!("line {}: empty key or value", lineno + 1));
                continue;
            }
            let key = canonical_key(&k.to_lowercase());
            match section.as_str() {
                "interface" => {
                    if !seen_iface_keys.insert(key.clone()) {
                        imp.reject(format!(
                            "line {}: duplicate field `{k}` in [Interface]",
                            lineno + 1
                        ));
                        continue;
                    }
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
                    if !seen_peer_keys[peer_index].insert(key.clone()) {
                        imp.reject(format!(
                            "line {}: duplicate field `{k}` in [Peer]",
                            lineno + 1
                        ));
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
        if imp.peers.len() > 1 {
            imp.reject("multiple [Peer] sections (expected exactly one)".to_string());
        }
        if !imp.secrets.contains_key("interface.private_key")
            && imp.verdict == ImportVerdict::Accepted
        {
            imp.reject("missing `PrivateKey` in [Interface]".to_string());
        }
        // Field-level validation (errors collected first: reject() takes
        // &mut while peers are borrowed, so no clone-the-vec workaround).
        let mut field_errors = Vec::new();
        for (i, peer) in imp.peers.iter().enumerate() {
            if let Some(ep) = peer.get("endpoint") {
                if let Err(e) = check_endpoint(ep) {
                    field_errors.push(format!("peer {i} `Endpoint`: {e}"));
                }
            }
            if let Some(aips) = peer.get("allowed_ips") {
                for part in aips.split(',').map(str::trim) {
                    if let Err(e) = check_cidr(part) {
                        field_errors.push(format!("peer {i} `AllowedIPs` entry `{part}`: {e}"));
                    }
                }
            }
        }
        for e in field_errors {
            imp.reject(e);
        }
        if let Some(addr) = imp.interface.get("address").cloned() {
            for part in addr.split(',').map(str::trim) {
                if let Err(e) = check_cidr(part) {
                    imp.reject(format!("`Address` entry `{part}`: {e}"));
                }
            }
        }
        // Any AWG key flips the format; ABSENT numerics read as 0/disabled
        // (deliberately lenient, unlike stored records which are strict —
        // see below). Generator-written configs are routinely partial, and
        // every consumer treats 0 as absent, so completeness here would be
        // interop friction, not safety. Stored records are machine-written
        // complete, so a truncated `[awg]` table there IS corruption
        // (`truncated_awg_record_fails_closed` pins that side).
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

fn check_cidr(entry: &str) -> Result<(), String> {
    let (ip, prefix) = entry
        .split_once('/')
        .ok_or_else(|| "is not CIDR (need `address/prefix`)".to_string())?;
    let addr: std::net::IpAddr = ip
        .parse()
        .map_err(|_| format!("`{ip}` is not an IP literal"))?;
    let max: u8 = if addr.is_ipv4() { 32 } else { 128 };
    let bits: u8 = prefix
        .parse()
        .map_err(|_| format!("prefix `{prefix}` is not numeric"))?;
    if bits > max {
        return Err(format!("prefix `{bits}` exceeds /{max}"));
    }
    Ok(())
}

fn check_endpoint(ep: &str) -> Result<(), String> {
    let (host, port) = ep
        .rsplit_once(':')
        .ok_or_else(|| format!("`{ep}` is not host:port"))?;
    if host.is_empty() {
        return Err(format!("`{ep}` has an empty host"));
    }
    // Unbracketed IPv6 is ambiguous (`::1`, `2001:db8::1:51820`): the last
    // colon split misreads address bytes as host/port, so require brackets
    // and reject any other multi-colon host.
    if host.starts_with('[') {
        if !host.ends_with(']') {
            return Err(format!("`{ep}` has an unbalanced bracket"));
        }
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("`{ep}` is not bracketed IPv6 with port"))?;
    } else {
        if host.contains(':') {
            return Err(format!(
                "`{ep}` is ambiguous: bracket IPv6 hosts (`[::1]:{}`)",
                "<port>"
            ));
        }
        if host.parse::<std::net::IpAddr>().is_err()
            && !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            return Err(format!("`{ep}` has an invalid hostname"));
        }
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("port `{port}` is not numeric"))?;
    if port == 0 {
        return Err("port `0` is not a connectable endpoint".to_string());
    }
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
    // `CON`/`NUL`/… stay alphanumeric through the map above, but `<ref>.toml`
    // collides with the Windows console device even with an extension (the
    // read path refuses such refs): suffix so store-then-load round-trips.
    if is_reserved_import_ref(&s) {
        s.push_str("-import");
    }
    s
}

/// Import store layout: `<config_dir>/imports/<ref>.toml` (non-secret fields
/// only) + secrets in the [`SecretStore`] under `import/<ref>/<field>`.
pub fn imports_dir(dirs: &ProfileDirs) -> PathBuf {
    dirs.config_dir.join("imports")
}

/// Resolve `<ref>.toml` inside the imports dir, rejecting refs that escape
/// it (empty, NUL, separators, `.`/`..` segments, Windows-forbidden
/// `<>:\"|?*` plus `:`, and reserved device basenames `CON`/`PRN`/`AUX`/
/// `NUL`/`COM1-9`/`LPT1-9`). Read paths trust caller-supplied refs —
/// chain files, `--export`, FFI/JNI — while the write path sanitizes
/// instead, so reads guard containment rather than rewriting the ref: dots,
/// spaces, and unicode names (incl. hand-placed files) keep working.
/// Deliberately NOT `starts_with` on the joined path: `Path::starts_with`
/// is lexical and matches through `..` segments.
pub(crate) fn import_path(dirs: &ProfileDirs, import_ref: &str) -> Result<PathBuf, String> {
    let has_forbidden = import_ref
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'));
    let escaped = import_ref.is_empty()
        || import_ref.contains('\0')
        || has_forbidden
        || is_reserved_import_ref(import_ref)
        || import_ref
            .split(['/', '\\'])
            .any(|seg| seg.is_empty() || seg == "." || seg == "..");
    if escaped {
        return Err(format!("invalid import ref `{import_ref}`"));
    }
    Ok(imports_dir(dirs).join(format!("{import_ref}.toml")))
}

/// Windows device basenames (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`,
/// `LPT1-9`, case-insensitive, before the first `.`): `<ref>.toml` would
/// collide with the device even with an extension, so reject fail-closed.
fn is_reserved_import_ref(import_ref: &str) -> bool {
    let base = import_ref.split('.').next().unwrap_or(import_ref);
    let base = base.trim_end_matches([' ', '.']);
    matches!(
        base.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Per-dir secret namespace (same FNV-1a scheme as the identity store in
/// `crate::identity::store`): parallel test dirs and parallel profiles never
/// share keyring accounts, so concurrent imports of same-named refs cannot
/// race on one entry. New saves always go to the current namespace; reads
/// fall back to the pre-namespace `qcore-imports` service (miss only, never
/// on empty — mirroring the identity legacy contract).
fn secret_store(dirs: &ProfileDirs) -> SecretStore {
    let h = namespace_hash(&namespace_input(dirs));
    SecretStore::new(
        format!("qcore-imports-{h:016x}"),
        dirs.config_dir.join("secrets"),
    )
}

fn legacy_secret_store(dirs: &ProfileDirs) -> SecretStore {
    SecretStore::new("qcore-imports", dirs.config_dir.join("secrets"))
}

/// Resolve one import secret: current namespace first, legacy namespace on
/// miss only.
fn get_import_secret(
    store: &SecretStore,
    legacy: &SecretStore,
    import_ref: &str,
    field: &str,
) -> Result<SecretString, String> {
    let account = format!("import/{import_ref}/{field}");
    match store.get(&account) {
        Err(_) => legacy.get(&account),
        ok => ok,
    }
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
    if imp.peers.len() > 1 {
        return Err("import has multiple [Peer] sections (expected exactly one)".to_string());
    }
    dirs.ensure_dirs().map_err(|e| e.to_string())?;
    let dir = imports_dir(dirs);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Defense in depth: the write path sanitizes instead of guarding, so a
    // reserved stem reaching here (hand-built `ConfigImport`, old data) must
    // not land on a device file even with an extension.
    let mut name = imp.ref_name.clone();
    if is_reserved_import_ref(&name) {
        name.push_str("-import");
    }
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
    // Migration hygiene: the secrets now live under the current namespace.
    // Drop any legacy-namespace keyring copies (keyring only — the file
    // fallback is namespace-independent and shared, so files stay).
    // Failures are silently ignored (leftovers are inert — loads prefer
    // the current namespace).
    let legacy = legacy_secret_store(dirs);
    for field in imp.secrets.keys() {
        legacy.delete_keyring(&format!("import/{name}/{field}"));
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
        // Stored records are machine-written complete: any unknown field at
        // any level is corruption, fail closed naming the field.
        if let Some(t) = v.as_table() {
            for k in t.keys() {
                if !["ref_name", "source_format", "interface", "peers", "awg"].contains(&k.as_str())
                {
                    return Err(format!("import record: unknown field `{k}`"));
                }
            }
        }
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
        // Stored interface carries non-secret, non-AWG fields only
        // (`address`/`dns`/`mtu`); anything else is corruption.
        if let Some(t) = v.get("interface").and_then(|x| x.as_table()) {
            for k in t.keys() {
                if !["address", "dns", "mtu"].contains(&k.as_str()) {
                    return Err(format!("import record: unknown field `interface.{k}`"));
                }
            }
        }
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
                for k in t.keys() {
                    if k != "index"
                        && ![
                            "public_key",
                            "allowed_ips",
                            "endpoint",
                            "persistent_keepalive",
                        ]
                        .contains(&k.as_str())
                    {
                        return Err(format!("import record: unknown field `peers.{k}`"));
                    }
                }
                peers.push(table_to_map(t)?);
            }
        }
        if peers.len() > 1 {
            return Err(
                "import record: multiple [Peer] sections (expected exactly one)".to_string(),
            );
        }
        let awg = match v.get("awg") {
            None => None,
            Some(a) => {
                let t = a
                    .as_table()
                    .ok_or_else(|| "import record: awg is not a table".to_string())?;
                for k in t.keys() {
                    if ![
                        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1",
                        "i2", "i3", "i4", "i5",
                    ]
                    .contains(&k.as_str())
                    {
                        return Err(format!("import record: unknown field `awg.{k}`"));
                    }
                }
                // Missing or mistyped numerics are corruption, not zeros:
                // records are machine-written complete, so fail closed.
                // Integer-typed values parse like their string forms:
                // TOML's natural encoding for numbers is integers, and
                // hand-edited records may use bare `jc = 1`.
                let num = |k: &str| {
                    let x = t
                        .get(k)
                        .ok_or_else(|| format!("import record: awg `{k}` missing"))?;
                    if let Some(n) = x.as_integer() {
                        return u32::try_from(n)
                            .map_err(|_| format!("import record: awg `{k}` not a uint"));
                    }
                    x.as_str()
                        .ok_or_else(|| {
                            format!("import record: awg `{k}` neither a uint nor a string")
                        })
                        .and_then(|s| {
                            s.parse::<u32>()
                                .map_err(|_| format!("import record: awg `{k}` not a uint"))
                        })
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
    let path = import_path(dirs, import_ref)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("unknown import `{import_ref}` (see `qcore import`)"))?;
    let stored = StoredImport::from_toml(&text)?;
    let store = secret_store(dirs);
    let legacy = legacy_secret_store(dirs);
    let mut secrets = BTreeMap::new();
    // PrivateKey is always required for a usable import.
    match get_import_secret(&store, &legacy, import_ref, "interface.private_key") {
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
        if let Ok(s) = get_import_secret(&store, &legacy, import_ref, &field) {
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
                let path = import_path(dirs, import_ref)
                    .map_err(|e| ChainError::new(None, Some(hop.id.clone()), e, None))?;
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
        if stored.peers.len() > 1 {
            return Err(ChainError::new(
                None,
                Some(hop.id.clone()),
                format!(
                    "import `{import_ref}` has multiple [Peer] sections (expected exactly one)"
                ),
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
        // Transient base64 copy: wiped on drop (boundary decode only; the
        // hex below and the stored secret are the survivors).
        let priv_b64 = Zeroizing::new(
            String::from_utf8_lossy(
                secrets
                    .get("interface.private_key")
                    .map(|s| s.expose())
                    .unwrap_or_default(),
            )
            .into_owned(),
        );
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
            let psk_str = Zeroizing::new(String::from_utf8_lossy(psk.expose()).into_owned());
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

/// Minimal standard-base64 decoder (WG keys canonical). Backed by the
/// vetted `base64` crate (already linked); whitespace is stripped first so
/// multi-line values behave as before.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64: {e}"))
}

/// Standard-base64 encode (tests + tooling; canonical WG alphabet).
pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
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
    fn b64_rejection_shape_is_stable() {
        // Rejection reasons surface in CLI output (`PrivateKey: ...`): the
        // `base64: ` prefix is contractual, the crate's detail after it is
        // not (it changed once already, hand-rolled strings to crate text).
        let err = b64_decode("!!!").unwrap_err();
        assert!(err.starts_with("base64: "), "got: {err}");
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

    #[test]
    fn truncated_awg_record_fails_closed() {
        // A present-but-incomplete [awg] table is corruption: missing
        // numerics error instead of silently defaulting to zero.
        let text =
            "ref_name = \"r\"\nsource_format = \"amneziawg\"\n[interface]\n[awg]\njc = \"1\"\n";
        let err = StoredImport::from_toml(text).unwrap_err();
        assert!(err.contains("awg `jmin` missing"), "got: {err}");
    }

    #[test]
    fn integer_typed_awg_numerics_parse() {
        // TOML's natural encoding for numbers is integers: hand-edited or
        // older-writer records with bare `jc = 1` must parse like `"1"`.
        let text = "ref_name = \"r\"\nsource_format = \"amneziawg\"\n[interface]\n[awg]\njc = 1\njmin = \"2\"\njmax = 3\ns1 = 0\ns2 = 0\ns3 = 0\ns4 = 0\nh1 = 0\nh2 = 0\nh3 = 0\nh4 = 0\n";
        let rec = StoredImport::from_toml(text).expect("integer numerics parse");
        let awg = rec.awg.expect("awg present");
        assert_eq!((awg.jc, awg.jmin, awg.jmax), (1, 2, 3));
        // Out-of-range integers still fail closed naming the field.
        let bad = text.replace("jc = 1", "jc = 4294967296");
        let err = StoredImport::from_toml(&bad).unwrap_err();
        assert!(
            err.contains("jc") && err.contains("not a uint"),
            "got: {err}"
        );
    }

    #[test]
    fn endpoint_without_host_rejected() {
        assert!(check_endpoint("203.0.113.10:51820").is_ok());
        assert!(check_endpoint("[::1]:51820").is_ok());
        let err = check_endpoint(":80").unwrap_err();
        assert!(err.contains("empty host"), "got: {err}");
        assert!(check_endpoint("no-port").is_err());
    }

    #[test]
    fn import_path_contains_refs_in_store() {
        let base = std::env::temp_dir().join(format!("qcore-import-guard-{}", std::process::id()));
        let dirs = ProfileDirs::resolve(Some(base), None);
        // Ordinary refs resolve inside the store — including characters
        // the write-time sanitizer rewrites, which hand-placed files may
        // still use. Reads guard containment; they never rewrite the ref.
        for ok in ["wg-home", "my.vpn", "with space", "uniçode", "a..b", "..."] {
            let p = import_path(&dirs, ok).expect("ordinary ref resolves");
            assert!(
                p.starts_with(imports_dir(&dirs)),
                "escaped the store: {}",
                p.display()
            );
            assert_eq!(
                p.file_name().unwrap().to_string_lossy(),
                format!("{ok}.toml")
            );
        }
        // Traversal, absolute, empty, NUL, Windows-forbidden, and reserved
        // device refs fail closed.
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/../../b",
            "/abs",
            "x/",
            "a//b",
            "nul\0byte",
            "a\\..\\b",
            "a:b",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "CON",
            "con",
            "PRN",
            "aux",
            "NUL",
            "COM1",
            "com9",
            "LPT1",
            "lpt9",
            "CON.foo",
            "com1.txt",
            "aux ",
        ] {
            assert!(import_path(&dirs, bad).is_err(), "accepted: {bad:?}");
        }
    }

    #[test]
    fn reserved_basename_check_is_first_dot_component() {
        // Only the part before the first `.` decides: `my.vpn` keeps working
        // while `CON.anything` is a device even with an extension.
        assert!(is_reserved_import_ref("CON"));
        assert!(is_reserved_import_ref("con"));
        assert!(is_reserved_import_ref("CON.foo"));
        assert!(!is_reserved_import_ref("my.vpn"));
        assert!(!is_reserved_import_ref("a..b"));
        assert!(!is_reserved_import_ref("..."));
        assert!(!is_reserved_import_ref("wg-home"));
    }

    fn keys() -> (String, String) {
        // 32-byte keys: deterministic vectors for INI duplicate tests.
        let priv_b64 = b64_encode(&[7u8; 32]);
        let pub_b64 = b64_encode(&[9u8; 32]);
        (priv_b64, pub_b64)
    }

    #[test]
    fn duplicate_interface_key_rejected() {
        let (priv_b64, pub_b64) = keys();
        let text = format!(
            "[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.0.0.2/32\nAddress = 10.0.0.3/32\n\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
        );
        let imp =
            ConfigImport::parse_str(&text, std::path::Path::new("dup.conf")).expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Rejected);
        assert!(
            imp.reasons.join(" ").contains("duplicate"),
            "duplicate: {:?}",
            imp.reasons
        );
        assert!(
            imp.reasons.join(" ").contains("Address"),
            "names field: {:?}",
            imp.reasons
        );
    }

    #[test]
    fn duplicate_peer_key_rejected_case_insensitive() {
        let (priv_b64, pub_b64) = keys();
        // `Endpoint` vs `endpoint` share the canonical key: last-wins would
        // silently pick one, so duplicates fail closed.
        let text = format!(
            "[Interface]\nPrivateKey = {priv_b64}\n\n[Peer]\nPublicKey = {pub_b64}\nEndpoint = 203.0.113.10:51820\nendpoint = 203.0.113.11:51820\n"
        );
        let imp =
            ConfigImport::parse_str(&text, std::path::Path::new("dup.conf")).expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Rejected);
        assert!(imp.reasons.join(" ").contains("duplicate"));
    }

    #[test]
    fn multi_peer_import_rejected() {
        let (priv_b64, pub_b64) = keys();
        let text = format!(
            "[Interface]\nPrivateKey = {priv_b64}\n\n[Peer]\nPublicKey = {pub_b64}\nEndpoint = 203.0.113.10:51820\n\n[Peer]\nPublicKey = {pub_b64}\nEndpoint = 203.0.113.11:51820\n"
        );
        let imp =
            ConfigImport::parse_str(&text, std::path::Path::new("multi.conf")).expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Rejected);
        assert!(
            imp.reasons.join(" ").contains("[Peer]"),
            "names section: {:?}",
            imp.reasons
        );
    }

    #[test]
    fn stored_record_unknown_fields_rejected() {
        for (label, text) in [
            (
                "top",
                "ref_name = \"r\"\nsource_format = \"wireguard\"\nbogus = \"1\"\n[interface]\n",
            ),
            (
                "interface",
                "ref_name = \"r\"\nsource_format = \"wireguard\"\n[interface]\nbogus = \"1\"\n",
            ),
            (
                "peer",
                "ref_name = \"r\"\nsource_format = \"wireguard\"\n[interface]\n[[peers]]\nindex = 0\nbogus = \"1\"\n",
            ),
            (
                "awg",
                "ref_name = \"r\"\nsource_format = \"amneziawg\"\n[interface]\n[awg]\njc = \"1\"\njmin = \"2\"\njmax = \"3\"\ns1 = \"0\"\ns2 = \"0\"\ns3 = \"0\"\ns4 = \"0\"\nh1 = \"0\"\nh2 = \"0\"\nh3 = \"0\"\nh4 = \"0\"\nbogus = \"1\"\n",
            ),
        ] {
            let err = StoredImport::from_toml(text).unwrap_err();
            assert!(
                err.contains("unknown field") && err.contains("bogus"),
                "{label}: got: {err}"
            );
        }
    }

    #[test]
    fn stored_multi_peer_record_rejected() {
        let text = "ref_name = \"r\"\nsource_format = \"wireguard\"\n[interface]\n[[peers]]\nindex = 0\npublic_key = \"x\"\n[[peers]]\nindex = 1\npublic_key = \"y\"\n";
        let err = StoredImport::from_toml(text).unwrap_err();
        assert!(
            err.contains("multiple") && err.contains("[Peer]"),
            "got: {err}"
        );
    }

    fn wg_hop(priv_b64: &str, pub_b64: &str, extra_iface: &str, endpoint: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {priv_b64}\n{extra_iface}\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n"
        )
    }

    #[test]
    fn duplicate_interface_section_rejected() {
        let (priv_b64, pub_b64) = keys();
        let text = format!(
            "[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.0.0.2/32\n[Interface]\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
        );
        let imp = ConfigImport::parse_str(&text, std::path::Path::new("dup-iface.conf"))
            .expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Rejected);
        assert!(
            imp.reasons.join(" ").contains("[Interface]"),
            "names section: {:?}",
            imp.reasons
        );
    }

    #[test]
    fn reserved_stem_sanitizes_and_round_trips() {
        assert_eq!(sanitize_ref("CON"), "CON-import");
        assert_eq!(sanitize_ref("aux"), "aux-import");
        assert_eq!(sanitize_ref("wg-home"), "wg-home");
        // Collision suffixes are never device names either.
        assert!(!is_reserved_import_ref("CON-import"));
    }

    #[test]
    fn partial_awg_keys_accepted_with_zeros() {
        // Live imports are lenient by design (generator-written partial
        // configs interop): absent numerics read as 0/disabled. Stored
        // records stay strict (machine-written complete); see
        // `truncated_awg_record_fails_closed` for that side.
        let (priv_b64, pub_b64) = keys();
        let text = format!("[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.0.0.2/32\nJc = 6\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.20:51820\n");
        let imp = ConfigImport::parse_str(&text, std::path::Path::new("partial-awg.conf"))
            .expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Accepted, "{:?}", imp.reasons);
        assert_eq!(imp.source_format, SourceFormat::Amneziawg);
        let awg = imp.awg.expect("awg detected");
        assert_eq!((awg.jc, awg.jmin, awg.jmax), (6, 0, 0));
    }

    #[test]
    fn bad_cidr_rejected() {
        assert!(check_cidr("10.0.0.2/32").is_ok());
        assert!(check_cidr("::/0").is_ok());
        assert!(check_cidr("999.999.999.999/99").is_err());
        assert!(check_cidr("garbage/garbage").is_err());
        assert!(check_cidr("10.0.0.1").is_err());
        assert!(check_cidr("10.0.0.1/33").is_err());
        let (priv_b64, pub_b64) = keys();
        let imp = ConfigImport::parse_str(
            &wg_hop(
                &priv_b64,
                &pub_b64,
                "Address = 999.999.999.999/99",
                "203.0.113.10:51820",
            ),
            std::path::Path::new("bad-cidr.conf"),
        )
        .expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Rejected);
    }

    #[test]
    fn ambiguous_endpoints_rejected() {
        assert!(check_endpoint("example.com:51820").is_ok());
        assert!(check_endpoint("1.2.3.4:51820").is_ok());
        assert!(check_endpoint("[2001:db8::1]:51820").is_ok());
        for bad in [
            "::1",
            "2001:db8::1:51820",
            "::::80",
            "1.2.3.4:0",
            "1.2.3.4:notaport",
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn free_form_i_values_keep_hash_and_semi() {
        let (priv_b64, pub_b64) = keys();
        let text = format!(
            "[Interface]\nPrivateKey = {priv_b64}\nAddress = 10.0.0.2/32\nJc = 6\nJmin = 64\nJmax = 256\nS1 = 24\nS2 = 18\nS3 = 30\nS4 = 16\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\nI1 = foo#bar\nI2 = foo;bar\n[Peer]\nPublicKey = {pub_b64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.20:51820\n"
        );
        let imp =
            ConfigImport::parse_str(&text, std::path::Path::new("hash-val.conf")).expect("verdict");
        assert_eq!(imp.verdict, ImportVerdict::Accepted, "{:?}", imp.reasons);
        let awg = imp.awg.expect("awg detected");
        assert_eq!(awg.i1.as_deref(), Some("foo#bar"));
        assert_eq!(awg.i2.as_deref(), Some("foo;bar"));
    }
}
