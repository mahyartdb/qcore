//! Shipped WARP/MASQUE endpoint candidates (002 FR-014, research R5).
//!
//! The scanner stays a sieve — this module finally gives it candidates.
//! `profiles/warp.toml` (profile-dir override, else the shipped data)
//! carries provider ranges, per-family seeds, port pools, and the default
//! scan choice: replaceable data, validated shape, never content provenance
//! (FR-028).
//!
//! Bounds (documented, deterministic — constitution V): seeds expand over
//! every listed port; range samples ride the primary port only; IPv4 CIDRs
//! sample evenly up to [`MAX_HOSTS_PER_RANGE`]; totals cap at
//! [`MAX_SEEDED_CANDIDATES`]. Same file, same family → same candidates.

use crate::config::profile_dir::ProfileDirs;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

/// Shipped defaults (profiles/warp.toml); the zero-config front door.
pub const SHIPPED_WARP_TOML: &str = include_str!("../../../../profiles/warp.toml");

/// Hard cap on seeded candidates per scan (keeps scans inside profile
/// `rtt_budget_ms` bounds).
pub const MAX_SEEDED_CANDIDATES: usize = 512;
/// Even-sample cap per IPv4 range.
pub const MAX_HOSTS_PER_RANGE: usize = 32;

/// Candidates for one transport section of warp.toml.
#[derive(Debug, Clone)]
pub struct TransportCandidates {
    pub ranges: Vec<String>,
    pub seeds: Vec<String>,
    pub ports: Vec<u16>,
    pub v6_ranges: Vec<String>,
    pub v6_seeds: Vec<String>,
}

/// Parsed warp.toml: both transports plus the default scan choice.
#[derive(Debug, Clone)]
pub struct WarpProfiles {
    pub warp: TransportCandidates,
    pub masque: TransportCandidates,
    pub default_scan_profile: String,
}

/// Load warp.toml: profile-dir override when present, else the shipped
/// data. Shape errors fail closed naming the file and field. A
/// present-but-unreadable override fails closed — only `NotFound` falls
/// back to shipped data (mirrors `config::obfuscation::load_profiles`).
pub fn load_warp_profiles(dirs: &ProfileDirs) -> Result<WarpProfiles, String> {
    let path = dirs.profile_dir.join("warp.toml");
    let (text, file) = match std::fs::read_to_string(&path) {
        Ok(t) => (t, "warp.toml"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (SHIPPED_WARP_TOML.to_string(), "shipped warp.toml")
        }
        Err(e) => {
            return Err(format!("warp.toml: cannot read {}: {e}", path.display()));
        }
    };
    parse_warp_toml(&text).map_err(|e| format!("{file}: {e}"))
}

fn parse_warp_toml(text: &str) -> Result<WarpProfiles, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("invalid TOML ({e})"))?;
    let section = |name: &str| {
        v.get(name)
            .and_then(|x| x.as_table())
            .ok_or_else(|| format!("missing [{name}]"))
    };
    let strings = |t: &toml::map::Map<String, toml::Value>, section: &str, key: &str| {
        t.get(key)
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("[{section}] missing `{key}`"))?
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("[{section}] `{key}` entries must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let load_transport = |name: &str| {
        let t = section(name)?;
        let ports: Vec<u16> = t
            .get("ports")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("[{name}] missing `ports`"))?
            .iter()
            .map(|x| {
                x.as_integer()
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0)
                    .ok_or_else(|| format!("[{name}] `ports` entries must be 1..=65535"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if ports.is_empty() {
            return Err(format!("[{name}] `ports` must not be empty"));
        }
        let seeds = strings(t, name, "seeds")?;
        for s in &seeds {
            s.parse::<IpAddr>()
                .map_err(|_| format!("[{name}] `seeds` entry `{s}` is not an IP literal"))?;
        }
        Ok(TransportCandidates {
            ranges: strings(t, name, "ranges")?,
            seeds,
            ports,
            v6_ranges: strings(t, name, "v6_ranges")?,
            v6_seeds: strings(t, name, "v6_seeds")?,
        })
    };
    let warp = load_transport("warp")?;
    let masque = load_transport("masque")?;
    // v6 seeds must be v6 literals (a v4 seed under v6 silently selects
    // nothing on v6 scans — fail at load instead).
    for s in warp.v6_seeds.iter().chain(masque.v6_seeds.iter()) {
        match s.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => {}
            _ => return Err(format!("`v6_seeds` entry `{s}` is not an IPv6 literal")),
        }
    }
    let default_scan_profile = v
        .get("defaults")
        .and_then(|x| x.as_table())
        .and_then(|t| t.get("scan_profile"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| "[defaults] missing `scan_profile`".to_string())?
        .to_string();
    Ok(WarpProfiles {
        warp,
        masque,
        default_scan_profile,
    })
}

/// Seeded candidates for a transport + family, deterministic order.
/// Transport mapping: `warp`|`wireguard`|`gool` → warp section,
/// `masque` → masque section; anything else selects nothing (the sieve
/// stays empty rather than guessing).
pub fn candidates_for(profiles: &WarpProfiles, transport: &str, family: &str) -> Vec<SocketAddr> {
    let section = match transport {
        "warp" | "wireguard" | "gool" => &profiles.warp,
        "masque" => &profiles.masque,
        _ => return Vec::new(),
    };
    let mut out = BTreeSet::new();
    let want_v4 = family != "ipv6";
    let want_v6 = family != "ipv4";
    let primary_port = section.ports[0];
    if want_v4 {
        for seed in &section.seeds {
            if let Ok(IpAddr::V4(ip)) = seed.parse() {
                for port in &section.ports {
                    out.insert(SocketAddr::new(IpAddr::V4(ip), *port));
                }
            }
        }
        for range in &section.ranges {
            for host in sample_cidr_v4(range) {
                out.insert(SocketAddr::new(IpAddr::V4(host), primary_port));
            }
        }
    }
    if want_v6 {
        for seed in &section.v6_seeds {
            if let Ok(IpAddr::V6(ip)) = seed.parse() {
                for port in &section.ports {
                    out.insert(SocketAddr::new(IpAddr::V6(ip), *port));
                }
            }
        }
        for range in &section.v6_ranges {
            if let Some(host) = first_host_v6(range) {
                out.insert(SocketAddr::new(IpAddr::V6(host), primary_port));
            }
        }
    }
    out.into_iter().take(MAX_SEEDED_CANDIDATES).collect()
}

/// Even, deterministic sample of an IPv4 CIDR (`a.b.c.d/n`): skip network +
/// broadcast for prefixes < 31 (unusable), stride-sample longer ranges.
/// Unparseable ranges select nothing (data is advisory, never fatal).
fn sample_cidr_v4(cidr: &str) -> Vec<std::net::Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(x) => x,
        None => return Vec::new(),
    };
    let base_u32 = u32::from(base);
    let host_bits = 32 - prefix;
    if host_bits == 0 {
        return vec![base];
    }
    let total = 1u64 << host_bits;
    if host_bits == 1 {
        return vec![
            std::net::Ipv4Addr::from(base_u32),
            std::net::Ipv4Addr::from(base_u32 + 1),
        ];
    }
    let usable = total - 2; // network + broadcast
    let count = usable.min(MAX_HOSTS_PER_RANGE as u64);
    let stride = (usable / count).max(1);
    // No clamping: parse_cidr_v4 masks the base address, so
    // base + total <= 2^32 always and every sampled address fits u32.
    // The debug_assert pins that invariant; the saturating conversion is
    // belt-and-braces that never fires (and never panics in release).
    let last_usable = base_u32 as u64 + total - 2;
    (0..count)
        .map(|i| {
            let addr = base_u32 as u64 + 1 + i * stride;
            debug_assert!(addr <= last_usable);
            std::net::Ipv4Addr::from(u32::try_from(addr).unwrap_or(u32::MAX))
        })
        .collect()
}

fn parse_cidr_v4(cidr: &str) -> Option<(std::net::Ipv4Addr, u32)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let base: std::net::Ipv4Addr = ip.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((std::net::Ipv4Addr::from(u32::from(base) & mask), prefix))
}

/// First usable host of an IPv6 range (`base/prefix` → base+1). Full-range
/// enumeration is infeasible; seeds carry v6 discovery.
fn first_host_v6(cidr: &str) -> Option<std::net::Ipv6Addr> {
    let (ip, _) = cidr.split_once('/')?;
    let base: std::net::Ipv6Addr = ip.parse().ok()?;
    let mut segments = base.segments();
    segments[7] = segments[7].wrapping_add(1);
    Some(std::net::Ipv6Addr::from(segments))
}

/// Zero-config default scan profile name (FR-014): warp.toml's choice, or
/// `balanced` when the file is missing or malformed (never fatal here —
/// the scanner validates the profile itself downstream).
pub fn default_scan_profile_name(dirs: &ProfileDirs) -> String {
    load_warp_profiles(dirs)
        .map(|p| p.default_scan_profile)
        .unwrap_or_else(|_| "balanced".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_sampling_rules() {
        // /32 is the address itself.
        assert_eq!(
            sample_cidr_v4("127.0.0.1/32"),
            vec!["127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        // /31 keeps both (no broadcast).
        assert_eq!(sample_cidr_v4("127.0.0.0/31").len(), 2);
        // /30 skips .0 and .3.
        let hosts = sample_cidr_v4("127.0.0.0/30");
        assert_eq!(hosts.len(), 2);
        assert!(hosts
            .iter()
            .all(|h| h.octets()[3] == 1 || h.octets()[3] == 2));
        // /24 caps at 32, evenly spread and deterministic.
        let a = sample_cidr_v4("162.159.192.0/24");
        let b = sample_cidr_v4("162.159.192.0/24");
        assert_eq!(a.len(), MAX_HOSTS_PER_RANGE);
        assert_eq!(a, b);
        // Garbage selects nothing.
        assert!(sample_cidr_v4("nope").is_empty());
        assert!(sample_cidr_v4("1.2.3.4/33").is_empty());
        // High ranges stay inside the CIDR. No overflow is possible here
        // (parse_cidr_v4 masks the base, so base + total <= 2^32 always):
        // this pins containment as a characterization test.
        let high = sample_cidr_v4("255.255.0.0/16");
        assert_eq!(high.len(), MAX_HOSTS_PER_RANGE);
        let base = u32::from("255.255.0.0".parse::<std::net::Ipv4Addr>().unwrap());
        assert!(high.iter().all(|h| {
            let n = u32::from(*h);
            n > base && n <= base + 65534
        }));
    }

    #[test]
    fn shipped_shape_parses() {
        let p = parse_warp_toml(SHIPPED_WARP_TOML).expect("shipped parses");
        assert_eq!(p.default_scan_profile, "balanced");
        assert_eq!(p.warp.ports[0], 2408);
        assert_eq!(p.masque.ports[0], 443);
    }

    #[test]
    fn load_fails_closed_only_not_found_falls_back() {
        // Absent file falls back to shipped data.
        let base = std::env::temp_dir().join(format!("qcore-warp-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dirs = ProfileDirs::resolve(None, Some(base.join("prof")));
        let p = load_warp_profiles(&dirs).expect("missing falls back");
        assert_eq!(p.default_scan_profile, "balanced");
        // Present-but-unreadable (a directory at the file path) fails closed
        // instead of silently using shipped data.
        let base2 = std::env::temp_dir().join(format!("qcore-warp-unread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base2);
        let prof = base2.join("prof");
        std::fs::create_dir_all(prof.join("warp.toml")).unwrap();
        let dirs2 = ProfileDirs::resolve(None, Some(prof));
        let err = load_warp_profiles(&dirs2).unwrap_err();
        assert!(
            err.contains("cannot read") && err.contains("warp.toml"),
            "fail closed: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&base2);
    }
}
