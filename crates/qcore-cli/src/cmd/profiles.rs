//! Profiles listing (US5 T073): transports+modes, scan profiles,
//! obfuscation profiles, composition presets, and generated chain shortcuts
//! — everything selectable, from data, in one place.

use qcore_core::api::Engine;

use crate::exit;

/// Mode hints per transport kind (display only; validation is descriptor- and
/// data-driven elsewhere).
const MODES: &[(&str, &str)] = &[
    ("wireguard", "peer=warp|imported|awg"),
    ("masque", "alpn=h3|h2"),
    ("tor", "-"),
    ("psiphon", "-"),
    ("relay", "-"),
    ("mock", "-"),
];

pub fn run(engine: &Engine, dirs: &qcore_core::config::profile_dir::ProfileDirs) -> i32 {
    println!("transports:");
    for kind in engine.registry().kinds() {
        let mode = MODES
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, m)| *m)
            .unwrap_or("-");
        println!("  {kind}  ({mode})");
    }
    println!("scan profiles:");
    for name in ["turbo", "balanced", "stealth"] {
        match qcore_core::scan::load_profile(dirs, name) {
            Ok(p) => println!(
                "  {name}  (concurrency={} rtt_budget_ms={} probe={:?} families={:?}{})",
                p.concurrency,
                p.rtt_budget_ms,
                p.probe_kind,
                p.family_order,
                if p.stealth { " stealth" } else { "" },
            ),
            Err(e) => println!("  {name}  (unavailable: {e})"),
        }
    }
    println!("endpoint candidates (warp.toml):");
    match qcore_core::scan::seeds::load_warp_profiles(dirs) {
        Ok(wp) => {
            let warp_n = qcore_core::scan::seeds::candidates_for(&wp, "warp", "dual").len();
            let masque_n = qcore_core::scan::seeds::candidates_for(&wp, "masque", "dual").len();
            println!(
                "  warp: {warp_n} candidates  masque: {masque_n} candidates  default scan profile: {}",
                wp.default_scan_profile
            );
        }
        Err(e) => println!("  (unavailable: {e})"),
    }
    println!("obfuscation profiles:");
    match qcore_core::config::obfuscation::load_profiles(dirs) {
        Ok(profiles) => {
            for (name, p) in &profiles {
                let modes: Vec<String> = p
                    .compatible_modes
                    .iter()
                    .map(|m| {
                        let mut s = m.kind.clone();
                        if let Some(peer) = &m.peer {
                            s.push_str(&format!(" peer={peer}"));
                        }
                        if let Some(alpn) = &m.alpn {
                            s.push_str(&format!(" alpn={alpn}"));
                        }
                        s
                    })
                    .collect();
                let family = match p.family {
                    qcore_core::config::obfuscation::ObfFamily::Noize => "noize",
                    qcore_core::config::obfuscation::ObfFamily::Awg => "awg",
                };
                println!("  {name}  ({family}; {})", modes.join(", "));
            }
        }
        Err(e) => println!("  (unavailable: {e})"),
    }
    println!("presets:");
    // Single resolution shared with shortcuts below: resolving twice would
    // read the file twice and handle override errors inconsistently.
    let presets = match qcore_core::chain::preset::resolve_presets(dirs) {
        Ok(presets) => {
            for p in &presets {
                println!("  {}", p.name);
            }
            presets
        }
        Err(e) => {
            // Name the fallback explicitly: the names below are builtins,
            // not the effective configuration (every consumer of
            // resolve_presets fails closed on this error).
            println!("  (unavailable: {e}; showing builtin fallback)");
            qcore_core::chain::preset::builtin_presets()
        }
    };
    println!("shortcuts:");
    crate::cmd::shortcuts::print_shortcuts(engine, &presets);
    exit::SUCCESS
}
