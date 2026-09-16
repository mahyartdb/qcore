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
    match qcore_core::chain::preset::resolve_presets(dirs) {
        Ok(presets) => {
            for p in &presets {
                println!("  {}", p.name);
            }
        }
        Err(e) => println!("  (unavailable: {e})"),
    }
    println!("shortcuts:");
    let presets = qcore_core::chain::preset::resolve_presets(dirs)
        .unwrap_or_else(|_| qcore_core::chain::preset::builtin_presets());
    crate::cmd::shortcuts::print_shortcuts(engine, &presets);
    exit::SUCCESS
}
