//! `preflight` / `check`: validate chain + profiles + config, open ZERO
//! network sockets (FR-029, SC-002d). Refusal is exit 2 naming the offending
//! hop and reason.

use qcore_core::api::{Engine, EngineConfig};
use qcore_core::chain::ExpandedHop;
use qcore_core::config::profile_dir::ProfileDirs;

use crate::exit;

/// Shared chain-input resolution (US3 T056): `--chain`, `--chain-file`,
/// positional file, repeatable `--hop` in argv order. Returns authored hops
/// plus an optional file-requested max depth. Conflicting sources are a
/// usage error (exit 6); bad inputs are validation errors (exit 2).
pub struct ResolvedInputs {
    pub specs: Vec<ExpandedHop>,
    pub max_depth: Option<u32>,
}

/// Chain-default obfuscation (US5 T073 `-O`): hops without an explicit
/// `obfuscation=` key inherit the profile. Preset references are untouched
/// (their expansion carries its own keys or none). Returns the hop count
/// that received the default (zero means `-O` matched nothing).
pub fn apply_obfuscation_default(specs: &mut [ExpandedHop], profile: &str) -> usize {
    let mut n = 0;
    for s in specs.iter_mut() {
        if let ExpandedHop::Hop(h) = s {
            match &mut h.config {
                qcore_core::config::HopConfig::Wireguard(c) if c.obfuscation.is_none() => {
                    c.obfuscation = Some(profile.to_string());
                    n += 1;
                }
                qcore_core::config::HopConfig::Masque(c) if c.obfuscation.is_none() => {
                    c.obfuscation = Some(profile.to_string());
                    n += 1;
                }
                // Plugin hops (SC-002c) carry `obfuscation=` opaquely.
                qcore_core::config::HopConfig::Plugin(c)
                    if !c.fields.contains_key("obfuscation") =>
                {
                    c.fields
                        .insert("obfuscation".to_string(), profile.to_string());
                    n += 1;
                }
                _ => {}
            }
        }
    }
    n
}

pub fn resolve_inputs(
    engine: &Engine,
    chain: Option<&str>,
    chain_file: Option<&str>,
    positional: Option<&str>,
    hops: &[String],
) -> Result<ResolvedInputs, (i32, String)> {
    let file = match (chain_file, positional) {
        (Some(_), Some(_)) => {
            return Err((
                exit::USAGE,
                "--chain-file and positional file conflict".into(),
            ))
        }
        (Some(f), None) => Some(f),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    };
    if chain.is_some() && file.is_some() {
        return Err((exit::USAGE, "--chain and --chain-file conflict".into()));
    }
    if !hops.is_empty() && (chain.is_some() || file.is_some()) {
        return Err((
            exit::USAGE,
            "--hop and --chain/--chain-file conflict".into(),
        ));
    }
    if let Some(path) = file {
        let cf = qcore_core::config::chain_file::load_chain_file(std::path::Path::new(path))
            .map_err(|e| (exit::INVALID, e.to_string()))?;
        return Ok(ResolvedInputs {
            specs: cf.hops,
            max_depth: cf.max_depth,
        });
    }
    if !hops.is_empty() {
        let mut specs = Vec::new();
        for h in hops {
            match engine.parse_chain(h) {
                Ok(mut s) => specs.append(&mut s),
                Err(e) => return Err((exit::INVALID, e.to_string())),
            }
        }
        return Ok(ResolvedInputs {
            specs,
            max_depth: None,
        });
    }
    match chain {
        Some(expr) => match engine.parse_chain(expr) {
            Ok(specs) => Ok(ResolvedInputs {
                specs,
                max_depth: None,
            }),
            Err(e) => Err((exit::INVALID, e.to_string())),
        },
        None => Err((
            exit::USAGE,
            "no chain: pass --chain, --hop, --chain-file or a file".into(),
        )),
    }
}

/// Parse `--chain "<expr>"` (full grammar), a preset name, or a bare
/// transport kind into authored hops.
pub fn parse_chain_arg(engine: &Engine, expr: &str) -> Result<Vec<ExpandedHop>, String> {
    engine.parse_chain(expr).map_err(|e| e.to_string())
}

pub fn run(engine: &Engine, chain: &str, json: bool) -> i32 {
    let inputs = match resolve_inputs(engine, Some(chain), None, None, &[]) {
        Ok(i) => i,
        Err((code, msg)) => {
            eprintln!("qcore: {msg}");
            return code;
        }
    };
    run_resolved(engine, &inputs, json, false)
}

pub fn run_resolved(engine: &Engine, inputs: &ResolvedInputs, json: bool, quiet: bool) -> i32 {
    match engine.preflight(inputs.specs.clone()) {
        qcore_core::api::engine::Preflight::Ok { depth } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "depth": depth, "sockets_opened": 0})
                );
            } else if !quiet {
                eprintln!("preflight ok: depth {depth}, zero sockets opened");
            }
            exit::SUCCESS
        }
        qcore_core::api::engine::Preflight::Rejected(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "hop_index": e.hop_index,
                        "hop_id": e.hop_id,
                        "reason": e.reason,
                        "fix": e.fix,
                    })
                );
            } else {
                eprintln!("qcore: invalid chain (exit 2)");
                match (e.hop_index, &e.hop_id) {
                    (Some(i), Some(id)) => eprintln!("  hop {i} `{id}`: {}", e.reason),
                    _ => eprintln!("  {}", e.reason),
                }
                if let Some(fix) = &e.fix {
                    eprintln!("  fix: {fix}");
                }
            }
            exit::INVALID
        }
    }
}

pub fn default_engine(dirs: ProfileDirs) -> Engine {
    Engine::new(EngineConfig {
        dirs,
        ..Default::default()
    })
}

/// Fail-closed refusal when `-O` matches no hop, in the same shape as other
/// preflight rejections (text or one JSON document).
pub fn reject_obfuscation_without_target(profile: &str, json: bool) -> i32 {
    let reason = format!("obfuscation profile `{profile}` applies to no hop in this chain");
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": false,
                "hop_index": None::<u32>,
                "hop_id": None::<String>,
                "reason": reason,
                "fix": None::<String>,
            })
        );
    } else {
        eprintln!("qcore: invalid chain (exit 2)\n  {reason}");
    }
    exit::INVALID
}
