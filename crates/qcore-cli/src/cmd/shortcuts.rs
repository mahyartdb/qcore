//! Generated chain shortcuts (US3 T057).
//!
//! A chain token (`qcore tor-warp`) is minted iff all six hold:
//! 1. Every hyphen-segment resolves to exactly one registry token (a
//!    transport kind in default mode, or a preset).
//! 2. The expanded chain is within the depth cap (over-depth still parses
//!    but is unadvertised and fails closed exit 2 when invoked).
//! 3. No collision with command/alias/global-flag names.
//! 4. Pure alias: resolution feeds the identical connect/preflight path as
//!    the long form (same ConnectionReport, same exit code).
//! 5. Generated from the registry with zero CLI edits (candidates are
//!    computed, never hand-listed).
//! 6. Never encodes a mode-with-options: option values are never registry
//!    tokens, so rule 1 already rejects `masque-h2` (asserted in tests).
//!
//! Segmentation is longest-preset-first, then single-segment kinds (kinds
//! never contain hyphens). Unknown tokens are exit 6, never fuzzy-resolved.

use qcore_core::api::Engine;
use qcore_core::chain::preset::CompositionPreset;
use qcore_core::chain::{ChainError, ExpandedHop};

/// Command/alias/global-flag names shortcuts may never collide with.
pub const RESERVED: &[&str] = &[
    "connect",
    "up",
    "stop",
    "down",
    "preflight",
    "check",
    "scan",
    "import",
    "export",
    "profiles",
    "ls",
    "status",
    "version",
    "help",
    "chain",
    "chain-file",
    "hop",
    "file",
    "family",
    "prefer",
    "obfuscation",
    "max-depth",
    "timeout",
    "json",
    "report-out",
    "config",
    "profile-dir",
    "log-level",
    "no-color",
    "quiet",
    "verbose",
    "non-interactive",
    "yes",
    "detach",
    "bind",
    "child",
];

/// A minted shortcut: name plus authored specs (presets unexpanded, so the
/// connect path expands exactly like the long form — rule 4).
#[derive(Debug, Clone)]
pub struct Shortcut {
    pub name: String,
    pub specs: Vec<ExpandedHop>,
}

#[derive(Debug)]
pub enum ResolveFailure {
    Unknown(String),
    Invalid(ChainError),
}

/// Segment a shortcut name longest-preset-first, then kinds.
fn segment<'a>(
    name: &'a str,
    engine: &Engine,
    presets: &'a [CompositionPreset],
) -> Result<Vec<Segment<'a>>, ResolveFailure> {
    let raw: Vec<&str> = name.split('-').collect();
    if raw.iter().any(|s| s.is_empty()) {
        return Err(ResolveFailure::Unknown(name.to_string()));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        // Longest preset match at this position.
        let mut hit: Option<(&'a str, usize)> = None;
        for p in presets {
            let segs: Vec<&str> = p.name.split('-').collect();
            if raw[i..].starts_with(&segs[..]) && hit.map(|(_, n)| segs.len() > n).unwrap_or(true) {
                hit = Some((p.name.as_str(), segs.len()));
            }
        }
        if let Some((pname, n)) = hit {
            out.push(Segment::Preset(pname));
            i += n;
            continue;
        }
        let seg = raw[i];
        let is_kind = engine.registry().get(seg).is_some();
        let is_preset = presets.iter().any(|p| p.name == seg);
        match (is_kind, is_preset) {
            (true, false) => out.push(Segment::Kind(seg)),
            (false, true) => out.push(Segment::Preset(
                presets
                    .iter()
                    .find(|p| p.name == seg)
                    .expect("preset presence checked via `any` above")
                    .name
                    .as_str(),
            )),
            (true, true) => {
                return Err(ResolveFailure::Unknown(format!(
                    "{name}: `{seg}` is both a kind and a preset"
                )))
            }
            (false, false) => return Err(ResolveFailure::Unknown(name.to_string())),
        }
        i += 1;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum Segment<'a> {
    Kind(&'a str),
    Preset(&'a str),
}

/// Resolve a shortcut name to authored specs (rule 4: identical downstream).
pub fn resolve(
    engine: &Engine,
    presets: &[CompositionPreset],
    max_depth: u32,
    name: &str,
) -> Result<Vec<ExpandedHop>, ResolveFailure> {
    if RESERVED.contains(&name) {
        return Err(ResolveFailure::Unknown(name.to_string()));
    }
    let segs = segment(name, engine, presets)?;
    let mut specs = Vec::new();
    let mut n = 0u32;
    for s in segs {
        match s {
            Segment::Preset(p) => specs.push(ExpandedHop::Preset(p.to_string())),
            Segment::Kind(k) => {
                let mut spec = engine
                    .parse_single_hop_in(k, "")
                    .map_err(ResolveFailure::Invalid)?;
                spec.id = format!("{k}-{n}");
                n += 1;
                specs.push(ExpandedHop::Hop(spec));
            }
        }
    }
    // Validate now so invocation fails closed identically (rule 4); depth
    // included (rule 2).
    qcore_core::chain::ChainBuilder::new(engine.registry(), max_depth)
        .build_with(specs.clone(), presets)
        .map_err(ResolveFailure::Invalid)?;
    Ok(specs)
}

/// All minted shortcuts: 1- and 2-token joins of kinds and presets passing
/// all six rules (rule 5: computed from the registry).
pub fn advertised(engine: &Engine, presets: &[CompositionPreset], max_depth: u32) -> Vec<Shortcut> {
    let mut tokens: Vec<String> = engine
        .registry()
        .kinds()
        .iter()
        .map(|s| s.to_string())
        .collect();
    for p in presets {
        if !tokens.contains(&p.name) {
            tokens.push(p.name.clone());
        }
    }
    let mut names = tokens.clone();
    for a in &tokens {
        for b in &tokens {
            names.push(format!("{a}-{b}"));
        }
    }
    let mut out = Vec::new();
    for name in names {
        if RESERVED.contains(&name.as_str()) {
            continue;
        }
        if let Ok(specs) = resolve(engine, presets, max_depth, &name) {
            out.push(Shortcut { name, specs })
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Canonical `--chain` expression for authored specs (used to re-spawn the
/// detach child faithfully): presets by name, hops as `kind k=v...`. Values
/// containing `,`, whitespace, `=`, or quotes are quoted (the grammar
/// requires it); without quoting, reparse splits or misparses them.
pub fn canonical_expr(specs: &[ExpandedHop]) -> String {
    specs
        .iter()
        .map(|s| match s {
            ExpandedHop::Preset(p) => p.clone(),
            ExpandedHop::Hop(h) => {
                let pairs = h.config.to_factory_config();
                let mut parts = vec![h.config.kind().to_string()];
                let mut keys: Vec<&str> = pairs.fields.keys().map(|k| k.as_str()).collect();
                keys.sort();
                for k in keys {
                    if k == "hop_id" {
                        continue;
                    }
                    parts.push(format!("{k}={}", quote_value(&pairs.fields[k])));
                }
                parts.join(" ")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Quote a canonical value iff the grammar needs it (see `tokenize`); quote
/// and backslash are escaped so reparse restores the exact string.
fn quote_value(v: &str) -> String {
    if v.chars()
        .all(|c| !c.is_whitespace() && c != ',' && c != '=' && c != '"' && c != '\'')
        && !v.is_empty()
    {
        return v.to_string();
    }
    // Escape only what the grammar needs: `"` always (it would close the
    // span); `\` only when it would escape the next char or the closing
    // quote (`C:\Program Files\app.exe` stays readable unescaped).
    let chars: Vec<char> = v.chars().collect();
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for (i, c) in chars.iter().enumerate() {
        let next = chars.get(i + 1);
        if *c == '"' || (*c == '\\' && matches!(next, None | Some('"') | Some('\\'))) {
            out.push('\\');
        }
        out.push(*c);
    }
    out.push('"');
    out
}

/// Validate the six-rule generator itself (rule 5 regression net).
pub fn audit(engine: &Engine, presets: &[CompositionPreset], max_depth: u32) -> Vec<String> {
    let mut problems = Vec::new();
    for s in advertised(engine, presets, max_depth) {
        // Rule 4 spot-check: re-parsing the canonical form validates equal.
        match engine.parse_chain(&canonical_expr(&s.specs)) {
            Ok(_) => {}
            Err(e) => problems.push(format!("{}: canonical reparse: {e}", s.name)),
        }
    }
    // Rule 6: mode-with-options never mints.
    if advertised(engine, presets, max_depth)
        .iter()
        .any(|s| s.name == "masque-h2")
    {
        problems.push("masque-h2 minted".to_string());
    }
    problems
}

/// Print one shortcut section (shared by the full profiles listing so `ls`
/// keeps listing every advertised shortcut — T057 rule intact).
pub fn print_shortcuts(engine: &Engine, presets: &[qcore_core::chain::preset::CompositionPreset]) {
    for s in advertised(engine, presets, 3) {
        println!("  {}  (= {})", s.name, canonical_expr(&s.specs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let _ = qcore_transports::linked_kinds();
        Engine::new(qcore_core::api::EngineConfig::default())
    }

    #[test]
    fn no_shortcut_collides_with_commands() {
        let e = engine();
        let presets = qcore_core::chain::preset::builtin_presets();
        for s in advertised(&e, &presets, 3) {
            assert!(
                !RESERVED.contains(&s.name.as_str()),
                "collision: {}",
                s.name
            );
        }
    }

    #[test]
    fn unknown_token_never_resolves() {
        let e = engine();
        let presets = qcore_core::chain::preset::builtin_presets();
        assert!(matches!(
            resolve(&e, &presets, 3, "frobnicate"),
            Err(ResolveFailure::Unknown(_))
        ));
        assert!(matches!(
            resolve(&e, &presets, 3, "masque-h2"),
            Err(ResolveFailure::Unknown(_))
        ));
    }

    #[test]
    fn canonical_quotes_values_needing_it() {
        // Values with spaces/commas/equals must quote or reparse breaks
        // (detach re-spawn and audit reparse consume this form).
        assert_eq!(quote_value("plain"), "plain");
        assert_eq!(quote_value(""), "\"\"");
        assert_eq!(
            quote_value("C:\\Program Files\\app.exe"),
            "\"C:\\Program Files\\app.exe\""
        );
        assert_eq!(quote_value("a,b=c"), "\"a,b=c\"");
        assert_eq!(quote_value("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn tor_warp_mints_and_canonical_roundtrips() {
        let e = engine();
        let presets = qcore_core::chain::preset::builtin_presets();
        let specs = resolve(&e, &presets, 3, "tor-warp").expect("tor-warp mints");
        assert_eq!(canonical_expr(&specs), "tor-warp");
        // Pure alias: identical verdict to the long form.
        let a = e.preflight(specs);
        let b = e.preflight(vec![ExpandedHop::Preset("tor-warp".into())]);
        assert!(matches!(
            (a, b),
            (
                qcore_core::api::engine::Preflight::Ok { .. },
                qcore_core::api::engine::Preflight::Ok { .. }
            )
        ));
    }
}
