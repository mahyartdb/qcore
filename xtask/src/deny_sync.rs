//! `xtask deny-sync`: keep `denylist.toml` `[bans] skip` entries honest
//! against the actual dependency graph (supply-chain wave H3.11a).
//!
//! cargo-deny with `multiple-versions = "deny"` + `skip` entries fails when
//! a NEW unskipped duplicate appears, but its `unmatched-skip` /
//! `unnecessary-skip` diagnostics are only WARNINGS by default — a dead
//! skip line passes the gate silently (and the CI never denies them), and
//! the check runs once against one target graph, not the 9 configured
//! ones. This subcommand recomputes, for EVERY target in the denylist
//! `[graph] targets` list, which crate names appear at more than one
//! version and cross-checks them against the skip list:
//!
//! - a skip entry whose crate matches NO version in ANY target graph fails
//!   (dead policy line — remove it or scope it);
//! - a duplicate-name target graph without a matching skip entry fails
//!   (cargo-deny would have failed the same run, but naming the exact
//!   crate here makes the fix actionable).
//!
//! Target graphs are built from `cargo metadata --filter-platform <t>`
//! with dev-dependencies included (matching cargo-deny's default
//! `multiple-versions-include-dev = false` semantics is intentional: we
//! check the NAME-level coverage of the skip list, which must be a
//! superset of any mode cargo-deny runs in).
//!
//! Exit is nonzero on any mismatch; output names crate, versions, and the
//! offending skip line.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// denylist.toml path (repo root, cargo-deny's contracted config).
const DENYLIST_TOML: &str = "denylist.toml";

/// One parsed `[bans] skip` entry: `crate = "name@version"` plus any
/// `targets-external: <triple>, ...` marker in the reason (an entry that is
/// deliberately scoped OUT of the configured `[graph]` targets and instead
/// verified against the named triples' graphs).
#[derive(Debug)]
struct SkipEntry {
    crate_spec: String,
    external_targets: Vec<String>,
    line_no: usize,
}

/// Parse the skip list + `[graph] targets` triples out of denylist.toml.
/// Shape errors fail closed naming the line (same policy as the cargo-deny
/// config itself: a malformed denylist is a broken gate, not a soft skip).
///
/// A skip entry whose reason contains `targets-external:` followed by a
/// comma-separated triple list declares itself scoped OUT of the configured
/// `[graph]` targets; deny-sync verifies it against those triples' graphs
/// instead (so the entry can never go silently dead — its claim is checked).
fn parse_denylist(text: &str) -> Result<(Vec<SkipEntry>, Vec<String>), String> {
    let mut skips = Vec::new();
    let mut targets = Vec::new();
    let mut in_skip = false;
    let mut in_targets = false;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let l = raw.trim();
        if l.starts_with('#') || l.is_empty() {
            continue;
        }
        // Section headers reset block membership. `[graph]` also restarts
        // its target list; `[bans]` restarts the skip list.
        if l.starts_with('[') {
            in_skip = l == "[bans]";
            in_targets = l == "[graph]";
            continue;
        }
        if in_skip {
            if let Some(rest) = l.strip_prefix("{ crate = ") {
                let (spec_part, reason_part) = rest.split_once(", reason = ").ok_or_else(|| {
                    format!(
                        "denylist.toml:{line_no}: skip entry without a reason (policy: every skip documents its subtree)"
                    )
                })?;
                let spec = spec_part.trim().trim_matches('"').to_string();
                if spec.is_empty() {
                    return Err(format!(
                        "denylist.toml:{line_no}: skip entry with empty crate spec"
                    ));
                }
                let reason = reason_part
                    .trim_end_matches(['}', ','])
                    .trim()
                    .trim_matches('"');
                let external_targets = reason
                    .split("targets-external:")
                    .nth(1)
                    .map(|tail| {
                        tail.split(',')
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                skips.push(SkipEntry {
                    crate_spec: spec,
                    external_targets,
                    line_no,
                });
            }
        }
        if in_targets {
            if let Some(rest) = l.strip_prefix("{ triple = ") {
                let t = rest
                    .trim_end_matches(['}', ','])
                    .trim()
                    .trim_matches('"')
                    .to_string();
                if t.is_empty() {
                    return Err(format!(
                        "denylist.toml:{line_no}: [graph] target with empty triple"
                    ));
                }
                targets.push(t);
            }
        }
    }
    if skips.is_empty() {
        return Err("denylist.toml: [bans] skip list is empty — deny-sync assumes the policy tracks duplicates; if duplicates were truly eliminated, delete this gate from `ci` too".to_string());
    }
    if targets.is_empty() {
        return Err(
            "denylist.toml: [graph] has no targets — cannot scope the duplicate check".to_string(),
        );
    }
    Ok((skips, targets))
}

/// Versions of one crate name in a resolved lockfile-level graph: cargo
/// metadata's `packages` is lockfile-shaped (every resolved version once),
/// already target-filtered when `--filter-platform` is passed.
fn duplicate_names(
    meta: &serde_json_lite::Value,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let pkgs = meta
        .get("packages")
        .ok_or_else(|| "cargo metadata output has no `packages`".to_string())?;
    let arr = match pkgs {
        serde_json_lite::Value::Arr(a) => a,
        _ => return Err("`packages` is not an array".to_string()),
    };
    let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in arr {
        let name = p.str_field("name");
        let version = p.str_field("version");
        if name.is_empty() || version.is_empty() {
            return Err("cargo metadata package with empty name/version".to_string());
        }
        by_name.entry(name).or_default().insert(version);
    }
    Ok(by_name.into_iter().filter(|(_, vs)| vs.len() > 1).collect())
}

/// Run `cargo metadata --filter-platform <triple>` (with dependencies: the
/// full transitive graph is the thing being checked) and parse it.
fn metadata_for_target(triple: &str) -> Result<serde_json_lite::Value, String> {
    let out = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            triple,
        ])
        .output()
        .map_err(|e| format!("spawn cargo metadata (target {triple}): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata --filter-platform {triple} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json_lite::parse(&String::from_utf8_lossy(&out.stdout))
        .map_err(|e| format!("parse cargo metadata (target {triple}): {e}"))
}

pub fn run(_args: Vec<String>) -> super::anyhow::Result<()> {
    let denylist = std::fs::read_to_string(DENYLIST_TOML)
        .map_err(|e| super::anyhow::Error::msg(format!("read {DENYLIST_TOML}: {e}")))?;
    let (skips, targets) = parse_denylist(&denylist).map_err(super::anyhow::Error::msg)?;
    println!(
        "deny-sync: {} skip entries, {} configured targets",
        skips.len(),
        targets.len()
    );

    // Duplicates seen across ALL target graphs (a skip is honest if the
    // crate duplicates on ANY configured target — per-target graphs shrink
    // differently, so the union is the check that matches cargo-deny's
    // all-targets behavior).
    let mut union: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Same, for the external triples named in `targets-external:` reasons.
    let mut external_union: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();
    for triple in &targets {
        let meta = metadata_for_target(triple).map_err(super::anyhow::Error::msg)?;
        let dups = duplicate_names(&meta).map_err(super::anyhow::Error::msg)?;
        // Duplicate name without a skip entry (name-level): cargo-deny's
        // `multiple-versions = "deny"` would fail, but name the culprit
        // here with its versions so the fix is one edit.
        for (name, versions) in &dups {
            union
                .entry(name.clone())
                .or_default()
                .extend(versions.iter().cloned());
            let covered = skips
                .iter()
                .any(|s| crate_name_of(&s.crate_spec) == name.as_str());
            if !covered {
                let mut vs: Vec<_> = versions.iter().cloned().collect();
                vs.sort();
                errors.push(format!(
                    "duplicate `{}` (versions {}) has NO skip entry in denylist.toml [bans]",
                    name,
                    vs.join(", ")
                ));
            }
        }
        println!("deny-sync: {triple}: {} duplicate name(s)", dups.len());
    }

    // Graphs for externally-scoped skips: verify each entry's claim against
    // the triples it names, so a stale `targets-external:` marker fails too.
    let external_triples: BTreeSet<_> = skips
        .iter()
        .flat_map(|s| s.external_targets.iter().cloned())
        .collect();
    for triple in &external_triples {
        let meta = metadata_for_target(triple).map_err(super::anyhow::Error::msg)?;
        let dups = duplicate_names(&meta).map_err(super::anyhow::Error::msg)?;
        for (name, versions) in dups {
            external_union.entry(name).or_default().extend(versions);
        }
        println!("deny-sync: {triple} (external): checked");
    }

    // Skip entries matching nothing anywhere: dead policy. Entries with a
    // `targets-external:` scope are checked against the external graphs
    // only — they must match there, and must NOT match the configured
    // targets (otherwise the scope marker is a lie).
    for s in &skips {
        let name = crate_name_of(&s.crate_spec);
        let matches_in = |graph: &BTreeMap<String, BTreeSet<String>>| {
            graph
                .get(name)
                .map(|vs| match version_of(&s.crate_spec) {
                    Some(v) => vs.contains(v),
                    // Bare-name skip (no @version): matches any version.
                    None => true,
                })
                .unwrap_or(false)
        };
        if s.external_targets.is_empty() {
            if !matches_in(&union) {
                errors.push(format!(
                    "denylist.toml:{}: skip `{}` matches no version in any configured target graph (dead entry — remove it or scope it with `targets-external: <triple>` in the reason)",
                    s.line_no, s.crate_spec
                ));
            }
        } else {
            if matches_in(&union) {
                errors.push(format!(
                    "denylist.toml:{}: skip `{}` declares targets-external ({}) but ALSO matches a configured target graph — the scope marker is stale, remove it",
                    s.line_no,
                    s.crate_spec,
                    s.external_targets.join(", ")
                ));
            }
            if !matches_in(&external_union) {
                errors.push(format!(
                    "denylist.toml:{}: skip `{}` declares targets-external ({}) but matches no version in any of those graphs — the claim is stale",
                    s.line_no,
                    s.crate_spec,
                    s.external_targets.join(", ")
                ));
            }
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("deny-sync: FAIL: {e}");
        }
        return Err(super::anyhow::Error::msg(format!(
            "deny-sync: {} mismatch(es) between denylist.toml skip entries and the resolved graph",
            errors.len()
        )));
    }
    println!("deny-sync: ok — every skip matches, every duplicate is covered");
    Ok(())
}

/// `name@version` → name; bare name passes through.
fn crate_name_of(spec: &str) -> &str {
    spec.split('@').next().unwrap_or(spec)
}

/// `name@version` → Some(version); bare name → None.
fn version_of(spec: &str) -> Option<&str> {
    spec.split_once('@').map(|(_, v)| v)
}

/// Minimal JSON reader — same zero-dependency approach as release.rs (kept
/// module-local: the release one is private and sbom-shaped).
mod serde_json_lite {
    use std::collections::BTreeMap;

    pub enum Value {
        Null,
        Str(String),
        Arr(Vec<Value>),
        Obj(BTreeMap<String, Value>),
    }

    pub fn parse(s: &str) -> Result<Value, String> {
        let mut p = Parser {
            b: s.as_bytes(),
            i: 0,
        };
        p.value()
    }

    struct Parser<'a> {
        b: &'a [u8],
        i: usize,
    }

    impl Parser<'_> {
        fn ws(&mut self) {
            while self.i < self.b.len() && (self.b[self.i] as char).is_whitespace() {
                self.i += 1;
            }
        }
        fn value(&mut self) -> Result<Value, String> {
            self.ws();
            match self.b.get(self.i) {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => Ok(Value::Str(self.string()?)),
                Some(b'n') => self.lit("null", Value::Null),
                Some(b't') => self.lit("true", Value::Null),
                Some(b'f') => self.lit("false", Value::Null),
                Some(c) if c.is_ascii_digit() || *c == b'-' => self.number(),
                _ => Err("unexpected json".to_string()),
            }
        }
        fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
            if self.b[self.i..].starts_with(word.as_bytes()) {
                self.i += word.len();
                Ok(v)
            } else {
                Err("bad literal".to_string())
            }
        }
        fn number(&mut self) -> Result<Value, String> {
            let start = self.i;
            while self.i < self.b.len()
                && ((self.b[self.i] as char).is_alphanumeric()
                    || b"+-._eE".contains(&self.b[self.i]))
            {
                self.i += 1;
            }
            Ok(Value::Str(
                String::from_utf8_lossy(&self.b[start..self.i]).into_owned(),
            ))
        }
        fn string(&mut self) -> Result<String, String> {
            self.i += 1; // open quote
            let mut out = String::new();
            loop {
                let c = *self.b.get(self.i).ok_or("unterminated string")?;
                self.i += 1;
                match c {
                    b'"' => break,
                    b'\\' => {
                        let e = *self.b.get(self.i).ok_or("bad escape")?;
                        self.i += 1;
                        match e {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'n' => out.push('\n'),
                            b't' => out.push('\t'),
                            b'u' => {
                                if self.i + 4 > self.b.len() {
                                    return Err("bad \\u".to_string());
                                }
                                let hex = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                    .map_err(|_| "bad \\u")?;
                                let n = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u")?;
                                out.push(char::from_u32(n).ok_or("bad \\u")?);
                                self.i += 4;
                            }
                            _ => return Err("bad escape".to_string()),
                        }
                    }
                    _ => out.push(c as char),
                }
            }
            Ok(out)
        }
        fn array(&mut self) -> Result<Value, String> {
            self.i += 1;
            let mut out = Vec::new();
            loop {
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    break;
                }
                out.push(self.value()?);
                self.ws();
                match self.b.get(self.i) {
                    Some(b',') => {
                        self.i += 1;
                    }
                    Some(b']') => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err("bad array".to_string()),
                }
            }
            Ok(Value::Arr(out))
        }
        fn object(&mut self) -> Result<Value, String> {
            self.i += 1;
            let mut out = BTreeMap::new();
            loop {
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    break;
                }
                self.ws();
                if self.b.get(self.i) != Some(&b'"') {
                    return Err("bad object key".to_string());
                }
                let k = self.string()?;
                self.ws();
                if self.b.get(self.i) != Some(&b':') {
                    return Err("missing colon".to_string());
                }
                self.i += 1;
                out.insert(k, self.value()?);
                self.ws();
                match self.b.get(self.i) {
                    Some(b',') => {
                        self.i += 1;
                    }
                    Some(b'}') => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err("bad object".to_string()),
                }
            }
            Ok(Value::Obj(out))
        }
    }

    impl Value {
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Obj(m) => m.get(key),
                _ => None,
            }
        }
        pub fn str_field(&self, key: &str) -> String {
            match self.get(key) {
                Some(Value::Str(s)) => s.clone(),
                _ => String::new(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_packages_array() {
            let v = parse(
                r#"{"packages":[{"name":"a","version":"1.0"},{"name":"a","version":"2.0"},{"name":"b","version":"3.0"}]}"#,
            )
            .expect("parses");
            assert!(v.get("packages").is_some());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_denylist_skips_and_targets() {
        let text = r#"
[graph]
targets = [
  { triple = "x86_64-pc-windows-msvc" },
  { triple = "aarch64-linux-android" },
]

[bans]
skip = [
    { crate = "a@1.0.0", reason = "x" },
    { crate = "b@2.0.0", reason = "y" },
]
"#;
        let (skips, targets) = parse_denylist(text).expect("parses");
        assert_eq!(skips.len(), 2);
        assert_eq!(skips[0].crate_spec, "a@1.0.0");
        assert_eq!(
            targets,
            vec![
                "x86_64-pc-windows-msvc".to_string(),
                "aarch64-linux-android".to_string()
            ]
        );
    }

    #[test]
    fn empty_skip_list_fails_closed() {
        let err = parse_denylist("[bans]\n").expect_err("empty skip list fails");
        assert!(err.contains("skip list is empty"), "{err}");
    }

    #[test]
    fn empty_targets_fail_closed() {
        // Skips present but no [graph] targets: the target-scope check
        // cannot run.
        let err =
            parse_denylist("[bans]\nskip = [\n    { crate = \"a@1.0\", reason = \"x\" },\n]\n")
                .expect_err("no targets fails");
        assert!(err.contains("[graph] has no targets"), "{err}");
    }

    #[test]
    fn duplicate_names_finds_multi_version_crates() {
        let v = serde_json_lite::parse(
            r#"{"packages":[
                {"name":"x","version":"1.0"},
                {"name":"x","version":"2.0"},
                {"name":"y","version":"3.0"}
            ]}"#,
        )
        .expect("parses");
        let dups = duplicate_names(&v).expect("dups");
        assert_eq!(dups.len(), 1, "only x duplicates: {dups:?}");
        assert!(dups.contains_key("x"));
        assert!(!dups.contains_key("y"));
    }

    #[test]
    fn spec_name_and_version_split() {
        assert_eq!(crate_name_of("windows-sys@0.52.0"), "windows-sys");
        assert_eq!(version_of("windows-sys@0.52.0"), Some("0.52.0"));
        assert_eq!(crate_name_of("just-a-name"), "just-a-name");
        assert_eq!(version_of("just-a-name"), None);
    }

    #[test]
    fn real_denylist_parses() {
        // The shipped policy file must stay parseable by this gate — this
        // test runs from the xtask crate dir, so walk up to the repo root.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let text =
            std::fs::read_to_string(root.join(DENYLIST_TOML)).expect("denylist.toml readable");
        let (skips, targets) = parse_denylist(&text).expect("shipped denylist parses");
        assert_eq!(targets.len(), 9, "9-target contract: {targets:?}");
        assert!(
            skips
                .iter()
                .any(|s| s.crate_spec == "windows_i686_gnu@0.52.6"
                    && s.external_targets == vec!["i686-pc-windows-gnu"]),
            "the externally-scoped gnu-leg skip stays present with its claim"
        );
    }

    #[test]
    fn targets_external_marker_is_parsed() {
        let text = "[graph]\ntargets = [\n    { triple = \"x86_64-pc-windows-msvc\" },\n]\n\n[bans]\nskip = [\n    { crate = \"a@1.0\", reason = \"scoped; verified against targets-external: x86_64-pc-windows-gnu, a-pc-windows-gnu\" },\n]\n";
        let (skips, _) = parse_denylist(text).expect("parses");
        assert_eq!(skips[0].external_targets.len(), 2);
        assert_eq!(skips[0].external_targets[0], "x86_64-pc-windows-gnu");
    }

    #[test]
    fn reasonless_skip_entry_fails_closed() {
        let err = parse_denylist("[bans]\nskip = [\n    { crate = \"a@1.0\" },\n]\n")
            .expect_err("no-reason skip fails");
        assert!(err.contains("without a reason"), "{err}");
    }
}
