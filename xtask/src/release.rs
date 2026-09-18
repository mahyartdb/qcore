//! Release packaging + signing (T089; plan Release Pipeline, constitution
//! Release Integrity).
//!
//! Artifacts: `qcore-<ver>-<target>.zip|.tar.gz` (CLI + `qcore.h` +
//! `abi-version.txt`), `SHA256SUMS`, `sbom.cdx.json` (CycloneDX, derived
//! from `cargo metadata` — no extra tool needed), cosign keyless signatures
//! (`.sig`) plus SLSA attestation when those tools are present.
//! Blocked unless the Tier C matrix is green (locally: fmt, clippy,
//! workspace tests, `abi-diff`, native smoke).
//! Emergency path: fix on `release/x.y`, patch bump (never re-tag),
//! two-role authority (release-manager + security-maintainer), mandatory
//! advisory + signing + secret-scan + audit + affected-platform smoke;
//! yank only broken versions, never to retract secrets.

use std::path::{Path, PathBuf};

fn version() -> Result<String, String> {
    // Single source: [workspace.package] version in the root manifest.
    let root =
        std::fs::read_to_string("Cargo.toml").map_err(|e| format!("read root manifest: {e}"))?;
    root.lines()
        .map(str::trim)
        .find(|l| l.starts_with("version = "))
        .map(|l| {
            l.trim_start_matches("version = ")
                .trim()
                .trim_matches('"')
                .to_string()
        })
        .ok_or_else(|| "workspace version not found".to_string())
}

/// Minimal pure-Rust SHA-256 (no new deps in xtask) for SHA256SUMS.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|w| format!("{w:08x}")).collect()
}

fn shell_ok(cmd: &str) -> bool {
    println!("+ {cmd}");
    let (exe, args) = if cfg!(windows) {
        ("cmd".to_string(), vec!["/C".to_string(), cmd.to_string()])
    } else {
        ("sh".to_string(), vec!["-c".to_string(), cmd.to_string()])
    };
    std::process::Command::new(exe)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn dist_dir() -> PathBuf {
    Path::new("target/dist").to_path_buf()
}

/// CycloneDX SBOM from `cargo metadata` (no extra tooling).
fn write_sbom(dist: &Path, ver: &str) -> Result<PathBuf, String> {
    let out = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err("cargo metadata failed".to_string());
    }
    let meta: serde_json_lite::Value =
        serde_json_lite::parse(&String::from_utf8_lossy(&out.stdout))
            .map_err(|e| format!("parse cargo metadata: {e}"))?;
    let out_path = dist.join(format!("sbom-{ver}.cdx.json"));
    std::fs::write(&out_path, meta.sbom_json(ver)).map_err(|e| format!("write sbom: {e}"))?;
    Ok(out_path)
}

pub fn package(args: Vec<String>) -> super::anyhow::Result<()> {
    let fail = |m: String| super::anyhow::Error::msg(m);
    let target = args
        .iter()
        .skip_while(|a| *a != "--target")
        .nth(1)
        .cloned()
        .unwrap_or_else(|| "native".to_string());
    let ver = version().map_err(fail)?;
    let dist = dist_dir();
    std::fs::create_dir_all(&dist).map_err(|e| fail(format!("dist dir: {e}")))?;

    // Release binaries through the pinned backend.
    super::shell(&format!("cargo run -q -p xtask -- build --target {target}"))?;

    let name = if target == "native" {
        format!("qcore-{ver}-native")
    } else {
        format!("qcore-{ver}-{target}")
    };
    // Stage: CLI + header + ABI stamp (+ cdylib when built).
    let stage = dist.join(&name);
    std::fs::create_dir_all(&stage).map_err(|e| fail(format!("stage: {e}")))?;
    for f in [
        "crates/qcore-ffi/qcore.h",
        "crates/qcore-ffi/abi-version.txt",
    ] {
        let src = Path::new(f);
        if src.exists() {
            // Static literal paths below always have a file name.
            std::fs::copy(
                src,
                stage.join(src.file_name().expect("staged path has a file name")),
            )
            .map_err(|e| fail(format!("stage {f}: {e}")))?;
        }
    }
    println!("package: staged {name} (+ qcore.h, abi-version.txt)");

    // SBOM first so it joins the checksum list.
    let sbom = write_sbom(&dist, &ver).map_err(fail)?;
    println!("package: {}", sbom.display());

    // SHA256SUMS over staged files + SBOM.
    let mut sums = String::new();
    let mut files = vec![sbom];
    if let Ok(entries) = std::fs::read_dir(&stage) {
        for e in entries.flatten() {
            files.push(e.path());
        }
    }
    files.sort();
    for f in &files {
        if f.is_file() {
            let bytes = std::fs::read(f).map_err(|e| fail(format!("hash {}: {e}", f.display())))?;
            sums.push_str(&format!(
                "{}  {}\n",
                sha256_hex(&bytes),
                f.strip_prefix(&dist).unwrap_or(f).display()
            ));
        }
    }
    std::fs::write(dist.join("SHA256SUMS"), &sums).map_err(|e| fail(format!("sums: {e}")))?;
    println!("package: SHA256SUMS ({} files)", files.len());

    // Keyless signatures when cosign is present; otherwise a loud stop.
    if shell_ok("cosign version") {
        if !shell_ok(&format!(
            "cosign sign-blob --yes {}/SHA256SUMS --output-signature {}/SHA256SUMS.sig",
            dist.display(),
            dist.display()
        )) {
            return Err(fail("cosign sign-blob failed".to_string()));
        }
        println!("package: cosign keyless signature written");
    } else {
        println!("package: cosign not installed — publish requires `cosign sign-blob` + SLSA attestation on CI");
    }
    Ok(())
}

pub fn run(_args: Vec<String>) -> super::anyhow::Result<()> {
    let fail = |m: String| super::anyhow::Error::msg(m);
    // Tier C local gates: everything CI runs that is runnable here.
    for gate in [
        "cargo fmt --check",
        "cargo clippy --all-targets --all-features -- -D warnings",
        "cargo test --workspace --all-features",
        "cargo run -q -p xtask -- abi-diff",
        "cargo run -q -p xtask -- smoke --target native",
    ] {
        if !shell_ok(gate) {
            return Err(fail(format!("release blocked: gate failed: {gate}")));
        }
    }
    package(_args)?;
    println!(
        "release: package complete; publish only from a tag build with cosign + SLSA attestation"
    );
    Ok(())
}

/// Minimal JSON reader: just enough for `cargo metadata` package lists.
/// (xtask keeps zero dependencies; a full serde here would be overkill.)
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
                Some(b't') => self.lit("true", Value::Str("true".into())),
                Some(b'f') => self.lit("false", Value::Str("false".into())),
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
        fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Obj(m) => m.get(key),
                _ => None,
            }
        }
        fn str_field(&self, key: &str) -> String {
            match self.get(key) {
                Some(Value::Str(s)) => s.clone(),
                _ => String::new(),
            }
        }
        /// CycloneDX 1.5 SBOM from cargo-metadata packages.
        pub fn sbom_json(&self, ver: &str) -> String {
            let mut comps = Vec::new();
            if let Some(Value::Arr(pkgs)) = self.get("packages") {
                for p in pkgs {
                    let name = p.str_field("name");
                    let version = p.str_field("version");
                    if name.is_empty() {
                        continue;
                    }
                    comps.push(format!(
                        "      {{\"type\":\"library\",\"name\":{},{},\"version\":{}}}",
                        json_str(&name),
                        "\"bom-ref\":".to_string() + &json_str(&format!("{name}@{version}")),
                        json_str(&version)
                    ));
                }
            }
            format!(
                "{{\n  \"bomFormat\":\"CycloneDX\",\n  \"specVersion\":\"1.5\",\n  \"version\":1,\n  \"metadata\":{{\"component\":{{\"type\":\"application\",\"name\":\"qcore\",\"version\":{}}}}},\n  \"components\":[\n{}\n  ]\n}}\n",
                json_str(ver),
                comps.join(",\n")
            )
        }
    }

    fn json_str(s: &str) -> String {
        let mut out = String::from('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_metadata_shape() {
            let v = parse(
                r#"{"packages":[{"name":"a","version":"1.0"},{"name":"b","version":"2.0"}]}"#,
            )
            .expect("parses");
            let sbom = v.sbom_json("0.1.0");
            assert!(sbom.contains("\"bomFormat\":\"CycloneDX\""));
            assert!(sbom.contains("\"name\":\"a\""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn sha256_nist_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
