//! Release packaging + signing (T089; plan Release Pipeline, constitution
//! Release Integrity).
//!
//! Artifacts: `qcore-<ver>-<target>.zip|.tar.gz` (CLI binary + cdylib +
//! `qcore.h` + `abi-version.txt`), `SHA256SUMS`, `sbom-<ver>.cdx.json`
//! (CycloneDX 1.5 over the FULL `cargo metadata` package graph — first-party
//! plus every transitive crate, name+version, sorted deterministically; no
//! extra tool needed), cosign keyless signatures (`.sig`).
//! The container format comes from the target's `delivery` field in
//! `targets.toml` (`cli-zip` → zip, `cli-targz`/`termux-cli` → tar.gz); a
//! package without the built CLI binary or the cdylib fails closed instead
//! of shipping an empty archive.
//! Blocked unless the Tier C matrix is green (locally: fmt, clippy,
//! workspace tests, `abi-diff`, native smoke).
//! Emergency path: fix on `release/x.y`, patch bump (never re-tag),
//! two-role authority (release-manager + security-maintainer), mandatory
//! advisory + signing + secret-scan + audit + affected-platform smoke;
//! yank only broken versions, never to retract secrets.

use std::path::{Path, PathBuf};

/// Single source for the contracted target list: `targets.toml` next to this
/// file. Parsed the same way as `smoke.rs` so the manifest and the gate
/// cannot drift (T7 story 18).
const TARGETS_TOML: &str = include_str!("targets.toml");

/// One `[[target]]` entry: the triple, its runner label and delivery spec.
struct TargetEntry {
    triple: String,
    runner: String,
    delivery: Vec<String>,
}

fn contract_target_entries() -> Vec<TargetEntry> {
    let mut out = Vec::new();
    let mut current: Option<TargetEntry> = None;
    for l in TARGETS_TOML.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("triple = ") {
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            current = Some(TargetEntry {
                triple: v.trim().trim_matches('"').to_string(),
                runner: String::new(),
                delivery: Vec::new(),
            });
        } else if let Some(v) = l.strip_prefix("runner = ") {
            if let Some(c) = current.as_mut() {
                c.runner = v.trim().trim_matches('"').to_string();
            }
        } else if let Some(v) = l.strip_prefix("delivery = ") {
            if let Some(c) = current.as_mut() {
                let inner = v.trim().trim_start_matches('[').trim_end_matches(']');
                c.delivery = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }
    if let Some(last) = current.take() {
        out.push(last);
    }
    out
}

fn contract_targets() -> Vec<String> {
    contract_target_entries()
        .into_iter()
        .map(|t| t.triple)
        .collect()
}

/// The proof side of the contract: the tag matrix in
/// `.github/workflows/release.yml`, embedded at compile time. Parsing it here
/// instead of keeping a second hand-maintained list means a leg added or
/// dropped in ONE of the two files fails the release gate in that same commit
/// (issue #16 triage: the old COVERED const was a documented stub that had to
/// be remembered).
const RELEASE_WORKFLOW: &str = include_str!("../../.github/workflows/release.yml");

/// Triples the release matrix proves, in workflow order: the `- target:` rows
/// under `matrix.include`.
fn matrix_targets() -> Vec<String> {
    matrix_rows()
        .into_iter()
        .map(|(triple, _)| triple)
        .collect()
}

/// `(triple, runner)` pairs from the release matrix, in workflow order. The
/// runner half is checked against `targets.toml` too: the 3/9 matrix this
/// replaced chose its runner with `contains(target, 'aarch64')`, which sends
/// aarch64 linux and android legs to the Windows ARM runner.
fn matrix_rows() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for l in RELEASE_WORKFLOW.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("- target: ") {
            out.push((v.trim().trim_matches('"').to_string(), String::new()));
        } else if let Some(v) = l.strip_prefix("runner: ") {
            if let Some(last) = out.last_mut() {
                last.1 = v.trim().trim_matches('"').to_string();
            }
        }
    }
    out
}

/// Delivery container per the `targets.toml` `delivery` field: windows legs
/// declare `cli-zip`, linux legs `cli-targz`, android legs ship the Termux
/// CLI + JNI cdylib in the unix-native tar.gz. The native package follows
/// the host platform. An unrecognized delivery spec fails closed instead of
/// guessing a container.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ArchiveFmt {
    Zip,
    TarGz,
}

fn archive_fmt_for(target: &str) -> Result<ArchiveFmt, String> {
    if target == "native" {
        return Ok(if cfg!(windows) {
            ArchiveFmt::Zip
        } else {
            ArchiveFmt::TarGz
        });
    }
    let entry = contract_target_entries()
        .into_iter()
        .find(|t| t.triple == target)
        .ok_or_else(|| format!("target `{target}` not in targets.toml"))?;
    if entry.delivery.iter().any(|d| d.contains("zip")) {
        Ok(ArchiveFmt::Zip)
    } else if entry
        .delivery
        .iter()
        .any(|d| d.contains("targz") || d.contains("termux"))
    {
        Ok(ArchiveFmt::TarGz)
    } else {
        Err(format!(
            "target `{target}` delivery {:?} names no archive container (expected cli-zip | cli-targz | termux-cli)",
            entry.delivery
        ))
    }
}

fn archive_extension(fmt: ArchiveFmt) -> &'static str {
    match fmt {
        ArchiveFmt::Zip => "zip",
        ArchiveFmt::TarGz => "tar.gz",
    }
}

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

/// tar.gz writer (linux/android delivery): deterministic entries, mode
/// preserved where meaningful.
fn write_tar_gz(stage: &Path, out: &Path) -> Result<(), String> {
    let file = std::fs::File::create(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.mode(tar::HeaderMode::Deterministic);
    for entry in read_dir_sorted(stage)? {
        let meta = entry
            .metadata()
            .map_err(|e| format!("stat {}: {e}", entry.path().display()))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(meta.len());
        header.set_mode(0o755);
        header.set_cksum();
        let f = std::fs::File::open(entry.path())
            .map_err(|e| format!("open {}: {e}", entry.path().display()))?;
        tar.append_data(
            &mut header,
            entry.path().file_name().ok_or("stage entry unnamed")?,
            f,
        )
        .map_err(|e| format!("tar append: {e}"))?;
    }
    tar.into_inner()
        .map_err(|e| format!("tar finish: {e}"))?
        .finish()
        .map_err(|e| format!("gzip finish: {e}"))?;
    Ok(())
}

/// Minimal std-only ZIP writer (STORE method, no compression): the windows
/// `cli-zip` delivery needs only containment, not ratio — the payloads are
/// already large binaries where deflate gains little. CRC-32 (IEEE) is
/// computed inline; no new dependency family.
fn write_zip(stage: &Path, out: &Path) -> Result<(), String> {
    let mut out_bytes: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let entries = read_dir_sorted(stage)?;
    let entry_count = entries.len() as u16;
    for entry in &entries {
        let path = entry.path();
        let name = path
            .file_name()
            .ok_or("stage entry unnamed")?
            .to_str()
            .ok_or("stage entry name not UTF-8")?
            .as_bytes()
            .to_vec();
        let data = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let crc = crc32_ieee(&data);
        let offset = out_bytes.len() as u32;
        // Local file header: sig, version 20 (2.0), flags 0, method 0 (store),
        // zeroed mod time/date (deterministic), crc, sizes, name.
        out_bytes.extend_from_slice(&0x04034b50u32.to_le_bytes());
        out_bytes.extend_from_slice(&20u16.to_le_bytes());
        out_bytes.extend_from_slice(&0u16.to_le_bytes());
        out_bytes.extend_from_slice(&0u16.to_le_bytes());
        out_bytes.extend_from_slice(&0u16.to_le_bytes());
        out_bytes.extend_from_slice(&0u16.to_le_bytes());
        out_bytes.extend_from_slice(&crc.to_le_bytes());
        out_bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out_bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out_bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out_bytes.extend_from_slice(&0u16.to_le_bytes());
        out_bytes.extend_from_slice(&name);
        out_bytes.extend_from_slice(&data);
        // Central directory record.
        central.extend_from_slice(&0x02014b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(&name);
    }
    let central_offset = out_bytes.len() as u32;
    let central_len = central.len() as u32;
    out_bytes.extend_from_slice(&central);
    // End of central directory.
    out_bytes.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out_bytes.extend_from_slice(&0u16.to_le_bytes());
    out_bytes.extend_from_slice(&0u16.to_le_bytes());
    out_bytes.extend_from_slice(&entry_count.to_le_bytes());
    out_bytes.extend_from_slice(&entry_count.to_le_bytes());
    out_bytes.extend_from_slice(&central_len.to_le_bytes());
    out_bytes.extend_from_slice(&central_offset.to_le_bytes());
    out_bytes.extend_from_slice(&0u16.to_le_bytes());
    std::fs::write(out, &out_bytes).map_err(|e| format!("write {}: {e}", out.display()))?;
    Ok(())
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<std::fs::DirEntry>, String> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .flatten()
        .collect();
    v.sort_by_key(|e| e.file_name());
    Ok(v)
}

/// CycloneDX SBOM from FULL `cargo metadata` (with dependencies): the
/// component list covers first-party AND transitive crates (name+version
/// only), sorted+deduped so the document is deterministic for a given
/// lockfile. An empty package graph fails closed — metadata without
/// packages means the workspace did not resolve, not "no components".
fn write_sbom(dist: &Path, ver: &str) -> Result<PathBuf, String> {
    let out = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let meta: serde_json_lite::Value =
        serde_json_lite::parse(&String::from_utf8_lossy(&out.stdout))
            .map_err(|e| format!("parse cargo metadata: {e}"))?;
    let out_path = dist.join(format!("sbom-{ver}.cdx.json"));
    std::fs::write(&out_path, meta.sbom_json(ver)).map_err(|e| format!("write sbom: {e}"))?;
    Ok(out_path)
}

/// Stage the deliverables and build the container archive (the testable
/// core of `package`): copies `bin` + `cdylib` + the header/ABI stamp into
/// `stage`, then writes the `fmt` archive beside it. Every expected input
/// must exist — absent deliverables fail closed.
fn stage_and_archive(
    dist: &Path,
    stage: &Path,
    bin: &Path,
    cdylib: &Path,
    header: &Path,
    abi_version: &Path,
    fmt: ArchiveFmt,
) -> Result<PathBuf, String> {
    let fail = |m: String| format!("package: {m}");
    if stage.exists() {
        // A stale stage dir from a previous run must not leak old files
        // into the new archive: wipe it before staging.
        std::fs::remove_dir_all(stage).map_err(|e| fail(format!("clean stage: {e}")))?;
    }
    std::fs::create_dir_all(stage).map_err(|e| fail(format!("stage: {e}")))?;
    for (file, label) in [
        (bin, "CLI binary"),
        (cdylib, "cdylib"),
        (header, "qcore.h"),
        (abi_version, "abi-version.txt"),
    ] {
        if !file.exists() {
            return Err(fail(format!(
                "{label} missing (expected {}); refusing to package an empty artifact",
                file.display()
            )));
        }
        let dest = stage.join(file.file_name().expect("artifact path has a file name"));
        std::fs::copy(file, &dest).map_err(|e| fail(format!("stage {}: {e}", file.display())))?;
    }
    let archive_path = dist.join(format!(
        "{}.{}",
        stage
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| fail("stage dir unnamed".to_string()))?,
        archive_extension(fmt)
    ));
    match fmt {
        ArchiveFmt::Zip => write_zip(stage, &archive_path).map_err(fail)?,
        ArchiveFmt::TarGz => write_tar_gz(stage, &archive_path).map_err(fail)?,
    }
    let staged: Vec<_> = read_dir_sorted(stage)
        .map_err(fail)?
        .into_iter()
        .map(|e| e.path())
        .collect();
    if staged.len() < 4 {
        return Err(fail(format!(
            "staging incomplete ({} files, want >= 4: CLI binary, cdylib, qcore.h, abi-version.txt)",
            staged.len()
        )));
    }
    Ok(archive_path)
}

pub fn package(args: Vec<String>) -> super::anyhow::Result<()> {
    let fail = |m: String| super::anyhow::Error::msg(m);
    // Shared parser: both `--target X` and `--target=X` spellings; a
    // valueless flag errors instead of silently meaning native.
    let target = super::args::parse_target_arg(&args)
        .map_err(fail)?
        .unwrap_or_else(|| "native".to_string());
    if target != "native" && !contract_targets().contains(&target) {
        return Err(fail(format!(
            "unknown target `{target}` (see xtask/src/targets.toml)"
        )));
    }
    let ver = version().map_err(fail)?;
    let dist = dist_dir();
    std::fs::create_dir_all(&dist).map_err(|e| fail(format!("dist dir: {e}")))?;

    // Release binaries through the pinned backend (build.rs: every
    // non-native backend builds --release into target/<triple>/release/).
    super::shell(&format!("cargo run -q -p xtask -- build --target {target}"))?;

    let name = if target == "native" {
        format!("qcore-{ver}-native")
    } else {
        format!("qcore-{ver}-{target}")
    };
    let stage = dist.join(&name);

    // Built deliverables from the target's build dir, named for the TARGET
    // platform (cross builds on a foreign host still produce the target's
    // binary/cdylib layout).
    let bin_dir = super::build::artifact_dir(&target, true);
    let bin_name = super::build::cli_binary_name_for_triple(&target);
    let cdylib_name = if target == "native" {
        super::build::cdylib_name_host()
    } else {
        super::build::cdylib_name_for_triple(&target)
    };
    let fmt = archive_fmt_for(&target).map_err(fail)?;
    let archive_path = stage_and_archive(
        &dist,
        &stage,
        &bin_dir.join(bin_name),
        &bin_dir.join(cdylib_name),
        Path::new("crates/qcore-ffi/qcore.h"),
        Path::new("crates/qcore-ffi/abi-version.txt"),
        fmt,
    )
    .map_err(fail)?;
    println!("package: staged {name} (CLI {bin_name}, {cdylib_name}, qcore.h, abi-version.txt)");
    println!("package: {}", archive_path.display());

    // SBOM first so it joins the checksum list. Full dependency graph
    // (first-party + transitive); an empty component list means metadata
    // did not resolve — fail closed instead of shipping an empty SBOM.
    let sbom = write_sbom(&dist, &ver).map_err(fail)?;
    let sbom_text = std::fs::read_to_string(&sbom).map_err(|e| fail(format!("read sbom: {e}")))?;
    if !sbom_text.contains("\"type\":\"library\"") {
        return Err(fail(
            "SBOM has no components (cargo metadata resolved nothing); refusing to package"
                .to_string(),
        ));
    }
    println!("package: {}", sbom.display());

    // SHA256SUMS over the archive + staged files + SBOM: the checksums now
    // cover the real deliverable, not just the header stamp.
    let mut files = vec![archive_path.clone(), sbom];
    if let Ok(entries) = std::fs::read_dir(&stage) {
        for e in entries.flatten() {
            files.push(e.path());
        }
    }
    files.sort();
    files.dedup();
    let mut sums = String::new();
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

pub fn run(args: Vec<String>) -> super::anyhow::Result<()> {
    let fail = |m: String| super::anyhow::Error::msg(m);

    // Release-matrix honesty: no release invocation — local OR
    // publish-finalize — may claim more proof than the workflow's matrix
    // actually runs. Coverage is parsed from `.github/workflows/release.yml`
    // (the proof side) and compared against `targets.toml` (the contract
    // side), both at compile time, so an edit to either file alone fails
    // closed here instead of shipping a claim no runner backs. A deliberately
    // partial matrix still needs the explicit --allow-partial-matrix
    // acknowledgment, which names the unproven targets in the log.
    let contract = contract_targets();
    let covered = matrix_targets();
    let undeclared: Vec<_> = covered.iter().filter(|t| !contract.contains(t)).collect();
    if !undeclared.is_empty() {
        return Err(fail(format!(
            "release blocked: release.yml builds targets absent from targets.toml: {}. targets.toml is the contract; removing/demoting a target needs a constitution amendment.",
            undeclared
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let uncovered: Vec<_> = contract.iter().filter(|t| !covered.contains(t)).collect();
    if uncovered.is_empty() {
        println!(
            "release: full matrix covered: {}/{} targets (release.yml <-> targets.toml)",
            covered.len(),
            contract.len()
        );
    } else if !args.iter().any(|a| a == "--allow-partial-matrix") {
        return Err(fail(format!(
            "release blocked: tag matrix covers {}/{} targets ({}); unproven: {}. Re-run with --allow-partial-matrix to acknowledge, or add the missing legs to .github/workflows/release.yml.",
            covered.len(),
            contract.len(),
            covered.join(", "),
            uncovered
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    } else {
        println!(
            "release: partial-matrix acknowledged; unproven targets: {}",
            uncovered
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // CI finalize mode (`--staged-artifacts <dir>`): the workflow's matrix
    // legs each built + smoked + packaged + uploaded their own target
    // artifact; the publish job downloaded them all into one directory.
    // This mode skips the local gates + native packaging (the matrix already
    // proved them — re-running gates here would rebuild the world on the
    // publish runner) and only stages the downloaded archives into
    // `target/dist`, writes the SBOM over the full dependency graph, and
    // produces SHA256SUMS + the cosign keyless signature. Fail closed:
    // every artifact must exist on disk, non-empty, before anything is
    // hashed.
    if let Some(staged) = super::args::flag_value(&args, "--staged-artifacts").map_err(fail)? {
        return finalize_staged(Path::new(&staged)).map_err(fail);
    }

    // Tier C local gates: the same workspace-wide nextest invocations CI runs
    // (`xtask ci` in main.rs; T7 story 15). Local and CI results agree by
    // construction — a single definition, not two similar command lists.
    for gate in [
        "cargo fmt --check",
        "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        "cargo nextest run --workspace --all-features --exclude tests-conformance",
        "cargo nextest run -p tests-conformance",
        "cargo run -q -p xtask -- abi-diff",
        "cargo run -q -p xtask -- smoke --target native",
    ] {
        if !shell_ok(gate) {
            return Err(fail(format!("release blocked: gate failed: {gate}")));
        }
    }
    package(args)?;
    println!(
        "release: package complete; publish only from a tag build with cosign + SLSA attestation"
    );
    Ok(())
}

/// Stage every downloaded matrix artifact into `target/dist`, then emit the
/// SBOM + SHA256SUMS + cosign signature over exactly those files. Used by
/// the release workflow's publish job (per-target artifacts built on their
/// proven runners); never invents an archive that was not uploaded.
fn finalize_staged(staged: &Path) -> Result<(), String> {
    let fail = |m: String| format!("release finalize: {m}");
    if !staged.is_dir() {
        return Err(fail(format!(
            "staged-artifacts dir {} missing (publish job must download the matrix artifacts first)",
            staged.display()
        )));
    }
    let ver = version()?;
    let dist = dist_dir();
    std::fs::create_dir_all(&dist).map_err(|e| fail(format!("dist dir: {e}")))?;
    let mut artifacts: Vec<PathBuf> = Vec::new();
    for entry in read_dir_sorted(staged)? {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let meta = entry
            .metadata()
            .map_err(|e| fail(format!("stat {}: {e}", p.display())))?;
        if meta.len() == 0 {
            return Err(fail(format!(
                "staged artifact {} is empty (upload/download broken); refusing to publish",
                p.display()
            )));
        }
        let dest = dist.join(
            p.file_name()
                .ok_or_else(|| fail(format!("unnamed staged artifact {}", p.display())))?,
        );
        std::fs::copy(&p, &dest).map_err(|e| fail(format!("copy {}: {e}", p.display())))?;
        artifacts.push(dest);
    }
    if artifacts.is_empty() {
        return Err(fail(
            "no staged artifacts found; refusing to publish an empty release".to_string(),
        ));
    }
    println!(
        "release finalize: staged {} artifact(s) into {}",
        artifacts.len(),
        dist.display()
    );

    // SBOM over the full dependency graph joins the checksum list.
    let sbom = write_sbom(&dist, &ver)?;
    println!("release finalize: {}", sbom.display());

    // SHA256SUMS over every staged archive + the SBOM.
    let mut files = artifacts.clone();
    files.push(sbom);
    files.sort();
    files.dedup();
    let mut sums = String::new();
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
    println!("release finalize: SHA256SUMS ({} files)", files.len());

    // Keyless signature when cosign is present; otherwise fail closed in
    // finalize mode — this function is the publish path (the workflow
    // installs cosign before calling it, but a missing install must never
    // degrade into an unsigned release that `gh release upload` ships
    // anyway). The lenient print stays only for local `package` runs.
    // `sign_sums` is a seam so tests can pin the cosign-presence decision;
    // production always uses the real probe.
    sign_sums(&dist, &mut shell_ok).map_err(fail)?;
    println!("release finalize: cosign keyless signature written");
    println!(
        "release finalize: complete for qcore {ver}; upload {}/* to the GitHub release",
        dist.display()
    );
    Ok(())
}

/// Sign SHA256SUMS via `cosign sign-blob`. `probe` answers "is cosign
/// available"; finalize treats a missing cosign as a hard error (fail
/// closed), not a degraded success.
fn sign_sums(dist: &Path, probe: &mut dyn FnMut(&str) -> bool) -> Result<(), String> {
    if !probe("cosign version") {
        return Err(
            "cosign not installed; finalize would produce an unsigned release. Install cosign (workflow uses sigstore/cosign-installer) and re-run".to_string(),
        );
    }
    if !probe(&format!(
        "cosign sign-blob --yes {}/SHA256SUMS --output-signature {}/SHA256SUMS.sig",
        dist.display(),
        dist.display()
    )) {
        return Err("cosign sign-blob failed".to_string());
    }
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
        /// CycloneDX 1.5 SBOM from cargo-metadata packages: first-party +
        /// transitive crates (name+version only), deduped and sorted by
        /// `name@version` so a given lockfile always yields byte-identical
        /// output. Empty package graph fails closed upstream in `write_sbom`
        /// via the component-count check in `package`.
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
            // Deterministic ordering (sort + dedup on name@version): cargo
            // metadata lists packages in manifest order, and the same crate
            // can appear once per workspace member it backs.
            comps.sort();
            comps.dedup();
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

        #[test]
        fn sbom_components_are_sorted_and_deduped() {
            // Full metadata lists one package entry per workspace member
            // (the same crate repeats); components must come out sorted by
            // bom-ref with duplicates removed — a deterministic SBOM, not a
            // manifest-order dump.
            let v = parse(
                r#"{"packages":[
                    {"name":"zlib","version":"1.0"},
                    {"name":"a","version":"0.1"},
                    {"name":"qcore-core","version":"0.3.0"},
                    {"name":"a","version":"0.1"},
                    {"name":"qcore-core","version":"0.3.0"}
                ]}"#,
            )
            .expect("parses");
            let sbom = v.sbom_json("0.1.0");
            let a = sbom.find("\"name\":\"a\"").expect("a present");
            let q = sbom
                .find("\"name\":\"qcore-core\"")
                .expect("qcore-core present");
            let z = sbom.find("\"name\":\"zlib\"").expect("zlib present");
            assert!(a < q && q < z, "components sorted: {sbom}");
            assert_eq!(
                sbom.matches("\"name\":\"a\"").count(),
                1,
                "duplicate package entries deduped: {sbom}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{archive_fmt_for, contract_targets, sha256_hex, stage_and_archive, ArchiveFmt};

    #[test]
    fn contract_targets_match_manifest() {
        // The release gate reads the contract from targets.toml: 9 triples,
        // Windows legs first. Manifest edits flow here with no code change.
        let contract = contract_targets();
        assert_eq!(contract.len(), 9, "manifest triple count: {contract:?}");
        assert!(contract.contains(&"x86_64-pc-windows-msvc".to_string()));
        assert!(contract.contains(&"aarch64-linux-android".to_string()));
    }

    #[test]
    fn workflow_matrix_matches_contract() {
        // Coverage is parsed from release.yml, not a second hand-kept list: a
        // leg added or dropped in one file alone must fail here instead of at
        // tag time. Runner placement is asserted with the triple, so a
        // `contains(..., 'aarch64')`-style runner guess cannot send a linux or
        // android leg to the Windows ARM runner again.
        let mut workflow = super::matrix_rows();
        let mut contract: Vec<_> = super::contract_target_entries()
            .into_iter()
            .map(|t| (t.triple, t.runner))
            .collect();
        workflow.sort();
        contract.sort();
        assert_eq!(
            workflow, contract,
            "release.yml (target, runner) vs targets.toml"
        );
    }

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

    #[test]
    fn archive_fmt_follows_delivery_field() {
        // targets.toml delivery: windows = zip, linux = targz, android =
        // termux-cli (tar.gz container for the Termux APK-less install).
        assert_eq!(
            archive_fmt_for("x86_64-pc-windows-msvc").unwrap(),
            ArchiveFmt::Zip
        );
        assert_eq!(
            archive_fmt_for("x86_64-unknown-linux-gnu").unwrap(),
            ArchiveFmt::TarGz
        );
        assert_eq!(
            archive_fmt_for("aarch64-linux-android").unwrap(),
            ArchiveFmt::TarGz
        );
        assert!(archive_fmt_for("not-a-target").is_err());
    }

    /// Fake built artifacts in a tmpdir; asserts the staged archive exists
    /// and contains the CLI binary payload.
    fn stage_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base =
            std::env::temp_dir().join(format!("qcore-xtask-release-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let build = base.join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("qcore.exe"), b"fake-cli-binary-payload").unwrap();
        std::fs::write(build.join("qcore"), b"fake-cli-binary-payload").unwrap();
        std::fs::write(build.join("qcore_ffi.dll"), b"fake-cdylib-payload").unwrap();
        std::fs::write(build.join("libqcore_ffi.so"), b"fake-cdylib-payload").unwrap();
        let header = base.join("qcore.h");
        std::fs::write(&header, b"/* header */ uint32_t qcore_abi_version(void);").unwrap();
        let abi = base.join("abi-version.txt");
        std::fs::write(&abi, "3\n").unwrap();
        (base, build)
    }

    #[test]
    fn stage_and_archive_zip_contains_staged_binary() {
        let (base, build) = stage_fixture("zip");
        let dist = base.join("dist");
        let stage = dist.join("qcore-0.1.0-native");
        let archive = stage_and_archive(
            &dist,
            &stage,
            &build.join("qcore.exe"),
            &build.join("qcore_ffi.dll"),
            &base.join("qcore.h"),
            &base.join("abi-version.txt"),
            ArchiveFmt::Zip,
        )
        .expect("stage + zip");
        assert_eq!(archive, dist.join("qcore-0.1.0-native.zip"));
        let bytes = std::fs::read(&archive).unwrap();
        // The archive must exist, be a zip, and contain the fake CLI
        // binary payload (store method keeps bytes verbatim).
        assert_eq!(&bytes[..4], &[0x50, 0x4b, 0x03, 0x04], "zip local header");
        let needle = b"fake-cli-binary-payload";
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "zip contains the staged CLI binary"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn stage_and_archive_targz_contains_staged_binary() {
        let (base, build) = stage_fixture("targz");
        let dist = base.join("dist");
        let stage = dist.join("qcore-0.1.0-x86_64-unknown-linux-gnu");
        let archive = stage_and_archive(
            &dist,
            &stage,
            // Cross linux leg: the CLI has no .exe suffix, the cdylib is a
            // .so — the target platform decides the staged names.
            &build.join("qcore"),
            &build.join("libqcore_ffi.so"),
            &base.join("qcore.h"),
            &base.join("abi-version.txt"),
            ArchiveFmt::TarGz,
        )
        .expect("stage + tar.gz");
        assert_eq!(
            archive,
            dist.join("qcore-0.1.0-x86_64-unknown-linux-gnu.tar.gz")
        );
        let bytes = std::fs::read(&archive).unwrap();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic");
        // Decode and confirm all four staged members are present.
        let gz = flate2::read::GzDecoder::new(&bytes[..]);
        let mut tar = tar::Archive::new(gz);
        let mut names = Vec::new();
        for e in tar.entries().unwrap() {
            names.push(e.unwrap().path().unwrap().to_string_lossy().into_owned());
        }
        names.sort();
        assert_eq!(
            names,
            vec![
                "abi-version.txt".to_string(),
                "libqcore_ffi.so".to_string(),
                "qcore".to_string(),
                "qcore.h".to_string(),
            ],
            "tar members: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn stage_and_archive_fails_closed_on_missing_binary() {
        let (base, build) = stage_fixture("failclosed");
        let dist = base.join("dist");
        let stage = dist.join("qcore-0.1.0-native");
        let err = stage_and_archive(
            &dist,
            &stage,
            &build.join("missing-binary"),
            &build.join("qcore_ffi.dll"),
            &base.join("qcore.h"),
            &base.join("abi-version.txt"),
            ArchiveFmt::Zip,
        )
        .expect_err("missing CLI binary fails closed");
        assert!(err.contains("CLI binary missing"), "{err}");
        // No archive written on the failure path.
        assert!(!dist.join("qcore-0.1.0-native.zip").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn stage_and_archive_rejects_stale_stage_files() {
        let (base, build) = stage_fixture("stale");
        let dist = base.join("dist");
        let stage = dist.join("qcore-0.1.0-native");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("stale-junk.txt"), b"old run").unwrap();
        let archive = stage_and_archive(
            &dist,
            &stage,
            &build.join("qcore.exe"),
            &build.join("qcore_ffi.dll"),
            &base.join("qcore.h"),
            &base.join("abi-version.txt"),
            ArchiveFmt::Zip,
        )
        .expect("stage + zip");
        let bytes = std::fs::read(&archive).unwrap();
        assert!(
            !bytes.windows(8).any(|w| w == b"old run"),
            "stale stage files must not leak into the archive"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sign_sums_fails_closed_without_cosign() {
        // Finalize is the publish path: a missing cosign must be a hard
        // error, never the degraded Ok that let an unsigned release ship.
        let base = std::env::temp_dir().join(format!(
            "qcore-xtask-signsums-nocosign-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let dist = base.join("dist");
        std::fs::create_dir_all(&dist).unwrap();

        let mut no_cosign = |cmd: &str| -> bool {
            // `cosign version` absent; a later sign-blob probe would only
            // fire after the presence check, so keep a named stub for it.
            if cmd == "cosign version" {
                false
            } else {
                assert!(cmd.contains("cosign sign-blob"), "unexpected probe: {cmd}");
                true
            }
        };
        let err = super::sign_sums(&dist, &mut no_cosign)
            .expect_err("missing cosign must fail finalize closed");
        assert!(
            err.contains("cosign not installed"),
            "error names the missing dependency: {err}"
        );
        assert!(
            !dist.join("SHA256SUMS.sig").exists(),
            "no signature file on the failure path"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sign_sums_signing_failure_is_an_error() {
        // cosign present but sign-blob failing must not degrade to Ok either.
        let base = std::env::temp_dir().join(format!(
            "qcore-xtask-signsums-signfail-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let dist = base.join("dist");
        std::fs::create_dir_all(&dist).unwrap();

        let mut failing_sign = |cmd: &str| -> bool { cmd == "cosign version" };
        let err = super::sign_sums(&dist, &mut failing_sign)
            .expect_err("failed sign-blob must fail finalize");
        assert!(
            err.contains("cosign sign-blob failed"),
            "error names the failed step: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
