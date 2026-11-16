# Research: 9-target release matrix proof (3/9 → 9/9)

**Date:** 2026-09-28
**Decision this informs:** Whether to expand release matrix from 3/9 to 9/9 (amendment + runner capacity + tag dry-run) — feeds `/decide`.
**Confidence overall:** medium

## TL;DR

Local repo declares 9 triples authoritative but proves 3/9 Windows-only in `release.yml`; CI gate and local Tier C gate are native-only. Official docs say Windows-msvc needs native runners, Windows-gnu and Linux-gnu are cross-provable, Android Tier-2 needs NDK + emulator/device (no direct exec). Web norm for proof is per-target build+smoke logs plus keyless cosign/SLSA-L2 minimum; cost math punishes wide matrices.

## Key findings

### 1. Authoritative list is 9, proven legs are 3/9 Windows

**Fact** — `xtask/src/targets.toml:1-4` declares itself authoritative (amendment to remove/demote); `:6-71` lists 9 `[[target]]`: `i686/x86_64/aarch64-pc-windows-msvc`, `x86_64/i686/aarch64/armv7-unknown-linux-gnu` (4), `aarch64-linux-android`, `armv7-linux-androideabi`. Sources: [L1].
**Fact** — `release.yml:22-25` matrix builds only 3/9 (3 Windows); `:10-18` self-reports KNOWN GAP #16: expansion deferred, needs amendment + linux/android runner capacity + tag dry-run, do-not-tag warning. Sources: [L1].
**Fact** — `AGENTS.md:27` matches 3/9 wording; publish job already has checkout/toolchain/cosign. Sources: [L1].

### 2. Build vs smoke vs package are not the same proof

**Fact** — `build.rs:18-28` selects backend by triple (`native-msvc`/`cargo-ndk`/`cargo-zigbuild`/`cross-rs`); `:30-52` shells one build command with pinned versions `:13-15`. Sources: [L1].
**Fact** — `smoke.rs:69-118` native runs full offline matrix (version/preflight/ls/import-exit-5/empty-scan-exit-4); `:158-183` cross-target only validates triple + shells build + prints build-OK; android `:179-181` defers to emulator on CI. Sources: [L1].
**Fact** — `release.yml:30-31` per-matrix-leg steps are `xtask build` + `xtask smoke`; `:32-45` publish on `ubuntu-22.04` runs bare `xtask package` then `xtask release` (re-gates + re-packages). Sources: [L1].
**Inference** — Cross-target smoke is build-plus-symbol scaffolding, not per-target execution; publish packages native artifact, not matrix outputs. Evidence: file:lines above; leap is interpretation of missing per-target package/upload step — judge accordingly.
**Inference** — Conflicts with `tasks.md:211` T086 claim of stub-peer connect over ipv4/ipv6/dual for all 9 incl. emulator. Evidence cited, leap is conflict reading.

### 3. CI and local gates are native-only

**Fact** — `ci.yml:13-103` single `gate` on `ubuntu-22.04`: fmt, clippy `--workspace`, nextest workspace excl. conformance, conformance, abi-diff, deny, semver git-baseline, gitleaks v8.30.1 + trufflehog `--only-verified`, native smoke. No matrix legs. Sources: [L1].
**Fact** — `release.rs:216-229` local Tier C gate is native-only (fmt, clippy, `cargo test`, abi-diff, `smoke --target native`); doc `:8-9` says blocked unless Tier C green (locally native smoke). Sources: [L1].
**Fact** — Spec tiers `spec.md:494-499`: A=PR native, B=nightly broad cross-build, C=tag all-targets green-blocked; `plan.md:291-298` expects gnu+musl + ndk android; `plan.md:325-335` flow tag→matrix→smoke→package→cosign/attest/SBOM→publish. Sources: [L1].
**Fact** — `tasks.md:214` T089 done, `tasks.md:36` T009 done (packaging/signing/blocked-unless-green + shells). Sources: [L1].

### 4. Tier and toolchain reality (official docs)

**Fact** — Tier 1 with host tools: `x86_64-pc-windows-msvc`, `x86_64-pc-windows-gnu`, `aarch64-pc-windows-msvc`, `x86_64/i686/aarch64-unknown-linux-gnu`. `i686-pc-windows-msvc` Tier 1 without host tools; `i686-pc-windows-gnu` Tier 2. Sources: [D1], [D2].
**Fact** — `aarch64-linux-android` + `x86_64-linux-android` Tier 2 without host tools, std yes; guaranteed to build, not to pass tests. Actual repo Android legs are `aarch64-linux-android` + `armv7-linux-androideabi` (see §1), not `x86_64`. Sources: [D3].
**Fact** — Non-Windows→`*windows-msvc` may be possible but not supported; needs native Windows MSVC host. `*windows-gnu` explicitly supports cross (Binutils 2.44 + GCC 14.2 + mingw-w64 12.0.0 floor). Sources: [D2], [D4], [D5].
**Fact** — Android is cross-only, needs latest LTS NDK; clang `$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=<triple><api>`. Sources: [D3], [D6].
**Fact** — Hosted runners exist: `ubuntu-22.04`, `ubuntu-22.04-arm`, `windows-2022`, `windows-11-arm`. Sources: [D7].
**Inference** — Tier-1 triples provable natively (x64 on x64, aarch64 via -arm runners); `aarch64-linux-gnu` from x64-ubuntu needs cross-linker+sysroot, weaker than native -arm runner. Evidence above.
**Inference** — Android ELF cannot smoke by direct exec on ubuntu runner; requires emulator/device job (x86_64 AVD cheapest; arm64 needs KVM/arm runner or Test Lab). Evidence: emulator docs [D8].

### 5. Supply-chain proof bar (upstream only)

**Fact** — SLSA L1=provenance exists; L2=signed+hosted; L3=hardened non-forgeable isolated. Sources: [D9].
**Fact** — GH artifact attestations = SLSA-L2 alone (Sigstore Public Good), L3 only with isolated reusable workflow; supports SBOM attestation; `gh attestation verify`. Sources: [D10].
**Fact** — Sigstore keyless = Cosign + Fulcio short-lived cert (OIDC) + Rekor log; `cosign verify --certificate-identity --certificate-oidc-issuer`. Sources: [D11].
**Inference** — Small-team minimum cited on web is keyless cosign + provenance attestation; full SLSA-3/SBOM-per-artifact uneven in 2025-26. See web §6.

### 6. Web failure modes + accepted proof

**Fact** — `-msvc` needs native link.exe/libs; linux→msvc unsupported without MS linker (rustup#1470 backlog, UNVERIFIED single-source, corroborated by forums). Sources: [W7].
**Fact** — `-gnu` Windows cross fails at link + in crypto deps; `ring` does not cross linux→windows-gnu (mingw64) per backlog issues (pre-2025, still-cited pattern). Sources: [W8].
**Fact** — Android needs per-ABI NDK linker config; default host linker → link error; `cargo-ndk`/cargo config per target is practice. Sources: [W9].
**Fact** — `cargo test` unsupported for some triples; `cross test` containers fill gap. Sources: [W6], [W12].
**Fact** — Cost multipliers: Windows 2×, macOS 10× Linux minutes; self-hosted +$0.002/min from 2026-03-01; hosted cut 15-39% from 2026-01-01. Sources: [W1], [W2], [W3].
**Inference** — cargo-dist exists because releases have many steps; its changelog moved linux-arm64 to native runners after cross pain. Evidence: docs/CHANGELOG/issue #74 [W11] — interpretation.
**Inference** — Reviewer rule of thumb: no green per-target build+smoke log = unproven lane; matrix badges without per-target jobs treated as marketing. Single-cluster practitioner consensus, not controlled study.

### 7. Doc/code mismatches to close

**Fact** — musl variants in `build.rs:5,23-24`, `plan.md:297`, Tier B gnu/musl have zero triples in `targets.toml`. Sources: [L1].
**Fact (resolved after this note was written)** — Constitution header `:2-12` + footer `:191` v1.2.0 (2026-09-14/2026-09-25) vs `AGENTS.md:9` citing v1.1.0. Fixed by PR #22 (doc-map-vii): `AGENTS.md:9` now cites v1.2.0. Sources: [L1].
**Assumption** — Issue #16 triage details live outside repo (no local copy found); gap wording sourced from `release.yml:11` + `AGENTS.md:27` only. Needs validation against tracker.

## Contradictions / uncertainty

- Android 2nd leg: local list uses `armv7-linux-androideabi` while docs brief assumed `x86_64-linux-android` — local list wins; emulator cheap-path (x86_64 AVD) does not match armv7 leg. Cited both sides.
- T086 claims all-9 stub-peer connect incl. emulator vs `smoke.rs` cross-only build check — cannot both be current proof; needs run log to resolve.
- SBOM pressure: ENISA Jun-2026 + CRA discourse says increasingly expected vs practitioner norm says keyless cosign minimum suffices — scope-dependent, treat as INFERENCE.

## Evidence against

- Cost/runner math punishes 9 lanes (high, cited): 2×/10× multipliers + 2026 metering make 9 lanes multiples of Linux cost. Sources: [W1][W2][W3].
- Demand may not justify Android/armv7/musl lanes (medium, ASSUMPTION): small CLI bases cluster on x64 Linux/Win; no download telemetry found — insufficient data.
- Start-native-simple, add lanes on demand is documented guidance (medium, Inference): dist defaults shifted to native runners. Sources: [W11].
- Maintenance drag > one-time green (medium, Inference): each lane adds NDK/MSVC/toolchain pinning + cache/storage; stale lanes rot. Sources: [W9][W6].

## Gaps

**Update 2026-11-16 (W3)** - `.github/workflows/release.yml` now declares all
9 `targets.toml` triples in one matrix plus a `workflow_dispatch` dry-run mode
(publish guarded on `refs/tags/`), and `xtask/src/release.rs` derives coverage
from that file at compile time instead of the hand-kept `COVERED` list, so a
one-sided edit fails the release gate. The bullets below are the 2026-09-28
findings: "6/9 legs unbuilt" and the native-only package step are superseded in
declaration, not yet in proof. The missing green dry-run log stays open until
one dispatch run covers all nine legs.

- No green tag dry-run log proving matrix+publish (`.sig`/attestation/SBOM per artifact).
- 6/9 legs unbuilt (all linux + android) — needs ubuntu cross-rs/cargo-ndk jobs + capacity.
- Local `release` gate ≠ Tier C (native-only) — same dry-run closes it.
- No survey data on small-team lane counts; verdicts rest on pricing + guides.

## Recommended next steps

**Update 2026-11-16 (W3)** - Steps 1-2 are implemented in `release.yml` (9-leg
matrix, dry-run trigger, per-leg `cargo xtask build|smoke|package`, per-leg
upload); step 3's "publish per-target packaging step" is now per-leg. Step 1
itself - a green run with per-target logs - has not been executed: the matrix
is declared, unproven.

1. Run `v*` dry-run of `release.yml` matrix+publish to test release; capture per-target build+smoke logs + `.sig`/attestation/SBOM.
2. Add ubuntu-22.04 cross-rs/cargo-ndk jobs for 4 linux-gnu + 2 android legs (or amend `targets.toml` + constitution if de-scoping musl/armv7).
3. Fix doc mismatches: AGENTS.md constitution version, musl wording, publish per-target packaging step.

## Sources

[L1] Local repo read 2026-09-28 — `xtask/src/targets.toml`, `release.yml`, `build.rs`, `smoke.rs`, `release.rs`, `ci.yml`, `constitution.md`, `AGENTS.md`, `spec.md`, `plan.md`, `tasks.md` (file:line cites inline) — high for existence, medium for currency
[D1] Rustc platform support — https://doc.rust-lang.org/rustc/platform-support.html (2026-09-28) — high
[D2] Windows-msvc support — https://github.com/rust-lang/rust/blob/main/src/doc/rustc/src/platform-support/windows-msvc.md + https://doc.rust-lang.org/rustc/platform-support/windows-gnu.html (2026-09-28) — high
[D3] Android support — https://doc.rust-lang.org/rustc/platform-support/android.html (2026-09-28) — high
[D4] Rust setup Windows — https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup (2026-09-28) — high
[D5] See D2 gnu page — high
[D6] NDK other build systems — https://developer.android.com/ndk/guides/other_build_systems (2026-09-28) — high
[D7] GitHub-hosted runners — https://docs.github.com/en/actions/reference/runners/github-hosted-runners (2026-09-28) — high
[D8] Emulator run/test — https://developer.android.com/studio/run/emulator.html + emulator-commandline + command-line testing (2026-09-28) — high
[D9] SLSA levels — https://slsa.dev/spec/v1.1/levels (2026-09-28) — high
[D10] Artifact attestations — https://docs.github.com/actions/concepts/security/artifact-attestations + use-artifact-attestations (2026-09-28) — high
[D11] Sigstore cosign — https://docs.sigstore.dev/cosign/signing/overview/ + verifying/verify + signing_with_blobs (2026-09-28) — high
[W1] Actions runner pricing — https://docs.github.com/en/billing/reference/actions-runner-pricing — current 2026 — high
[W2] Multipliers discussion — https://github.com/orgs/community/discussions/108363 — longstanding — medium
[W3] Simpler pricing changelog — https://github.blog/changelog/2025-12-16-coming-soon-simpler-pricing-and-a-better-experience-for-github-actions/ — 2025-12-16 — high
[W4] Price change summary — https://www.warpbuild.com/blog/github-actions-price-change — 2025/26 — medium
[W5] Runners traps 2026 — https://bitrise.io/blog/post/best-github-actions-runners-in-2026-and-hidden-pricing-traps-to-avoid — 2026 — medium
[W6] Cross compilation in Rust — https://fpira.com/blog/2025/01/cross-compilation-in-rust/ — 2025-01 — medium
[W7] rustup#1470 msvc cross — https://github.com/rust-lang/rustup/issues/1470 — backlog — low (single-source)
[W8] ring#1363 + users forum windows-gnu link — https://github.com/briansmith/ring/issues/1363 — backlog — low-medium
[W9] Rust Android lessons — https://greptime.com/blogs/2025-04-14-rust-in-android-edge-based-practice — 2025-04-14 — medium
[W10] Cross-platform pipeline — https://ahmedjama.com/blog/2025/12/cross-platform-rust-pipeline-github-actions — 2025-12 — medium
[W11] cargo-dist docs/CHANGELOG/issue#74 — https://axodotdev.github.io/cargo-dist/ — current — medium
[W12] cross-rs/cross — https://github.com/cross-rs/cross — current — medium
