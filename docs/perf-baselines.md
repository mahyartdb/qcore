# Release metrics baselines (constitution VII)

First recording per the v1.2.0 Sync Impact Report follow-up TODO.
Method is the contract: same profile, payload, and harness every time.
Unexpected regressions must be explained in the change description.

## Environment (this recording)

- CPU: 12th Gen Intel i5-12400 (6C/12T), RAM 48 GB, Windows 11 build 26200
- Toolchain: rustc 1.97.1 (`rust-toolchain.toml`)
- Profile: `[profile.release] lto = true, codegen-units = 1, strip = true`
- Tree: `chore/dep-bumps-2026-09` (base64 0.23, getrandom 0.4, toml 1.1,
  rcgen 0.14; keyring held at 3 — see below)

## Baselines (2026-09-28, native x86_64-pc-windows-msvc)

| Metric | Value | Harness |
|---|---|---|
| `qcore.exe` size | 13.92 MB | `cargo xtask build --release`, `target/release/qcore.exe` |
| `qcore_ffi.dll` size | 15.46 MB | same build |
| Clean build time | 290 s | `cargo clean` + timed `cargo xtask build --release` |
| Peak session memory (lifecycle) | ~5.3 MB | `target/release/embed-host.exe` (mock session start→status→stop), OS-reported `PeakWorkingSet64`, max of 5 runs |
| Peak session memory (30 s held) | ~5.3 MB | `embed-host.exe 30` (session held open, status polled 1/s), same sampler, max of 3 runs: 5.22/5.23/5.25 MB — an idle held session adds nothing measurable over the lifecycle peak |

## Caveats

- Memory harness is mock-transport only (offline stub peer) and short-lived;
  it bounds the session-lifecycle floor, not a loaded Tor/MASQUE session. A
  sustained-session harness is follow-up work, not a blocker.
- keyring 4.2.0 was evaluated three times and REVERTED, with the full
  mechanism proven, not just the correlation. Its Windows backend drops
  keyring ops transiently under parallel-test load; the suite then fails
  two independent ways: (a) transient GET misses with no file fallback
  present read as missing identity (`inject`/`store` assertion failures);
  (b) transient PUT failures engage the file fallback, whose files land in
  `config_dir`, where the secret-hygiene scan flags them as leaks — a
  leftover `warp-outer_sprivate__key.secret` from a failed run confirmed
  it. A bounded 3-attempt retry (`SecretStore::keyring_retry`, unit-tested,
  still fails closed) cut the rate but could not eliminate backend drops,
  and the remaining fixes (fallback relocation, test weakening) trade away
  hygiene guarantees for a version number — rejected. Retry + per-dir
  import namespaces (same FNV-1a scheme as the identity store, with a
  `qcore-imports` legacy read fallback) stay: namespaces killed the proven
  value-race (two tests, one `wg-home` ref, one shared account →
  wrong-secret handshakes), retry hardens real users against transient
  Credential Manager failures on keyring 3 too.
