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
| Peak session memory | ~5.3 MB | `target/release/embed-host.exe` (mock session start→status→stop), OS-reported `PeakWorkingSet64`, max of 5 runs |

## Caveats

- Memory harness is mock-transport only (offline stub peer) and short-lived;
  it bounds the session-lifecycle floor, not a loaded Tor/MASQUE session. A
  sustained-session harness is follow-up work, not a blocker.
- keyring 4.2.0 was evaluated and REVERTED on this branch: master + keyring 4
  flaked 4/6 full-suite runs (vs 0/2 on master) via a latent shared-keyring
  race in `tests/chains/tests/imported_chain.rs` (two tests, one `wg-home`
  ref, constant `qcore-imports` service). Partial fix landed (unique ref per
  test); keyring retry stays deferred until a full hermeticity pass.
