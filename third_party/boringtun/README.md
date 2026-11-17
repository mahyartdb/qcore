# boringtun (vendored, modified)

This directory is a **vendored, modified copy** of
[Cloudflare's boringtun](https://github.com/cloudflare/boringtun) 0.7.1, used
as the WireGuard protocol engine behind `qcore-transport-wireguard`.

It is not upstream boringtun. It does not build upstream's `boringtun-cli`
binary, TUN device, or FFI/JNI bindings; only the Rust `rlib` is built.

- Every deviation from upstream (AmneziaWG wire transforms, removed modules
  and dependencies) is listed in [QCORE_PATCHES.md](QCORE_PATCHES.md).
- Upstream provenance — crates.io `.crate` sha256 and the git commit — is
  pinned in that file.
- Licence: BSD-3-Clause (Cloudflare). The full text is in
  [LICENSE.md](LICENSE.md); the repository root `THIRD-PARTY-NOTICES.md`
  carries the distribution notice, and both ship with every release archive
  and container image.
- The root `Cargo.toml` replaces crates.io `boringtun` with this path through
  `[patch.crates-io]`; the package version and licence fields are upstream's,
  so the patch is a drop-in replacement.
