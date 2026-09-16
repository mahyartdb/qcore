//! CLI command modules (T082 surface): every command is a thin consumer of
//! the public engine API — no CLI-only paths (see the `cli_api_parity`
//! conformance test).
//!
//! - [`preflight`]: validate chain + profiles + config, zero sockets.
//! - [`scan`]: endpoint discovery + `--scan`/`--no-scan` on connect.
//! - [`import`]: WireGuard/AmneziaWG import (exit 5) + redacted export.
//! - [`profiles`]: `ls`/`profiles` listing (transports, scan + obfuscation
//!   profiles, presets, shortcuts) and the `-O` chain-default helper.
//! - [`shortcuts`]: generated pure-alias chain shortcuts.
//!
//! Validation refusals are exit 2 naming the offending hop
//! (`hop_index` + `hop_id` + `reason` + `fix`); status states map to
//! not_running exit 10 / dead exit 1 / unverifiable exit 12 (fail closed).

pub mod import;
pub mod preflight;
pub mod profiles;
pub mod scan;
pub mod shortcuts;
