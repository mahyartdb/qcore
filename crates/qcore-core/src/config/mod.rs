//! Typed config module: hop types, profile-dir resolution, secrets.
//!
//! Profiles (scan/obfuscation/compositions) live in the application profile
//! directory and are replaceable without editing secret-embedded config (FR-028).

pub mod chain_file;
pub mod export;
pub mod hop;
pub mod import;
pub mod obfuscation;
pub mod profile_dir;
pub mod secret;

pub use hop::{
    allowed_fields, resolve_import_ref, HopConfig, HopSpec, MasqueConfig, MockConfig,
    PsiphonConfig, RelayConfig, TorConfig, WireguardConfig,
};
