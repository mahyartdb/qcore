//! Independently versioned surfaces (FR-003f).
//!
//! - `API_VERSION`: public Rust API.
//! - `ABI_VERSION`: stable C ABI (`qcore_abi_version()`).
//! - `SCHEMA_VERSION`: config/report schemas.

pub const API_VERSION: &str = "0.1.0";
pub const ABI_VERSION: u32 = 1;
pub const SCHEMA_VERSION: &str = "0.1.0";
