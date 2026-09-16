//! Public engine API: version constants, Engine facade.
//!
//! Everything the CLI can do is reachable here (FR-003c). Internal types stay
//! private.

pub mod engine;
pub mod version;

pub use engine::{Engine, EngineConfig, Preflight};
pub use version::{ABI_VERSION, API_VERSION, SCHEMA_VERSION};
