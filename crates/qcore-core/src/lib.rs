//! qcore engine core: registry, chain, session, scan, config, diag.
//!
//! The engine reads transport descriptors from the [`registry`] and never
//! matches on a transport kind (constitution I). All validation is total and
//! side-effect free: an invalid chain never partially starts (FR-010/FR-027).

pub mod api;
pub mod chain;
pub mod config;
pub mod diag;
pub mod registry;
pub mod scan;
pub mod session;
