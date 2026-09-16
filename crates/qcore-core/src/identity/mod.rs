//! Provider identity: registration, renewal, MASQUE enrollment (002).
//!
//! The engine core owns the whole lifecycle (research R0 split: thin
//! clients orchestrate); storage is profile-dir TOML + secret store
//! (research R2); renewal is classified refusal-only (research R3).
//!
//! Flow modules land with their user stories: `register` + `gool` (US1),
//! `renew` (US3), `masque` (US4). Session wiring (`preconnect_identity`)
//! lives on [`crate::api::Engine`] so the CLI stays thin.

pub mod gool;
pub mod https;
pub mod masque;
pub mod model;
pub mod register;
pub mod renew;
pub mod report;
pub mod store;
