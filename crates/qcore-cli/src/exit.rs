//! Exit codes (contracts/cli.md). Single source is
//! `qcore_core::session::report`; re-exported here for CLI call sites.
//! Secrets are never emitted (FR-026).

pub use qcore_core::session::report::{
    EXIT_HOP_FAILURE as HOP_FAILURE, EXIT_IMPORT_REJECTED as IMPORT_REJECTED,
    EXIT_INVALID as INVALID, EXIT_NO_SESSION as NO_SESSION, EXIT_SCAN_EMPTY as SCAN_EMPTY,
    EXIT_SUCCESS as SUCCESS, EXIT_UNVERIFIABLE as UNVERIFIABLE, EXIT_USAGE as USAGE,
};
