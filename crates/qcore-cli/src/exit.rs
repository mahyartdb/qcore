//! Exit codes (contracts/cli.md). Single source is
//! `qcore_core::session::report`; re-exported here for CLI call sites.
//! Secrets are never emitted (FR-026).

pub use qcore_core::session::report::{
    EXIT_HOP_FAILURE as HOP_FAILURE, EXIT_IMPORT_REJECTED as IMPORT_REJECTED,
    EXIT_INVALID as INVALID, EXIT_NO_SESSION as NO_SESSION, EXIT_SCAN_EMPTY as SCAN_EMPTY,
    EXIT_SUCCESS as SUCCESS, EXIT_UNVERIFIABLE as UNVERIFIABLE, EXIT_USAGE as USAGE,
};

/// Emit one stderr diagnostic in the contracted shape: `qcore: <msg> (exit N)`.
/// The suffix is appended here so drift (the ~10 sites that predate it) cannot
/// recur: callers pass the code once and the mapping is mechanical.
pub fn diag_exit(code: i32, msg: &str) {
    eprintln!("qcore: {msg} (exit {code})");
}
