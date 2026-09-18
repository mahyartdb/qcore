//! Diagnostics: central redaction, structured JSON, events.
//!
//! Redaction is central (constitution IV): typed-field-first, entropy +
//! denylist second, heuristic masking never the sole control. Unclassifiable
//! values fail closed (drop record + placeholder). The [`events`] NDJSON
//! stream carries the same guarantees per line (T085).

pub mod events;
pub mod redact;

pub use events::{to_ndjson, DiagEvent, DIAG_STREAM_VERSION};
pub use redact::{
    drops_record, masked_failure_line, masked_value, prefixed_cause, redact_record, redact_value,
    Redaction,
};
