//! Structured diag NDJSON stream (T085, FR-025).
//!
//! One JSON document per line on stdout/stderr-adjacent sinks:
//! `{"v","schema","ts_ms","kind","hop_id","payload"}`. `schema` is the public
//! [`SCHEMA_VERSION`](crate::api::version::SCHEMA_VERSION), so the stream is
//! versioned alongside the public API: a schema break bumps both.
//!
//! Every string payload value passes through central redaction
//! ([`redact_value`](super::redact::redact_value)); a value tripping the
//! record-drop predicate replaces the whole payload with a metadata-only
//! placeholder (fail closed, FR-026b). Diagnostics never carry secrets.

use crate::api::version::SCHEMA_VERSION;
use crate::diag::redact::{drops_record, redact_value, Redaction};
use crate::session::report::ConnectionReport;
use qcore_transport_api::{FailureReport, HopEvent};

/// Stream framing version (orthogonal to `schema`: framing changes bump
/// this; report-shape changes bump `SCHEMA_VERSION`).
pub const DIAG_STREAM_VERSION: u32 = 1;

/// One redacted diag record.
#[derive(Debug, Clone)]
pub enum DiagEvent<'a> {
    Hop(&'a HopEvent),
    Failure(&'a FailureReport),
    Report(&'a ConnectionReport),
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Recursively redact string values in place. Returns true when any value
/// trips the record-drop predicate (caller substitutes the placeholder).
fn redact_json(key: &str, value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => {
            if drops_record(key, s) {
                return true;
            }
            match redact_value(key, s) {
                Redaction::Redacted => *s = "<redacted>".to_string(),
                // Keep payload may carry in-place token masking.
                Redaction::Keep(masked) => *s = masked,
            }
            false
        }
        serde_json::Value::Array(items) => {
            let mut drop_record = false;
            for (i, item) in items.iter_mut().enumerate() {
                let k = format!("{key}[{i}]");
                drop_record |= redact_json(&k, item);
            }
            drop_record
        }
        serde_json::Value::Object(map) => {
            let mut drop_record = false;
            for (k, v) in map.iter_mut() {
                drop_record |= redact_json(k, v);
            }
            drop_record
        }
        _ => false,
    }
}

/// Render one NDJSON line (no trailing newline; the sink delimits records).
pub fn to_ndjson(event: DiagEvent<'_>) -> String {
    let (kind, hop_id, mut payload) = match event {
        DiagEvent::Hop(e) => (
            "hop",
            hop_id_of(e).map(str::to_string),
            serde_json::to_value(e).unwrap_or(serde_json::Value::Null),
        ),
        DiagEvent::Failure(r) => (
            "failure",
            Some(r.hop_id.clone()),
            serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
        ),
        DiagEvent::Report(r) => (
            "report",
            Some(r.exit_hop_id.clone()),
            serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
        ),
    };
    if redact_json(kind, &mut payload) {
        payload = serde_json::json!({
            "dropped": true,
            "reason": "unclassifiable secret-like value; record dropped fail-closed",
        });
    }
    serde_json::json!({
        "v": DIAG_STREAM_VERSION,
        "schema": SCHEMA_VERSION,
        "ts_ms": now_ms(),
        "kind": kind,
        "hop_id": hop_id,
        "payload": payload,
    })
    .to_string()
}

fn hop_id_of(e: &HopEvent) -> Option<&str> {
    match e {
        HopEvent::Started { hop_id }
        | HopEvent::HealthChanged { hop_id, .. }
        | HopEvent::EndpointSelected { hop_id, .. }
        | HopEvent::Failed { hop_id, .. }
        | HopEvent::Stopped { hop_id } => Some(hop_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qcore_transport_api::FailureLayer;

    #[test]
    fn hop_event_line_is_versioned_and_secret_free() {
        let e = HopEvent::Started {
            hop_id: "mock-0".into(),
        };
        let line = to_ndjson(DiagEvent::Hop(&e));
        let v: serde_json::Value = serde_json::from_str(&line).expect("one JSON doc");
        assert_eq!(v["v"], 1);
        assert_eq!(v["schema"], SCHEMA_VERSION);
        assert_eq!(v["kind"], "hop");
        assert_eq!(v["hop_id"], "mock-0");
        assert!(v["ts_ms"].as_u64().is_some());
    }

    #[test]
    fn failure_line_names_layer_and_hop() {
        let r = FailureReport::new(FailureLayer::Transport, "mock-0", "refused", "unreachable");
        let line = to_ndjson(DiagEvent::Failure(&r));
        assert!(line.contains("\"kind\":\"failure\""));
        assert!(line.contains("mock-0"));
        assert!(line.contains("Transport"));
    }

    #[test]
    fn secret_like_value_drops_payload_fail_closed() {
        let r = FailureReport::new(
            FailureLayer::Transport,
            "mock-0",
            "mystery xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==",
            "weird",
        );
        let line = to_ndjson(DiagEvent::Failure(&r));
        assert!(line.contains("\"dropped\":true"), "got: {line}");
        assert!(!line.contains("xT4vN7qW"), "secret-like value leaked");
    }

    #[test]
    fn low_entropy_value_under_innocuous_key_is_kept() {
        let r = FailureReport::new(FailureLayer::Config, "wg-0", "bad token abc", "invalid");
        let line = to_ndjson(DiagEvent::Failure(&r));
        assert!(!line.contains("\"dropped\""), "got: {line}");
        // `cause` is an innocuous key but low-entropy: kept as-is.
        assert!(line.contains("bad token abc"));
    }
}
