//! ConnectionReport + FailureReport emission (US1 T049).
//!
//! stdout is results, stderr is diagnostics: `--json` prints exactly one JSON
//! document on stdout. `secret_redaction` is always true — the constructor
//! enforces it and there is no setter (FR-026). Active-profile fields are
//! populated by T068 (scan) / T073 (obfuscation); until then they are `None`.

use crate::diag::redact::masked_value;
use qcore_transport_api::{FailureLayer, FailureReport, HopHealth};

/// Exit codes, single source (contracts/cli.md). The CLI re-exports these.
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_INVALID: i32 = 2;
pub const EXIT_HOP_FAILURE: i32 = 3;
pub const EXIT_SCAN_EMPTY: i32 = 4;
pub const EXIT_IMPORT_REJECTED: i32 = 5;
pub const EXIT_USAGE: i32 = 6;
pub const EXIT_NO_SESSION: i32 = 10;
pub const EXIT_UNVERIFIABLE: i32 = 12;

/// Map a failure report to its exit code: validation failures are exit 2
/// (before any hop started); transport/chain/sidecar/config build failures
/// are exit 3 (a hop failed); scan emptiness is exit 4.
pub fn exit_code_for_failure(r: &FailureReport) -> i32 {
    match r.layer {
        FailureLayer::Validation => EXIT_INVALID,
        FailureLayer::Transport
        | FailureLayer::Chain
        | FailureLayer::Sidecar
        | FailureLayer::Config => EXIT_HOP_FAILURE,
        FailureLayer::Scan => EXIT_SCAN_EMPTY,
    }
}

/// One hop's report: kind, family actually in effect, endpoint, status,
/// plus nesting: incoming carrier (`via`), whether the uplink rides it
/// (`nested`), and the layered inner MTU (`mtu`). `obfuscation` names the
/// active profile, if any (US5 T073).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HopReport {
    pub hop_id: String,
    pub kind: String,
    pub family: String,
    pub endpoint: Option<String>,
    pub status: String,
    pub via: String,
    pub nested: bool,
    pub mtu: u16,
    pub obfuscation: Option<String>,
}

pub fn health_status(h: HopHealth) -> String {
    match h {
        HopHealth::Starting => "starting",
        HopHealth::Healthy => "up",
        HopHealth::Degraded => "degraded",
        HopHealth::Failed => "failed",
        HopHealth::Stopped => "stopped",
    }
    .to_string()
}

/// Machine-readable session report (data-model ConnectionReport).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionReport {
    pub ordered_chain: Vec<HopReport>,
    pub exit_hop_id: String,
    pub secret_redaction: bool,
    pub active_scan_profile: Option<String>,
    pub active_obfuscation: Option<String>,
    pub failure: Option<FailureReport>,
}

impl ConnectionReport {
    pub fn new(ordered_chain: Vec<HopReport>, exit_hop_id: impl Into<String>) -> Self {
        ConnectionReport {
            ordered_chain,
            exit_hop_id: exit_hop_id.into(),
            secret_redaction: true,
            active_scan_profile: None,
            active_obfuscation: None,
            failure: None,
        }
    }
}

/// Exactly one JSON document (stdout contract). The failure cause is
/// redacted like in [`to_text`]: `--json` stdout and FFI status buffers are
/// sinks too (FR-026). Serialization of this shape is infallible in
/// practice; the fallback keeps the no-panic convention (and the
/// one-document contract) on the impossible path.
pub fn to_json(r: &ConnectionReport) -> String {
    let mut redacted = r.clone();
    if let Some(f) = redacted.failure.as_mut() {
        f.cause = masked_value("cause", &f.cause);
    }
    serde_json::to_string(&redacted).unwrap_or_else(|_| encode_fallback())
}

/// Impossible-path fallback: an explicit failure marker, never a
/// success-shaped document — `failure: null` would present a serialization
/// bug as success to downstream parsers. Built with `json!` (not a literal)
/// so the shape cannot rot when fields are added.
fn encode_fallback() -> String {
    serde_json::json!({
        "ordered_chain": [],
        "exit_hop_id": "<encode-error>",
        "secret_redaction": true,
        "active_scan_profile": null,
        "active_obfuscation": null,
        "failure": {
            "layer": "Config",
            "hop_id": "",
            "cause": "report serialization failed",
            "kind": "encode",
        }
    })
    .to_string()
}

/// Human form (stdout; diagnostics stay on stderr).
pub fn to_text(r: &ConnectionReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("exit: {}\n", r.exit_hop_id));
    for h in &r.ordered_chain {
        out.push_str(&format!(
            "hop {} `{}` family={} endpoint={} status={} via={} nested={} mtu={}\n",
            h.hop_id,
            h.kind,
            h.family,
            h.endpoint.as_deref().unwrap_or("-"),
            h.status,
            h.via,
            h.nested,
            h.mtu
        ));
    }
    if let Some(f) = &r.failure {
        // Same shape as FailureReport's Display, with the free-text cause
        // passed through central redaction: unlike the NDJSON stream (which
        // redacts), this text path renders raw fields, so a secret-like
        // cause is masked here (fail closed, FR-026).
        out.push_str(&format!(
            "failure: layer={} hop={} kind={} cause={}\n",
            f.layer,
            f.hop_id,
            f.kind,
            masked_value("cause", &f.cause)
        ));
    }
    out
}

/// Emit a report: one JSON document on stdout with `--json`, else text.
pub fn emit_report(r: &ConnectionReport, json: bool) {
    if json {
        println!("{}", to_json(r));
    } else {
        print!("{}", to_text(r));
    }
}

/// Emit a failure to stderr; returns the mapped exit code. The cause is
/// redacted like in [`to_text`]: stderr is an unredacted sink.
pub fn emit_failure(r: &FailureReport) -> i32 {
    eprintln!(
        "qcore: layer={} hop={} kind={} cause={}",
        r.layer,
        r.hop_id,
        r.kind,
        masked_value("cause", &r.cause)
    );
    exit_code_for_failure(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_is_always_on() {
        let r = ConnectionReport::new(vec![], "h0");
        assert!(r.secret_redaction);
        let back: ConnectionReport = serde_json::from_str(&to_json(&r)).unwrap();
        assert!(back.secret_redaction);
    }

    #[test]
    fn exit_mapping() {
        let t = |layer| exit_code_for_failure(&FailureReport::new(layer, "h", "c", "k"));
        assert_eq!(t(FailureLayer::Validation), EXIT_INVALID);
        assert_eq!(t(FailureLayer::Transport), EXIT_HOP_FAILURE);
        assert_eq!(t(FailureLayer::Chain), EXIT_HOP_FAILURE);
        assert_eq!(t(FailureLayer::Sidecar), EXIT_HOP_FAILURE);
        assert_eq!(t(FailureLayer::Config), EXIT_HOP_FAILURE);
        assert_eq!(t(FailureLayer::Scan), EXIT_SCAN_EMPTY);
    }

    #[test]
    fn json_is_one_document() {
        let r = ConnectionReport::new(
            vec![HopReport {
                hop_id: "wg-0".into(),
                kind: "wireguard".into(),
                family: "dual".into(),
                endpoint: None,
                status: "up".into(),
                via: "root".into(),
                nested: false,
                mtu: 1500,
                obfuscation: None,
            }],
            "wg-0",
        );
        let doc = to_json(&r);
        assert_eq!(doc.lines().count(), 1);
        assert!(doc.contains("secret_redaction"));
    }

    #[test]
    fn text_failure_line_masks_secret_like_cause() {
        let failure = FailureReport::new(
            FailureLayer::Transport,
            "wg-0",
            "boom xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==",
            "transport",
        );
        let r = ConnectionReport {
            failure: Some(failure),
            ..ConnectionReport::new(vec![], "wg-0")
        };
        let text = to_text(&r);
        assert!(
            text.contains("failure: layer=transport hop=wg-0"),
            "got: {text}"
        );
        assert!(
            !text.contains("xT4vN7qW"),
            "secret-like cause leaked: {text}"
        );
        assert!(text.contains("cause=<redacted>"), "got: {text}");
        // Ordinary causes render exactly like FailureReport's Display.
        let plain = FailureReport::new(
            FailureLayer::Transport,
            "wg-0",
            "connection refused",
            "transport",
        );
        let r2 = ConnectionReport {
            failure: Some(plain.clone()),
            ..ConnectionReport::new(vec![], "wg-0")
        };
        assert!(to_text(&r2).contains(&format!("failure: {plain}")));
    }

    #[test]
    fn json_failure_masks_secret_like_cause() {
        const SECRET: &str = "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==";
        // Diluted exactly like a provider echo: whole-value entropy is below
        // threshold, so only token-level masking can catch this.
        let cause = format!("ref {} {SECRET} end", "ok ".repeat(60));
        let r = ConnectionReport {
            failure: Some(FailureReport::new(
                FailureLayer::Transport,
                "wg-0",
                cause,
                "transport",
            )),
            ..ConnectionReport::new(vec![], "wg-0")
        };
        let doc = to_json(&r);
        assert!(!doc.contains(SECRET), "secret-like cause leaked: {doc}");
        let back: ConnectionReport = serde_json::from_str(&doc).unwrap();
        let back_cause = back.failure.expect("failure round-trips").cause;
        assert!(!back_cause.contains(SECRET), "leaked after round-trip");
        assert!(back_cause.contains("<redacted>"), "got: {back_cause}");
    }

    #[test]
    fn json_encode_fallback_is_failure_shaped() {
        let back: ConnectionReport = serde_json::from_str(&encode_fallback()).unwrap();
        assert!(
            back.failure.is_some(),
            "fallback must not look like success"
        );
        assert!(!back.exit_hop_id.is_empty());
    }
}
