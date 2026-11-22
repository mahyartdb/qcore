//! ConnectionReport + FailureReport emission (US1 T049).
//!
//! stdout is results, stderr is diagnostics: `--json` prints exactly one JSON
//! document on stdout. `secret_redaction` is always true — the constructor
//! enforces it and there is no setter (FR-026). Active-profile fields are
//! populated by T068 (scan) / T073 (obfuscation); until then they are `None`.

use crate::diag::redact::{masked_failure_line, masked_value};
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
    /// Cumulative congestion drops observed for this hop (session-bus lag
    /// counted by the hop's forwarder; WG stream/dgram drops arrive as
    /// `Congested` events on the bus). Zero when nothing was ever dropped.
    /// Additive field (#15): readers must ignore unknown fields, never
    /// reject.
    pub dropped: u64,
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
    /// Session state while not Up (F2): `"degraded"` during a watchdog
    /// rebuild window. `None`/absent = Up (the stable shape — the JSON
    /// stays byte-identical to pre-F2 reports on the happy path).
    /// Additive fields: pre-F2 readers that reject unknown keys don't exist
    /// (serde default derive shape is structural), and the CLI contract
    /// treats absent as Up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    /// Successful watchdog reconnects so far (F2). Serialized only when
    /// nonzero-then-reset... kept simple: serialized when Some, set
    /// alongside `session_state = "degraded"` and after a rebuild so the
    /// count is observable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnects: Option<u32>,
    /// Aggregate relay bytes observed for this session (additive field):
    /// `bytes_in` = delivered to local SOCKS/HTTP clients (exit → client),
    /// `bytes_out` = sent from clients through the exit (client → exit).
    /// Serialized only when relay traffic was observed (both `None` keeps
    /// the Up-shape document byte-identical — same discipline as the F2
    /// fields above); sessions that never served a proxy report neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
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
            session_state: None,
            reconnects: None,
            bytes_in: None,
            bytes_out: None,
        }
    }
}

/// Exactly one JSON document (stdout contract). The failure cause is
/// redacted like in [`to_text`]: `--json` stdout and FFI status buffers are
/// sinks too (FR-026). Chain hop ids (including the exit id, which is one of
/// them) go through the same masker: an authored chain-file id can be
/// secret-shaped and must not leak. Serialization of this shape is
/// infallible in practice; the fallback keeps the no-panic convention (and
/// the one-document contract) on the impossible path.
pub fn to_json(r: &ConnectionReport) -> String {
    let mut redacted = r.clone();
    redacted.exit_hop_id = masked_value("hop_id", &redacted.exit_hop_id);
    for h in redacted.ordered_chain.iter_mut() {
        h.hop_id = masked_value("hop_id", &h.hop_id);
    }
    if let Some(f) = redacted.failure.as_mut() {
        f.cause = masked_value("cause", &f.cause);
        // Same masking as the text sink (`masked_failure_line` masks hop_id):
        // a secret-shaped hop id must not leak through `--json` stdout or the
        // FFI status buffer.
        f.hop_id = masked_value("hop_id", &f.hop_id);
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
        "session_state": null,
        "reconnects": null,
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
    out.push_str(&format!(
        "exit: {}\n",
        masked_value("hop_id", &r.exit_hop_id)
    ));
    for h in &r.ordered_chain {
        out.push_str(&format!(
            "hop {} `{}` family={} endpoint={} status={} via={} nested={} mtu={}\n",
            masked_value("hop_id", &h.hop_id),
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
        // Shared masked rendering (see `masked_failure_line`): unlike the
        // NDJSON stream (which redacts), this text path renders raw fields,
        // so a secret-like cause is masked here (fail closed, FR-026).
        out.push_str(&format!("failure: {}\n", masked_failure_line(f)));
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
/// redacted via the shared helper: stderr is an unredacted sink. The
/// `(exit N)` suffix is the contract's diagnostic shape (contracts/cli.md
/// §1) — every stderr failure line carries it, and this is the primary
/// connect-failure path.
pub fn emit_failure(r: &FailureReport) -> i32 {
    eprintln!(
        "qcore: {} (exit {})",
        masked_failure_line(r),
        exit_code_for_failure(r)
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
    fn emit_failure_line_carries_exit_suffix() {
        // contracts/cli.md §1: stderr failure lines are `qcore: <msg>
        // (exit N)` — emit_failure is the primary connect-failure path and
        // must print the same shape the CLI's other diagnostics do. The
        // expected line is built exactly as emit_failure builds it, so the
        // suffix pin lives beside the format string that must keep it.
        let r = FailureReport::new(
            FailureLayer::Transport,
            "wg-0",
            "connection refused",
            "transport",
        );
        let code = exit_code_for_failure(&r);
        let line = format!("qcore: {} (exit {code})", masked_failure_line(&r));
        assert_eq!(
            line,
            "qcore: layer=transport hop=wg-0 kind=transport cause=connection refused (exit 3)",
            "emit_failure's stderr shape must keep the (exit N) suffix"
        );
        assert_eq!(emit_failure(&r), code, "returns the mapped exit code");
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
                dropped: 0,
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
        // Token-scan masking (redact.rs): multi-word values are never
        // redacted wholesale, so the benign word survives and the
        // secret-like token is masked in place — context kept, secret gone.
        assert!(text.contains("cause=boom <redacted>"), "got: {text}");
        // Ordinary causes render through the shared masked helper — pinned
        // here, not against Display (Display renders the raw cause and must
        // never reach a sink).
        let plain = FailureReport::new(
            FailureLayer::Transport,
            "wg-0",
            "connection refused",
            "transport",
        );
        assert_eq!(
            masked_failure_line(&plain),
            "layer=transport hop=wg-0 kind=transport cause=connection refused"
        );
        let r2 = ConnectionReport {
            failure: Some(plain),
            ..ConnectionReport::new(vec![], "wg-0")
        };
        assert!(to_text(&r2).contains("failure: layer=transport hop=wg-0 kind=transport"));
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
    fn json_failure_masks_secret_like_hop_id() {
        // Uniformity across sinks (redact.rs pins that both `cause` and
        // `hop_id` mask): the text sink masks hop_id via
        // `masked_failure_line`, so the JSON sink must too.
        const SECRET: &str = "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==";
        let r = ConnectionReport {
            failure: Some(FailureReport::new(
                FailureLayer::Transport,
                SECRET,
                "connection refused",
                "transport",
            )),
            ..ConnectionReport::new(vec![], "wg-0")
        };
        let doc = to_json(&r);
        assert!(!doc.contains(SECRET), "secret-like hop_id leaked: {doc}");
        let back: ConnectionReport = serde_json::from_str(&doc).unwrap();
        assert_eq!(
            back.failure.expect("failure round-trips").hop_id,
            "<redacted>",
            "masked identically to the text sink"
        );
        let text = to_text(&r);
        assert!(!text.contains(SECRET), "text sink leaked: {text}");
        assert!(text.contains("hop=<redacted>"), "text sink masks: {text}");
        // Ordinary hop ids survive untouched in both sinks.
        let plain = ConnectionReport {
            failure: Some(FailureReport::new(
                FailureLayer::Transport,
                "wg-0",
                "refused",
                "transport",
            )),
            ..ConnectionReport::new(vec![], "wg-0")
        };
        let plain_doc = to_json(&plain);
        assert!(
            plain_doc.contains("\"hop_id\":\"wg-0\""),
            "ordinary hop id must not be masked: {plain_doc}"
        );
    }

    #[test]
    fn chain_hop_ids_mask_secret_shaped_values_in_both_sinks() {
        // A chain-file hop id is authored data, but `status` is a sink like
        // any other: a secret-shaped id (a UUID pasted into a label) must not
        // ride out raw, exactly like the failure hop_id above.
        const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
        let hop = |id: &str| HopReport {
            hop_id: id.into(),
            kind: "wireguard".into(),
            family: "ipv4".into(),
            endpoint: None,
            status: "up".into(),
            via: "root".into(),
            nested: false,
            mtu: 1420,
            obfuscation: None,
            dropped: 0,
        };
        let r = ConnectionReport::new(vec![hop(UUID)], UUID);
        let doc = to_json(&r);
        assert!(
            !doc.contains(UUID),
            "secret-shaped chain hop id leaked through --json: {doc}"
        );
        let back: ConnectionReport = serde_json::from_str(&doc).expect("round-trips");
        assert_eq!(
            back.ordered_chain[0].hop_id, "<redacted>",
            "the ordered chain masks the id: {doc}"
        );
        assert_eq!(
            back.exit_hop_id, "<redacted>",
            "the exit id is the same hop id and masks identically: {doc}"
        );
        let text = to_text(&r);
        assert!(!text.contains(UUID), "text sink leaked: {text}");
        assert!(
            text.contains("exit: <redacted>") && text.contains("hop <redacted> `wireguard`"),
            "the text sink masks both id positions: {text}"
        );

        // Benign ids stay readable in both sinks (no over-redaction).
        let benign = ConnectionReport::new(vec![hop("wg-0")], "wg-0");
        let doc = to_json(&benign);
        assert!(
            doc.contains("\"hop_id\":\"wg-0\"") && doc.contains("\"exit_hop_id\":\"wg-0\""),
            "benign chain ids must not be masked: {doc}"
        );
        let text = to_text(&benign);
        assert!(
            text.contains("exit: wg-0") && text.contains("hop wg-0 `wireguard`"),
            "benign chain ids stay readable in text: {text}"
        );
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

    #[test]
    fn happy_path_report_json_is_stable_without_f2_fields() {
        // The F2 additive fields serialize only when set: the Up-shape
        // document stays byte-identical to pre-F2 reports (JSON contract
        // stability, F2 constraint "keep JSON stable").
        let r = ConnectionReport::new(vec![], "wg-0");
        let doc = to_json(&r);
        assert!(
            !doc.contains("session_state") && !doc.contains("reconnects"),
            "Up-shape report must not carry F2 fields: {doc}"
        );
    }

    #[test]
    fn byte_counter_fields_serialize_only_when_observed() {
        // Additive-shape stability (S3.1): a report without relay traffic
        // carries neither `bytes_in` nor `bytes_out` — the Up-shape document
        // stays byte-identical to pre-counter reports.
        let r = ConnectionReport::new(vec![], "wg-0");
        let doc = to_json(&r);
        assert!(
            !doc.contains("bytes_in") && !doc.contains("bytes_out"),
            "counter-free report must not carry byte fields: {doc}"
        );
        // Observed traffic serializes into the exact additive fields, and
        // round-trips (serde default: pre-counter readers ignore nothing —
        // the fields are simply present; legacy documents without them
        // still parse on this reader).
        let mut r = ConnectionReport::new(vec![], "wg-0");
        r.bytes_in = Some(1234);
        r.bytes_out = Some(5678);
        let doc = to_json(&r);
        assert!(doc.contains("\"bytes_in\":1234"), "{doc}");
        assert!(doc.contains("\"bytes_out\":5678"), "{doc}");
        let back: ConnectionReport = serde_json::from_str(&doc).expect("round-trips");
        assert_eq!(back.bytes_in, Some(1234));
        assert_eq!(back.bytes_out, Some(5678));
        let legacy: ConnectionReport = serde_json::from_str(
            "{\"ordered_chain\":[],\"exit_hop_id\":\"x\",\"secret_redaction\":true,\"active_scan_profile\":null,\"active_obfuscation\":null,\"failure\":null}",
        )
        .expect("legacy doc parses");
        assert_eq!(legacy.bytes_in, None);
        assert_eq!(legacy.bytes_out, None);
    }

    #[test]
    fn degraded_report_carries_state_and_reconnects() {
        let mut r = ConnectionReport::new(vec![], "wg-0");
        r.session_state = Some("degraded".to_string());
        r.reconnects = Some(2);
        let doc = to_json(&r);
        assert!(doc.contains("\"session_state\":\"degraded\""), "{doc}");
        assert!(doc.contains("\"reconnects\":2"), "{doc}");
        let back: ConnectionReport = serde_json::from_str(&doc).expect("round-trips");
        assert_eq!(back.session_state.as_deref(), Some("degraded"));
        assert_eq!(back.reconnects, Some(2));
        // Absent in the wire shape still parses (serde default): a pre-F2
        // document never rejects on a new reader.
        let old: ConnectionReport =
            serde_json::from_str("{\"ordered_chain\":[],\"exit_hop_id\":\"x\",\"secret_redaction\":true,\"active_scan_profile\":null,\"active_obfuscation\":null,\"failure\":null}").expect("legacy doc parses");
        assert_eq!(old.session_state, None);
        assert_eq!(old.reconnects, None);
    }
}
