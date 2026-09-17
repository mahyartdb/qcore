//! Central secret redaction (FR-026/026a/026b).
//!
//! Typed-field-first: secret fields are always redacted by key.
//! Entropy-and-denylist scanning second, for free-form values.
//! Scope: the entropy scan detects random-looking blobs (16+ chars), whole
//! or embedded as whitespace-delimited tokens. Short or human-readable
//! credentials under innocuous keys are NOT detected — those must use a
//! typed secret key or a denylist entry.
//! Fail-closed: a value that cannot be classified safe and cannot be proven
//! secret is NOT emitted — the whole record is dropped and a placeholder with
//! metadata only is written.

use std::collections::BTreeMap;

/// Keys always treated as secret (case-insensitive substring match).
pub const SECRET_KEYS: &[&str] = &[
    "privatekey",
    "private_key",
    "privkey",
    "publickey",
    "public_key",
    "pubkey",
    "presharedkey",
    "psk",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "apikey",
    "api_key",
    "auth",
    "headerprotectionkey",
    "header_protection",
    "seed",
    "mnemonic",
];

/// Denylist fragments proving secrecy in free-form values.
const DENYLIST: &[&str] = &[
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "PRIVATE KEY-----",
];

/// Redaction verdict for one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redaction {
    /// Safe to emit as-is.
    Keep(String),
    /// Proven secret: replaced, never emitted.
    Redacted,
}

/// Placeholder metadata written when a record is dropped fail-closed.
#[derive(Debug, Clone)]
pub struct DroppedRecord {
    pub field_count: usize,
    pub keys: Vec<String>,
    pub reason: &'static str,
}

impl std::fmt::Display for DroppedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "record dropped fail-closed ({} fields): {}",
            self.field_count, self.reason
        )
    }
}

/// Minimum byte length for a free-form value to count as secret-like.
const MIN_RANDOM_LEN: usize = 16;
/// Minimum Shannon entropy (bits/char) for a value to count as secret-like.
const ENTROPY_BITS_PER_CHAR: f64 = 4.2;
/// Minimum byte length for an unanchored secret-like value to drop the
/// whole record fail-closed (shorter values are redacted in place).
const MIN_DROP_LEN: usize = 44;

fn key_is_secret(key: &str) -> bool {
    let k = key.to_lowercase().replace(['-', '_', ' '], "");
    SECRET_KEYS.iter().any(|sk| k.contains(sk))
}

/// Typed-anchor check only (no entropy heuristic): true when the key is
/// secret-named or the value matches the denylist. For validating
/// operator-authored config, where the probabilistic entropy scan would
/// false-positive on benign identifiers (and miss short secrets anyway —
/// see `redact_value` scope). Heuristic hunting stays in diagnostic sinks.
pub fn has_secret_anchor(key: &str, value: &str) -> bool {
    key_is_secret(key) || value_matches_denylist(value)
}

fn value_matches_denylist(v: &str) -> bool {
    DENYLIST.iter().any(|d| v.contains(d))
}

/// Shannon entropy in bits/char.
fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_random(s: &str) -> bool {
    s.len() >= MIN_RANDOM_LEN
        && entropy(s) > ENTROPY_BITS_PER_CHAR
        && s.bytes().any(|b| b.is_ascii_alphanumeric())
}

/// Record-drop predicate shared by [`redact_record`] and the NDJSON event
/// stream: a secret-like value under an innocuous key with no typed anchor
/// cannot be proven safe — the whole record is dropped fail-closed (FR-026b).
pub fn drops_record(key: &str, value: &str) -> bool {
    !key_is_secret(key)
        && !value_matches_denylist(value)
        && looks_random(value)
        && value.len() >= MIN_DROP_LEN
}

/// Mask a free-text value when it is secret-like, else return it
/// unchanged. Shared by diagnostic sinks that render raw fields (session
/// text/stderr reports, FFI error messages), which — unlike the NDJSON
/// stream — have no per-field redaction pass.
pub fn masked_value(key: &str, value: &str) -> String {
    match redact_value(key, value) {
        Redaction::Keep(s) => s,
        Redaction::Redacted => "<redacted>".to_string(),
    }
}

/// One masked `layer=… hop=… kind=… cause=…` line shared by every sink that
/// renders a failure report as text (session text/stderr reports, FFI error
/// messages). The free-text cause is masked; the raw `Display` impl is never
/// emitted to a sink. One format means a `FailureReport` shape change lands
/// here, not in three hand-copied literals that silently diverge.
pub fn masked_failure_line(f: &qcore_transport_api::FailureReport) -> String {
    format!(
        "layer={} hop={} kind={} cause={}",
        f.layer,
        f.hop_id,
        f.kind,
        masked_value("cause", &f.cause)
    )
}

/// Keep an actionable `prefix` and mask a secret-like `detail` (fail
/// closed). Shared by CLI-facing cause builders (registration reports).
pub fn prefixed_cause(prefix: &str, detail: &str) -> String {
    match redact_value("cause", detail) {
        Redaction::Keep(masked) => format!("{prefix}{masked}"),
        Redaction::Redacted => format!("{prefix}<redacted>"),
    }
}
/// Classify one key/value pair.
///
/// Whole-value checks first (typed keys, denylist, whole-value entropy),
/// then a token scan: a secret embedded in longer low-entropy prose dilutes
/// whole-value entropy below threshold, so secret-like whitespace-delimited
/// tokens are masked in place and the sentence is kept with context intact.
/// Scope: only random-looking blobs of [`MIN_RANDOM_LEN`]+ chars are
/// detected. Short or human-readable credentials under innocuous keys are
/// NOT caught by this heuristic — those need a typed secret key or a
/// denylist entry.
pub fn redact_value(key: &str, value: &str) -> Redaction {
    if key_is_secret(key) || value_matches_denylist(value) {
        return Redaction::Redacted;
    }
    // Free-form high-entropy values are treated as secret (fail closed at the
    // value level); see redact_record for the record-level fail-closed path.
    if looks_random(value) {
        return Redaction::Redacted;
    }
    if value.split(char::is_whitespace).any(looks_random) {
        return Redaction::Keep(mask_secret_tokens(value));
    }
    Redaction::Keep(value.to_string())
}

/// Replace secret-like whitespace-delimited tokens with `<redacted>`,
/// preserving every other byte (including separator runs) exactly, so a
/// value with no secret-like token round-trips byte-identical.
fn mask_secret_tokens(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for span in value.split_inclusive(char::is_whitespace) {
        // trim_end_matches strips the trailing separator run; the remainder
        // is one token. (Separator matching is the same char::is_whitespace
        // predicate as the split, so word + sep == span.)
        let (word, sep) = span.split_at(span.trim_end_matches(char::is_whitespace).len());
        out.push_str(if looks_random(word) {
            "<redacted>"
        } else {
            word
        });
        out.push_str(sep);
    }
    out
}

/// Redact a whole record. Returns the redacted map, or a [`DroppedRecord`]
/// placeholder when any value is unclassifiable-but-secret-like without a
/// typed key to anchor it (fail closed, FR-026b).
pub fn redact_record(
    fields: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, DroppedRecord> {
    let mut out = BTreeMap::new();
    for (k, v) in fields {
        // Unclassifiable: secret-like value under an innocuous key with no
        // typed anchor — cannot be proven safe (see drops_record).
        if drops_record(k, v) {
            return Err(DroppedRecord {
                field_count: fields.len(),
                keys: fields.keys().cloned().collect(),
                reason: "unclassifiable secret-like value; record dropped fail-closed",
            });
        }
        match redact_value(k, v) {
            Redaction::Keep(s) => {
                out.insert(k.clone(), s);
            }
            Redaction::Redacted => {
                out.insert(k.clone(), "<redacted>".to_string());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn typed_secret_fields_always_redacted() {
        assert_eq!(redact_value("PrivateKey", "cB6V3Xk8="), Redaction::Redacted);
        assert_eq!(redact_value("token", "abc"), Redaction::Redacted);
        assert_eq!(
            redact_value("note", "hello world"),
            Redaction::Keep("hello world".into())
        );
    }

    #[test]
    fn denylist_hits_redacted() {
        assert_eq!(
            redact_value("blob", "xx BEGIN PRIVATE KEY----- yy"),
            Redaction::Redacted
        );
    }

    #[test]
    fn unclassifiable_long_random_drops_record() {
        let r = rec(&[
            ("endpoint", "203.0.113.10:51820"),
            (
                "mystery",
                "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==",
            ),
        ]);
        let dropped = redact_record(&r).unwrap_err();
        assert_eq!(dropped.field_count, 2);
        assert!(dropped.keys.contains(&"mystery".to_string()));
    }

    #[test]
    fn ordinary_record_passes_with_secrets_masked() {
        let r = rec(&[
            ("kind", "wireguard"),
            ("PrivateKey", "cB6V3Xk8pR2mN5qW7zT9yU1iO4pA6sD8fG0hJ2kL4=="),
        ]);
        let out = redact_record(&r).unwrap();
        assert_eq!(out["kind"], "wireguard");
        assert_eq!(out["PrivateKey"], "<redacted>");
        assert!(!out["PrivateKey"].contains("cB6V"));
    }

    #[test]
    fn sink_helpers_mask_only_secret_like_values() {
        assert_eq!(
            masked_value("cause", "connection refused"),
            "connection refused"
        );
        assert_eq!(
            masked_value(
                "cause",
                "boom xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2=="
            ),
            "<redacted>"
        );
        assert_eq!(
            prefixed_cause("provider refused: ", "quota gone"),
            "provider refused: quota gone"
        );
        assert_eq!(
            prefixed_cause(
                "provider refused: ",
                "quota gone xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2=="
            ),
            "provider refused: <redacted>"
        );
    }

    const ECHO_44: &str = "xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==";

    #[test]
    fn masked_failure_line_masks_cause_keeps_shape() {
        use qcore_transport_api::{FailureLayer, FailureReport};
        let f = FailureReport::new(
            FailureLayer::Transport,
            "wg-0",
            format!("boom {ECHO_44}"),
            "transport",
        );
        let line = masked_failure_line(&f);
        assert!(!line.contains(ECHO_44), "leaked: {line}");
        assert_eq!(
            line,
            "layer=transport hop=wg-0 kind=transport cause=<redacted>"
        );
    }

    #[test]
    fn embedded_secret_in_prose_is_masked_in_place() {
        // ~190 chars of low-entropy boilerplate around one 48-char secret:
        // well within the 220-char provider-body budget, whole-value entropy
        // dilutes below threshold -> pre-fix this leaks verbatim (Keep).
        let detail = format!("ref {} {ECHO_44} end", "ok ".repeat(60));
        let out = masked_value("cause", &detail);
        assert!(!out.contains(ECHO_44), "embedded secret leaked: {out}");
        assert!(out.contains("<redacted>"), "nothing masked: {out}");
        assert!(out.contains("end"), "context lost: {out}");
    }

    #[test]
    fn prefixed_cause_masks_embedded_secret_keeps_prefix() {
        let detail = format!("{} {ECHO_44} done", "note ".repeat(40));
        let out = prefixed_cause("provider refused: ", &detail);
        assert!(out.starts_with("provider refused: "), "prefix lost: {out}");
        assert!(!out.contains(ECHO_44), "embedded secret leaked: {out}");
    }

    #[test]
    fn benign_prose_passes_through_byte_identical() {
        let msg = "connection reset by peer after idle timeout exceeded";
        assert_eq!(masked_value("cause", msg), msg);
    }
}
