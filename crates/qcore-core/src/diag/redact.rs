//! Central secret redaction (FR-026/026a/026b).
//!
//! Typed-field-first: secret fields are always redacted by key.
//! Entropy-and-denylist scanning second, for free-form values.
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

/// Keep an actionable `prefix` and mask a secret-like `detail` (fail
/// closed). Shared by CLI-facing cause builders (registration reports).
pub fn prefixed_cause(prefix: &str, detail: &str) -> String {
    match redact_value("cause", detail) {
        Redaction::Keep(_) => format!("{prefix}{detail}"),
        Redaction::Redacted => format!("{prefix}<redacted>"),
    }
}
/// Classify one key/value pair.
pub fn redact_value(key: &str, value: &str) -> Redaction {
    if key_is_secret(key) || value_matches_denylist(value) {
        return Redaction::Redacted;
    }
    // Free-form high-entropy values are treated as secret (fail closed at the
    // value level); see redact_record for the record-level fail-closed path.
    if looks_random(value) {
        return Redaction::Redacted;
    }
    Redaction::Keep(value.to_string())
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
}
