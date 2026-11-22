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
use std::ops::Range;

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
        // Field names are not secrets: operators triaging a dropped record
        // need to know which keys were present.
        write!(
            f,
            "record dropped fail-closed ({} fields: {}): {}",
            self.field_count,
            self.keys.join(", "),
            self.reason
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

/// Long hex strings top out at 4 bits/char, below the entropy bar, so
/// device IDs and license keys need an explicit rule.
const MIN_HEX_LEN: usize = 32;

fn is_hex_token(s: &str) -> bool {
    s.len() >= MIN_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Group lengths of a UUID: 8-4-4-4-12 hex digits.
const UUID_GROUP_LENS: [usize; 5] = [8, 4, 4, 4, 12];

/// UUID-shaped tokens (device IDs). The separators break the all-hex rule
/// and their share of the characters drags entropy under the random bar, so
/// a hyphenated UUID would otherwise pass every sink raw. The shape is
/// anchored to 8-4-4-4-12 groups so separator-rich non-secrets (a full-form
/// IPv6 endpoint, say) stay actionable triage text.
fn is_uuid_token(s: &str) -> bool {
    let groups: Vec<&str> = s.split(['-', '_', ':']).collect();
    groups.len() == UUID_GROUP_LENS.len()
        && groups
            .iter()
            .zip(UUID_GROUP_LENS)
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Byte ranges of device-id-shaped substrings inside one whitespace-delimited
/// token. The whole-token checks above miss an id carrying decorations
/// (`…:443`, `id=…,`, quotes): the glue changes the token's group count.
/// Runs are bounded by characters that are neither hex nor one of the
/// [`is_uuid_token`] separators, and two shapes anchor detection: a bare run
/// of [`MIN_HEX_LEN`]+ hex digits (an unseparated id glued to `id=`), and
/// five consecutive groups with the 8-4-4-4-12 lengths. The shape anchors
/// are what keep separator-rich non-secrets (a full-form IPv6 endpoint, MAC
/// chains, `0000-…` padding) unflagged.
fn uuid_subranges(s: &str) -> Vec<Range<usize>> {
    fn is_sep(b: u8) -> bool {
        matches!(b, b'-' | b'_' | b':')
    }
    let bytes = s.as_bytes();
    let mut ranges = Vec::new();
    let mut run_start = 0;
    while run_start < bytes.len() {
        if !(bytes[run_start].is_ascii_hexdigit() || is_sep(bytes[run_start])) {
            run_start += 1;
            continue;
        }
        let mut run_end = run_start;
        while run_end < bytes.len()
            && (bytes[run_end].is_ascii_hexdigit() || is_sep(bytes[run_end]))
        {
            run_end += 1;
        }
        // Split the run on separators: each group is a maximal hex run. A
        // group of MIN_HEX_LEN+ digits is a bare device id; any five
        // consecutive groups with the 8-4-4-4-12 lengths are a decorated
        // UUID. Extra groups around either shape (a leading `-`, a suffix)
        // leave the window anchored to the id.
        let mut groups = Vec::new();
        let mut group_start = run_start;
        for (offset, &b) in bytes[run_start..run_end].iter().enumerate() {
            if is_sep(b) {
                groups.push(group_start..run_start + offset);
                group_start = run_start + offset + 1;
            }
        }
        groups.push(group_start..run_end);
        for g in &groups {
            if g.end - g.start >= MIN_HEX_LEN {
                ranges.push(g.clone());
            }
        }
        for window in groups.windows(UUID_GROUP_LENS.len()) {
            let shaped = window.iter().zip(UUID_GROUP_LENS).all(|(g, n)| {
                g.end - g.start == n && bytes[g.start..g.end].iter().all(|b| b.is_ascii_hexdigit())
            });
            if shaped {
                let last = window.len() - 1;
                ranges.push(window[0].start..window[last].end);
            }
        }
        run_start = run_end;
    }
    // A run can yield a bare group and a shape window out of order (and two
    // shape windows can overlap when a group sequence matches at both
    // offsets); callers walk the ranges left to right.
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match merged.last_mut() {
            Some(last) if r.start < last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    merged
}

fn looks_secret(s: &str) -> bool {
    looks_random(s) || is_hex_token(s) || is_uuid_token(s)
}

fn token_is_secret(s: &str) -> bool {
    looks_secret(s) || !uuid_subranges(s).is_empty()
}

/// Record-drop predicate shared by [`redact_record`] and the NDJSON event
/// stream: a secret-like value under an innocuous key with no typed anchor
/// cannot be proven safe — the whole record is dropped fail-closed (FR-026b).
pub fn drops_record(key: &str, value: &str) -> bool {
    !key_is_secret(key)
        && !value_matches_denylist(value)
        && looks_secret(value)
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
/// messages). Free-text fields are masked like the NDJSON stream masks them:
/// the cause by key (`cause`), and `hop_id` by value so a secret-shaped hop
/// id is never emitted raw from any sink (same `masked_value` semantics —
/// hop ids are hop-local labels, and a provider echo that put a secret in
/// one must not survive rendering). One format means a `FailureReport`
/// shape change lands here, not in three hand-copied literals that silently
/// diverge.
pub fn masked_failure_line(f: &qcore_transport_api::FailureReport) -> String {
    format!(
        "layer={} hop={} kind={} cause={}",
        f.layer,
        masked_value("hop_id", &f.hop_id),
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
/// Whole-value checks first (typed keys, denylist, single-token shapes and
/// entropy), then a token scan: secret-like whitespace-delimited tokens are
/// masked in place and the sentence is kept with context intact. Whole-value
/// entropy is deliberately NOT applied to multi-word values — prose entropy
/// is a property of the sentence, not a secrecy proof, and a diagnostic
/// sentence that happens to clear the bar (an FR-021 rejection message, say)
/// must not be redacted wholesale. The record-level fail-closed path
/// ([`drops_record`]) still treats any long secret-like value as
/// unclassifiable.
/// Scope: only random-looking blobs of [`MIN_RANDOM_LEN`]+ chars are
/// detected. Short or human-readable credentials under innocuous keys are
/// NOT caught by this heuristic — those need a typed secret key or a
/// denylist entry.
pub fn redact_value(key: &str, value: &str) -> Redaction {
    if key_is_secret(key) || value_matches_denylist(value) {
        return Redaction::Redacted;
    }
    // Hex/UUID whole-value shapes are single-token rules; a separator-bearing
    // shape or a lone blob cannot contain whitespace.
    if is_hex_token(value) || is_uuid_token(value) {
        return Redaction::Redacted;
    }
    if !value.contains(char::is_whitespace) && looks_random(value) {
        return Redaction::Redacted;
    }
    if value.split(char::is_whitespace).any(token_is_secret) {
        return Redaction::Keep(mask_secret_tokens(value));
    }
    Redaction::Keep(value.to_string())
}

/// Replace secret-like whitespace-delimited tokens with `<redacted>`,
/// preserving every other byte (including separator runs) exactly, so a
/// value with no secret-like token round-trips byte-identical. A token that
/// only carries a UUID substring keeps its decoration (`id=`, `:443`, quotes,
/// commas) and loses just the UUID body.
fn mask_secret_tokens(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for span in value.split_inclusive(char::is_whitespace) {
        // trim_end_matches strips the trailing separator run; the remainder
        // is one token. (Separator matching is the same char::is_whitespace
        // predicate as the split, so word + sep == span.)
        let (word, sep) = span.split_at(span.trim_end_matches(char::is_whitespace).len());
        if looks_secret(word) {
            out.push_str("<redacted>");
        } else {
            push_masked_uuids(&mut out, word);
        }
        out.push_str(sep);
    }
    out
}

fn push_masked_uuids(out: &mut String, word: &str) {
    let mut last = 0;
    for range in uuid_subranges(word) {
        out.push_str(&word[last..range.start]);
        out.push_str("<redacted>");
        last = range.end;
    }
    out.push_str(&word[last..]);
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
        // Multi-word prose keeps its non-secret words and masks only the
        // secret-like token.
        assert_eq!(
            masked_value(
                "cause",
                "boom xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2=="
            ),
            "boom <redacted>"
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
            "provider refused: quota gone <redacted>"
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
            "layer=transport hop=wg-0 kind=transport cause=boom <redacted>"
        );
    }

    #[test]
    fn masked_failure_line_masks_secret_like_hop_id() {
        // FIX: `hop_id` reaches sinks raw (`layer=… hop=…`) while the same
        // string in `cause` gets masked — a secret-shaped hop id must mask
        // with the same `masked_value` semantics in every sink.
        use qcore_transport_api::{FailureLayer, FailureReport};
        let hop = ECHO_44;
        let f = FailureReport::new(FailureLayer::Transport, hop, "refused", "transport");
        let line = masked_failure_line(&f);
        assert!(!line.contains(hop), "secret-like hop_id leaked: {line}");
        assert!(line.contains("hop=<redacted>"), "masked in place: {line}");
        // Ordinary hop ids pass through untouched.
        let plain = FailureReport::new(FailureLayer::Transport, "wg-0", "refused", "transport");
        assert!(masked_failure_line(&plain).contains("hop=wg-0"));
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

    #[test]
    fn denylist_covers_pem_headers() {
        // Review pin (#13): every PEM private-key header the provider or a
        // config could echo is caught even under an innocuous key.
        for marker in [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "payload PRIVATE KEY----- tail",
        ] {
            assert_eq!(
                redact_value("blob", marker),
                Redaction::Redacted,
                "{marker}"
            );
        }
    }

    #[test]
    fn drop_threshold_boundary_pins_44() {
        // Review pin (#13): thresholds stay put — a 43-char random-looking
        // value under an innocuous key redacts in place, while 44 chars
        // (one WireGuard key) drops the whole record fail-closed. A
        // threshold tweak must update this test deliberately.
        let v44 = ECHO_44;
        let v43 = &ECHO_44[..43];
        assert!(drops_record("mystery", v44), "44 must drop");
        assert!(!drops_record("mystery", v43), "43 must not drop");
        assert_eq!(redact_value("mystery", v43), Redaction::Redacted);
    }

    #[test]
    fn license_type_labels_are_not_typed_secrets() {
        // Review verdict (#13): `license` stays OUT of SECRET_KEYS. License
        // *keys* are high-entropy (caught by the entropy layer); license
        // *labels* (`free`, `plus`) are actionable triage text and must not
        // be masked. Typed-secret status would over-redact them.
        assert_eq!(
            redact_value("license", "plus"),
            Redaction::Keep("plus".into())
        );
        assert_eq!(redact_value("license", ECHO_44), Redaction::Redacted);
    }

    #[test]
    fn hyphenated_uuid_tokens_are_secret() {
        // Cloudflare device IDs are hyphenated UUIDs: the separators break
        // the all-hex rule and the dashes drag entropy under the random
        // bar, so a 36-char UUID used to pass every sink raw.
        const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(redact_value("mystery", UUID), Redaction::Redacted);
        let prose = format!("device {UUID} refused");
        let masked = masked_value("cause", &prose);
        assert!(!masked.contains(UUID), "uuid leaked: {masked}");
        assert!(masked.contains("<redacted>"), "nothing masked: {masked}");
        assert!(masked.contains("refused"), "context lost: {masked}");
        // The failure sink is the one the leak was reported through.
        use qcore_transport_api::{FailureLayer, FailureReport};
        let f = FailureReport::new(
            FailureLayer::Transport,
            "wg-0",
            format!("boom device {UUID}"),
            "transport",
        );
        let line = masked_failure_line(&f);
        assert!(!line.contains(UUID), "uuid leaked through the sink: {line}");
        // The rule is UUID-shaped, not "anything with separators": a
        // full-form IPv6 endpoint stays actionable triage text.
        const V6: &str = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        assert_eq!(
            redact_value("endpoint", V6),
            Redaction::Keep(V6.to_string())
        );
    }

    #[test]
    fn uuid_with_port_suffix_is_masked_in_place() {
        // A port glued to a UUID changes the token's group count, so the
        // whole-token shape check misses it. The UUID body must still be
        // masked, with the port and surrounding prose kept for triage.
        const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
        let detail = format!("device {UUID}:443 refused");
        let masked = masked_value("cause", &detail);
        assert!(!masked.contains(UUID), "uuid leaked: {masked}");
        assert_eq!(masked, "device <redacted>:443 refused");
    }

    #[test]
    fn uuid_glued_to_prefix_and_suffix_is_masked_in_place() {
        // `id=` and the comma glue to the UUID, so the token is not exactly
        // UUID-shaped. Only the UUID body may disappear; the decoration is
        // actionable context.
        const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
        let detail = format!("id={UUID}, retry 2");
        let masked = masked_value("cause", &detail);
        assert!(!masked.contains(UUID), "uuid leaked: {masked}");
        assert_eq!(masked, "id=<redacted>, retry 2");
        // Quotes are another non-hex boundary: the UUID body goes, the
        // quotes and the surrounding prose stay.
        let quoted = format!("\"{UUID}\" refused");
        assert_eq!(masked_value("cause", &quoted), "\"<redacted>\" refused");
    }

    #[test]
    fn uuid_shape_anchor_ignores_hyphenated_non_uuids() {
        // The 8-4-4-4-12 shape is the precision anchor: MAC chains, padding
        // runs and near-miss group counts stay actionable triage text.
        for value in [
            "00-11-22-33-44-55",
            "0000-0000-0000-0000-0000-0000",
            "01234567-89ab-cdef-0123-456789ab",
        ] {
            assert_eq!(
                redact_value("endpoint", value),
                Redaction::Keep(value.to_string()),
                "{value}"
            );
        }
    }

    #[test]
    fn long_hex_tokens_are_secret_despite_low_entropy() {
        // Hex tops out at 4 bits/char, below the entropy bar: a 32-char hex
        // token (device ID, license key) must still redact under an innocuous
        // key, and mask in place inside prose.
        const HEX_32: &str = "0123456789abcdef0123456789abcdef";
        assert_eq!(redact_value("mystery", HEX_32), Redaction::Redacted);
        assert_eq!(
            redact_value("mystery", &HEX_32[..31]),
            Redaction::Keep(HEX_32[..31].to_string())
        );
        let prose = format!("id {} ok", HEX_32);
        let masked = masked_value("cause", &prose);
        assert!(!masked.contains(HEX_32), "hex leaked: {masked}");
        assert!(masked.contains("<redacted>"), "nothing masked: {masked}");
    }

    #[test]
    fn multi_word_prose_is_not_whole_value_entropy_redacted() {
        // FR-021 rejection text is multi-word diagnostic prose whose aggregate
        // entropy can clear the random-looking bar. Whole-value entropy must
        // not turn a shipped profile name into a redacted sentence: the
        // tokens carry no secret, and the operator needs the field/mode.
        let msg = "obfuscation profile awg-balanced excludes mode wireguard peer=warp (FR-021)";
        assert_eq!(redact_value("cause", msg), Redaction::Keep(msg.into()));
        assert_eq!(masked_value("cause", msg), msg);
        // The family variant names the family and the hop kind.
        let family =
            "obfuscation profile awg-balanced (family awg) does not apply to a masque hop (FR-021)";
        assert_eq!(masked_value("cause", family), family);
    }

    #[test]
    fn prose_with_embedded_hex_masks_token_keeps_sentence() {
        // Multi-word prose is diagnostic text: the token scan masks the
        // secret-like token in place and the surrounding sentence survives.
        const HEX_32: &str = "0123456789abcdef0123456789abcdef";
        let prose = format!("device {HEX_32} refused");
        assert_eq!(
            redact_value("cause", &prose),
            Redaction::Keep("device <redacted> refused".into())
        );
        // A single-token high-entropy blob still redacts whole: the
        // fail-closed path for a lone secret is unchanged.
        assert_eq!(redact_value("cause", ECHO_44), Redaction::Redacted);
    }

    #[test]
    fn decorated_non_hyphenated_ids_are_masked_in_place() {
        // A bare 32-hex device id glued to a prefix: the whole token is not
        // all-hex, so only a subrange scan can catch it.
        let glued = "id=deadbeefdeadbeefdeadbeefdeadbeef refused";
        assert_eq!(masked_value("cause", glued), "id=<redacted> refused");
        // UUID shape split on `_`, the other separator `is_uuid_token`
        // accepts.
        let underscored = "id=550e8400_e29b_41d4_a716_446655440000 refused";
        assert_eq!(masked_value("cause", underscored), "id=<redacted> refused");
        // Colon-separated shape is the same rule.
        let colon = "id=550e8400:e29b:41d4:a716:446655440000 refused";
        assert_eq!(masked_value("cause", colon), "id=<redacted> refused");
    }
}
