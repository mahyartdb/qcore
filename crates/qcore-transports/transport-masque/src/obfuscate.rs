//! Noize application for MASQUE (US5 T070).
//!
//! Per-path rules (profiles are data in `profiles/obfuscation.toml`, this
//! code only applies them):
//! - H2 over TCP: never a junk train (random bytes before the client preface
//!   break the handshake). Noize here is H2 byte-stream fragmentation —
//!   writes chunk at the profile `fragment` size — plus reporting.
//! - H2 datagrams are atomic messages and are never fragmented.
//! - H3 over QUIC: quinn owns the UDP socket, so a pre-handshake junk train
//!   is not injectable in US5; the profile is validated, carried, and
//!   reported, and QUIC's inherent properties apply. Explicit follow-up,
//!   never silently claimed.

use qcore_transport_api::{HopConfig, HopError};

/// Fragment size for H2 byte-stream writes, if a noize profile is active.
/// Strict: malformed `noize_*` fields fail closed naming the field (matching
/// the wireguard parse), never silently disable obfuscation.
pub fn fragment_size(cfg: &HopConfig) -> Result<Option<usize>, HopError> {
    let hop_id = cfg.get("hop_id").unwrap_or("masque-0");
    qcore_transport_api::obfuscate::NoizeParams::try_from_fields(&cfg.fields)
        .map_err(|e| {
            qcore_transport_api::HopError::new(
                qcore_transport_api::HopErrorKind::Config,
                Some(hop_id.to_string()),
                format!("masque noize profile: {e}"),
            )
        })
        .map(|n| n.and_then(|n| n.fragment))
}

/// Chunk length for one `send_data`: at most the fragment size.
pub fn chunk_for_send(wanted: usize, fragment: Option<usize>) -> usize {
    match fragment {
        Some(f) if f > 0 => wanted.min(f),
        _ => wanted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_respect_fragment() {
        assert_eq!(chunk_for_send(16384, Some(512)), 512);
        assert_eq!(chunk_for_send(100, Some(512)), 100);
        assert_eq!(chunk_for_send(16384, None), 16384);
    }

    #[test]
    fn malformed_noize_field_fails_closed_naming_field() {
        let mut cfg = HopConfig::new("masque");
        cfg.fields.insert("hop_id".into(), "masque-nz-0".into());
        cfg.fields.insert("noize_fragment".into(), "many".into());
        let err = fragment_size(&cfg).expect_err("malformed noize must fail closed");
        assert_eq!(err.kind, qcore_transport_api::HopErrorKind::Config);
        assert_eq!(err.hop_id.as_deref(), Some("masque-nz-0"));
        assert!(err.message.contains("noize_fragment"), "names field: {err}");
        assert!(
            err.message.contains("masque"),
            "names the build path: {err}"
        );
    }

    #[test]
    fn no_noize_fields_parse_none_without_error() {
        let cfg = HopConfig::new("masque");
        assert_eq!(fragment_size(&cfg).expect("absent profile"), None);
    }
}
