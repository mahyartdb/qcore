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

use qcore_transport_api::HopConfig;

/// Fragment size for H2 byte-stream writes, if a noize profile is active.
pub fn fragment_size(cfg: &HopConfig) -> Option<usize> {
    qcore_transport_api::obfuscate::NoizeParams::from_fields(&cfg.fields).and_then(|n| n.fragment)
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
}
