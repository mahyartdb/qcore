// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// AmneziaWG wire transforms (qcore vendoring patch; QCORE_PATCHES.md records
// every deviation). Mirrors amneziawg-go v3 (`device/noise-protocol.go`,
// `device/send.go`, `device/receive.go`):
//
//   * S1..S4 random bytes are prepended to each handshake/cookie/transport
//     message. MAC1/MAC2 cover the message alone, then the whole message
//     (MACs included) is XORed with a ChaCha20 keystream nonced by the first
//     12 prefix bytes (`HeaderProtectionCipher`). The transport header is
//     protected over its 16-byte header only; its ciphertext is AEAD.
//   * H1..H4 replace the little-endian uint32 message type of
//     initiation/response/cookie/transport. Zero keeps the stock value.
//   * Handshake trailers pad up to `DefaultUdpWindow` (500) bytes. Transport
//     padding is zeroes inside the AEAD, so the IP length trims it.
//
// Junk trains (`Jc`/`Jmin`/`Jmax`) and signature packets (I1..I5) are
// separate datagrams and stay in the transport crate, which owns uplink
// scheduling.
//
// Every helper is a no-op for `AwgParams::default()`, so an unconfigured
// `Tunn` emits and parses stock WireGuard unchanged.

use super::{COOKIE_REPLY_SZ, DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use rand_core::{OsRng, RngCore};
use std::convert::TryInto;

/// `HeaderProtectionKey` length (amneziawg-go `HeaderCipherKeySize`).
pub const HEADER_PROTECTION_KEY_LEN: usize = 32;
/// Header-protection nonce: first bytes of the S1..S4 crypto padding.
pub const HEADER_PROTECTION_NONCE_LEN: usize = 12;
/// `MessageTransportHeaderSize`: type + receiver index + counter.
const TRANSPORT_HEADER_SZ: usize = 16;

/// amneziawg-go `DefaultUdpWindow`; bounds random handshake trailers.
pub(super) const UDP_WINDOW: usize = 500;
const MAX_PADDING: u32 = 65535;

/// Message families whose header and padding are transformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Initiation,
    Response,
    Cookie,
    Transport,
}

impl Kind {
    /// Stock WireGuard message type this family parses as.
    pub(super) fn canonical(self) -> u32 {
        match self {
            Kind::Initiation => super::HANDSHAKE_INIT,
            Kind::Response => super::HANDSHAKE_RESP,
            Kind::Cookie => super::COOKIE_REPLY,
            Kind::Transport => super::DATA,
        }
    }

    fn wire_len(self) -> usize {
        match self {
            Kind::Initiation => HANDSHAKE_INIT_SZ,
            Kind::Response => HANDSHAKE_RESP_SZ,
            Kind::Cookie => COOKIE_REPLY_SZ,
            Kind::Transport => DATA_OVERHEAD_SZ,
        }
    }
}

/// Validated AmneziaWG transform parameters. The transport crate owns
/// parsing and user-facing validation; this type carries checked values and
/// [`AwgParams::validate`] re-asserts the invariants the wire format needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AwgParams {
    pub s1: u32,
    pub s2: u32,
    pub s3: u32,
    pub s4: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
    /// `None` disables header protection; S1..S4 must then not be relied on
    /// as a key salt.
    pub header_protection_key: Option<[u8; HEADER_PROTECTION_KEY_LEN]>,
    pub content_padding_min: u32,
    pub content_padding_max: u32,
    pub random_trailers: bool,
    /// amneziawg-go `disable_cookies`: skip MAC2 verification and cookie
    /// replies even while under load.
    pub disable_cookies: bool,
}

impl AwgParams {
    /// Reject parameter sets that cannot be applied safely, so a directly
    /// constructed set can never emit unprotected or ambiguous headers.
    pub(super) fn validate(&self) -> bool {
        if self.s1 > MAX_PADDING
            || self.s2 > MAX_PADDING
            || self.s3 > MAX_PADDING
            || self.s4 > MAX_PADDING
        {
            return false;
        }
        if self.content_padding_min > MAX_PADDING || self.content_padding_max > MAX_PADDING {
            return false;
        }
        if self.content_padding_min > self.content_padding_max {
            return false;
        }
        let headers = [self.h1, self.h2, self.h3, self.h4];
        let present: Vec<u32> = headers.iter().copied().filter(|h| *h != 0).collect();
        let mut unique = present.clone();
        unique.sort_unstable();
        unique.dedup();
        if unique.len() != present.len() {
            return false;
        }
        if self.header_protection_key.is_some() {
            let min = HEADER_PROTECTION_NONCE_LEN as u32;
            if self.s1 < min || self.s2 < min || self.s3 < min || self.s4 < min {
                return false;
            }
        }
        true
    }

    /// Wire type value for a message family (`H1`..`H4`, 0 = stock).
    pub(super) fn message_type(&self, kind: Kind) -> u32 {
        let configured = match kind {
            Kind::Initiation => self.h1,
            Kind::Response => self.h2,
            Kind::Cookie => self.h3,
            Kind::Transport => self.h4,
        };
        if configured == 0 {
            kind.canonical()
        } else {
            configured
        }
    }

    pub(super) fn prefix_len(&self, kind: Kind) -> usize {
        match kind {
            Kind::Initiation => self.s1 as usize,
            Kind::Response => self.s2 as usize,
            Kind::Cookie => self.s3 as usize,
            Kind::Transport => self.s4 as usize,
        }
    }

    /// Fill the crypto padding with random bytes.
    pub(super) fn fill_prefix(&self, prefix: &mut [u8]) {
        OsRng.fill_bytes(prefix);
    }

    /// ChaCha20 XOR over the message keyed by the prefix (header
    /// protection). The prefix-length invariant is enforced by
    /// [`AwgParams::validate`].
    pub(super) fn protect(&self, prefix: &[u8], msg: &mut [u8]) {
        let key = match self.header_protection_key {
            Some(key) => key,
            None => return,
        };
        debug_assert!(prefix.len() >= HEADER_PROTECTION_NONCE_LEN);
        header_cipher(&key, prefix).apply_keystream(msg);
    }

    /// Zero padding appended to the plaintext before AEAD, in bytes.
    pub(super) fn content_padding(&self) -> usize {
        let lo = self.content_padding_min as usize;
        let hi = (self.content_padding_max as usize).max(lo);
        if hi == 0 {
            return 0;
        }
        lo + random_below(hi - lo + 1)
    }

    /// Append `rand(UDP_WINDOW - msg_end)` random bytes; returns the new end.
    pub(super) fn append_trailer(&self, dst: &mut [u8], msg_end: usize) -> usize {
        if !self.random_trailers || dst.len() <= msg_end {
            return msg_end;
        }
        let bound = UDP_WINDOW.saturating_sub(msg_end).min(dst.len() - msg_end);
        let len = random_below(bound);
        OsRng.fill_bytes(&mut dst[msg_end..msg_end + len]);
        msg_end + len
    }
}

fn header_cipher(key: &[u8; HEADER_PROTECTION_KEY_LEN], salt: &[u8]) -> ChaCha20 {
    let mut k = Key::default();
    k.copy_from_slice(key);
    let mut nonce = Nonce::default();
    nonce.copy_from_slice(&salt[..HEADER_PROTECTION_NONCE_LEN]);
    ChaCha20::new(&k, &nonce)
}

fn random_below(bound: usize) -> usize {
    if bound == 0 {
        0
    } else {
        (OsRng.next_u32() as usize) % bound
    }
}

/// Apply header protection to a finished message.
pub(super) fn finish_message(params: &AwgParams, prefix: &[u8], msg: &mut [u8]) {
    params.protect(prefix, msg);
}

/// Append a random handshake trailer; returns the packet end offset.
pub(super) fn finish_packet(params: &AwgParams, dst: &mut [u8], msg_end: usize) -> usize {
    params.append_trailer(dst, msg_end)
}

/// Inbound inverse transform. Deobfuscates the header in place and returns
/// the message family, its offset, and (for fixed-size messages) its exact
/// length so trailers can be ignored. `None` means "not an AWG packet this
/// peer can parse" (junk, wrong parameters, truncated, bad length).
pub(super) fn deobfuscate_incoming(
    datagram: &mut [u8],
    params: &AwgParams,
) -> Option<(Kind, usize, Option<usize>)> {
    let keystream_type = params.header_protection_key.map(|key| {
        if datagram.len() < HEADER_PROTECTION_NONCE_LEN {
            return None;
        }
        let mut ks = [0u8; 4];
        header_cipher(&key, datagram).apply_keystream(&mut ks);
        Some(ks)
    });
    if matches!(keystream_type, Some(None)) {
        return None;
    }

    // Probe order matches amneziawg-go `DeterminePacketTypeAndPadding`.
    for kind in [
        Kind::Initiation,
        Kind::Response,
        Kind::Cookie,
        Kind::Transport,
    ] {
        let offset = params.prefix_len(kind);
        let msg_len = kind.wire_len();
        let size = datagram.len();
        let expected = offset + msg_len;
        // Handshake sizes are exact unless random trailers are negotiated;
        // transport messages only have a minimum.
        let size_ok = match kind {
            Kind::Transport => size >= expected,
            _ => size == expected || (params.random_trailers && size > expected),
        };
        if !size_ok {
            continue;
        }
        let wire = u32::from_le_bytes(datagram[offset..offset + 4].try_into().ok()?);
        let plain = match &keystream_type {
            Some(Some(ks)) => wire ^ u32::from_le_bytes(*ks),
            _ => wire,
        };
        if plain != params.message_type(kind) {
            continue;
        }
        if let Some(key) = params.header_protection_key {
            let span = match kind {
                Kind::Transport => TRANSPORT_HEADER_SZ,
                _ => msg_len,
            };
            header_cipher(&key, datagram).apply_keystream(&mut datagram[offset..offset + span]);
        }
        let exact = match kind {
            Kind::Transport => None,
            _ => Some(msg_len),
        };
        return Some((kind, offset, exact));
    }
    None
}
