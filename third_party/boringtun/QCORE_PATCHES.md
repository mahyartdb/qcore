# qcore vendoring patch — boringtun 0.7.1 + AmneziaWG transforms

Provenance: crates.io `boringtun 0.7.1` (Cloudflare), BSD-3-Clause.
`LICENSE.md` is the upstream repository licence (the packaged crate omits it).
Version (`0.7.1`) and `license` field are unchanged, so the root
`[patch.crates-io]` is a drop-in replacement; `cargo tree -p
qcore-transport-wireguard -i boringtun` resolves to
`third_party/boringtun`.

Upstream provenance pins (recheck with `sha256sum` on the downloaded `.crate`
and `git rev-parse` in a checkout of the 0.7.1 tag):

- crates.io `boringtun-0.7.1.crate` sha256:
  `15dd6a8a89cbe8997f37ca0cf035e6ea4d64cd2ecea4aed83ffb9f99f7126939`
- upstream git commit: `051c9d47dc9c5cb36e461b7d36dcd673820dc98b`

This file records every deviation from upstream. The vendored copy is a
carrier for AmneziaWG wire transforms; nothing else is changed unless listed
here.

## Removed upstream surface

- `src/device/` (TUN device, Linux/macOS backends, privileged drop,
  integration tests) and the dependencies only it used: `socket2`,
  `thiserror`, `ip_network`, `ip_network_table`, `libc` and `hex`.
  `nix` is **retained** — `src/sleepyinstant/unix.rs` calls
  `nix::time::clock_gettime` on every unix target, so the earlier list that
  named `nix` as a removed device dependency was wrong and is corrected here.
- The `untrusted` dependency (upstream's device/serialization helper) went
  with the modules that used it. `hex` and `untrusted` are therefore absent
  from the vendored `Cargo.toml`.
- `src/ffi/`, `src/jni.rs`, `src/wireguard_ffi.h` and the
  `ffi-bindings`/`jni-bindings` features. qcore embeds the Rust API only.
- `src/serialization.rs` and the `base64` dependency: only the removed
  device/ffi code parsed key strings through it.
- The `boringtun-cli` binary, `benches/`, examples and integration tests, plus
  the `Benches`/`lib` crate types. Only the `rlib` is built.
- Upstream dev-dependencies `tracing-subscriber` and `criterion`
  (benchmark/logging only); `etherparse` is the sole remaining dev-dependency.
- Upstream `README.md`: it advertised the `boringtun-cli` binary, FFI/JNI
  bindings and privileged TUN setup that this copy does not build. Replaced
  with a short vendored-copy note pointing at upstream and at this file.
- The remaining `Cargo.toml` keeps upstream's edition (2018) and version; the
  dependency set is the pruned list above, not upstream's full list.
  `chacha20 = "0.9"` was **added** for header protection.

## Lint policy

`src/lib.rs` carries `#![allow(deprecated)]` (ring's constant-time helper is
deprecated upstream) and `#![allow(clippy::all)]`. Upstream code is not
clippy-clean under qcore's `-D warnings` gate; the allow keeps the diff to
the AWG work instead of a wholesale rewrite. `cargo clippy -p boringtun
--all-targets -- -D warnings` therefore passes, but the vendored crate is
exempt from qcore's lint expectations by design.

## New module: `src/noise/awg.rs`

Canonical semantics follow `amneziawg-vpn/amneziawg-go` (`device/send.go`,
`device/receive.go`, `device/noise-protocol.go`, `device/device.go`):

- `S1..S4` random bytes are prepended to initiation, response, cookie reply
  and transport messages respectively. MACs cover the message without the
  prefix.
- `H1..H4` are the little-endian `uint32` **message-type values** for
  initiation/response/cookie/transport. `0` keeps the stock type (1/2/3/4).
  (The task text described these as reserved/sender/receiver fields; the
  upstream implementation substitutes the type field, and that is what is
  implemented. MAC1 is computed over the header containing the H value.)
- Header protection: the whole message (handshake MACs included) is XORed
  with a ChaCha20 keystream keyed by the 32-byte shared key, nonce = the
  first 12 bytes of the message's S-prefix. For transport packets only the
  16-byte header (type + receiver index + counter) is protected; the payload
  is authenticated ciphertext. Keyed protection requires every S* >= 12;
  `set_awg_params` rejects anything else.
- Handshake/cookie trailers: random bytes appended after the fixed message,
  bounded by `DefaultUdpWindow` (500 bytes), only when `random_trailers`.
- Transport content padding: random zero bytes appended to the plaintext
  before AEAD seal (`content_padding_min..=max`), clamped to the destination
  buffer. The receiver trims by the IP header length.

Inbound inverse (`deobfuscate_incoming`) mirrors
`DeterminePacketTypeAndPadding`: probe initiation, response, cookie,
transport; handshakes require `len == S + fixed_size` (or `> expected` when
trailers are negotiated), transport requires `len >= S4 + 32`; strip the
prefix, deobfuscate, and truncate handshakes to their fixed size so trailers
cannot reach the parser.

### All-zero plaintext is a keepalive

A content-padded keepalive decrypts to all zeroes. WireGuard has no valid IP
packet starting with version nibble 0, so `validate_decapsulated_packet`
returns `TunnResult::Done` for an all-zero payload. This rule is
unconditional (it also holds for stock WireGuard, where it can only fire on
an already-invalid packet).

## Public API changes

- `Tunn::set_awg_params(Option<awg::AwgParams>) -> Result<(), WireGuardError>`
  installs validated transforms; `Tunn::new` is unchanged.
- `WireGuardError::InvalidAwgConfig` reports rejected params.
- `Tunn::decapsulate` takes `datagram: &mut [u8]` instead of `&[u8]`.
  AmneziaWG deobfuscation rewrites the datagram in place before MAC1 is
  verified, and copying every inbound datagram would add an allocation on
  the hot path. qcore-transport-wireguard is the only consumer; its pump and
  test harness pass mutable receive buffers.
- Internal: `Handshake::set_awg`, `RateLimiter::set_awg`,
  `Tunn::parse_incoming_packet_as`, `RateLimiter::verify_packet_kind`.

## Wire-path changes

- `Handshake::format_handshake_initiation` / `format_handshake_response`:
  S1/S2 prefix, H1/H2 type, MAC1/MAC2 over the unprefixed message, then
  header protection, then an optional trailer. `None` keeps upstream bytes
  exactly.
- `Session::format_packet_data`: S4 prefix, H4 type, content padding inside
  AEAD, header protection over the 16-byte header.
- `RateLimiter::format_cookie_reply`: S3 prefix, H3 type, header protection,
  optional trailer.
- `RateLimiter::verify_packet_kind`: MAC1/MAC2 verification over the
  deobfuscated message; `disable_cookies` skips MAC2 and cookie replies even
  under load.
- `Tunn::decapsulate_message`: the cookie-reply scratch buffer is carved out
  of the caller's output buffer for handshake decapsulation, because an
  AmneziaWG cookie reply may exceed the stock 64 bytes (S3 + trailer). Data
  packets do not reserve that space.

## Deliberate differences from amneziawg-go

- `Jc`/`Jmin`/`Jmax` junk trains and `I1..I5` signature packets remain in
  `qcore-transport-wireguard` (`awg.rs::handshake_preamble`): they are
  separate datagrams and uplink policy, while `Tunn` returns one buffer per
  call. The vendored `AwgParams` carries only per-message transforms.
- `I1..I5` are literal printable-ASCII payloads (bounded, validated in the
  transport crate), not amneziawg-go's `<b>/<r>/<t>` signature-packet
  grammar. Exported AmneziaWG configs using that grammar are not interpreted
  beyond the literal string.
- Header protection is never derived from peer keys: the transport requires
  an explicit 32-byte `awg_header_protection_key`. qcore's current chain
  grammar and import mapping cannot carry that field, so a profile that
  requests `header_protection` fails closed at hop build naming
  `awg_header_protection_key`. The shipped `awg-balanced` and
  `awg-aggressive` profiles therefore ship with header protection off
  (S/H transforms, padding and trailers still apply); a hop that turns it
  back on without supplying the key is refused. This is a
  configuration-plumbing gap, not a wire-format gap.
- Timers, `PersistentKeepalive` and session rekey remain stock WireGuard
  values; AmneziaWG's optional randomised timer behaviour is not modelled.

## Tests added here

`noise::tests::awg_*` cover: initiation length and H1/HP wire type,
non-protected H type, handshake + bidirectional data round-trip with content
padding, mismatched H1 handshake failure, AWG vs plain WireGuard in both
directions, and random trailers. The stock WireGuard tests are unchanged and
still pass, which pins that `AwgParams::default()`/`None` is byte-identical.
