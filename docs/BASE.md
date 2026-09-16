# Base: fork of CluvexStudio/Aether (FR-002)

`qcore` is a fork of [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether) (Rust).
Retained and built on from the base:

- WireGuard transport (data plane reimplemented over `boringtun`)
- MASQUE transports over HTTP/3 and HTTP/2 (single QUIC provider per research R4)
- Tor transport via `arti-client`
- Endpoint scanner and scan profiles
- noize obfuscation profiles

Aether's hardcoded GOOL/MIM/Tor ordering branches are replaced by the
`qcore-transport-api` plugin boundary: GOOL and MIM survive as composition
presets (`gool` = two `wireguard peer=warp` hops, `mim` = two `masque alpn=h3`
hops), not as transports. See `specs/001-multi-protocol-vpn/plan.md`.
