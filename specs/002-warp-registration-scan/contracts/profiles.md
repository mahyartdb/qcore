# Contract: Profiles & Identity Records (002)

## `profiles/warp.toml` (shipped defaults, replaceable per FR-028)

```toml
# Built-in endpoint candidates: provider address ranges used only to
# *find* a working endpoint by measurement. Operators may replace this
# file wholesale; the scanner validates shape, never content provenance.
[warp]
ranges = ["<provider-ipv4-range>", "..."]
seeds = ["<ip>", "..."]
ports = [2408, "..."]          # tried in listed order
v6_ranges = ["<provider-ipv6-range>"]
v6_seeds = ["<ip>"]

[masque]
ranges = ["<provider-ipv4-range>"]
seeds = ["<ip>"]
ports = [443, 500, 1701, 4500, 4443, 8443, 8095]
v6_ranges = ["<provider-ipv6-range>"]

[defaults]
scan_profile = "balanced"      # used when the user picks none
```

Shape errors fail closed naming the file and field; missing file falls
back to compiled-in defaults identical in shape.

## Identity record (`identity-warp.toml`, `identity-warp-inner.toml`)

TOML, user-readable-only, atomic write. Field names only — values shown
are shapes, never real secrets:

```toml
device_id = "<opaque id>"
access_token = "<secret: redacted everywhere>"
private_key = "<secret: X25519, redacted everywhere>"
peer_key = "<provider public key>"
interface_v4 = "<addr>"; interface_v6 = "<addr>"
refused = false
license_upgraded = false
[masque]  # present after enrollment
cert_issued_at = 0  # rotation math anchor
```

Corrupt or partial file reads as missing (re-register, never crash).
