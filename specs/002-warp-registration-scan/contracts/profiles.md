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

Split storage (FR-002/FR-012): the TOML record holds non-secret fields
only; secrets live in the OS keyring (0600 file fallback) under a
per-profile service namespace and are never written beside the record.
Field names below are contractual — values shown are shapes, never real
secrets:

```toml
device_id = "<opaque id>"
peer_key_b64 = "<provider public key, base64>"
interface_v4 = "<addr>"; interface_v6 = "<addr>"
refused = false
license_upgraded = false
[masque]  # present after enrollment
cert_pem = "<self-issued certificate PEM, public>"
issued_at_ms = 0  # rotation math anchor
lifetime_days = 365
renew_before_days = 7
```

Secrets (not in this file — keyring/file store only): `access_token`,
`private_key_b64` (X25519 device key, base64), MASQUE `key_pem`.

Corrupt, partial, or secret-missing files read as missing (re-register,
never crash). Record writes are atomic (temp + rename, 0600) behind a
per-role lock file, so concurrent registrations resolve to exactly one
winner.
