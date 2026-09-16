# Contract: Config Formats

Three data formats. All profiles are **data, not code** (FR-018, Principle V).

## 1. Chain declaration

TOML (preferred) or a compact CLI expression.

```toml
[chain]
max_depth = 3            # hops after preset expansion; default 3 (FR-010a)

[[chain.hop]]
kind = "tor"
id   = "tor0"

[[chain.hop]]
kind = "wireguard"
id   = "wg0"
peer = "warp"
family = "dual"

[[chain.hop]]
kind = "psiphon"
id   = "psiphon0"
sidecar_path = "/usr/local/bin/psiphon"
# last hop = exit; effective public path (FR-011)
```

CLI expression equivalent: `--chain tor,wireguard peer=warp,psiphon` where the last
hop is the exit.

Ordering semantics: hop *n+1* dials through hop *n*'s egress. The **last** hop is
the exit whose traffic leaves the device network (FR-011). Either order of any pair
is expressible by reordering entries (FR-008).

Composition presets expand before validation:

```toml
[compositions.gool]     hops = [{ kind = "wireguard", peer = "warp" }, { kind = "wireguard", peer = "warp" }]
[compositions.mim]      hops = [{ kind = "masque", alpn = "h3" }, { kind = "masque", alpn = "h3" }]
[compositions.tor-warp] hops = [{ kind = "tor" }, { kind = "relay" }, { kind = "wireguard", peer = "warp" }]
```

Presets expand exactly one level (FR-007a). `gool` at depth budget 3 leaves room for
one more hop; `gool,gool` = 4 => rejected. Depth is plain hop counting after
expansion, owned solely by the validator.

The `relay` adapter provides UDP-over-TCP framing. A bare
`tor,wireguard peer=warp` chain is rejected with the insertion named; `tor-warp`
already includes the relay, so Tor-first is valid.

## 2. Scan profile

```toml
name = "balanced"
concurrency = 32
rtt_budget_ms = 400
probe_kind = "data-plane"     # or "handshake"
family_order = ["ipv4", "ipv6"]
stealth = false
```

Shipped set: `turbo`, `balanced` (default), `stealth`.

## 3. Obfuscation profile

noize family (applies to wireguard and masque modes):

```toml
name = "masque-balanced"
family = "noize"
compatible_modes = [
  { kind = "masque", alpn = "h3" },
  { kind = "wireguard", peer = "warp" },
]
params = { junk_before = 1, junk_size = [32, 96], i1 = "crlf,ts,r16" }
```

AmneziaWG family (applies to the `wireguard` `peer=awg` mode only, against a
supporting peer):

```toml
name = "awg-balanced"
family = "awg"
compatible_modes = [{ kind = "wireguard", peer = "awg" }]
params = { header_protection = true, s1 = [16,32], jc = 6,
           jmin = 64, jmax = 256, i1 = "quic", content_padding = [0,96],
           random_trailers = true, disable_cookies = true }
```

Shipped set: `masque-balanced` (default), `awg-balanced` (default for `peer=awg`),
`awg-off`.

Compatibility rule: selecting a profile whose `compatible_modes` excludes the hop's
mode MUST be rejected (FR-021). AmneziaWG server-negotiated fields MUST NOT be
applied to plain `wireguard`/WARP.

## 4. Imported WireGuard / AmneziaWG config

Standard INI. Import preserves every recognized field and rejects unknown fields by
name (FR-023). Export reproduces values equivalently (FR-024):

```ini
[Interface]
PrivateKey = <redacted in all output>
Address = 10.0.0.2/32, fd00::2/128   # dual-stack preserved (Principle II)
Jc = 6
S1 = 24
H1 = 1234567

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = host:port
```

Rules: absent AWG keys => standard WireGuard behavior; `H1..H4` non-overlapping;
`HeaderProtectionKey`/`S*`/`H*` only against a supporting peer; private keys never
logged/exported in plaintext (FR-026).