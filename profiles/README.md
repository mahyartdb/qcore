# profiles/ — scan / obfuscation / composition data (FR-018, Principle V)

Profiles are **data, not code**. Layout (files land with their stories):

- `scan.toml` — exactly `turbo`, `balanced` (default), `stealth` (US4)
- `obfuscation.toml` — noize + awg families with `compatible_modes` (US5)
- `compositions.toml` — `gool`, `mim`, `tor-warp` presets (US3)
- `routing.toml` — OPTIONAL, operator-authored (not shipped): ordered
  `proxy` / `direct` / `block` rules for proxy targets (see below)

`SCHEMA_VERSION` records the profile-schema version, bumped with a changelog
migration note on breaking change (FR-003f).

## Reference: shipped data files

Five data files ship here (plus `SCHEMA_VERSION`):

| File | Contents |
|------|----------|
| `scan.toml` | Scan profiles: `turbo`, `balanced` (default), `stealth` — concurrency, RTT budget, probe kind (`handshake` vs `data-plane`), family order, stealth flag. Also `[discovery.<transport>]` seed tables (see below). |
| `warp.toml` | Default WARP/MASQUE endpoint candidates per transport section (`[warp]`, `[masque]`): `ranges`, `seeds`, `ports`, `v6_ranges`, `v6_seeds`, plus `[defaults]` (`scan_profile = "balanced"`). Operators may replace wholesale via `--profile-dir`; secrets never live here. |
| `obfuscation.toml` | Obfuscation profiles (names below) with `family` (`noize` or `awg`), `compatible_modes`, and `params`. |
| `compositions.toml` | Presets `gool` (2× `wireguard peer=warp`), `mim` (2× `masque alpn=h3`), `tor-warp` (`tor`, `relay`, `wireguard peer=warp`). Must equal `builtin_presets()` (unit-pinned); a profile-dir override replaces builtins by design. |
| `SCHEMA_VERSION` | Profile-schema version stamp. |

### Legal obfuscation profile names (`-O` / `obfuscation=` values)

- `masque-balanced` (noize; masque h2/h3, wireguard warp/imported)
- `masque-aggressive` (noize; masque h2/h3, wireguard warp)
- `awg-balanced` (awg; wireguard `peer=awg` only)
- `awg-aggressive` (awg; wireguard `peer=awg` only)
- `awg-off` (awg; wireguard `peer=awg` only — protection/junk disabled)

A profile whose `compatible_modes` excludes the hop mode is rejected (FR-021).

### AmneziaWG wire behavior (`peer=awg`)

With `peer=awg`, every message is transformed by the vendored boringtun
(`third_party/boringtun`, deviations in `QCORE_PATCHES.md`). Field by field:

| Param | Wire effect |
|-------|-------------|
| `s1`..`s4` | Random prefix before initiation, response, cookie reply and transport packets; the receiver strips it. Also the ChaCha20 nonce source for header protection. |
| `h1`..`h4` | Replace the 4-byte message type of initiation/response/cookie/transport (`0` keeps the stock value). |
| `jc`, `jmin`, `jmax` | `jc` random-size datagrams (`jmin..=jmax` bytes) before the initiation, on direct uplinks only. |
| `i1`..`i5` | Literal ASCII datagrams sent before the junk train, on direct uplinks only. Upstream's `<b>/<r>/<t>` chain grammar is not modelled. |
| `header_protection` | ChaCha20 header protection (handshake MACs included; transport's 16-byte header only). Requires `awg_header_protection_key` (32 bytes, hex, shared with the peer) and `s1..s4 >= 12`; both fail closed at hop build naming the field. |
| `content_padding` | Random zero bytes inside the AEAD; the receiver trims to the IP length. Padded keepalives are accepted as keepalives. |
| `random_trailers` | Random trailing bytes on handshake/cookie datagrams, capped at 500 bytes total; the receiver trims to the fixed message size. |
| `disable_cookies` | MAC2 is not required and no cookie reply is sent under load. |

Honest limits:

- The shipped AWG profiles keep `header_protection = false`: the transform
  needs `awg_header_protection_key`, a per-peer shared secret that does not
  belong in profile data, and neither the chain grammar nor the `.conf`
  import mapping carries it yet. A hop that requests header protection
  without the key fails closed at hop build naming the field, so enabling it
  needs a config path for the key first. (A custom profile *could* put
  `header_protection_key` in `params` — the only path today — but profile
  data is not a secret store.)
- `i1`..`i5` are literal datagram payloads, not upstream's programmable
  signature-packet grammar.

### `scan.toml` `[discovery.<transport>]` keys

One table per transport (e.g. `[discovery.warp]`); empty by default —
discovery providers plug in here. Legal keys:

- `seeds` — list of socket addresses (`host:port`), tried in full;
  capped by the scanner; malformed entries fail closed naming the field.

Ranged candidate sampling (`ranges`/`ports`/`v6_*`) lives in `warp.toml`,
not in `scan.toml` discovery tables.

### Optional `routing.toml` (operator-authored, not shipped)

`<profile-dir>/routing.toml` decides where each SOCKS5/HTTP CONNECT (and UDP
ASSOCIATE) target goes. `connect --routing <path>` loads a different file;
an absent or empty file means every target proxies through the tunnel, the
historic behavior.

Rules are an ordered array and the **first match wins**. Each rule has a
`match` table (at least one field; present fields must all agree) and an
`action`:

```toml
# Host-network egress for an intranet suffix; everything else stays in the
# tunnel unless a later rule says otherwise.
[[rules]]
match = { domain = "intranet.example" }
action = "direct"

# SMB inside RFC1918 is refused before any egress.
[[rules]]
match = { cidr = "10.0.0.0/8", port = 445 }
action = "block"

# Port-only rules match any host.
[[rules]]
match = { port = 25 }
action = "block"
```

- `domain` is a DNS suffix matched on label boundaries, case-insensitively:
  `example.com` covers `example.com` and `a.example.com`, never
  `notexample.com`. Only the CONNECT target is consulted — the proxy does
  not sniff TLS/HTTP. Wildcards are rejected; a bare suffix already covers
  subdomains.
- `cidr` matches a literal target IP and, for a domain target, the address
  resolved through the tunnel resolver (never the OS resolver). Without a
  tunnel resolver such a target fails closed instead of guessing.
- `port` alone matches any host.
- `domain` and `cidr` are mutually exclusive in one rule (`10.0.0.0/8` is
  not a name), and unknown keys anywhere fail closed naming the rule and
  field — exit 6 from `connect`. A typo must not silently turn a block rule
  into a no-op.
- `direct` bypasses the tunnel: the destination sees the host's IP and the
  domain is resolved locally. That is the point of the rule, and the leak
  trade-off is documented in `contracts/cli.md` §4.
- `block` refuses before any dial (SOCKS `0x02`, HTTP `403`); UDP
  datagrams to a blocked destination are dropped.

An explicit `--routing` file must exist; only the profile-dir default may
be absent.
