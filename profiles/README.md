# profiles/ — scan / obfuscation / composition data (FR-018, Principle V)

Profiles are **data, not code**. Layout (files land with their stories):

- `scan.toml` — exactly `turbo`, `balanced` (default), `stealth` (US4)
- `obfuscation.toml` — noize + awg families with `compatible_modes` (US5)
- `compositions.toml` — `gool`, `mim`, `tor-warp` presets (US3)

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

### `scan.toml` `[discovery.<transport>]` keys

One table per transport (e.g. `[discovery.warp]`); empty by default —
discovery providers plug in here. Legal keys:

- `seeds` — list of socket addresses (`host:port`), tried in full;
  capped by the scanner; malformed entries fail closed naming the field.

Ranged candidate sampling (`ranges`/`ports`/`v6_*`) lives in `warp.toml`,
not in `scan.toml` discovery tables.
