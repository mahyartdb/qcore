# profiles/ — scan / obfuscation / composition data (FR-018, Principle V)

Profiles are **data, not code**. Layout (files land with their stories):

- `scan.toml` — exactly `turbo`, `balanced` (default), `stealth` (US4)
- `obfuscation.toml` — noize + awg families with `compatible_modes` (US5)
- `compositions.toml` — `gool`, `mim`, `tor-warp` presets (US3)

`SCHEMA_VERSION` records the profile-schema version, bumped with a changelog
migration note on breaking change (FR-003f).
