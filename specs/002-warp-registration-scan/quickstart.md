# Quickstart: WARP Registration & Endpoint Scan

Validation guide. Gating run is **offline** against fixture doubles; live
provider runs are nightly-only, non-blocking (constitution II).

## Prerequisites

- Workspace builds (`cargo xtask build`); debug CLI suffices for gating.
- A scratch profile dir so the real one is untouched:
  `export QCORE_PROFILE=/tmp/qcore-002` (via `--profile-dir`).

## Gating run (offline, must pass)

```bash
# 1. Register against the fixture double (no network)
qcore register --provider http://127.0.0.1:9/fixture --json
# → {"action":"registered","identity":"<id>",...}, exit 0

# 2. Refusal classification: refused fixture re-registers, timeout fixture keeps identity
qcore renew --provider <refused-fixture> --json   # → action: re_registered
qcore renew --provider <timeout-fixture> --json   # → identity kept, rescan path

# 3. Seeded scan over loopback candidates
qcore scan --transport warp --profile balanced --json
# → ranked list with latency figures, winner cached

# 4. Empty scan stays exit 4 (no silent fallback)
qcore scan --transport warp --profile balanced --family ipv6 --json  # exit 4

# 5. License key never leaks (flag form warns, nothing echoes)
qcore register --license-key DUMMY --json 2>stderr.log
# → stderr has exactly the visibility warning; key in no output file

# 6. Full gate
cargo xtask ci
```

Expected: all exits as noted; secret-hygiene suite extended to the new
artifacts passes; clippy/fmt clean.

## Nightly live run (supplementary)

```bash
qcore register --json                 # SC-001 < 60 s, unblocked net
qcore scan --transport warp --json    # SC-002 ranked + latency
qcore up --chain "wireguard peer=warp" --json   # SC-003 carries traffic
qcore up --chain "gool" --json        # outer+inner identities
qcore connect --chain "masque alpn=h3" --json   # SC-006 (then alpn=h2)
```

Live failures from blocked networks are reported (blocked vs refused),
never retried as renewals.
