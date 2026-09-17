# Contract: CLI (002 additions)

Extends the 001 CLI contract. All commands honor global `--json` (exactly
one JSON document on stdout) and `--config/--profile-dir` overrides.

## `qcore register [--license-key KEY | --license-file PATH] [--gool]`

Provisions identity/identities. `--gool` provisions the outer+inner pair.
License key optional per operation (flag prints a stderr visibility
warning; prompt used when a TTY is present and no flag/file given).
Each provisioned role also enrolls its MASQUE credential best-effort:
enrollment failure appends "; MASQUE enrollment deferred (...)" to the
cause and keeps exit 0 (the WARP identity is good).

- Exit 0: `RegistrationReport` with `action: registered`.
- Exit 2: `action: blocked|refused` with `cause` (blocked vs refused
  distinguished).
- `--gool` emits one document `{"outer": <report>, "inner": <report>}`;
  exit 0 only when both roles succeed, else exit 2.
- License prompt reads one terminal line (echoes; scripts and the cautious
  use `--license-file`); `--non-interactive` never prompts.

## `qcore renew [--masque-only] [--hop outer|inner|both]`

Refresh-in-place when accepted, fresh re-registration on refusal signals
only (never on timeouts/silence/empty scan). Reports `reused` when a
healthy identity needed nothing. Failed midway: previous identity intact.
`--hop both` (default) renews every stored identity; explicit
`--hop inner` with nothing stored is exit 2.

## `qcore scan --transport warp|masque [--profile turbo|balanced|stealth]`

Existing scan command with seeded candidates (FR-014 defaults when the
user supplies none). Cache winner re-verified first; empty result stays
exit 4 with no silent fallback.

## `connect` integration (no new flags)

- No stored identity → auto-register inline, then connect (FR-003).
- Refusal signals mid-connect → auto re-register once, then retry
  (FR-004); other failures keep identity, rescan/retry.
- MASQUE credential in rotation window → auto-rotate inline (FR-005).
- Inline events print one stderr notice line (`qcore: ...`); fatal
  identity failures exit 2 with the cause (and the report under `--json`).
- At start, stored identities and cached endpoints merge into warp/masque
  hops in memory (explicit chain values always win): a WARP hop needs a
  stored identity (`register` first) plus an endpoint — its own
  `endpoint=`, else the newest family-matching cached winner, else exit 2
  naming `scan`. A MASQUE hop needs a cached endpoint the same way
  (its credential is account-level and rides enrollment, not the hop).
- WARP endpoints are UDP and cannot be TCP-probed: live warp scans find
  nothing (exit 4, correctly). Until UDP handshake probing exists, supply
  warp endpoints explicitly (`endpoint=162.159.192.1:2408`) or rely on a
  previously cached winner; MASQUE `:443` endpoints scan normally.

## RegistrationReport JSON (all register/renew outcomes)

```json
{"action": "registered|reused|refreshed|re_registered|rotated|refused|blocked",
 "identity": "<device_id|null>", "endpoint": "<ip:port|null>",
 "cause": "<actionable, redacted>", "license_applied": false}
```

No field ever carries a private key, token, or license value.

`--provider <url>` is a test-only override pointing at fixture doubles;
it is never part of the stable surface.
