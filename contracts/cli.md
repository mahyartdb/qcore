# contracts/cli.md — qcore CLI contract (NORMATIVE)

**Status: normative.** This file is the single source the code cites
(`contracts/cli.md` is referenced from doc comments across `qcore-core`
and `qcore-cli` — grep for the exact count, it moves with edits; citations
also live in `tests/conformance`). The constants in `crates/qcore-core/src/session/report.rs`
(`EXIT_*`) and their re-exports in `crates/qcore-cli/src/exit.rs` implement
this contract; when this file and the code disagree, it is a bug in one of
them — fix it in the same change, never paper over it.

## 1. Streams

Exactly two output streams, with disjoint duties:

- **stdout = results.** With `--json`, exactly ONE JSON document, nothing
  else — no banners, no progress, no second document. A command that cannot
  honor the one-document rule must reject `--json` as a usage error (the
  precedent: `ls --json` exits 6).
- **stderr = diagnostics.** Human-readable, `qcore: <msg> (exit N)` for
  failure lines. Diagnostics never carry secrets: causes pass through the
  central `masked_value` / `masked_failure_line` redactors, and unclassifiable
  content degrades to a metadata-only fail-closed placeholder.

## 2. Exit codes

| Code | Constant (`exit.rs`) | Meaning | Emitted by |
|-----:|----------------------|---------|------------|
| 0 | `SUCCESS` | Success. | Every command on success. |
| 1 | — (not re-exported) | Session record exists but is dead (`state` = stopped/failed and the control process is observably gone). | `status`; `stop` converges instead of failing here. |
| 2 | `INVALID` | Invalid chain / invalid config content — validation failed BEFORE any hop started, zero sockets opened. Also: a provider-level registration outcome (`Refused`/`Blocked`) on `register`/`renew` — provider sockets may have been opened there. | `connect`, `preflight`, `register`, `renew` |
| 3 | `HOP_FAILURE` | A hop failed (transport / chain / sidecar / config build). Includes scan-pipeline errors. | `connect`, `scan`, `import` IO beyond the target file |
| 4 | `SCAN_EMPTY` | Scan found nothing reachable. In JSON mode the shape `{"ok":false,...,"candidates":[]}` goes to stdout; in table mode stdout stays silent and stderr carries `qcore: scan found nothing reachable (exit 4)`. Never a silent last-known-good fallback. | `scan` |
| 5 | `IMPORT_REJECTED` | Config import rejected: content problems name every offending field. A missing/unreadable target file is usage (6), not 5. | `import`, `export` |
| 6 | `USAGE` | Usage error: unknown command/kind, conflicting chain sources, out-of-range globals (`--max-depth`, `--timeout`), `--json` on a command that cannot honor it, missing required values under `--non-interactive`. Also: connect's pre-start proxy-bind failures — a malformed `--bind`/`--http-proxy` address, a non-loopback listener without `--expose-lan`, or a taken/unavailable port (no hop has started; §4). | any command |
| 10 | `NO_SESSION` | No session: no `session.json` record (fresh profile). | `status`, `stop` |
| 12 | `UNVERIFIABLE` | Fail closed: the state is not provably alive or dead. Present-but-unparseable `session.json`, unreadable record, control-channel timeout/EOF, or a live-looking record whose control answer cannot be parsed. Never a false green. | `status`, `stop` |

Mapping rules (enforced by `exit_code_for_failure` in
`crates/qcore-core/src/session/report.rs`):

- `FailureLayer::Validation` → 2; `Transport | Chain | Sidecar | Config` → 3;
  `Scan` → 4.
- Register/renew do not produce `FailureReport`s: the
  `RegistrationReport.exit_code()` mapping in
  `crates/qcore-core/src/identity/report.rs` sends `Refused`/`Blocked`
  provider outcomes to 2 (fail closed; the cause names the next step).
  These commands open provider HTTPS sockets by design, so the "zero
  sockets" wording of row 2 applies only to validation refusals.
- Exit 1 is deliberately outside the `EXIT_*` constant set: it is a status
  verdict (`SessionStatus::Dead`), not a failure layer.

## 3. `status` / `stop` semantics

`status` reads `session.json` + `control.json` and reports honestly:

- record absent → `not_running`, exit 10 (`qcore: no session (exit 10)`).
- record `state` = `stopped`/`failed` → `dead`, exit 1. The control channel
  is not consulted.
- record present, control answer refused (nothing listens) → `dead`, exit 1.
- record parse/IO error or control timeout/EOF → `unverifiable`, exit 12 —
  fail closed, never a false green, never a false "no session".
- control answers with a valid report → `live`, report on stdout, exit 0.

Degraded sessions (F2 auto-reconnect watchdog): while the watchdog rebuilds
after a hop failure, the session is honest about it. `session.json` reads
`state: "degraded"` and the live report carries the additive fields
`session_state: "degraded"` + `reconnects` (`<n>` successful rebuilds so
far); both serialize only while degraded — the Up-shape report JSON stays
byte-identical to the pre-F2 contract (absent fields = Up). Status still
exits 0 while degraded (the control channel answers), and the durable
`reconnects` counter survives into the terminal record on give-up (Failed
with a cause naming the attempts or the flap).

`stop`: a refused control connection converges the records (control.json
removed, session marked stopped) so a later `status` reports `dead` instead
of stale-up. An explicit `ERR bad token` reply also converges to exit 0 and
removes `control.json`, marking the record stopped: the listener proved it
is foreign (our session always holds the token), so the rendezvous is
stale, not unverifiable. Any error that proves nothing (timeout,
connection failure, malformed reply) is exit 12 with `control.json` left
intact for a retry.

## 4. Command-specific rows (from AGENTS.md)

- `preflight` / `check`: validates chain + profiles + config and opens ZERO
  sockets. Refusal is exit 2 naming the offending hop and reason.
- `ls` (alias `profiles`): human-readable only. `ls --json` is rejected with
  exit 6 — it would silently violate the one-document stdout contract.
- `scan`: `--output json` (or global `--json` without `--output ndjson`)
  prints exactly one JSON document. Empty scan is exit 4: the JSON shape
  `{"ok":false,...,"candidates":[]}` goes to stdout in JSON mode; in table
  mode stdout stays silent and stderr carries
  `qcore: scan found nothing reachable (exit 4)`. `--json` combined with
  `--output ndjson` is a conflict → exit 6.
- `import`: exit 0 prints the ref; rejection is exit 5 listing each offending
  field; unreadable file is exit 6.
- `connect` (alias `up`): chain-source conflicts are usage errors (exit 6);
  content problems are validation errors (exit 2).
- Local proxy surface (`--bind`): a SOCKS5 listener (RFC 1928, no-auth)
  serving CONNECT and UDP ASSOCIATE through the exit hop. UDP relay egress
  is capability-gated by the exit hop's UDP support (an ASSOCIATE on an
  exit without it answers `0x07`); ATYP=domain targets resolve through the
  tunnel-routed DNS resolver (never the OS resolver; refused fail-closed
  without one). Peers are loopback-only by default; a LAN-facing listener
  requires the explicit `--expose-lan` opt-in (exit 6 without it).
  `--http-proxy <addr>` adds an HTTP/1.1 CONNECT listener (RFC 7231 §4.3.6;
  CONNECT only, other methods answer 405) with the same services and the
  same exposure policy. Bind failures (`--bind` / `--http-proxy` address
  taken or unavailable) are PRE-START failures: they map to usage (exit 6)
  like the malformed-address and non-loopback refusals, never to hop
  failure (3) — no hop has started when the listener binds.
- Routing rules (`connect --routing <path>`, default
  `<profile-dir>/routing.toml` when present; absent file = every target
  proxies through the tunnel, the historic behavior). Rules evaluate in file
  order, first match wins; each rule is `match = { domain | cidr | port }`
  (present fields ANDed, `domain` and `cidr` mutually exclusive) plus
  `action = "proxy" | "direct" | "block"`. A `domain` matches the CONNECT
  target name as a DNS suffix on label boundaries (`example.com` covers
  `a.example.com`, never `notexample.com`; no TLS/HTTP sniffing — only the
  CONNECT target is consulted); `port` alone matches any host. Decisions run
  after the handshake parse and before any dial: `block` refuses with SOCKS
  `0x02` / HTTP `403` (UDP datagrams are dropped; a concrete ASSOCIATE
  address answers `0x02`), `direct` dials from the host network stack
  (`tokio::net::TcpStream`, plain UDP socket for UDP) and never touches the
  tunnel dialer, and `proxy` keeps the existing tunnel path. **`direct` is a
  deliberate leak**: the destination sees the host's IP and a domain is
  resolved locally, so neither the tunnel's egress IP nor its
  tunnel-routed DNS applies. A CIDR rule needs an address; a domain target
  is resolved through the tunnel resolver (never the OS resolver) before
  CIDR rules run, so without a tunnel resolver such a target fails closed
  (SOCKS `0x08` / HTTP `501`) rather than guessing. Malformed or
  unknown-key rules are usage errors (exit 6) naming the file and field
  (fail closed: a typo must not silently turn a block rule into a no-op).
  When rules are active, `connect` prints one stderr line naming the file
  and rule count, and `status` (text mode) prints one line when the
  profile-default file is present; an explicit `--routing` path is visible
  in connect's line and the detached log, not in `status`.
- Unknown subcommand/shortcut: exit 6 (`qcore: unknown command or shortcut ...`).
- Global options are validated before any work: `--max-depth` outside 1..=5
  and `--timeout` < 1s are exit 6.
- Documented env bindings must exist as `env = ...` clap attributes, not just
  help text (e.g. `CONNECTION_TIMEOUT_SECONDS`).

## 5. Chain grammar (summary)

`hop (, hop)*` with preset names and `@label` references; repeatable `--hop`
accumulates in argv order; a positional file or `--chain-file` loads a TOML
chain declaration. Conflicting sources (`--chain` + `--chain-file`, `--hop`
+ either) are exit 6. Depth: default 3, hard limit 5. Field names per
transport come from the single `allowed_fields()` table — an unknown field
fails closed naming the field (exit 2 at the grammar gate).

Full grammar normative text lives with the parser
(`crates/qcore-core/src/chain/parse.rs`); this section pins only the CLI
observable behavior above.
