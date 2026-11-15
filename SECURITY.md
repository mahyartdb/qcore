# Security Policy

qcore is security-sensitive infrastructure: it moves traffic through tunnels,
handles provider credentials, and runs sidecar processes. This document
covers how vulnerabilities are reported and how advisories are handled.

## Reporting a vulnerability

Report privately — do NOT open a public GitHub issue for a vulnerability.

- **Contact (placeholder):** `security@qcore.invalid` — replace with the
  monitored inbox / private disclosure channel before first public release.
  Until then, use GitHub Security Advisories ("Report a vulnerability" on
  this repository) so the report stays private.
- Include: affected component (crate/module), version or commit, a
  minimal reproduction, and your assessment of impact. PoC code is welcome.
- You will get an acknowledgement within 5 business days and a status update
  at least every 14 days until resolution.
- Please do not test against third-party infrastructure you do not operate,
  and do not exfiltrate data. The lawful-use statements shipped in the
  product (`qcore legal`) apply to research on qcore too.

## Scope notes (what we treat as in-scope)

- Secret handling: keys, tokens, license inputs. The contract is that
  secrets never appear in argv, logs, reports, or `Debug` output, with one
  documented exception: `--license-key` (argv-visible by construction; it
  warns on use, and `--license-file` is the recommended form). Logs and
  reports stay fully covered: typed wrappers print exactly `<redacted>`,
  stderr passes through the central `masked_value` /
  `masked_failure_line` redactors, and unclassifiable content fails closed
  to a metadata-only placeholder.
- Control channel: token-authenticated loopback protocol (`control.json`
  rendezvous); directory permissions are the secrecy boundary.
- Fail-closed status semantics: a state that cannot be proven live or dead
  must exit 12 (unverifiable), never a false green.
- The FFI boundary: panics never cross, caller buffers never carry secrets.

## Advisory handling (cargo-deny / denylist.toml)

Dependency advisories are gated by `cargo deny --config denylist.toml check`
in CI. The process for an advisory:

1. **Verified/unpinned advisories fail the gate.** Fix by upgrading the
   affected subtree, or by an explicit `ignore` entry in `denylist.toml`
   `[advisories]` with a written reason and a reassessment condition
   (see the existing RUSTSEC entries for the expected shape).
2. **Every `ignore` entry must carry:** the crate path it arrives through,
   why the exposure does or does not apply to a tunnel core, and the upstream
   condition that lifts it. Bare ignores without rationale are rejected in
   review.
3. **Duplicate-major `skip` entries** (the `[bans]` section) pin older
   duplicate lines required by disjoint transitive subtrees (mostly the
   `arti-client 0.46` subtree). Any NEW duplicate fails — a new subtree that
   forces another duplicate needs its own evaluated `skip` line, never a
   loosened policy.
4. **Emergency path** (critical vuln in a shipped version): fix on a
   `release/x.y` branch, patch-bump (never re-tag), two-role authority
   (release-manager + security-maintainer), mandatory advisory text + signed
   artifacts + secret-scan + audit + affected-platform smoke; yank only
   broken versions, never to retract secrets.

## Supported versions

Pre-1.0: only the latest `main` receives security fixes. There are no
backport branches until a first tagged release exists (tagging is currently
prohibited — see AGENTS.md Release row).
