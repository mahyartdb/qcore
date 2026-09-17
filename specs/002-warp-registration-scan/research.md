# Phase 0 Research: WARP Registration & Endpoint Scan

Consolidated from the three reference implementations (cloned 2026-09-16)
plus workspace fit analysis. Format: Decision / Rationale / Alternatives.

## R0. What the references actually do (source)

- **Aether core** (`aether/`): owns everything. Registration = JSON
  signup/refresh/re-register against the provider API with an X25519 device
  key (MASQUE enrollment = P-256 key PATCH); TOML identity store written
  atomically with user-only permissions; renewal triggers ONLY on typed
  provider-refusal answers, everything else retries with the identity kept;
  MASQUE credential self-issued with a 365-day lifetime, rotated 7 days
  early. Endpoints = hardcoded provider address ranges + seeds + port
  pools, verified by handshake *and* traffic, RTT-ranked, winner cached
  (last-known-good) and re-verified first.
- **Oblivion**: no registration/scan code of its own — spawns the Aether
  core binary and steers it via environment/arguments, parsing its log
  markers. Scan modes (turbo/balanced/thorough/stealth/ironclad) are UI
  selections mapped to core flags.
- **PattNG**: same delegation. Its value-add is orchestration: renew by
  moving the identity dir aside and re-provisioning with a timeout, scan
  by running the binary and parsing winner lines, shareable endpoint URIs.
- Neither reference supports license-key upgrade; neither persists keys
  beyond the identity store.

## R1. Registration transport (HTTPS client)

- **Decision**: Minimal vendored HTTPS/1.1 client over the workspace's
  existing `rustls` + `tokio`, owned by `qcore-core/src/identity/`.
- **Rationale**: The signup surface is three JSON endpoints (register,
  refresh, enroll). `reqwest` would add ~100 transitive crates to a
  9-target matrix for POST/GET/PATCH of small JSON bodies. rustls is
  already vetted in-tree (constitution crypto rule); a small audited
  client keeps the dependency delta near zero and the behavior fully
  testable against a loopback fixture.
- **Alternatives**: reqwest (heavy, duplicates a vetted TLS stack);
  shelling curl (non-Rust process, untestable offline, FR-001 spirit).
- **Post-implementation note**: TLS runs through `tokio-rustls`, a thin
  adapter already in the lockfile (not an HTTP stack — the HTTP/1.1 framing
  stays vendored). The tree also enables rustls's `aws-lc-rs` backend via
  arti, so the client names `ring` explicitly instead of relying on a
  process-default provider (which panics when both backends are compiled
  in).

## R2. Identity store format

- **Decision**: TOML records in the profile dir (`identity-warp.toml`,
  `identity-warp-inner.toml` for GOOL), user-readable-only, atomic write
  (temp + rename), corrupt/partial reads treated as missing.
- **Rationale**: Matches the existing profile-directory model (FR-028)
  and the reference behavior; TOML keeps it hand-inspectable; atomicity
  gives the "exactly one identity wins" race guarantee.
- **Alternatives**: OS keyring for everything (opaque, uninspectable,
  complicates backup/replaceability); SQLite (new dependency, overkill).

## R3. Renewal classification table

- **Decision**: Re-register fresh ONLY on explicit provider-refusal
  signals (unknown/revoked/gone identity answers); refresh-in-place when
  accepted; every other failure (timeouts, handshake silence, TLS errors,
  empty scan, rate limits, server errors) keeps the identity and goes to
  rescan/retry with cooldown.
- **Rationale**: Verified against Aether's classifier (refusal-only
  re-registration); handshake silence cannot distinguish dead identity
  from blocked endpoint, so renewing on it burns identities with zero
  signal — the critical property on restricted networks (FR-004).
- **Alternatives**: Renew on any failure (identity churn, harmful);
  never auto-renew (contradicts clarified FR-004).

## R4. MASQUE credential lifecycle

- **Decision**: Self-issued P-256 credential via `rcgen` (small pure-Rust
  add), stored alongside the identity, rotated automatically when a
  connect finds it inside the rotation window (clarified).
- **Rationale**: Mirrors the reference lifecycle (yearly credential, early
  rotation, enroll via provider PATCH); `rcgen` avoids hand-rolled X.509.
- **Alternatives**: Hand-rolled DER (custom crypto surface, prohibited in
  spirit); no rotation (breaks long-lived installs).

## R5. Candidate/seed data model

- **Decision**: `profiles/warp.toml` ships provider address ranges, per-
  family seeds, WARP and MASQUE port pools, and the default scan choice —
  replaceable data, loaded by a seed provider into the existing scanner.
- **Rationale**: FR-014/FR-028 (profiles as data); the scanner stays a
  sieve and finally receives candidates; operators can override without
  touching secrets or code.
- **Alternatives**: Hardcoded in Rust (violates profiles-as-data);
  fetched from provider at runtime (bootstrap paradox on blocked nets).

## R6. GOOL dual identity

- **Decision**: Two independent records (outer + inner), each with the
  full register/refresh/re-register lifecycle, renewed independently.
- **Rationale**: Clarified option A; isolates revocation blast radius to
  one hop; matches the reference outer/inner provisioning.
- **Alternatives**: Shared identity (rejected at clarify: doubles as one
  device id is observable linkage and couples renewal).

## R7. License-key handling

- **Decision**: Accepted per operation via flag, interactive prompt, or
  key file; used for that operation's upgrade call only; never persisted,
  echoed, logged, or reported; flag use prints a one-line stderr warning.
- **Rationale**: Clarified option B + flag form; per-operation use bounds
  the secret's lifetime to the call; the warning makes the process-list
  exposure explicit rather than silent.
- **Alternatives**: Persisted key (rejected: permission creep on a paid
  credential); flag-only (leaks silently); prompt-only (breaks scripts).
