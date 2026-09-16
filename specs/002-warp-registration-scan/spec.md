# Feature Specification: WARP Registration & Endpoint Scan

**Feature Branch**: `002-warp-registration-scan`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "warp registeration for both warp and gool and masque. i want the ability to register and renew these. i also want the ability to scan working endpoints for these. the aether core and oblivion and pattn has these features we can research these and borrow from them"

## Clarifications

### Session 2026-09-16

- Q: How does the user hand the provider license key to the client? → A: Both a command-line flag and an interactive prompt (with file fallback for scripts); flag use prints a one-line stderr warning and the key is never echoed, logged, or persisted.
- Q: Connect with no stored identity — auto-register or refuse? → A: Auto-register as part of the connect (option A).
- Q: Refused identity at connect — auto or explicit renew? → A: Renew automatically but ONLY on explicit provider-refusal signals (option C, Aether-type): the provider's typed "unknown/revoked/gone identity" answers and MASQUE credential expiry. Timeouts, handshake silence, TLS failures, and empty scans NEVER trigger renewal — the identity is kept and the client rescans/retries instead, since on restricted networks those failures almost always mean a blocked endpoint, not a dead identity.
- Q: MASQUE credential in rotation window at connect — auto-rotate or explicit only? → A: Auto-rotate during the connect (option A).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Register a WARP identity and connect (Priority: P1)

A person with no prior setup registers a fresh WARP identity from the client
and connects a WARP hop with it — no hand-created keys, no pasted config.

**Why this priority**: Nothing else in this feature works without an identity;
registration is the front door to live WARP and GOOL testing.

**Independent Test**: On a fresh profile, register, then connect
`wireguard peer=warp` and carry traffic; disconnect cleanly.

**Acceptance Scenarios**:

1. **Given** no stored identity, **When** the user registers, **Then** the
   client obtains and stores an identity (device id, credentials, peer key,
   interface addresses) in under 60 seconds.
2. **Given** a stored identity, **When** the user connects a WARP hop,
   **Then** the tunnel establishes without re-registering.
3. **Given** registration fails (network blocked, provider refuses),
   **When** the attempt ends, **Then** the client reports which step failed
   and what to try next, and stores nothing half-written.
4. **Given** no stored identity, **When** the user connects directly
   without registering first, **Then** the client registers automatically
   and proceeds to connect.

---

### User Story 2 - Scan for working endpoints (Priority: P1)

A person scans for reachable WARP/MASQUE endpoints and the client ranks them
by measured latency, remembers the winner, and uses it on the next connect —
with no manual endpoint entry.

**Why this priority**: Equally front-door: the scanner is currently a sieve
with no candidates, so every live connection needs a hand-supplied endpoint.

**Independent Test**: Run a scan, confirm a ranked list with latency figures,
then connect and confirm the winning endpoint is used.

**Acceptance Scenarios**:

1. **Given** no cached endpoint, **When** the user scans, **Then** the client
   presents working endpoints ordered by measured round-trip time.
2. **Given** a fresh install with no configuration at all, **When** the user
   connects, **Then** the shipped default WARP profile supplies candidates
   and defaults and the connection proceeds with no manual input.
3. **Given** a previous winning endpoint, **When** the user scans or connects,
   **Then** the cached endpoint is re-verified first and a full scan is
   skipped while it still works.
4. **Given** a scan that finds nothing reachable, **When** it completes,
   **Then** the client says so plainly and does not connect to an
   unverified endpoint.

---

### User Story 3 - Renew an identity (Priority: P2)

A person whose identity stops being accepted (or whose MASQUE credential
nears expiry) renews it — refresh-in-place when possible, fresh
re-registration when the provider refuses the old one — without losing
their other settings.

**Why this priority**: Identities rot (refusals, expiring credentials);
without renewal the user is stuck deleting state by hand.

**Independent Test**: With a refused/expired identity, renew, then connect
successfully; other settings (profiles, imports, scan cache) are untouched.

**Acceptance Scenarios**:

1. **Given** a refused identity, **When** the user renews, **Then** a fresh
   working identity replaces it and the old one is discarded.
2. **Given** a healthy identity, **When** the user renews explicitly,
   **Then** the client confirms whether anything actually needed replacing.
3. **Given** a renewal attempt that fails midway, **When** it ends, **Then**
   the previous working identity (if any) is still intact.

---

### User Story 4 - MASQUE enrollment (Priority: P3)

A person enrolls the MASQUE credential tied to their identity and connects a
MASQUE hop (h3 or h2) through a working endpoint.

**Why this priority**: MASQUE live testing needs its own credential step;
it rides on the Story 1 identity.

**Independent Test**: Enroll, then connect `masque alpn=h3` and `masque
alpn=h2` through a scanned endpoint and carry traffic on each.

**Acceptance Scenarios**:

1. **Given** a registered identity, **When** the user enrolls MASQUE,
   **Then** the credential is stored alongside the identity.
2. **Given** an enrolled credential, **When** connecting either MASQUE mode,
   **Then** each establishes independently through a scanned endpoint.

---

### Edge Cases

- Registration endpoint itself is unreachable from the user's network: the
  client reports the blockage distinctly from a provider refusal.
- The provider refuses an existing identity mid-session (revocation): the
  next connect renews it automatically per FR-004 and reports what was
  replaced; only failures outside the refusal set surface to the user.
- Two registrations race (user double-invokes): exactly one identity wins;
  no merged/corrupt store.
- GOOL needs two working hops: the outer and inner hops each hold a
  separately registered identity (decided: option A).
- Scan runs while a session is up: the scan must not disturb the live session.
- Stored identity file is corrupt or partially written: treated as missing;
  the client re-registers rather than crashing.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The client MUST register a fresh WARP identity with the
  provider with no manual key handling by the user.
- **FR-002**: The client MUST store the identity (device id, credentials,
  peer key, interface addresses, MASQUE credential when enrolled) in the
  application profile directory, readable only by the user, written
  atomically (no half-written store on failure).
- **FR-003**: The client MUST reuse a stored healthy identity across
  connects without re-registering, and MUST automatically register a
  fresh identity as part of connect when none is stored (clarified
  2026-09-16: option A).
- **FR-004**: The client MUST renew an identity: refresh-in-place when the
  provider accepts it, fresh re-registration when the provider refuses it,
  preserving unrelated settings in both cases. Renewal MUST trigger only
  on explicit provider-refusal signals (unknown, revoked, or gone
  identity answers; MASQUE credential in its expiry window) — never on
  timeouts, handshake silence, transport errors, or empty scans, which
  MUST keep the identity and rescan/retry instead (clarified 2026-09-16:
  option C, Aether-type classification).
- **FR-005**: The client MUST enroll and rotate the MASQUE credential,
  including ahead-of-expiry rotation without user action at connect time:
  a connect that finds the credential inside its rotation window MUST
  rotate it automatically as part of that connect (clarified 2026-09-16:
  option A).
- **FR-006**: The client MUST verify scan candidates by handshake *and*
  actual traffic before ranking them (candidate provisioning itself ships
  with the default profile per FR-014).
- **FR-007**: The client MUST rank verified candidates by measured
  round-trip time.
- **FR-008**: The client MUST cache the winning endpoint and re-verify it
  first on the next scan/connect, skipping the full scan while it works.
- **FR-009**: The client MUST support GOOL operation with two separately
  registered identities: one for the outer hop, one for the inner hop,
  each renewable independently (decided: option A). Renewal addresses
  each identity independently; one command renews the pair only when
  explicitly asked for both.
- **FR-010**: The client MUST accept an optional provider license key via
  a command-line flag, an interactive prompt, or a key-file path, and
  apply it to that operation's identity upgrade. Flag use MUST print a
  one-line stderr warning that the key is visible to other processes. The
  key is a credential: used for the operation, never echoed, logged,
  reported, or persisted (decided: option B — accepted per operation, not
  persisted; clarified 2026-09-16: flag form also supported with warning).
- **FR-011**: Registration, renewal, and scanning traffic MUST use direct
  connections to the provider. Where the provider is unreachable, the
  client MUST fail closed with a report distinguishing "network blocked"
  from "provider refused" (decided: option A — direct only).
- **FR-012**: Private keys and access tokens MUST never appear in logs,
  reports, exports, or error output (constitution IV; existing redaction
  covers new flows).
- **FR-013**: Every new flow MUST work over IPv4-only, IPv6-only, and
  dual-stack hosts and report which family it used (constitution II).
- **FR-014**: The client MUST ship a default WARP profile as replaceable
  data (same profile-directory model as scan/obfuscation/composition
  profiles): built-in endpoint candidates, default ports, and default scan
  choice, so first-run connects with zero user configuration on an
  unblocked network.

### Key Entities *(include if feature involves data)*

- **ProviderIdentity**: A registered WARP identity — device id, access
  token, peer key, interface addresses, enrolled MASQUE credential, expiry
  metadata. Stored per profile, user-readable-only.
- **EndpointCandidate** (extends existing): A verified working endpoint with
  measured latency; the cache winner carries last-known-good status.
- **RegistrationReport**: Machine-readable outcome of register/renew/scan:
  what was created, reused, rotated, or refused, and why.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user goes from zero state to a registered identity in
  under 60 seconds on an unblocked network.
- **SC-002**: A scan over built-in candidates returns at least one
  traffic-verified endpoint with a measured latency on an unblocked network.
- **SC-003**: A WARP hop connects through a scanned endpoint and carries
  traffic with no hand-supplied endpoint or keys.
- **SC-004**: A refused identity is renewed to working state with unrelated
  settings untouched, verified by an automated test using a refused-identity
  fixture.
- **SC-005**: Zero private keys or access tokens appear in logs, reports, or
  error output across the new flows, verified by the secret-hygiene suite
  extended to registration artifacts.
- **SC-006**: MASQUE h3 and h2 each connect through a scanned endpoint and
  carry traffic.
- **SC-007**: On a fresh install with zero configuration, the user reaches
  a working WARP connection using only the shipped default profile.

## Assumptions

- The provider's public registration API remains available and its
  request/response shape stays compatible (researched against the Aether
  core's implementation, which Oblivion and PattNG both reuse by
  orchestration rather than reimplementation — this feature follows the
  same split: the engine core owns registration/scanning, thin clients
  orchestrate it).
- WARP keys themselves do not expire; "renewal" means refresh-on-accepted
  and re-register-on-refused, plus MASQUE credential rotation.
- Built-in endpoint candidates are public provider address ranges used only
  to *find* a working endpoint by measurement, and ship as replaceable data.
- Live-network tests are supplementary (nightly); gating tests use fixtures
  and loopback doubles per constitution II.
- Single-user, single-device: no identity sync or multi-device management.
