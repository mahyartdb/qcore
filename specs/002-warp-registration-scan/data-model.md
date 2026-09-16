# Data Model: WARP Registration & Endpoint Scan

Derived from the feature spec's Key Entities. Logical model; storage is
profile-dir files (no database). Extends — never replaces — the 001
data-model.md entities.

## ProviderIdentity

One registered WARP identity. Two records max per profile (outer/inner
for GOOL).

| Field | Type | Notes |
|---|---|---|
| `device_id` | string | Provider-assigned; uniqueness key |
| `access_token` | secret | Zeroizing wrapper; never logged/reported |
| `private_key` | secret | X25519 device key, generated locally |
| `peer_key` | string | Public peer key from registration |
| `interface_addrs` | v4 + v6 strings | Assigned addresses |
| `masque_cred` | MasqueCredential, optional | Enrolled separately (FR-005) |
| `refused` | bool | Set on refusal signal; triggers re-register |
| `license_upgraded` | bool | Whether a key was applied (key itself NOT stored) |

Validation: refused=true MUST NOT be used for connects; corrupt/partial
record reads as missing (FR-002).

## MasqueCredential

| Field | Type | Notes |
|---|---|---|
| `cert_pem`, `key_pem` | secrets | Self-issued P-256 |
| `issued_at` | timestamp | Rotation math anchor |
| `lifetime_days` | integer | Provider-defined (reference: 365) |
| `renew_before_days` | integer | Rotation window (reference: 7) |

State: `valid → rotating (inside window) → valid`; expiry without
rotation is a connect-time error naming renewal.

## EndpointCacheEntry (extends EndpointCandidate)

| Field | Type | Notes |
|---|---|---|
| `address` | IP + port | Winner address |
| `profile` | string | Scan profile that verified it |
| `verified_at` | timestamp | Re-verify-first ordering |
| `transport` | enum(warp, masque) | Separate winners per transport |

Rule: cache hit is re-verified (fast path) before use; failure evicts
and triggers full scan (FR-008).

## RegistrationReport (machine-readable, FR-025 shape)

| Field | Type | Notes |
|---|---|---|
| `action` | enum(registered, reused, refreshed, re_registered, rotated, refused, blocked) | What happened |
| `identity` | device_id or null | Never credentials |
| `endpoint` | string or null | Winning/verified endpoint if any |
| `cause` | string | Actionable, redacted |
| `license_applied` | bool | Upgrade applied this operation |

## GoolPair

| Field | Type | Notes |
|---|---|---|
| `outer`, `inner` | ProviderIdentity refs | Independently renewable (FR-009) |

Renewal of one MUST NOT touch the other.
