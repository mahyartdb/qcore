//! Provider identity types (002 FR-002/FR-009, data-model `ProviderIdentity`).
//!
//! A `ProviderIdentity` is a registered WARP identity: a provider-assigned
//! device id plus a locally generated X25519 device key. Secrets ride the
//! zeroizing [`SecretString`] wrapper and are never `Debug`-printed; the
//! [`RegistrationReport`](super::report::RegistrationReport) carries only the
//! device id, never credentials.

use crate::config::secret::SecretString;

/// One registered WARP identity. Two records max per profile (outer/inner
/// for GOOL, chosen by [`IdentityRole`](super::store::IdentityRole)).
///
/// `refused = true` MUST NOT be used for connects — it means the provider
/// answered unknown/revoked/gone and the record is awaiting re-registration
/// (FR-004).
#[derive(Debug)]
pub struct ProviderIdentity {
    /// Provider-assigned id; uniqueness key.
    pub device_id: String,
    /// Provider access token (secret).
    pub access_token: SecretString,
    /// Locally generated X25519 device key, base64 (secret).
    pub private_key_b64: SecretString,
    /// Provider peer public key, base64 (public).
    pub peer_key_b64: String,
    /// Assigned interface addresses.
    pub interface_v4: String,
    pub interface_v6: String,
    /// MASQUE credential, present after enrollment (FR-005).
    pub masque: Option<MasqueCredential>,
    /// Set on an explicit provider-refusal signal; triggers re-registration.
    pub refused: bool,
    /// Whether a license key was applied to this identity. The key itself is
    /// per-operation and is NEVER stored (FR-010).
    pub license_upgraded: bool,
}

/// MASQUE credential (data-model `MasqueCredential`).
///
/// Self-issued P-256 via `rcgen`, enrolled with the provider; rotated
/// automatically when a connect finds it inside the rotation window (FR-005).
#[derive(Debug)]
pub struct MasqueCredential {
    /// Self-issued certificate PEM (public).
    pub cert_pem: String,
    /// Certificate private key PEM (secret).
    pub key_pem: SecretString,
    /// Issuance time, millis since epoch; rotation math anchor.
    pub issued_at_ms: u64,
    /// Credential lifetime in days (provider-defined; 365).
    pub lifetime_days: u64,
    /// Rotate when this many days of lifetime remain (7).
    pub renew_before_days: u64,
}

impl MasqueCredential {
    pub const LIFETIME_DAYS: u64 = 365;
    pub const RENEW_BEFORE_DAYS: u64 = 7;

    /// True when inside the rotation window (or past expiry): a connect MUST
    /// rotate before using this credential (FR-005). A clock older than
    /// issuance (wound back, pre-epoch) cannot prove health: rotate instead
    /// of reporting healthy on an expired credential.
    pub fn needs_rotation(&self, now_ms: u64) -> bool {
        if now_ms < self.issued_at_ms {
            return true;
        }
        let lifetime_ms = self.lifetime_days.saturating_mul(86_400_000);
        let margin_ms = self.renew_before_days.saturating_mul(86_400_000);
        now_ms.saturating_add(margin_ms) >= self.issued_at_ms.saturating_add(lifetime_ms)
    }

    /// True when fully past lifetime: connects fail naming renewal. A clock
    /// older than issuance proves nothing (see `needs_rotation`).
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at_ms
            && now_ms
                >= self
                    .issued_at_ms
                    .saturating_add(self.lifetime_days.saturating_mul(86_400_000))
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(issued_at_ms: u64) -> MasqueCredential {
        MasqueCredential {
            cert_pem: "cert".into(),
            key_pem: SecretString::new("key"),
            issued_at_ms,
            lifetime_days: MasqueCredential::LIFETIME_DAYS,
            renew_before_days: MasqueCredential::RENEW_BEFORE_DAYS,
        }
    }

    #[test]
    fn rotation_window_math() {
        let day = 86_400_000u64;
        let now = 1_800_000_000_000u64;
        // Fresh: no rotation.
        assert!(!cred(now).needs_rotation(now));
        // Six days of lifetime left (inside the 7-day window): rotate.
        assert!(cred(now - 359 * day).needs_rotation(now));
        // Eight days left: leave alone.
        assert!(!cred(now - 357 * day).needs_rotation(now));
        // Past expiry: rotation (and expired).
        let old = cred(now - 400 * day);
        assert!(old.needs_rotation(now));
        assert!(old.expired(now));
        assert!(!cred(now).expired(now));
    }

    #[test]
    fn wound_back_clock_rotates_instead_of_healthy() {
        // Pre-epoch clock with a real credential: rotation due (fail toward
        // renewal), never expired (the clock proves nothing).
        let c = cred(1_800_000_000_000u64);
        assert!(c.needs_rotation(0));
        assert!(!c.expired(0));
        // Wound back to issuance time on a 400-day-old cert: same.
        let old = cred(1_800_000_000_000u64);
        assert!(old.needs_rotation(1_800_000_000_000u64 - 400 * 86_400_000u64));
        // Far-future issuance never reads as permanently fresh.
        let future = cred(u64::MAX);
        assert!(future.needs_rotation(1_800_000_000_000u64));
    }
}
