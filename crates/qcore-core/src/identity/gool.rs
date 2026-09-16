//! GOOL dual-identity provisioning (002 FR-009, research R6).
//!
//! Outer and inner hops each hold a separately registered identity with the
//! full lifecycle, renewed independently: a revocation hits one hop, never
//! both. Provisioning is sequential (outer then inner) — two registrations
//! still fit comfortably inside the 60 s budget and sequential writes can
//! never interleave secret material.

use crate::config::profile_dir::ProfileDirs;
use crate::config::secret::SecretString;
use crate::identity::model::ProviderIdentity;
use crate::identity::register::{register_fresh, ProviderOptions, RegisterError, RegisterOutcome};
use crate::identity::store::{load, save, IdentityRole};

/// Independently renewable outer+inner identities (data-model `GoolPair`).
pub struct GoolPair {
    pub outer: ProviderIdentity,
    pub inner: ProviderIdentity,
}

/// Full per-role outcomes of a pair provisioning (families may differ per
/// role under dual-stack resolution; each role reports its own).
pub struct PairOutcome {
    pub outer: RegisterOutcome,
    pub inner: RegisterOutcome,
}

impl PairOutcome {
    pub fn license_applied(&self) -> bool {
        self.outer.license_applied || self.inner.license_applied
    }
}

/// Register (or reuse, when `reuse` is set and the stored record is healthy)
/// the outer+inner pair, sequentially (outer then inner): two registrations
/// still fit the 60 s budget and sequential writes never interleave secret
/// material.
pub async fn provision_pair(
    dirs: &ProfileDirs,
    opts: &ProviderOptions,
    license: Option<&SecretString>,
    reuse: bool,
) -> Result<PairOutcome, RegisterError> {
    let outer = provision_role(dirs, IdentityRole::Outer, opts, license, reuse).await?;
    let inner = provision_role(dirs, IdentityRole::Inner, opts, license, reuse).await?;
    Ok(PairOutcome { outer, inner })
}

/// Provision one role: reuse the healthy stored record when `reuse` is set,
/// else register fresh and store atomically.
pub async fn provision_role(
    dirs: &ProfileDirs,
    role: IdentityRole,
    opts: &ProviderOptions,
    license: Option<&SecretString>,
    reuse: bool,
) -> Result<RegisterOutcome, RegisterError> {
    if reuse {
        if let Some(id) = load(dirs, role) {
            if !id.refused {
                return Ok(RegisterOutcome {
                    identity: id,
                    license_applied: false,
                    license_note: None,
                    // No exchange happened on the reuse path; the family
                    // claim would be fabricated, so it is marked as such.
                    family: "stored".to_string(),
                });
            }
        }
    }
    let outcome = register_fresh(opts, license).await?;
    save(dirs, role, &outcome.identity)
        .map_err(|e| RegisterError::Blocked(format!("identity store failed: {e}")))?;
    Ok(outcome)
}
