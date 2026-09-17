//! Renewal: refresh-in-place vs fresh re-registration (002 US3, research R3).
//!
//! The Aether-type rule (FR-004): ONLY explicit provider-refusal signals
//! (unknown/revoked/gone identity) trigger fresh re-registration. Every
//! other failure — timeouts, handshake silence, TLS errors, empty scans,
//! rate limits, server errors, shape mismatches — keeps the stored identity
//! and reports rescan/retry as the next step. On restricted networks most
//! failures are blocked endpoints, not dead identities; renewing on them
//! would burn identities with zero signal.

use crate::config::profile_dir::ProfileDirs;
use crate::config::secret::SecretString;
use crate::diag::redact::masked_value;
use crate::identity::masque::{enroll_credential, generate_credential};
use crate::identity::model::{now_ms, MasqueCredential, ProviderIdentity};
use crate::identity::register::{
    apply_license, refresh_stored, register_fresh, ProviderOptions, RegisterError,
};
use crate::identity::report::{report_for_error, RegistrationReport, ReportAction};
use crate::identity::store::{load, role_name, save, IdentityRole};

/// Renewal verdict for a failed refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalClass {
    /// Provider explicitly refused the identity: re-register fresh.
    Reregister,
    /// Anything else: keep the identity, rescan/retry instead.
    Keep,
}

/// Classify a refresh failure (FR-004 table).
pub fn classify(error: &RegisterError) -> RenewalClass {
    match error {
        RegisterError::Refused(_) => RenewalClass::Reregister,
        RegisterError::Blocked(_) | RegisterError::Rejected(_) | RegisterError::Protocol(_) => {
            RenewalClass::Keep
        }
    }
}

/// Renew one role (002 FR-004/005/009/010): refresh-in-place when accepted,
/// fresh re-registration on refusal signals only, MASQUE enroll/rotate under
/// `masque_only`. Unrelated settings are never touched (only this role's
/// record is rewritten). Always returns a report — never throws the stored
/// identity away on an ambiguous failure.
pub async fn renew_role(
    dirs: &ProfileDirs,
    role: IdentityRole,
    opts: &ProviderOptions,
    license: Option<&SecretString>,
    masque_only: bool,
) -> RegistrationReport {
    let Some(mut id) = load(dirs, role) else {
        return RegistrationReport {
            action: ReportAction::Blocked,
            identity: None,
            endpoint: None,
            cause: format!(
                "no stored {} identity — run `qcore register` first",
                role_name(role)
            ),
            license_applied: false,
        };
    };
    if masque_only {
        return renew_masque_only(dirs, role, opts, &mut id).await;
    }
    if id.refused {
        // Already known-dead: skip the refresh round-trip, re-register.
        return reregister(dirs, role, opts, license, Some(&id.device_id)).await;
    }
    match refresh_stored(opts, &id).await {
        Ok(r) => {
            id.interface_v4 = r.interface_v4;
            id.interface_v6 = r.interface_v6;
            let mut license_applied = false;
            let mut extra = String::new();
            if let Some(key) = license {
                // A key on a healthy renew upgrades in place (no re-register
                // needed for WARP+).
                let upgrade = apply_license(opts, &id, key).await;
                license_applied = upgrade.applied;
                id.license_upgraded = upgrade.applied;
                if let Some(note) = upgrade.note {
                    extra = format!(" ({note})");
                }
            }
            if let Err(e) = save(dirs, role, &id) {
                return RegistrationReport {
                    action: ReportAction::Blocked,
                    identity: Some(id.device_id.clone()),
                    endpoint: None,
                    cause: format!(
                        "identity store failed ({}); previous record intact",
                        masked_value("cause", &e)
                    ),
                    license_applied: false,
                };
            }
            if r.changed {
                RegistrationReport {
                    action: ReportAction::Refreshed,
                    identity: Some(id.device_id.clone()),
                    endpoint: None,
                    cause: format!("identity refreshed via {}{}", r.family, extra),
                    license_applied,
                }
            } else {
                RegistrationReport {
                    action: ReportAction::Reused,
                    identity: Some(id.device_id.clone()),
                    endpoint: None,
                    cause: format!(
                        "identity healthy via {}; nothing to replace{}",
                        r.family, extra
                    ),
                    license_applied,
                }
            }
        }
        Err(e) => match classify(&e) {
            RenewalClass::Reregister => {
                reregister(dirs, role, opts, license, Some(&id.device_id)).await
            }
            RenewalClass::Keep => RegistrationReport {
                action: ReportAction::Reused,
                identity: Some(id.device_id.clone()),
                endpoint: None,
                cause: format!(
                    "{}; identity kept — rescan/retry instead of renewing",
                    masked_value("cause", &e.to_string())
                ),
                license_applied: false,
            },
        },
    }
}

/// Fresh re-registration replacing `old_id` (if any). The previous record
/// is overwritten only after the new identity is fully built — a midway
/// failure leaves the old record intact.
async fn reregister(
    dirs: &ProfileDirs,
    role: IdentityRole,
    opts: &ProviderOptions,
    license: Option<&SecretString>,
    old_id: Option<&str>,
) -> RegistrationReport {
    let outcome = match register_fresh(opts, license).await {
        Ok(o) => o,
        Err(e) => return report_for_error(e),
    };
    if let Err(e) = save(dirs, role, &outcome.identity) {
        return RegistrationReport {
            action: ReportAction::Blocked,
            identity: None,
            endpoint: None,
            cause: format!(
                "identity store failed ({}); previous record intact",
                masked_value("cause", &e)
            ),
            license_applied: false,
        };
    }
    let mut cause = match old_id {
        Some(_) => format!(
            "previous identity refused by provider; fresh one provisioned via {}",
            outcome.family
        ),
        // Direct provisioning with no predecessor (defensive: all renewal
        // callers pass the refused id; identity comparison would be fragile
        // across independent providers).
        None => format!(
            "fresh {} identity provisioned via {}",
            role_name(role),
            outcome.family
        ),
    };
    if let Some(note) = outcome.license_note {
        cause.push_str(&format!(" ({note})"));
    }
    RegistrationReport {
        action: ReportAction::ReRegistered,
        identity: Some(outcome.identity.device_id.clone()),
        endpoint: None,
        cause,
        license_applied: outcome.license_applied,
    }
}

/// MASQUE-only renewal (FR-005): enroll when missing, rotate inside the
/// window, confirm otherwise. Warp material is never touched here.
async fn renew_masque_only(
    dirs: &ProfileDirs,
    role: IdentityRole,
    opts: &ProviderOptions,
    id: &mut ProviderIdentity,
) -> RegistrationReport {
    let now = now_ms();
    let needs = match &id.masque {
        None => true,
        Some(c) => c.needs_rotation(now),
    };
    if !needs {
        return RegistrationReport {
            action: ReportAction::Reused,
            identity: Some(id.device_id.clone()),
            endpoint: None,
            cause: "MASQUE credential healthy; no rotation needed".to_string(),
            license_applied: false,
        };
    }
    let enrolled_new = id.masque.is_none();
    let (cert_pem, key_pem) = match generate_credential() {
        Ok(k) => k,
        Err(e) => {
            return RegistrationReport {
                action: ReportAction::Blocked,
                identity: Some(id.device_id.clone()),
                endpoint: None,
                cause: format!("{}; warp identity intact", masked_value("cause", &e)),
                license_applied: false,
            }
        }
    };
    let family = match enroll_credential(opts, id, &cert_pem).await {
        Ok(f) => f,
        Err(e) => {
            return RegistrationReport {
                action: ReportAction::Blocked,
                identity: Some(id.device_id.clone()),
                endpoint: None,
                cause: format!(
                    "credential not enrolled ({}); warp identity intact — retry when reachable",
                    masked_value("cause", &e.to_string())
                ),
                license_applied: false,
            }
        }
    };
    id.masque = Some(MasqueCredential {
        cert_pem,
        key_pem,
        issued_at_ms: now,
        lifetime_days: MasqueCredential::LIFETIME_DAYS,
        renew_before_days: MasqueCredential::RENEW_BEFORE_DAYS,
    });
    if let Err(e) = save(dirs, role, id) {
        return RegistrationReport {
            action: ReportAction::Blocked,
            identity: Some(id.device_id.clone()),
            endpoint: None,
            cause: format!("identity store failed ({e}); previous record intact"),
            license_applied: false,
        };
    }
    RegistrationReport {
        action: ReportAction::Rotated,
        identity: Some(id.device_id.clone()),
        endpoint: None,
        cause: if enrolled_new {
            format!("MASQUE credential enrolled via {family}")
        } else {
            format!("MASQUE credential rotated via {family}")
        },
        license_applied: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_is_refusal_only() {
        // Only explicit provider refusals re-register (FR-004 table).
        assert_eq!(
            classify(&RegisterError::Refused("gone".into())),
            RenewalClass::Reregister
        );
        for e in [
            RegisterError::Blocked("timeout".into()),
            RegisterError::Rejected("status 500: busy".into()),
            RegisterError::Rejected("status 429: slow down".into()),
            RegisterError::Protocol("not JSON".into()),
        ] {
            assert_eq!(classify(&e), RenewalClass::Keep, "{e}");
        }
    }
}
