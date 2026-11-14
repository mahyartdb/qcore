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
            id.peer_key_b64 = r.peer_key_b64;
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
                // Quarantine first: if the fresh registration below fails
                // (offline), the stored record must say refused so connects
                // stop using a known-dead identity (`inject` honors the
                // flag). A successful reregister overwrites with refused=false.
                id.refused = true;
                let _ = save(dirs, role, &id);
                reregister(dirs, role, opts, license, Some(&id.device_id)).await
            }
            RenewalClass::Keep => RegistrationReport {
                action: ReportAction::Blocked,
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
            cause: format!(
                "identity store failed ({}); the provider already holds the new credential but the local record is stale — retry `renew --masque-only` to reconcile",
                masked_value("cause", &e.to_string())
            ),
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
    use crate::identity::report::ReportAction;

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

    fn b64_fill(byte: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn test_dirs(tag: &str) -> ProfileDirs {
        let dir = std::env::temp_dir().join(format!(
            "qcore-renew-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        ProfileDirs::resolve(Some(dir.join("config")), Some(dir.join("profiles")))
    }

    fn seed_identity(dirs: &ProfileDirs, peer_key_b64: &str) {
        let id = ProviderIdentity {
            device_id: "dev-keep-1".into(),
            access_token: SecretString::new("tok-keep-1"),
            private_key_b64: SecretString::new("cHJpdmF0ZTE="),
            peer_key_b64: peer_key_b64.to_string(),
            interface_v4: "172.16.0.2".into(),
            interface_v6: "2606:4700:110::2".into(),
            masque: None,
            refused: false,
            license_upgraded: false,
        };
        save(dirs, IdentityRole::Outer, &id).expect("seed identity");
    }

    fn refresh_body(device_id: &str, peer_key_b64: &str) -> String {
        format!(
            concat!(
                "{{\"id\":\"{id}\",\"token\":\"tok-keep-1\",",
                "\"config\":{{\"peers\":[{{\"public_key\":\"{peer}\",",
                "\"endpoint\":{{\"v4\":\"162.159.192.1:2408\"}}}}],",
                "\"interface\":{{\"addresses\":{{\"v4\":\"172.16.0.2/32\",",
                "\"v6\":\"2606:4700:110::2/128\"}}}}}},",
                "\"account\":{{\"type\":\"free\"}}}}"
            ),
            id = device_id,
            peer = peer_key_b64
        )
    }

    async fn read_head(s: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 65536 {
                break;
            }
        }
        raw
    }

    async fn write_json(s: &mut tokio::net::TcpStream, body: &str) {
        use tokio::io::AsyncWriteExt as _;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = s.write_all(resp.as_bytes()).await;
    }

    #[tokio::test]
    async fn peer_key_rotation_marks_changed_and_persists() {
        let old_peer = b64_fill(0x42);
        let new_peer = b64_fill(0x43);
        assert_ne!(old_peer, new_peer);
        let dirs = test_dirs("peer-rot");
        seed_identity(&dirs, &old_peer);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        let body = refresh_body("dev-keep-1", &new_peer);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let b = body.clone();
                tokio::spawn(async move {
                    read_head(&mut s).await;
                    write_json(&mut s, &b).await;
                });
            }
        });

        let opts = ProviderOptions {
            provider_base: format!("http://{addr}/v0test"),
            timeout_secs: 5,
            family: "dual".to_string(),
        };
        let report = renew_role(&dirs, IdentityRole::Outer, &opts, None, false).await;
        server.abort();
        assert_eq!(
            report.action,
            ReportAction::Refreshed,
            "peer-only rotation must count as changed: {}",
            report.cause
        );
        assert_eq!(report.exit_code(), 0);
        let stored = load(&dirs, IdentityRole::Outer).expect("stored");
        assert_eq!(
            stored.peer_key_b64, new_peer,
            "rotated peer key must persist"
        );
        assert_eq!(stored.interface_v4, "172.16.0.2");
        let _ = std::fs::remove_dir_all(&dirs.config_dir);
    }

    #[tokio::test]
    async fn refresh_timeout_is_blocked_not_reused() {
        let dirs = test_dirs("timeout-blocked");
        seed_identity(&dirs, &b64_fill(0x42));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt as _;
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                });
            }
        });

        let opts = ProviderOptions {
            provider_base: format!("http://{addr}/v0test"),
            timeout_secs: 1,
            family: "dual".to_string(),
        };
        let report = renew_role(&dirs, IdentityRole::Outer, &opts, None, false).await;
        server.abort();
        assert_eq!(
            report.action,
            ReportAction::Blocked,
            "failed refresh must not masquerade as healthy: {}",
            report.cause
        );
        assert_ne!(report.exit_code(), 0, "blocked renewal must fail closed");
        assert_eq!(report.exit_code(), 2);
        let stored = load(&dirs, IdentityRole::Outer).expect("kept");
        assert_eq!(stored.device_id, "dev-keep-1");
        let _ = std::fs::remove_dir_all(&dirs.config_dir);
    }
}
