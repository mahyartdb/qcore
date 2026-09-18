//! Machine-readable registration outcome (002 data-model
//! `RegistrationReport`, contracts/cli.md).
//!
//! Redacted by construction: the only identity field is the device id.
//! Private keys, access tokens, and license values have no field to live
//! in and MUST never be interpolated into `cause`.

use crate::diag::redact::prefixed_cause;
use crate::session::report::{EXIT_INVALID, EXIT_SUCCESS};
use serde::{Deserialize, Serialize};

/// What one register/renew operation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportAction {
    Registered,
    Reused,
    Refreshed,
    ReRegistered,
    Rotated,
    Refused,
    Blocked,
}

/// Outcome of register/renew/scan-adjacent identity work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationReport {
    pub action: ReportAction,
    pub identity: Option<String>,
    pub endpoint: Option<String>,
    pub cause: String,
    pub license_applied: bool,
}

impl RegistrationReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            "{\"action\":\"blocked\",\"identity\":null,\"endpoint\":null,\"cause\":\"report encode failed\",\"license_applied\":false}".to_string()
        })
    }

    /// Exit mapping (contracts/cli.md): working outcomes are 0;
    /// refused/blocked are exit 2 (fail closed, cause names the next step).
    pub fn exit_code(&self) -> i32 {
        match self.action {
            ReportAction::Registered
            | ReportAction::Reused
            | ReportAction::Refreshed
            | ReportAction::ReRegistered
            | ReportAction::Rotated => EXIT_SUCCESS,
            ReportAction::Refused | ReportAction::Blocked => EXIT_INVALID,
        }
    }
}

/// Registration failure → CLI-facing report (fail closed, exit 2; the cause
/// names the next step and carries no credentials). Shared by fresh
/// registration, renewal, and the connect-time hook.
pub fn report_for_error(e: super::register::RegisterError) -> RegistrationReport {
    use super::register::RegisterError;
    // Enforce the module's no-credentials-in-cause rule at the boundary:
    // provider bodies (220-char `detail`) flow into `e`, and a misbehaving
    // provider could echo secrets. The actionable prefix is always kept;
    // only a secret-like detail is replaced (fail closed) via the shared
    // [`crate::diag::redact::prefixed_cause`] helper.
    let (action, cause) = match e {
        RegisterError::Blocked(e) => (
            ReportAction::Blocked,
            prefixed_cause("provider unreachable: ", &e),
        ),
        RegisterError::Refused(e) => (
            ReportAction::Refused,
            prefixed_cause("provider refused: ", &e),
        ),
        RegisterError::Rejected(e) => (
            ReportAction::Refused,
            prefixed_cause("provider refused registration: ", &e),
        ),
        RegisterError::Protocol(e) => (
            ReportAction::Blocked,
            prefixed_cause("provider answer unusable (client too old?): ", &e),
        ),
    };
    RegistrationReport {
        action,
        identity: None,
        endpoint: None,
        cause,
        license_applied: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_and_exits() {
        let r = RegistrationReport {
            action: ReportAction::ReRegistered,
            identity: Some("dev-1".into()),
            endpoint: None,
            cause: "provider refused the old identity; fresh one provisioned".into(),
            license_applied: false,
        };
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["action"], "re_registered");
        assert_eq!(v["identity"], "dev-1");
        assert_eq!(r.exit_code(), 0);
        let b = RegistrationReport {
            action: ReportAction::Blocked,
            identity: None,
            endpoint: None,
            cause: "provider unreachable".into(),
            license_applied: false,
        };
        assert_eq!(b.exit_code(), 2);
    }

    #[test]
    fn secret_like_provider_detail_is_masked_prefix_kept() {
        let r = report_for_error(super::super::register::RegisterError::Refused(
            "quota gone xT4vN7qW2zR5uY8iO1pA3sD6fG9hJ0kL2mN4bV6cX8dE0gH2==".into(),
        ));
        assert!(
            r.cause.starts_with("provider refused: "),
            "got: {}",
            r.cause
        );
        assert!(
            !r.cause.contains("xT4vN7qW"),
            "secret-like detail leaked: {}",
            r.cause
        );
        assert!(r.cause.contains("<redacted>"), "got: {}", r.cause);
        // Ordinary low-entropy causes pass through untouched.
        let r2 = report_for_error(super::super::register::RegisterError::Blocked(
            "connection refused".into(),
        ));
        assert_eq!(r2.cause, "provider unreachable: connection refused");
    }
}
