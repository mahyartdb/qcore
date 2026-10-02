//! MASQUE credential lifecycle (002 FR-005, research R4).
//!
//! Self-issued P-256 via `rcgen` (no hand-rolled X.509), enrolled with the
//! provider, rotated automatically inside the renewal window. The enroll
//! body shape is fixture-defined until the nightly live run validates it
//! against the real provider (isolated here in [`enroll_credential`]).

use crate::config::secret::SecretString;
use crate::identity::https::{request_with_family, HttpMethod};
use crate::identity::model::ProviderIdentity;
use crate::identity::register::{ProviderOptions, RegisterError};
use std::time::Duration;
use zeroize::Zeroizing;

/// Self-issued credential: (certificate PEM public, key PEM secret).
pub fn generate_credential() -> Result<(String, SecretString), String> {
    let key = rcgen::generate_simple_self_signed(vec!["qcore-masque".to_string()])
        .map_err(|e| format!("credential generation failed: {e}"))?;
    Ok((
        key.cert.pem(),
        SecretString::new(key.signing_key.serialize_pem()),
    ))
}

/// Enroll (or rotate) the credential: PATCH the current certificate under
/// the identity. Any 2xx accepts only when the provider does not report an
/// enrollment error in the body (a bare 2xx carrying `{"error": ...}` is
/// still a failed enrollment: rotation must not count as done while the
/// tunnel would fail with an un-enrolled cert). Returns the exchange
/// family (FR-013).
pub async fn enroll_credential(
    opts: &ProviderOptions,
    identity: &ProviderIdentity,
    cert_pem: &str,
) -> Result<String, RegisterError> {
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        return Err(RegisterError::Protocol(
            "enroll refused locally: cert is not PEM-shaped".to_string(),
        ));
    }
    // Device ids ride the URL path: allow only path-safe characters and
    // never build `//` from a trailing-slash base (provider 404s).
    if !identity
        .device_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(RegisterError::Protocol(
            "enroll refused locally: device id is not URL-safe".to_string(),
        ));
    }
    let timeout = Duration::from_secs(opts.timeout_secs.max(1));
    let base = opts.provider_base.trim_end_matches('/');
    let url = format!("{base}/reg/{}", identity.device_id);
    // Transient auth buffer: wiped on drop; earliest-`drop` after the await.
    let token =
        Zeroizing::new(String::from_utf8_lossy(identity.access_token.expose()).into_owned());
    let auth = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let body = serde_json::json!({"cert": cert_pem, "key_type": "secp256r1"}).to_string();
    let (resp, family) = request_with_family(
        HttpMethod::Patch,
        &url,
        &[("Authorization", auth.as_str())],
        Some(body.as_bytes()),
        timeout,
        &opts.family,
    )
    .await?;
    drop(auth);
    drop(token);
    // Non-2xx already errors inside `request_with_family`; a 2xx carrying a
    // provider error object is still a failed enrollment, not success.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(resp.body_str().unwrap_or("")) {
        if v.get("error").is_some_and(|e| !e.is_null()) {
            return Err(RegisterError::Rejected(format!(
                "enrollment refused (status {}): {}",
                resp.status,
                v.get("error")
                    .map(|e| e.to_string().chars().take(120).collect::<String>())
                    .unwrap_or_default()
            )));
        }
    }
    Ok(family)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_credential_is_pem_shaped() {
        let (cert, key) = generate_credential().expect("generates");
        assert!(cert.contains("BEGIN CERTIFICATE"), "cert PEM");
        let key_text = String::from_utf8_lossy(key.expose()).into_owned();
        assert!(key_text.contains("BEGIN PRIVATE KEY"), "key PEM");
        // Two generations differ (fresh randomness, no reuse).
        let (cert2, _) = generate_credential().expect("generates");
        assert_ne!(cert, cert2);
    }
}
