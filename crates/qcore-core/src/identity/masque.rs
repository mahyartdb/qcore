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

/// Self-issued credential: (certificate PEM public, key PEM secret).
pub fn generate_credential() -> Result<(String, SecretString), String> {
    let key = rcgen::generate_simple_self_signed(vec!["qcore-masque".to_string()])
        .map_err(|e| format!("credential generation failed: {e}"))?;
    Ok((
        key.cert.pem(),
        SecretString::new(key.key_pair.serialize_pem()),
    ))
}

/// Enroll (or rotate) the credential: PATCH the current certificate under
/// the identity. Any 2xx accepts (the local credential is the record).
/// Returns the exchange family (FR-013).
pub async fn enroll_credential(
    opts: &ProviderOptions,
    identity: &ProviderIdentity,
    cert_pem: &str,
) -> Result<String, RegisterError> {
    let timeout = Duration::from_secs(opts.timeout_secs.max(1));
    let url = format!("{}/reg/{}", opts.provider_base, identity.device_id);
    let token = String::from_utf8_lossy(identity.access_token.expose()).into_owned();
    let auth = format!("Bearer {token}");
    let body = serde_json::json!({"cert": cert_pem, "key_type": "secp256r1"}).to_string();
    let (_resp, family) = request_with_family(
        HttpMethod::Patch,
        &url,
        &[("Authorization", auth.as_str())],
        Some(body.as_bytes()),
        timeout,
        &opts.family,
    )
    .await?;
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
