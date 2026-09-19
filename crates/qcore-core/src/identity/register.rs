//! Provider signup/refresh client (002 US1, research R0/R1).
//!
//! JSON shape mirrors the reference core's registration calls (register,
//! refresh, license upgrade); every response is parsed leniently but every
//! missing field fails naming the field. License keys and tokens live only
//! in transient request buffers — never stored, logged, or reported.

use crate::config::secret::SecretString;
use crate::identity::https::{request, request_with_family, HttpError, HttpMethod};
use crate::identity::model::ProviderIdentity;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Default provider base (real API host). Tests point `provider_base` at a
/// loopback fixture double instead (test-only override, never stable CLI).
pub const DEFAULT_PROVIDER_BASE: &str = "https://api.cloudflareclient.com/v0a4471";

/// Provider connection options.
#[derive(Debug, Clone)]
pub struct ProviderOptions {
    pub provider_base: String,
    pub timeout_secs: u64,
    /// `ipv4` | `ipv6` | `dual` (constitution II; the used family is reported).
    pub family: String,
}

impl Default for ProviderOptions {
    fn default() -> Self {
        ProviderOptions {
            provider_base: DEFAULT_PROVIDER_BASE.to_string(),
            timeout_secs: 20,
            family: "dual".to_string(),
        }
    }
}

/// Fresh registration: the identity plus whether a license key was applied.
pub struct RegisterOutcome {
    pub identity: ProviderIdentity,
    pub license_applied: bool,
    /// Set when a license was offered but NOT applied (the identity still
    /// works free-tier; the cause says so plainly — never silent).
    pub license_note: Option<String>,
    /// Address family the registration exchange used (FR-013).
    pub family: String,
}

/// Registration failure, pre-classified for the renewal table (FR-004):
/// only [`RegisterError::Refused`] may trigger re-registration.
#[derive(Debug)]
pub enum RegisterError {
    /// Network/TLS/timeout: the provider was never heard from — keep any
    /// stored identity and rescan/retry instead.
    Blocked(String),
    /// Explicit unknown/revoked/gone answers — re-register fresh.
    Refused(String),
    /// Any other provider answer (decoded excerpt, never credentials).
    Rejected(String),
    /// Unparseable answer or unusable material — names the field.
    Protocol(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::Blocked(e) => write!(f, "provider unreachable (network blocked?): {e}"),
            RegisterError::Refused(e) => write!(f, "identity refused by provider: {e}"),
            RegisterError::Rejected(e) => write!(f, "provider rejected the call: {e}"),
            RegisterError::Protocol(e) => write!(f, "bad provider answer: {e}"),
        }
    }
}

impl From<HttpError> for RegisterError {
    fn from(e: HttpError) -> Self {
        match e {
            HttpError::Blocked(e) => RegisterError::Blocked(e),
            HttpError::Usage(e) => RegisterError::Protocol(e),
            HttpError::Rejected { status, detail } if matches!(status, 401 | 404 | 410) => {
                RegisterError::Refused(format!("status {status}: {detail}"))
            }
            HttpError::Rejected { status, detail } => {
                RegisterError::Rejected(format!("status {status}: {detail}"))
            }
        }
    }
}

/// Register a fresh identity. Generates the X25519 device key locally;
/// nothing is asked of the user (FR-001).
pub async fn register_fresh(
    opts: &ProviderOptions,
    license: Option<&SecretString>,
) -> Result<RegisterOutcome, RegisterError> {
    let (private_key_b64, public_key_b64) = generate_device_key()?;
    let body = registration_body(&public_key_b64);
    let timeout = Duration::from_secs(opts.timeout_secs.max(1));
    let url = format!("{}/reg", opts.provider_base);
    let (resp, family) = request_with_family(
        HttpMethod::Post,
        &url,
        &[],
        Some(body.as_bytes()),
        timeout,
        &opts.family,
    )
    .await?;
    let parsed = parse_registration(resp.body_str().map_err(RegisterError::Protocol)?)?;
    let mut outcome = RegisterOutcome {
        identity: ProviderIdentity {
            device_id: parsed.device_id,
            access_token: SecretString::new(parsed.token),
            private_key_b64,
            peer_key_b64: parsed.peer_key_b64,
            interface_v4: parsed.interface_v4,
            interface_v6: parsed.interface_v6,
            masque: None,
            refused: false,
            license_upgraded: false,
        },
        license_applied: false,
        license_note: None,
        family,
    };
    if let Some(key) = license {
        // License upgrade is best-effort on top of a good registration: a
        // refused key leaves a working free-tier identity, and the outcome
        // says so plainly (never silent).
        let upgrade = apply_license(opts, &outcome.identity, key).await;
        outcome.license_applied = upgrade.applied;
        outcome.license_note = upgrade.note;
        outcome.identity.license_upgraded = upgrade.applied;
    }
    Ok(outcome)
}

/// Refresh a stored identity in place. Returns the current addresses plus
/// whether anything actually changed (unchanged = renew reports `reused`).
pub async fn refresh_stored(
    opts: &ProviderOptions,
    id: &ProviderIdentity,
) -> Result<Refreshed, RegisterError> {
    let timeout = Duration::from_secs(opts.timeout_secs.max(1));
    let url = format!("{}/reg/{}", opts.provider_base, id.device_id);
    // Transient auth buffer: wiped on drop; lives across the await because
    // the request borrows it (earliest-`drop` = right after, by convention).
    let token = Zeroizing::new(String::from_utf8_lossy(id.access_token.expose()).into_owned());
    let auth = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let (resp, family) = request_with_family(
        HttpMethod::Get,
        &url,
        &[("Authorization", auth.as_str())],
        None,
        timeout,
        &opts.family,
    )
    .await?;
    drop(auth);
    drop(token);
    let parsed = parse_registration(resp.body_str().map_err(RegisterError::Protocol)?)?;
    Ok(Refreshed {
        interface_v4: parsed.interface_v4.clone(),
        interface_v6: parsed.interface_v6.clone(),
        changed: parsed.interface_v4 != id.interface_v4
            || parsed.interface_v6 != id.interface_v6
            || parsed.device_id != id.device_id,
        family,
    })
}

/// Current addresses after a refresh.
pub struct Refreshed {
    pub interface_v4: String,
    pub interface_v6: String,
    pub changed: bool,
    /// Address family the refresh exchange used (FR-013).
    pub family: String,
}

/// PUT the license upgrade for one operation. Never fails the registration:
/// any refusal or transport error yields `applied: false` with a note. The
/// key travels in this call's transient buffer only — never persisted,
/// logged, or reported.
pub(crate) async fn apply_license(
    opts: &ProviderOptions,
    id: &ProviderIdentity,
    key: &SecretString,
) -> LicenseUpgrade {
    let timeout = Duration::from_secs(opts.timeout_secs.max(1));
    let url = format!("{}/reg/{}/account", opts.provider_base, id.device_id);
    // Transient buffers (token/auth/body): `Zeroizing` so the wipe is
    // vetted; the key copy drops pre-await (the body carries what the
    // provider needs), the rest drop right after last use.
    let token = Zeroizing::new(String::from_utf8_lossy(id.access_token.expose()).into_owned());
    let auth = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let key_text = Zeroizing::new(String::from_utf8_lossy(key.expose()).into_owned());
    let body = Zeroizing::new(serde_json::json!({"license": key_text.as_str()}).to_string());
    // Drop the plaintext copies at the earliest point (transient buffers;
    // SecretString itself zeroizes on drop).
    drop(key_text);
    let result = request(
        HttpMethod::Put,
        &url,
        &[("Authorization", auth.as_str())],
        Some(body.as_bytes()),
        timeout,
    )
    .await;
    drop(body);
    drop(auth);
    drop(token);
    match result {
        Ok(_) => LicenseUpgrade {
            applied: true,
            note: None,
        },
        Err(HttpError::Rejected { status, .. }) => LicenseUpgrade {
            applied: false,
            note: Some(format!(
                "license upgrade refused (status {status}); identity works free-tier"
            )),
        },
        Err(HttpError::Blocked(e)) => LicenseUpgrade {
            applied: false,
            note: Some(format!(
                "license upgrade not attempted ({e}); identity works free-tier"
            )),
        },
        Err(HttpError::Usage(e)) => LicenseUpgrade {
            applied: false,
            note: Some(format!("license upgrade misconfigured ({e})")),
        },
    }
}

/// One license-upgrade attempt.
pub(crate) struct LicenseUpgrade {
    pub(crate) applied: bool,
    pub(crate) note: Option<String>,
}

struct ParsedRegistration {
    device_id: String,
    token: String,
    peer_key_b64: String,
    interface_v4: String,
    interface_v6: String,
}

/// Parse a register/refresh answer. Every required field is named on absence
/// (FR-010a style); the peer key must decode to 32 bytes.
fn parse_registration(body: &str) -> Result<ParsedRegistration, RegisterError> {
    let proto =
        |what: &str| RegisterError::Protocol(format!("registration answer missing `{what}`"));
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| RegisterError::Protocol(format!("not JSON: {e}")))?;
    let str_at = |ptr: &str, name: &str| {
        v.pointer(ptr)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| proto(name))
    };
    let device_id = str_at("/id", "id")?;
    let token = str_at("/token", "token")?;
    let peer_key_b64 = str_at("/config/peers/0/public_key", "config.peers[0].public_key")?;
    use base64::Engine as _;
    let peer_bytes = base64::engine::general_purpose::STANDARD
        .decode(peer_key_b64.as_bytes())
        .map_err(|_| proto("config.peers[0].public_key (not base64)"))?;
    if peer_bytes.len() != 32 {
        return Err(proto("config.peers[0].public_key (not 32 bytes)"));
    }
    let strip_cidr = |s: String| s.split('/').next().unwrap_or("").to_string();
    let interface_v4 = strip_cidr(str_at(
        "/config/interface/addresses/v4",
        "config.interface.addresses.v4",
    )?);
    let interface_v6 = strip_cidr(str_at(
        "/config/interface/addresses/v6",
        "config.interface.addresses.v6",
    )?);
    Ok(ParsedRegistration {
        device_id,
        token,
        peer_key_b64,
        interface_v4,
        interface_v6,
    })
}

/// Fresh X25519 device keypair via the OS RNG + boringtun (data-plane crate
/// reused for pure key math only — no transport logic leaks into the core).
/// Returns (base64 secret, base64 public).
fn generate_device_key() -> Result<(SecretString, String), RegisterError> {
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk)
        .map_err(|e| RegisterError::Blocked(format!("no OS randomness: {e}")))?;
    let secret = boringtun::x25519::StaticSecret::from(sk);
    let public = boringtun::x25519::PublicKey::from(&secret);
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let private_b64 = engine.encode(sk);
    let public_b64 = engine.encode(public.as_bytes());
    // Vetted wipe (pre-v1 a non-volatile byte loop the optimizer could kill).
    sk.zeroize();
    drop(secret);
    // Empty public keys are never valid — a sanity trip-wire, not secrecy.
    if public_b64.is_empty() {
        return Err(RegisterError::Blocked("key generation failed".to_string()));
    }
    Ok((SecretString::new(private_b64), public_b64))
}

fn registration_body(public_key_b64: &str) -> String {
    let (serial, date) = device_fingerprint();
    serde_json::json!({
        "install_id": "",
        "tos": date,
        "key": public_key_b64,
        "fcm_token": "",
        "model": "PC",
        "serial_number": serial,
        "locale": "en_US",
    })
    .to_string()
}

/// (random hex serial, current-date tos) without a date crate: days-since-
/// epoch → civil date (Hinnant's algorithm).
fn device_fingerprint() -> (String, String) {
    let mut rnd = [0u8; 8];
    if getrandom::getrandom(&mut rnd).is_err() {
        rnd = [0x51u8; 8];
    }
    let serial: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let days = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    // days → civil (H. Hinnant): valid for the whole epoch range we use.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as i64;
    let m = if mp < 10 {
        mp as i64 + 3
    } else {
        mp as i64 - 9
    };
    let date = format!("{:04}-{:02}-{:02}T00:00:00Z", y + (m <= 2) as i64, m, d);
    (serial, date)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture_shape() {
        let body = r#"{"id":"d1","token":"t1","config":{"peers":[{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","endpoint":{"v4":"162.159.192.1:2408"}}],"interface":{"addresses":{"v4":"172.16.0.2/32","v6":"2606:4700:110::2/128"}}},"account":{"type":"free"}}"#;
        let p = parse_registration(body).expect("parses");
        assert_eq!(p.device_id, "d1");
        assert_eq!(p.token, "t1");
        assert_eq!(p.interface_v4, "172.16.0.2");
        assert_eq!(p.interface_v6, "2606:4700:110::2");
    }

    #[test]
    fn missing_fields_name_themselves() {
        // (matched, not unwrap_err: the Ok side carries secrets and has no
        // Debug impl on purpose.)
        let e = match parse_registration(r#"{"id":"d1"}"#) {
            Ok(_) => panic!("must fail without a token"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("token"), "{e}");
        let bad_key = r#"{"id":"d","token":"t","config":{"peers":[{"public_key":"nope"}],"interface":{"addresses":{"v4":"1.2.3.4","v6":"::1"}}}}"#;
        assert!(parse_registration(bad_key).is_err());
    }

    #[test]
    fn keygen_round_trip() {
        let (secret, public_b64) = generate_device_key().expect("keygen");
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;
        assert_eq!(engine.decode(secret.expose()).unwrap().len(), 32);
        assert_eq!(engine.decode(public_b64.as_bytes()).unwrap().len(), 32);
        assert!(!format!("{secret:?}").contains(&engine.encode(secret.expose())));
    }

    #[test]
    fn refusal_statuses_classify() {
        for status in [401u16, 404, 410] {
            let e = RegisterError::from(HttpError::Rejected {
                status,
                detail: "gone".into(),
            });
            assert!(matches!(e, RegisterError::Refused(_)), "{status}");
        }
        for status in [400u16, 429, 500] {
            let e = RegisterError::from(HttpError::Rejected {
                status,
                detail: "busy".into(),
            });
            assert!(!matches!(e, RegisterError::Refused(_)), "{status}");
        }
    }
}
