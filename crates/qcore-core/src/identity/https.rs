//! Minimal HTTP/1.1 client for provider registration (002 research R1).
//!
//! Three JSON endpoints (register, refresh, enroll) do not justify a full
//! HTTP stack on the 9-target matrix: this client speaks just enough
//! HTTP/1.1 (`GET`/`POST`/`PATCH`/`PUT`, `Content-Length` and
//! close-delimited and chunked bodies) over the already-vetted workspace
//! `rustls` + `tokio`.
//!
//! Security posture: `https://` anywhere; `http://` ONLY to loopback
//! (fixture doubles via the test-only `--provider` override). Anything
//! else fails closed before a socket opens.

use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// HTTP method for [`request`].
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Patch,
    Put,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Put => "PUT",
        }
    }
}

/// A completed response: status plus raw body. The body is wiped on drop
/// (registration answers carry tokens; callers parse then drop promptly).
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Drop for HttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl HttpResponse {
    pub fn body_str(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.body).map_err(|e| format!("response is not UTF-8: {e}"))
    }
}

/// Client failure, already classified for the renewal table (FR-004):
/// `Blocked` (network/TLS/timeout — identity is kept) vs `Rejected`
/// (the provider answered — the status decides renewal).
#[derive(Debug)]
pub enum HttpError {
    Blocked(String),
    Rejected { status: u16, detail: String },
    Usage(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Blocked(e) => write!(f, "network blocked: {e}"),
            HttpError::Rejected { status, detail } => {
                write!(f, "provider refused (status {status}): {detail}")
            }
            HttpError::Usage(e) => write!(f, "{e}"),
        }
    }
}

struct Url {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

/// Plain-or-TLS byte stream (one non-auto trait per object).
trait ReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ReadWrite for T {}

fn parse_url(url: &str) -> Result<Url, HttpError> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        HttpError::Usage("bad provider URL (need scheme://host/path)".to_string())
    })?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        _ => {
            return Err(HttpError::Usage(
                "provider URL scheme must be https (http only to loopback)".to_string(),
            ))
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| HttpError::Usage("bad provider URL port".to_string()))?,
        ),
        _ => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(HttpError::Usage(
            "bad provider URL (empty host)".to_string(),
        ));
    }
    if !tls && !is_loopback(&host) {
        return Err(HttpError::Usage(
            "plaintext http is only allowed to loopback fixture doubles".to_string(),
        ));
    }
    Ok(Url {
        tls,
        host,
        port,
        path,
    })
}

fn is_loopback(host: &str) -> bool {
    let h = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    h == "localhost"
        || h == "::1"
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// One request/response exchange within `timeout` (overall budget).
/// `headers` are extra `Name: value` pairs (e.g. authorization); never logged.
/// `family` is `ipv4` | `ipv6` | `dual` (constitution II: the used family is
/// reported back so callers can name it).
pub async fn request(
    method: HttpMethod,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, HttpError> {
    request_with_family(method, url, headers, body, timeout, "dual")
        .await
        .map(|(r, _)| r)
}

/// [`request`] plus the connected address family (`"ipv4"`/`"ipv6"`).
pub async fn request_with_family(
    method: HttpMethod,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    family: &str,
) -> Result<(HttpResponse, String), HttpError> {
    let u = parse_url(url)?;
    // Header values may carry bearer tokens: owned `Zeroizing` so the copies
    // wipe on drop instead of lingering as plain `String`s.
    let owned: Vec<(String, Zeroizing<String>)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
        .collect();
    tokio::time::timeout(
        timeout,
        exchange(method, &u, &owned, body.unwrap_or_default(), family),
    )
    .await
    .map_err(|_| HttpError::Blocked(format!("timed out after {}s", timeout.as_secs().max(1))))?
}

async fn exchange(
    method: HttpMethod,
    u: &Url,
    headers: &[(String, Zeroizing<String>)],
    body: &[u8],
    family: &str,
) -> Result<(HttpResponse, String), HttpError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Resolve + filter by family (constitution II); dual keeps resolver order.
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host(format!("{}:{}", u.host, u.port))
            .await
            .map_err(|e| HttpError::Blocked(format!("resolve {}: {e}", u.host)))?
            .collect();
    match family {
        "ipv4" => addrs.retain(|a| a.is_ipv4()),
        "ipv6" => addrs.retain(|a| a.is_ipv6()),
        _ => {}
    }
    if addrs.is_empty() {
        return Err(HttpError::Blocked(format!(
            "no {family} address for {}",
            u.host
        )));
    }
    let mut last_err = String::new();
    let mut connected: Option<(tokio::net::TcpStream, String)> = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => {
                connected = Some((tcp, family_of(addr)));
                break;
            }
            Err(e) => last_err = format!("connect {addr}: {e}"),
        }
    }
    let (tcp, used_family) = connected.ok_or(HttpError::Blocked(last_err))?;
    // Unify plain/TLS behind one object-safe stream.
    let mut stream: Box<dyn ReadWrite> = if u.tls {
        tls_wrap(&u.host, tcp).await?
    } else {
        Box::new(tcp)
    };
    // The request head embeds authorization values: `Zeroizing` so the
    // buffer wipes on drop; dropped right after the write (earliest point).
    let mut req = Zeroizing::new(format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        method.as_str(),
        u.path,
        u.host,
        body.len()
    ));
    for (k, v) in headers {
        req.push_str(&format!("{k}: {}\r\n", **v));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| HttpError::Blocked(format!("request write: {e}")))?;
    drop(req);
    stream
        .write_all(body)
        .await
        .map_err(|e| HttpError::Blocked(format!("request write: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| HttpError::Blocked(format!("request flush: {e}")))?;
    // Close-delimited: read to EOF, capped (registration answers are small).
    // The buffer may hold tokens: `Zeroizing` wipes it after parsing.
    let mut raw = Zeroizing::new(Vec::new());
    let mut buf = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| HttpError::Blocked(format!("response read: {e}")))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > 4 * 1024 * 1024 {
            return Err(HttpError::Blocked("response too large".to_string()));
        }
    }
    buf.zeroize();
    let resp = parse_response(&raw)?;
    Ok((resp, used_family))
}

async fn tls_wrap(host: &str, tcp: tokio::net::TcpStream) -> Result<Box<dyn ReadWrite>, HttpError> {
    let connector = tokio_rustls::TlsConnector::from(tls_config()?);
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| HttpError::Usage(format!("https to `{host}` needs a DNS name")))?;
    let tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| HttpError::Blocked(format!("TLS to {host}: {e}")))?;
    Ok(Box::new(tls))
}

/// TLS client config with an explicit crypto provider. `ClientConfig::
/// builder()` panics at runtime when the tree enables both `ring` and
/// `aws-lc-rs` (ours does: quinn vs arti) because no process default can be
/// auto-picked — so we name `ring` explicitly and touch no global state.
fn tls_config() -> Result<std::sync::Arc<rustls::ClientConfig>, HttpError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| HttpError::Blocked(format!("TLS setup: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(std::sync::Arc::new(config))
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, HttpError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| HttpError::Blocked("truncated response headers".to_string()))?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| HttpError::Blocked("response headers are not UTF-8".to_string()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpError::Blocked(format!("bad status line: {status_line}")))?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => content_length = v.trim().parse().ok(),
                "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => {
                    chunked = true;
                }
                _ => {}
            }
        }
    }
    let mut body = raw[header_end + 4..].to_vec();
    if chunked {
        body = decode_chunked(&body)?;
    } else if let Some(n) = content_length {
        if body.len() > n {
            body.truncate(n);
        }
    }
    if !(200..300).contains(&status) {
        let detail = String::from_utf8_lossy(&body);
        let short: String = detail.chars().take(220).collect();
        return Err(HttpError::Rejected {
            status,
            detail: if short.trim().is_empty() {
                "no details returned".to_string()
            } else {
                short
            },
        });
    }
    Ok(HttpResponse { status, body })
}

fn family_of(addr: std::net::SocketAddr) -> String {
    if addr.is_ipv4() {
        "ipv4".to_string()
    } else {
        "ipv6".to_string()
    }
}

fn decode_chunked(raw: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut rest = raw;
    loop {
        let eol = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| HttpError::Blocked("bad chunked body".to_string()))?;
        let size_line = std::str::from_utf8(&rest[..eol])
            .map_err(|_| HttpError::Blocked("bad chunked body".to_string()))?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| HttpError::Blocked("bad chunked body".to_string()))?;
        rest = &rest[eol + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 {
            return Err(HttpError::Blocked("truncated chunked body".to_string()));
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_builds_without_a_process_default() {
        // Regression: ClientConfig::builder() panics when the tree enables
        // both ring and aws-lc-rs (quinn vs arti). The explicit provider
        // must build with no global installed and no network.
        tls_config().expect("explicit ring provider builds");
    }

    #[test]
    fn plaintext_only_to_loopback() {
        assert!(parse_url("https://api.example.com/reg").is_ok());
        assert!(parse_url("http://127.0.0.1:9/fixture").is_ok());
        assert!(parse_url("http://[::1]:9/x").is_ok());
        assert!(parse_url("http://example.com/reg").is_err());
        assert!(parse_url("http://10.0.0.1/reg").is_err());
        assert!(parse_url("no-scheme").is_err());
    }

    #[tokio::test]
    async fn loopback_round_trip() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("POST /reg HTTP/1.1"));
            let body = r#"{"id":"d1"}"#;
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });
        let r = request(
            HttpMethod::Post,
            &format!("http://{addr}/reg"),
            &[],
            Some(br#"{"key":"abc"}"#),
            Duration::from_secs(5),
        )
        .await
        .expect("round trip");
        assert_eq!(r.status, 200);
        assert_eq!(r.body_str().unwrap(), r#"{"id":"d1"}"#);
    }

    #[tokio::test]
    async fn non_2xx_is_rejected_with_status() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"error\":\"unknown\"}")
                .await
                .unwrap();
        });
        let e = request(
            HttpMethod::Get,
            &format!("http://{addr}/reg/nope"),
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, HttpError::Rejected { status: 404, .. }), "{e}");
    }
}
