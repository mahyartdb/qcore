//! Loopback responders: real QUIC (h3) and HTTP/2 (h2) peers that echo
//! streams and datagrams. Used by the dual-stack conformance suite (US1).

use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};

/// Test-only certificate verifier: accepts any server cert on loopback.
/// NEVER used outside tests (production uses native roots).
#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    crate::ensure_provider();
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| format!("private key: {e}"))?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    )))
}

use std::sync::Arc;

/// A QUIC responder: echoes bidirectional streams, echoes DATAGRAM frames.
pub struct QuinnResponder {
    pub addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl QuinnResponder {
    pub async fn spawn(
        bind_ip: IpAddr,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let endpoint = quinn::Endpoint::server(
            server_config(cert_der, key_der)?,
            SocketAddr::new(bind_ip, 0),
        )?;
        let addr = endpoint.local_addr()?;
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                tokio::spawn(async move {
                    // Datagram echo loop.
                    let dgram_conn = conn.clone();
                    let dgram_task = tokio::spawn(async move {
                        loop {
                            let Ok(dg) = dgram_conn.read_datagram().await else {
                                break;
                            };
                            if dgram_conn.send_datagram(dg).is_err() {
                                break;
                            }
                        }
                    });
                    // Stream echo loop.
                    loop {
                        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                            break;
                        };
                        tokio::spawn(async move {
                            let mut buf = [0u8; 16384];
                            loop {
                                match recv.read(&mut buf).await {
                                    Ok(None) => break,
                                    Ok(Some(n)) => {
                                        if send.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            let _ = send.finish();
                        });
                    }
                    dgram_task.abort();
                });
            }
        });
        Ok(QuinnResponder { addr, _task: task })
    }
}

/// An HTTP/2 responder: echoes POST request bodies back as response bodies
/// (chunk for chunk), which is exactly what the h2 egress channels need.
pub struct H2Responder {
    pub addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl H2Responder {
    pub async fn spawn(bind_ip: IpAddr) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind_ip, 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::handshake(tcp).await else {
                        return;
                    };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        let mut body = req.into_body();
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let Ok(mut send) = respond.send_response(response, false) else {
                            break;
                        };
                        tokio::spawn(async move {
                            while let Some(chunk) = body.data().await {
                                let Ok(data) = chunk else { break };
                                let n = data.len();
                                if send.send_data(data, false).is_err() {
                                    break;
                                }
                                body.flow_control().release_capacity(n).ok();
                            }
                            let _ = send.send_data(Bytes::new(), true);
                        });
                    }
                });
            }
        });
        Ok(H2Responder { addr, _task: task })
    }
}
