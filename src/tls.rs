use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// TCP connect + TLS handshake share one budget: the probe should never take
/// longer than a single regular HTTP request would
const TLS_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TlsInfo {
    /// Issuer of the end-entity certificate (full distinguished name)
    pub issuer: String,
    /// Days until the certificate expires, negative when already expired
    pub days_left: i64,
    pub self_signed: bool,
}

/// Connects to the host, performs a TLS handshake without validating the
/// certificate chain and analyzes the certificate served by the host.
/// Validation is intentionally skipped: a self-signed or invalid certificate
/// is a finding, not an error, and no sensitive data is transmitted.
pub async fn check_tls(domain: &str) -> Result<TlsInfo, String> {
    let domain = domain.to_string();
    tokio::time::timeout(TLS_TIMEOUT, async {
        let tcp = TcpStream::connect(format!("{domain}:443"))
            .await
            .map_err(|e| format!("TCP connect failed: {e}"))?;
        // Owned server name: the connector requires 'static
        let server_name = ServerName::try_from(domain.as_str().to_string())
            .map_err(|e| format!("invalid server name: {e}"))?;
        let connector = TlsConnector::from(Arc::new(accept_all_config()));
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
        let certificate = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| String::from("no certificate served"))?;
        parse_certificate(certificate)
    })
    .await
    .map_err(|_| String::from("TLS probe timed out"))?
}

fn parse_certificate(certificate: &CertificateDer<'_>) -> Result<TlsInfo, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|e| format!("certificate could not be parsed: {e}"))?;

    let seconds_left = cert.validity().not_after.timestamp() - now_unix();
    Ok(TlsInfo {
        issuer: cert.issuer().to_string(),
        days_left: seconds_left.div_euclid(86_400),
        self_signed: cert.issuer().to_string() == cert.subject().to_string(),
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn accept_all_config() -> ClientConfig {
    let provider = Arc::new(ring_provider::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 1.2/1.3 are always supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth()
}

/// Accepts every certificate: the purpose of the TLS probe is to read the
/// certificate, not to build a trusted connection
#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
