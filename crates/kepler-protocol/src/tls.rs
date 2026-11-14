//! `keplers://`: the same exchange inside TLS.
//!
//! Certificates are accepted without verification. That is deliberate and it
//! is stated rather than hidden: kepler does not mandate encryption at all, so
//! `keplers://` is best read as "not in the clear" rather than "authenticated
//! peer". A caller who needs a verified identity should not infer one from the
//! scheme. Trust-on-first-use pinning, as gemini has, is the obvious upgrade
//! and is not implemented.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::client::{ClientError, Limits, Response, exchange_inner};

pub(crate) async fn exchange_tls(
    host: &str,
    port: u16,
    request: &[u8],
    limits: &Limits,
    deadline: tokio::time::Instant,
) -> Result<Response, ClientError> {
    crate::client::check_deadline(deadline)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Connect(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny { algorithms }))
        .with_no_client_auth();

    crate::client::check_deadline(deadline)?;
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| ClientError::Connect(format!("server name {host}: {e}")))?;
    crate::client::check_deadline(deadline)?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| ClientError::Connect(format!("tls handshake: {e}")))?;

    exchange_inner(stream, request, limits, deadline).await
}

/// Accepts any certificate. See the module note: this is confidentiality
/// without authentication, and the crate says so rather than implying more.
///
/// The handshake signature is still checked against the presented
/// certificate's key, by rustls, so the peer proves it holds that key.
#[derive(Debug)]
struct AcceptAny {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
#[path = "tls_signature_tests.rs"]
mod signature_tests;
