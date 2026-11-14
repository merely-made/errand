//! `gophers://`: the identical gopher wire inside TLS, on the same port 70.
//!
//! There is no formal gophers specification. The scheme, the port, and the
//! plain-TLS wrap are implemented per interoperating practice: the smolnet
//! portal (michael-lazar/smolnet-portal) proxies gophers this way, and real
//! gophers servers answer it.
//!
//! Certificates are accepted without verification, which is stated rather
//! than hidden: there is no CA convention and no recorded TOFU convention in
//! gopherspace, so `gophers://` is best read as "not in the clear" rather
//! than "authenticated peer".

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::client::ClientError;

/// Open a TLS connection for a gophers request.
pub(crate) async fn connect(
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ClientError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Connect(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny { algorithms }))
        .with_no_client_auth();

    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| ClientError::Connect(format!("server name {host}: {e}")))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| ClientError::Connect(format!("tls handshake: {e}")))
}

/// Accepts any certificate. See the module note.
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
