//! TLS for `scorpions://`.
//!
//! ## Why this module does not decide trust
//!
//! Scorpion's specification does not say how to validate a server
//! certificate. It says so outright: "There will be a separate document
//! written with further specifications about the handling of certificate
//! validation and of certificate chains", and elsewhere, of pinning, "the
//! specification for doing this is not written yet, and will be written
//! later."
//!
//! So this module carries the transport and leaves the policy to the caller.
//! Shipping a trust-on-first-use store here would be inventing a rule the
//! protocol has not made and presenting it as the protocol's, and a future
//! reader would have no way to tell the invention from the specification.
//! Gemini is a different case -- self-signed plus TOFU *is* its written
//! policy -- which is why `gemini-protocol` in this workspace does ship one.
//!
//! [`connect_with`] takes any `rustls` verifier, so a caller that already has
//! a pinning store, a CA bundle, or a policy of its own supplies it directly.
//! [`accept_any_verifier`] exists for callers that pin the certificate
//! themselves after the handshake, and is named to be hard to reach for by
//! accident.
//!
//! ## Two things the specification *does* require
//!
//! - **Session tickets are not reused.** They can be used for tracking, and
//!   the specification says clients "SHOULD NOT reuse tickets for multiple
//!   connections" (RFC 8446 §C.4). [`base_config`] disables resumption.
//! - **A client certificate over TLS 1.2 deserves a warning**, because client
//!   certificates are not encrypted before TLS 1.3. [`warn_on_client_cert`]
//!   reports whether a negotiated connection is in that position, so a caller
//!   can say so rather than leak an identity silently.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::client::{
    ClientError, DEFAULT_OPERATION_TIMEOUT, authority, deadline_after, within_deadline,
};

/// A `rustls` client config with the specification's transport requirements
/// applied, and `verifier` deciding trust.
pub fn base_config(verifier: Arc<dyn ServerCertVerifier>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provides the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // "clients SHOULD NOT reuse tickets for multiple connections", because a
    // reused ticket is a tracking identifier across connections.
    config.resumption = rustls::client::Resumption::disabled();
    config
}

/// Open a TLS connection to the host in `url`, with `verifier` deciding trust.
pub async fn connect_with(
    url: &str,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<TlsStream<TcpStream>, ClientError> {
    // Resolve malformed caller input before creating a timer.
    authority(url)?;
    let deadline = deadline_after(DEFAULT_OPERATION_TIMEOUT)?;
    connect_with_deadline(url, verifier, deadline).await
}

/// Open TCP/TLS before an absolute caller deadline. Pass the same deadline to
/// `client::exchange_until` and `client::read_response_until` to bound a whole
/// interactive operation without renewing its allowance after the handshake.
pub async fn connect_with_deadline(
    url: &str,
    verifier: Arc<dyn ServerCertVerifier>,
    deadline: tokio::time::Instant,
) -> Result<TlsStream<TcpStream>, ClientError> {
    let (host, port) = authority(url)?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| ClientError::Url(format!("{host} is not a valid server name")))?;
    let connector = TlsConnector::from(Arc::new(base_config(verifier)));
    within_deadline(deadline, async {
        let stream = TcpStream::connect((host.as_str(), port)).await?;
        connector
            .connect(server_name, stream)
            .await
            .map_err(ClientError::Io)
    })
    .await
}

/// A verifier that accepts any server certificate.
///
/// For callers that inspect the peer certificate themselves after the
/// handshake and decide there. It performs **no** validation of any kind, so
/// reaching for it without doing that check leaves the connection open to an
/// active attacker.
pub fn accept_any_verifier() -> Arc<dyn ServerCertVerifier> {
    Arc::new(AcceptAny)
}

/// Whether a negotiated connection would expose a client certificate.
///
/// Client certificates are sent in the clear under TLS 1.2 and earlier and are
/// encrypted from TLS 1.3 on, so the specification says clients "SHOULD warn"
/// in the former case. Returns `true` when a warning is owed.
pub fn warn_on_client_cert(connection: &rustls::ClientConnection) -> bool {
    !matches!(
        connection.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    )
}

/// Accepts anything. See [`accept_any_verifier`].
#[derive(Debug)]
struct AcceptAny;

const ACCEPTED_SCHEMES: [SignatureScheme; 10] = [
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::ED25519,
];

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ACCEPTED_SCHEMES.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_resumption_is_off_because_tickets_track() {
        // A behavioural requirement of the spec, not a preference: a reused
        // ticket is a stable identifier across connections.
        let config = base_config(accept_any_verifier());
        // `Resumption::disabled()` stores nothing; the observable proof is
        // that no session storage is retained between connections.
        let probe = base_config(accept_any_verifier());
        assert_eq!(
            format!("{:?}", config.resumption),
            format!("{:?}", probe.resumption),
            "resumption is configured identically and deliberately"
        );
        assert!(
            format!("{:?}", config.resumption).contains("Disabled"),
            "tickets must not be reused across connections: {:?}",
            config.resumption
        );
    }

    #[test]
    fn a_bad_host_is_refused_before_any_socket_is_opened() {
        // `connect_with` resolves the authority first, so a malformed URL
        // fails without a connection attempt.
        let error = crate::client::authority("scorpions:///no-host").unwrap_err();
        assert!(matches!(error, ClientError::Url(_)));
    }
}
