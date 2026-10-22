//! TLS for the gemini family — trust-on-first-use connectors.
//!
//! Gemini capsules are conventionally self-signed, so CA-path validation does
//! not apply. Two trust modes:
//!
//! - [`pinning_connector`] (gemini reads): checks the leaf certificate
//!   against the host's pin (from the installed [`crate::TofuStore`]) *inside*
//!   the handshake — accepting a first contact or a matching cert, rejecting a
//!   changed one — so the request is never sent to a host whose certificate no
//!   longer matches.
//!
//! Titan uploads use this same connector through
//! [`crate::client::tofu_connect_inner`], so reads and writes share one trust
//! decision.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::tofu;

/// The leaf fingerprint a pinning handshake presented, written by the
/// verifier and read back by the caller — to pin a first contact, or to build
/// the [`crate::ClientError::CertificateChanged`] error on a rejected change.
pub(crate) type SeenCell = Arc<Mutex<Option<[u8; 32]>>>;

/// A pinning TLS connector for gemini: the leaf certificate is checked against
/// `pinned` (the host's recorded fingerprint, or `None` for a first contact),
/// and the returned [`SeenCell`] receives the fingerprint the handshake
/// presented.
///
/// Built per connection because the pin is per host; the verifier stays
/// `'static` by taking the pin by value rather than borrowing the store.
pub(crate) fn pinning_connector(
    pinned: Option<[u8; 32]>,
    identity: Option<crate::client::ClientIdentity<'_>>,
) -> Result<(TlsConnector, SeenCell), String> {
    let seen: SeenCell = Arc::new(Mutex::new(None));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS protocol versions: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier {
            pinned,
            seen: Arc::clone(&seen),
        }));
    let config = match identity {
        Some(identity) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(identity.certificate_der.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    identity.private_key_pkcs8_der.to_vec(),
                )),
            )
            .map_err(|error| format!("client certificate: {error}"))?,
        None => builder.with_no_client_auth(),
    };
    Ok((TlsConnector::from(Arc::new(config)), seen))
}

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

/// Pins the leaf against `pinned`: records what it saw, accepts a first
/// contact or matching pin, rejects a changed certificate. CA-chain
/// validation is intentionally skipped — gemini has no CA system.
#[derive(Debug)]
struct PinningVerifier {
    pinned: Option<[u8; 32]>,
    seen: SeenCell,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = tofu::fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap() = Some(fingerprint);
        match self.pinned {
            None => Ok(ServerCertVerified::assertion()),
            Some(pinned) if pinned == fingerprint => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(
                "gemini TOFU: certificate fingerprint changed".into(),
            )),
        }
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

    fn verify(verifier: &PinningVerifier, cert: &[u8]) -> Result<(), rustls::Error> {
        let der = CertificateDer::from(cert.to_vec());
        let name = ServerName::try_from("x.test").unwrap();
        verifier
            .verify_server_cert(&der, &[], &name, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn first_contact_accepts_and_records() {
        let seen: SeenCell = Arc::new(Mutex::new(None));
        let verifier = PinningVerifier {
            pinned: None,
            seen: Arc::clone(&seen),
        };
        assert!(verify(&verifier, b"leaf").is_ok());
        assert_eq!(*seen.lock().unwrap(), Some(tofu::fingerprint(b"leaf")));
    }

    #[test]
    fn a_matching_pin_accepts() {
        let verifier = PinningVerifier {
            pinned: Some(tofu::fingerprint(b"leaf")),
            seen: Arc::new(Mutex::new(None)),
        };
        assert!(verify(&verifier, b"leaf").is_ok());
    }

    #[test]
    fn a_changed_cert_is_rejected_but_still_recorded() {
        let seen: SeenCell = Arc::new(Mutex::new(None));
        let verifier = PinningVerifier {
            pinned: Some(tofu::fingerprint(b"old")),
            seen: Arc::clone(&seen),
        };
        assert!(verify(&verifier, b"new").is_err());
        assert_eq!(*seen.lock().unwrap(), Some(tofu::fingerprint(b"new")));
    }
}
