//! A sender is identified by its client certificate's fingerprint, so the
//! server must make the sender prove it holds that certificate's private key
//! (the CertificateVerify signature); otherwise anyone replaying a sender's
//! public certificate can send mail as them.

use crate::ExposeSecret;
use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{MisfinServer, MisfinServerConfig};
use crate::client::tls_provider;
use crate::{
    MailboxStore, MisfinAddress, MisfinIdentitySpec, ServedMailbox, deterministic_identity,
    helpers::sha256_hex,
};

const MAILBOX: &str = "mark@example.test";

fn identity(seed: u8, address: &str) -> (Vec<u8>, Vec<u8>) {
    let material = deterministic_identity(
        &[seed; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse(address).unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    (
        material.certificate_der.clone(),
        material.private_key_pkcs8_der.expose_secret().to_vec(),
    )
}

/// The test client's own view of the server: any certificate, checked
/// signatures, all through rustls.
#[derive(Debug)]
struct AnyServer(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AnyServer {
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
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Sends one message presenting `cert` while signing with `key`, and returns
/// whatever the server answered (empty when it dropped the connection).
async fn send_as(
    address: std::net::SocketAddr,
    cert: &[u8],
    key: &[u8],
    version: &'static SupportedProtocolVersion,
) -> Vec<u8> {
    let provider = tls_provider();
    let signer = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())))
        .unwrap();
    let certified = CertifiedKey::new(vec![CertificateDer::from(cert.to_vec())], signer);
    let algorithms = provider.signature_verification_algorithms;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(algorithms)))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let Ok(mut stream) = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("example.test").unwrap(), tcp)
        .await
    else {
        return Vec::new();
    };
    let mut reply = Vec::new();
    if stream
        .write_all(format!("misfin://{MAILBOX} hello\r\n").as_bytes())
        .await
        .is_ok()
    {
        let _ = stream.read_to_end(&mut reply).await;
    }
    reply
}

#[tokio::test]
async fn a_replayed_sender_certificate_without_its_key_is_refused() {
    let (server_cert, server_key) = identity(1, MAILBOX);
    let config = MisfinServerConfig::new(
        server_cert.clone(),
        server_key,
        vec![ServedMailbox {
            address: MisfinAddress::parse(MAILBOX).unwrap(),
            fingerprint: sha256_hex(&server_cert),
        }],
    );
    let store = MailboxStore::in_memory().unwrap();
    let bound = MisfinServer::new(config, store.clone())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(bound.serve(async {
        let _ = stop_rx.await;
    }));

    let (sender_cert, sender_key) = identity(2, "ana@other.test");
    let (_, other_key) = identity(3, "ana@other.test");
    let mut delivered = 0;
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let honest = send_as(address, &sender_cert, &sender_key, version).await;
        assert!(
            honest.starts_with(b"20 "),
            "{:?}: {honest:?}",
            version.version
        );
        delivered += 1;
        let impostor = send_as(address, &sender_cert, &other_key, version).await;
        println!(
            "{:?}: impostor got {:?}",
            version.version,
            String::from_utf8_lossy(&impostor)
        );
        assert!(
            !impostor.starts_with(b"20 "),
            "{:?}: an impostor signing with another key sent mail as the sender",
            version.version
        );
        assert_eq!(store.list(MAILBOX).unwrap().len(), delivered);
    }
    stop_tx.send(()).unwrap();
    serve.await.unwrap().unwrap();
}
