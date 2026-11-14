//! Accepting any certificate still requires the server to prove it holds the
//! presented certificate's private key by signing the handshake.

use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio::net::TcpListener;

/// Presents `cert` and signs the handshake with `key`. `CertifiedKey::new`
/// does not check that they match, which lets a test play an impostor that
/// replays a real server's public certificate.
fn acceptor(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    version: &'static SupportedProtocolVersion,
) -> tokio_rustls::TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let signer = provider
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(key.serialize_der()).into())
        .unwrap();
    let certified = CertifiedKey::new(vec![cert.der().clone()], signer);
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

async fn handshake(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    version: &'static SupportedProtocolVersion,
) -> Result<(), String> {
    let acceptor = acceptor(cert, key, version);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(tcp).await;
    });
    let result = super::connect("127.0.0.1", port)
        .await
        .map(drop)
        .map_err(|error| error.to_string());
    server.await.unwrap();
    result
}

#[tokio::test]
async fn a_replayed_certificate_without_its_key_is_refused() {
    let real = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let honest = handshake(&real.cert, &real.signing_key, version).await;
        assert!(honest.is_ok(), "{:?}: {honest:?}", version.version);
        let impostor = handshake(&real.cert, &other.signing_key, version).await;
        assert!(
            impostor.is_err(),
            "{:?}: an impostor signing with another key was accepted",
            version.version
        );
        println!("{:?}: {}", version.version, impostor.unwrap_err());
    }
}
