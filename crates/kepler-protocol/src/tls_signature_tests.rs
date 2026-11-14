//! Accepting any certificate still requires the server to prove it holds the
//! presented certificate's private key by signing the handshake.

use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::client::{ClientError, fetch};

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

async fn exchange(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    version: &'static SupportedProtocolVersion,
) -> Result<Vec<u8>, ClientError> {
    let acceptor = acceptor(cert, key, version);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("keplers://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = acceptor.accept(tcp).await else {
            return;
        };
        let mut byte = [0u8; 1];
        while stream.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {}
        let _ = stream.write_all(b"20 4 12 34 text/plain\r\nabcd").await;
        let _ = stream.shutdown().await;
    });
    let result = fetch(&url, 123, "en").await.map(|response| response.body);
    server.await.unwrap();
    result
}

#[tokio::test]
async fn a_replayed_certificate_without_its_key_is_refused() {
    let real = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let honest = exchange(&real.cert, &real.signing_key, version).await;
        assert_eq!(honest.unwrap(), b"abcd", "{:?}", version.version);
        let impostor = exchange(&real.cert, &other.signing_key, version).await;
        assert!(
            matches!(&impostor, Err(ClientError::Connect(message)) if message.starts_with("tls handshake")),
            "{:?}: an impostor signing with another key was not refused: {impostor:?}",
            version.version
        );
        println!("{:?}: {impostor:?}", version.version);
    }
}
