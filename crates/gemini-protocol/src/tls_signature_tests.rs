//! A pinned certificate is not enough: the server must prove it holds the
//! certificate's private key by signing the handshake.

use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio::net::{TcpListener, TcpStream};

use super::pinning_connector;
use crate::tofu;

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
    pinned: Option<[u8; 32]>,
) -> Result<(), String> {
    let acceptor = acceptor(cert, key, version);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(tcp).await;
    });
    let (connector, _) = pinning_connector(pinned, None).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let result = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
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
    let pin = tofu::fingerprint(real.cert.der().as_ref());
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for pinned in [None, Some(pin)] {
            let honest = handshake(&real.cert, &real.signing_key, version, pinned).await;
            assert!(honest.is_ok(), "{:?}: {honest:?}", version.version);
            let impostor = handshake(&real.cert, &other.signing_key, version, pinned).await;
            assert!(
                impostor.is_err(),
                "{:?}, pinned {}: an impostor signing with another key was accepted",
                version.version,
                pinned.is_some()
            );
            println!(
                "{:?} pinned={}: {}",
                version.version,
                pinned.is_some(),
                impostor.unwrap_err()
            );
        }
    }
}
