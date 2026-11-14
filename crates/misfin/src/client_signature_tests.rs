//! Accepting any self-signed certificate still requires the server to prove
//! it holds the presented certificate's private key by signing the handshake;
//! otherwise anyone replaying a mailbox's public certificate passes its
//! fingerprint pin.

use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{SendError, SendOptions, send, tls_provider};
use crate::{MisfinAddress, MisfinIdentitySpec, deterministic_identity, helpers::sha256_hex};

fn identity(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let material = deterministic_identity(
        &[seed; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("target@localhost").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    (material.certificate_der, material.private_key_pkcs8_der)
}

/// Presents `cert` and signs the handshake with `key`. `CertifiedKey::new`
/// does not check that they match, which lets a test play an impostor.
fn acceptor(
    cert: &[u8],
    key: &[u8],
    version: &'static SupportedProtocolVersion,
) -> tokio_rustls::TlsAcceptor {
    let provider = tls_provider();
    let signer = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())))
        .unwrap();
    let certified = CertifiedKey::new(vec![CertificateDer::from(cert.to_vec())], signer);
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

async fn deliver(
    cert: &[u8],
    key: &[u8],
    version: &'static SupportedProtocolVersion,
) -> Result<super::SendReceipt, SendError> {
    let acceptor = acceptor(cert, key, version);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = acceptor.accept(tcp).await else {
            return;
        };
        let mut byte = [0u8; 1];
        while stream.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {}
        let _ = stream.write_all(b"20 mailbox-fingerprint\r\n").await;
        let _ = stream.shutdown().await;
    });
    let options = SendOptions {
        connect_addr: Some(address),
        expected_fingerprint: Some(sha256_hex(cert)),
        ..SendOptions::default()
    };
    let result = send(
        &MisfinAddress::parse("target@localhost").unwrap(),
        "hello",
        &options,
    )
    .await;
    server.await.unwrap();
    result
}

#[tokio::test]
async fn a_replayed_certificate_without_its_key_is_refused() {
    let (cert, key) = identity(0x61);
    let (_, other_key) = identity(0x62);
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let honest = deliver(&cert, &key, version).await;
        assert!(honest.is_ok(), "{:?}: {honest:?}", version.version);
        let impostor = deliver(&cert, &other_key, version).await;
        assert!(
            impostor.is_err(),
            "{:?}: an impostor signing with another key passed the pin",
            version.version
        );
        println!("{:?}: {impostor:?}", version.version);
    }
}
