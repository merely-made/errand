//! With a pinning store installed, a first contact is pinned and a changed
//! certificate on the same target is refused. Its own test binary, because
//! the store is process-wide.
#![cfg(feature = "tls")]

use std::sync::Arc;

use gemini_protocol::{ClientError, InMemoryTofu, set_trust_store};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn acceptor() -> TlsAcceptor {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

#[tokio::test]
async fn a_changed_certificate_is_refused_once_pinned() {
    set_trust_store(Arc::new(InMemoryTofu::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Two connections to one target, each answered with a different
    // certificate. The second server records whether any request arrived.
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor().accept(tcp).await.unwrap();
        let mut request = [0u8; 256];
        let _ = tls.read(&mut request).await.unwrap();
        tls.write_all(b"20 text/gemini\r\nfirst\n").await.unwrap();
        tls.shutdown().await.unwrap();

        let (tcp, _) = listener.accept().await.unwrap();
        match acceptor().accept(tcp).await {
            Ok(mut tls) => {
                let mut request = Vec::new();
                let _ = tls.read_to_end(&mut request).await;
                request
            }
            Err(_) => Vec::new(),
        }
    });

    let url = format!("gemini://localhost:{port}/");
    let first = gemini_protocol::fetch(&url).await.unwrap();
    assert_eq!(
        first.body, b"first\n",
        "first contact is accepted and pinned"
    );

    match gemini_protocol::fetch(&url).await {
        Err(ClientError::CertificateChanged { host, pinned, seen }) => {
            assert_eq!(host, format!("localhost:{port}"));
            assert_ne!(pinned, seen);
        }
        other => panic!("expected CertificateChanged, got {other:?}"),
    }
    assert!(
        server.await.unwrap().is_empty(),
        "no request bytes reach a server whose certificate changed"
    );
}
