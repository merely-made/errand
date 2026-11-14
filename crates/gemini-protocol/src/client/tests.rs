use super::*;

#[cfg(feature = "tls")]
#[derive(Debug)]
struct AcceptAnyClient;

#[cfg(feature = "tls")]
impl rustls::server::danger::ClientCertVerifier for AcceptAnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
        ]
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn caller_identity_is_presented_in_the_tls_handshake() {
    use std::sync::Arc;

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    // This test is about the client certificate, not server trust.
    crate::set_trust_store(Arc::new(crate::PermissiveTofu));
    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&server_key)
        .unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&client_key)
        .unwrap();
    let expected_client_cert = client_cert.der().to_vec();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(AcceptAnyClient))
        .with_single_cert(
            vec![CertificateDer::from(server_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let presented = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .expect("the client presented its certificate")
            .as_ref()
            .to_vec();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 256];
            let read = tls.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before the Gemini request");
            request.extend_from_slice(&chunk[..read]);
            if request.ends_with(b"\r\n") {
                break;
            }
        }
        tls.write_all(b"20 text/gemini\r\n# identity received\n")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
        presented
    };
    let url = Url::parse(&format!("gemini://localhost:{port}/private")).unwrap();
    let client_key_der = client_key.serialize_der();
    let client = fetch_url_with_identity(
        &url,
        ClientIdentity {
            certificate_der: client_cert.der().as_ref(),
            private_key_pkcs8_der: &client_key_der,
        },
    );
    let (presented, response) = tokio::join!(server, client);

    assert_eq!(presented, expected_client_cert);
    assert_eq!(response.unwrap().body, b"# identity received\n");
}

#[test]
fn parses_success_header_and_body() {
    let r = parse_response(b"20 text/gemini; charset=utf-8\r\n# Hello\nworld\n").unwrap();
    assert_eq!(r.status, Status::Success);
    assert_eq!(r.code, 20);
    assert_eq!(r.mime(), Some("text/gemini"));
    assert_eq!(r.body, b"# Hello\nworld\n");
}

#[test]
fn redirect_meta_is_the_target_and_body_is_dropped() {
    let r = parse_response(b"31 gemini://example.org/moved\r\nignored").unwrap();
    assert_eq!(r.status, Status::Redirect);
    assert_eq!(r.meta, "gemini://example.org/moved");
    assert!(r.body.is_empty());
}

#[test]
fn temporary_and_permanent_failure_stay_apart() {
    // The distinction a client needs in order to know whether retrying is
    // sensible, and the one a flattened `Failure` throws away.
    let temporary = parse_response(b"44 slow down\r\n").unwrap();
    assert_eq!(temporary.status, Status::TemporaryFailure);
    assert_eq!(temporary.code, 44);

    let permanent = parse_response(b"51 not found\r\n").unwrap();
    assert_eq!(permanent.status, Status::PermanentFailure);
    assert_eq!(permanent.code, 51);
}

#[test]
fn cert_required_class() {
    let r = parse_response(b"60 client cert required\r\n").unwrap();
    assert_eq!(r.status, Status::CertificateRequired);
}

#[test]
fn empty_meta_is_fine() {
    let r = parse_response(b"20 \r\nbody").unwrap();
    assert_eq!(r.mime(), None);
    assert_eq!(r.body, b"body");
}

#[test]
fn a_non_success_has_no_mime_even_with_a_meta() {
    let r = parse_response(b"31 gemini://example.org/\r\n").unwrap();
    assert_eq!(r.mime(), None);
}

#[test]
fn missing_crlf_is_a_protocol_error() {
    assert!(matches!(
        parse_response(b"20 text/gemini"),
        Err(ClientError::Protocol(_))
    ));
}

#[test]
fn non_numeric_status_is_a_protocol_error() {
    assert!(matches!(
        parse_response(b"xx nope\r\n"),
        Err(ClientError::Protocol(_))
    ));
}

#[test]
fn an_undefined_status_class_is_refused() {
    assert!(matches!(
        parse_response(b"90 what\r\n"),
        Err(ClientError::Protocol(_))
    ));
}

#[tokio::test]
async fn exchange_runs_over_any_stream() {
    // A mock capsule over an in-memory duplex: no TCP, no TLS. This is the
    // proof the exchange is transport-independent, and the exact code path
    // a Reticulum `LinkStream` (also `AsyncRead + AsyncWrite`) drives.
    let (client, mut server) = tokio::io::duplex(4096);
    let url = Url::parse("gemini://capsule.example/hello").unwrap();

    let server = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"gemini://capsule.example/hello\r\n");
        server
            .write_all(b"20 text/gemini\r\n# Hello over an arbitrary stream\n")
            .await
            .unwrap();
        // Close so the client's read-to-EOF completes.
        server.shutdown().await.unwrap();
    });

    let mut client = client;
    let response = exchange(&url, &mut client).await.unwrap();
    server.await.unwrap();

    assert_eq!(response.status, Status::Success);
    assert_eq!(response.mime(), Some("text/gemini"));
    assert_eq!(response.body, b"# Hello over an arbitrary stream\n");
}

#[tokio::test]
async fn streaming_exchange_reports_a_prefix_before_the_tail_arrives() {
    let (client, mut server) = tokio::io::duplex(4096);
    let url = Url::parse("gemini://capsule.example/live").unwrap();
    let prefix_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server_release = prefix_seen.clone();
    let server = tokio::spawn(async move {
        let mut request = [0_u8; 1024];
        let _ = server.read(&mut request).await.unwrap();
        server
            .write_all(b"20 text/gemini\r\n# Prefix\n")
            .await
            .unwrap();
        while !server_release.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        server.write_all(b"Tail\n").await.unwrap();
        server.shutdown().await.unwrap();
    });

    let mut client = client;
    let mut chunks = Vec::new();
    let response = exchange_streaming(&url, &mut client, |head, chunk| {
        assert_eq!(head.mime(), Some("text/gemini"));
        chunks.push(chunk.to_vec());
        prefix_seen.store(true, std::sync::atomic::Ordering::Release);
    })
    .await
    .unwrap();
    server.await.unwrap();

    assert_eq!(chunks, [b"# Prefix\n".to_vec(), b"Tail\n".to_vec()]);
    assert_eq!(response.body, b"# Prefix\nTail\n");
}

#[tokio::test]
async fn an_over_long_request_never_reaches_the_wire() {
    let (mut client, _server) = tokio::io::duplex(64);
    let url = Url::parse(&format!("gemini://example.org/{}", "x".repeat(1100))).unwrap();
    assert!(matches!(
        exchange(&url, &mut client).await,
        Err(ClientError::Protocol(_))
    ));
}
