use super::*;
use crate::ExposeSecret;
use crate::{MisfinIdentitySpec, MisfinStatus, client, deterministic_identity};
use rustls::{
    DigitallySignedStruct, SignatureScheme, client::danger::HandshakeSignatureValid,
    pki_types::UnixTime,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A "now" inside the minted certificates' validity window (2024-2099).
const NOW: u64 = 1_750_000_000;

fn spec(addr: &str) -> MisfinIdentitySpec {
    MisfinIdentitySpec {
        address: MisfinAddress::parse(addr).unwrap(),
        blurb: Some("Test".to_string()),
    }
}

/// Mint a certificate DER for use as a peer/client certificate in a test.
pub(super) fn cert_der(seed: u8, addr: &str) -> Vec<u8> {
    deterministic_identity(&[seed; 32], &spec(addr))
        .unwrap()
        .certificate_der
}

pub(super) fn dispatcher_for(mailbox: &str) -> (Dispatcher, String) {
    let identity = deterministic_identity(&[9u8; 32], &spec(mailbox)).unwrap();
    let fingerprint = sha256_hex(&identity.certificate_der);
    let dispatcher = Dispatcher {
        served: vec![ServedMailbox {
            address: MisfinAddress::parse(mailbox).unwrap(),
            fingerprint: fingerprint.clone(),
        }],
        store: MailboxStore::in_memory().unwrap(),
        require_sender_identity: false,
        reject_changed_sender: true,
    };
    (dispatcher, fingerprint)
}

#[test]
fn response_encodes_status_and_meta() {
    assert_eq!(MisfinResponse::new(20, "abc").encode(), "20 abc\r\n");
    assert_eq!(
        MisfinResponse::new(51, "Mailbox doesn't exist.").encode(),
        "51 Mailbox doesn't exist.\r\n"
    );
}

#[test]
fn no_certificate_is_rejected_with_60() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let response = dispatcher.dispatch("misfin://mark@example.test hi", None, NOW);
    assert_eq!(response.status, 60);
}

#[test]
fn malformed_request_is_rejected_with_59() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    // No space → no message.
    assert_eq!(
        dispatcher
            .dispatch("misfin://mark@example.test", Some(&cert), NOW)
            .status,
        59
    );
    // Wrong scheme.
    assert_eq!(
        dispatcher
            .dispatch("gemini://mark@example.test hi", Some(&cert), NOW)
            .status,
        59
    );
}

#[test]
fn unserved_host_is_rejected_with_53() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let response = dispatcher.dispatch("misfin://mark@elsewhere.test hi", Some(&cert), NOW);
    assert_eq!(response.status, 53);
}

#[test]
fn unknown_mailbox_on_served_host_is_rejected_with_51() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let response = dispatcher.dispatch("misfin://ghost@example.test hi", Some(&cert), NOW);
    assert_eq!(response.status, 51);
}

#[test]
fn delivered_message_records_the_claimed_sender_identity() {
    let (dispatcher, recipient_fingerprint) = dispatcher_for("mark@example.test");
    let sender_der = cert_der(3, "ana@other.test");
    let cert = CertificateDer::from(sender_der.clone());

    let response = dispatcher.dispatch("misfin://mark@example.test Hello Mark", Some(&cert), NOW);
    assert_eq!(response.status, 20);
    assert_eq!(
        response.meta, recipient_fingerprint,
        "META is the recipient's fingerprint"
    );

    let inbox = dispatcher.store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "Hello Mark");
    assert_eq!(inbox[0].sender_fingerprint, sha256_hex(&sender_der));
    assert_eq!(inbox[0].sender_address.as_deref(), Some("ana@other.test"));
    assert_eq!(inbox[0].received_at, NOW);
}

#[test]
fn a_changed_fingerprint_for_a_known_identity_is_rejected_with_63() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let first = CertificateDer::from(cert_der(3, "ana@other.test"));
    let second = CertificateDer::from(cert_der(4, "ana@other.test"));

    assert_eq!(
        dispatcher
            .dispatch("misfin://mark@example.test hi", Some(&first), NOW)
            .status,
        20
    );
    let response = dispatcher.dispatch(
        "misfin://mark@example.test hi again",
        Some(&second),
        NOW + 1,
    );
    assert_eq!(response.status, 63, "same claimed address, new key");

    // The original key keeps working.
    assert_eq!(
        dispatcher
            .dispatch("misfin://mark@example.test still me", Some(&first), NOW + 2)
            .status,
        20
    );
}

#[test]
fn an_expired_certificate_is_rejected_with_62() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let expired =
        crate::identity::identity_with_validity_years(&spec("old@stale.test"), 2001, 2003).unwrap();
    let cert = CertificateDer::from(expired.certificate_der);
    // `now` far beyond 2003.
    let response = dispatcher.dispatch("misfin://mark@example.test hi", Some(&cert), 1_800_000_000);
    assert_eq!(response.status, 62);
}

#[tokio::test]
async fn round_trip_delivers_over_tls_via_the_public_client() {
    let server_identity = deterministic_identity(&[1u8; 32], &spec("mark@example.test")).unwrap();
    let server_fingerprint = sha256_hex(&server_identity.certificate_der);
    let store = MailboxStore::in_memory().unwrap();
    let config = MisfinServerConfig::new(
        server_identity.certificate_der.clone(),
        server_identity
            .private_key_pkcs8_der
            .expose_secret()
            .to_vec(),
        vec![ServedMailbox {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            fingerprint: server_fingerprint.clone(),
        }],
    );
    let server = MisfinServer::new(config, store.clone()).unwrap();
    let bound = server.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = bound.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serve = tokio::spawn(async move {
        let _ = bound
            .serve(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let sender = deterministic_identity(&[2u8; 32], &spec("ana@other.test")).unwrap();
    let options = client::SendOptions {
        identity: Some(sender),
        connect_addr: Some(addr),
        expected_fingerprint: Some(server_fingerprint.clone()),
        ..Default::default()
    };
    let receipt = client::send(
        &MisfinAddress::parse("mark@example.test").unwrap(),
        "Hi from Ana",
        &options,
    )
    .await
    .unwrap();

    assert_eq!(receipt.status, MisfinStatus::Delivered);
    assert_eq!(receipt.meta, server_fingerprint);
    assert_eq!(receipt.server_fingerprint, server_fingerprint);
    let inbox = store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "Hi from Ana");
    assert_eq!(inbox[0].sender_address.as_deref(), Some("ana@other.test"));

    let _ = shutdown_tx.send(());
    let _ = serve.await;
}

#[tokio::test]
async fn an_over_long_request_line_gets_59() {
    let server_identity = deterministic_identity(&[1u8; 32], &spec("mark@example.test")).unwrap();
    let fingerprint = sha256_hex(&server_identity.certificate_der);
    let config = MisfinServerConfig::new(
        server_identity.certificate_der.clone(),
        server_identity
            .private_key_pkcs8_der
            .expose_secret()
            .to_vec(),
        vec![ServedMailbox {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            fingerprint,
        }],
    );
    let server = MisfinServer::new(config, MailboxStore::in_memory().unwrap()).unwrap();
    let bound = server.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = bound.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let serve = tokio::spawn(async move {
        let _ = bound
            .serve(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    // Raw client: 3000 bytes, no CRLF.
    let raw = raw_exchange(addr, &"x".repeat(3000)).await;
    assert!(raw.starts_with("59 "), "expected 59, got {raw:?}");

    let _ = shutdown_tx.send(());
    let _ = serve.await;
}

/// A raw TLS exchange for wire-level tests the public client refuses to
/// produce (e.g. over-long request lines).
async fn raw_exchange(addr: SocketAddr, line: &str) -> String {
    let mut tls = test_tls_client(addr).await;
    tls.write_all(format!("{line}\r\n").as_bytes())
        .await
        .unwrap();
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.unwrap();
    String::from_utf8_lossy(&raw).to_string()
}

pub(super) async fn test_tls_client(
    addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::ServerName;

    #[derive(Debug)]
    struct AcceptAnyServer;
    impl ServerCertVerifier for AcceptAnyServer {
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
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ]
        }
    }

    let config = rustls::ClientConfig::builder_with_provider(crate::client::tls_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    connector.connect(server_name, tcp).await.unwrap()
}
