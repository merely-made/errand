//! Admission and joined-shutdown behavior for the public Misfin listener.

use std::future;
use std::io;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::{advance, timeout};

use super::{MisfinServer, MisfinServerConfig, finish_connections};
use crate::{
    MailboxStore, MisfinAddress, MisfinIdentitySpec, ServedMailbox, deterministic_identity,
};

fn test_identity(seed: u8, address: &str) -> (Vec<u8>, Vec<u8>) {
    let identity = deterministic_identity(
        &[seed; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse(address).unwrap(),
            blurb: Some("lifecycle test".into()),
        },
    )
    .unwrap();
    (identity.certificate_der, identity.private_key_pkcs8_der)
}

fn config_for(address: &str) -> (MisfinServerConfig, String) {
    let (certificate, private_key) = test_identity(1, address);
    let fingerprint = crate::helpers::sha256_hex(&certificate);
    let config = MisfinServerConfig::new(
        certificate,
        private_key,
        vec![ServedMailbox {
            address: MisfinAddress::parse(address).unwrap(),
            fingerprint: fingerprint.clone(),
        }],
    );
    (config, fingerprint)
}

fn assert_peer_closed(error: io::Error) {
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ),
        "expected transport closure, got {error}"
    );
}

#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verify_tls12_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

async fn identity_tls_client(
    addr: SocketAddr,
    identity: &(Vec<u8>, Vec<u8>),
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let config = rustls::ClientConfig::builder_with_provider(crate::client::tls_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_client_auth_cert(
            vec![CertificateDer::from(identity.0.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.1.clone())),
        )
        .unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("example.test").unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .unwrap()
}

#[test]
fn finite_admission_and_grace_defaults_and_validation_precede_tls_setup() {
    let mut config = MisfinServerConfig::new(Vec::new(), Vec::new(), Vec::new());
    assert_eq!(config.max_connections, 32);
    assert_eq!(config.shutdown_grace, Duration::from_secs(5));

    config.max_connections = 0;
    match MisfinServer::new(config, MailboxStore::in_memory().unwrap()) {
        Err(crate::MisfinServerError::Config(message)) => {
            assert_eq!(message, "invalid misfin connection limit")
        }
        _ => panic!("zero connection limit must fail before malformed TLS material is inspected"),
    }

    let mut config = MisfinServerConfig::new(Vec::new(), Vec::new(), Vec::new());
    config.shutdown_grace = Duration::MAX;
    match MisfinServer::new(config, MailboxStore::in_memory().unwrap()) {
        Err(crate::MisfinServerError::Config(message)) => {
            assert_eq!(message, "invalid misfin shutdown grace")
        }
        _ => panic!(
            "unrepresentable shutdown grace must fail before malformed TLS material is inspected"
        ),
    }

    // Zero grace is an explicit immediate-abort policy.
    let (config, _) = config_for("mark@example.test");
    let mut config = config;
    config.shutdown_grace = Duration::ZERO;
    assert!(MisfinServer::new(config, MailboxStore::in_memory().unwrap()).is_ok());
}

#[tokio::test]
async fn an_incomplete_request_releases_the_only_admission_slot() {
    let (mut config, _) = config_for("mark@example.test");
    config.max_connections = 1;
    config.timeout = Duration::from_secs(3);
    config.receive_timeout = Duration::from_secs(6);
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

    // A completed TLS handshake proves the first connection was admitted.
    // It remains blocked in request read until the peer is dropped below.
    let first = super::tests::test_tls_client(address).await;
    let sender = deterministic_identity(
        &[2; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("ana@other.test").unwrap(),
            blurb: Some("lifecycle test".into()),
        },
    )
    .unwrap();
    let options = crate::client::SendOptions {
        identity: Some(sender),
        connect_addr: Some(address),
        ..Default::default()
    };
    let mut second_send = tokio::spawn(async move {
        crate::client::send(
            &MisfinAddress::parse("mark@example.test").unwrap(),
            "after failure",
            &options,
        )
        .await
    });
    assert!(
        timeout(Duration::from_millis(700), &mut second_send)
            .await
            .is_err(),
        "the second TLS transaction must remain queued while the first occupies capacity"
    );

    drop(first); // Failed/incomplete first request releases its JoinSet slot.
    let receipt = timeout(Duration::from_secs(5), second_send)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, crate::MisfinStatus::Delivered);
    let inbox = store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "after failure");
    stop_tx.send(()).unwrap();
    serve.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_drains_admitted_mail_before_returning() {
    let (config, expected_fingerprint) = config_for("mark@example.test");
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

    let sender = test_identity(3, "ana@other.test");
    let mut tls = identity_tls_client(address, &sender).await;
    tokio::task::yield_now().await; // Let the server finish the admitted TLS handshake and wait for a request.
    stop_tx.send(()).unwrap();
    tls.write_all(b"misfin://mark@example.test during shutdown\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        format!("20 {expected_fingerprint}\r\n")
    );

    timeout(Duration::from_secs(3), serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let inbox = store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "during shutdown");
}

#[tokio::test]
async fn shutdown_aborts_and_joins_an_admitted_request_peer_after_grace() {
    let (mut config, _) = config_for("mark@example.test");
    config.shutdown_grace = Duration::from_secs(1);
    let bound = MisfinServer::new(config, MailboxStore::in_memory().unwrap())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(bound.serve(async {
        let _ = stop_rx.await;
    }));
    let mut peer = super::tests::test_tls_client(address).await;
    stop_tx.send(()).unwrap();
    let started = tokio::time::Instant::now();
    timeout(Duration::from_secs(3), serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "admitted work receives the configured grace"
    );
    assert_peer_closed(
        timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .unwrap()
            .unwrap_err(),
    );
}

struct DropMark(Arc<AtomicUsize>);
impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn shutdown_joins_a_peer_stalled_inside_the_tls_handshake() {
    let (mut config, _) = config_for("mark@example.test");
    config.shutdown_grace = Duration::from_millis(700);
    let store = MailboxStore::in_memory().unwrap();
    let bound = MisfinServer::new(config, store.clone())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(bound.serve(async {
        let _ = stopped.await;
    }));
    let client_config = rustls::ClientConfig::builder_with_provider(crate::client::tls_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("example.test").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
    peer.write_all(&hello).await.unwrap();
    // A native ServerHello proves acceptance. Withhold the client's Finished,
    // leaving the server inside its handshake when shutdown is signalled.
    assert_eq!(
        timeout(Duration::from_secs(3), peer.read_u8())
            .await
            .unwrap()
            .unwrap(),
        0x16
    );
    let started = tokio::time::Instant::now();
    stop.send(()).unwrap();
    timeout(Duration::from_secs(3), serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(500));
    let mut tail = Vec::new();
    let closed = timeout(Duration::from_secs(1), peer.read_to_end(&mut tail))
        .await
        .unwrap();
    if let Err(error) = closed {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
        ));
    }
    assert!(store.list("mark@example.test").unwrap().is_empty());
}

#[tokio::test]
async fn zero_grace_closes_an_admitted_peer_and_listener_before_returning() {
    let (mut config, _) = config_for("mark@example.test");
    config.shutdown_grace = Duration::ZERO;
    let bound = MisfinServer::new(config, MailboxStore::in_memory().unwrap())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serve = tokio::spawn(bound.serve(async {
        let _ = stopped.await;
    }));
    let mut peer = super::tests::test_tls_client(address).await;
    stop.send(()).unwrap();
    timeout(Duration::from_secs(2), serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_peer_closed(
        timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .unwrap()
            .unwrap_err(),
    );
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "returned serve must have closed its listener"
    );
}

#[tokio::test]
async fn dropping_serve_cancels_owned_peers_without_claiming_synchronous_join() {
    let (config, _) = config_for("mark@example.test");
    let bound = MisfinServer::new(config, MailboxStore::in_memory().unwrap())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let serve = tokio::spawn(bound.serve(future::pending()));
    let mut peer = super::tests::test_tls_client(address).await;
    serve.abort();
    assert!(serve.await.unwrap_err().is_cancelled());
    // Child abortion is requested by dropping the owned set. Await the peer
    // separately, since dropping serve itself cannot await connection joins.
    assert_peer_closed(
        timeout(Duration::from_secs(2), peer.read_u8())
            .await
            .unwrap()
            .unwrap_err(),
    );
}

#[tokio::test(start_paused = true)]
async fn finish_connections_joins_graceful_and_aborted_children_with_one_fixed_window() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let graceful_drops = drops.clone();
    let (graceful_started, graceful_ready) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _drop = DropMark(graceful_drops);
        graceful_started.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(4)).await;
    });
    let aborted_drops = drops.clone();
    let (pending_started, pending_ready) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _drop = DropMark(aborted_drops);
        pending_started.send(()).unwrap();
        future::pending::<()>().await;
    });
    graceful_ready.await.unwrap();
    pending_ready.await.unwrap();
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(5);
    let finish = tokio::spawn(async move {
        finish_connections(&mut tasks, deadline).await;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            2,
            "all child futures are dropped before finish returns"
        );
    });
    tokio::task::yield_now().await;
    advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(
        !finish.is_finished(),
        "the grace window is measured from shutdown, not renewed after a child completes"
    );
    advance(Duration::from_secs(1)).await;
    finish.await.unwrap();
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(5),
        "completion never renews the shutdown window"
    );
}

#[tokio::test(start_paused = true)]
async fn finish_connections_zero_grace_aborts_and_joins_immediately() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        let _ = started_tx.send(());
        future::pending::<()>().await;
    });
    started_rx.await.unwrap();
    finish_connections(&mut tasks, tokio::time::Instant::now()).await;
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn finish_connections_reaps_panics_and_joins_remaining_tasks() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (panic_started_tx, panic_started_rx) = tokio::sync::oneshot::channel();
    let panic_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(panic_drops);
        let _ = panic_started_tx.send(());
        panic!("controlled child panic");
    });
    let (pending_started_tx, pending_started_rx) = tokio::sync::oneshot::channel();
    let pending_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(pending_drops);
        let _ = pending_started_tx.send(());
        future::pending::<()>().await;
    });
    panic_started_rx.await.unwrap();
    pending_started_rx.await.unwrap();
    finish_connections(&mut tasks, tokio::time::Instant::now()).await;
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn delayed_drain_poll_cannot_restart_the_observed_shutdown_grace() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (started, ready) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        started.send(()).unwrap();
        future::pending::<()>().await;
    });
    ready.await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    advance(Duration::from_secs(6)).await;
    let before_drain = tokio::time::Instant::now();
    finish_connections(&mut tasks, deadline).await;
    assert_eq!(tokio::time::Instant::now(), before_drain);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
