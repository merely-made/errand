//! Native TLS admission and joined-shutdown behavior.

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
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{advance, timeout};
use tokio_rustls::TlsAcceptor;

use super::{Reply, ServerConfig, acceptor, finish_connections, serve};

fn test_acceptor() -> TlsAcceptor {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    acceptor(
        vec![certified.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der())),
    )
    .unwrap()
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

async fn tls_client(addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

async fn raw_exchange(addr: SocketAddr, path: &str) -> Vec<u8> {
    let mut tls = tls_client(addr).await;
    tls.write_all(format!("gemini://localhost{path}\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn assert_peer_closed(error: io::Error) {
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ),
        "expected native transport closure, got {error}"
    );
}

#[tokio::test]
async fn defaults_zero_grace_and_invalid_lifecycle_precede_acceptance() {
    let defaults = ServerConfig::default();
    assert_eq!(defaults.max_connections, 32);
    assert_eq!(defaults.shutdown_grace, Duration::from_secs(5));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_handler = calls.clone();
    let mut config = defaults.clone();
    config.max_connections = 0;
    let error = serve(
        listener,
        test_acceptor(),
        move |_| {
            calls_in_handler.fetch_add(1, Ordering::SeqCst);
            async { Reply::gemtext("unexpected") }
        },
        config,
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "invalid gemini connection limit");
    assert!(TcpStream::connect(address).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = defaults;
    config.shutdown_grace = Duration::MAX;
    let error = serve(
        listener,
        test_acceptor(),
        |_| async { Reply::gemtext("unexpected") },
        config,
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "invalid gemini shutdown grace");
    assert!(
        ServerConfig {
            shutdown_grace: Duration::ZERO,
            ..ServerConfig::default()
        }
        .shutdown_grace
        .is_zero()
    );
}

#[tokio::test]
async fn admission_cap_pauses_accept_and_reuses_capacity_after_completed_work() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let release = Arc::new(tokio::sync::Notify::new());
    let handler_release = release.clone();
    let config = ServerConfig {
        max_connections: 1,
        ..ServerConfig::default()
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        test_acceptor(),
        move |request: super::Request| {
            let tx = entered_tx.clone();
            let release = handler_release.clone();
            async move {
                tx.send(request.path().to_owned()).unwrap();
                if request.path() == "/first" {
                    release.notified().await;
                }
                Reply::gemtext(request.path().as_bytes().to_vec())
            }
        },
        config,
        async {
            let _ = stop_rx.await;
        },
    ));

    let mut first = tls_client(address).await;
    first
        .write_all(b"gemini://localhost/first\r\n")
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), entered_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        "/first"
    );

    let second = tokio::spawn(tls_client(address));
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !second.is_finished(),
        "TLS admission must wait while the only slot is held by active work"
    );
    release.notify_one();
    let mut first_reply = Vec::new();
    timeout(Duration::from_secs(3), first.read_to_end(&mut first_reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_reply, b"20 text/gemini\r\n/first");

    let mut second = timeout(Duration::from_secs(3), second)
        .await
        .unwrap()
        .unwrap();
    second
        .write_all(b"gemini://localhost/second\r\n")
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), entered_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        "/second"
    );
    let mut second_reply = Vec::new();
    timeout(
        Duration::from_secs(3),
        second.read_to_end(&mut second_reply),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(second_reply, b"20 text/gemini\r\n/second");
    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_drains_admitted_native_gemini_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(tokio::sync::Mutex::new(Some(entered_tx)));
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let finish_rx = Arc::new(tokio::sync::Mutex::new(Some(finish_rx)));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        test_acceptor(),
        move |_| {
            let entered_tx = entered_tx.clone();
            let finish_rx = finish_rx.clone();
            async move {
                entered_tx.lock().await.take().unwrap().send(()).unwrap();
                if let Some(finish_rx) = finish_rx.lock().await.take() {
                    let _ = finish_rx.await;
                }
                Reply::success("text/plain", b"ready".to_vec())
            }
        },
        ServerConfig {
            shutdown_grace: Duration::from_secs(2),
            ..ServerConfig::default()
        },
        async {
            let _ = stop_rx.await;
        },
    ));
    let client = tokio::spawn(raw_exchange(address, "/drain"));
    entered_rx.await.unwrap();
    stop_tx.send(()).unwrap();
    finish_tx.send(()).unwrap();
    assert_eq!(client.await.unwrap(), b"20 text/plain\r\nready");
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_aborts_and_joins_stalled_tls_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        test_acceptor(),
        |_| async { Reply::gemtext("unused") },
        ServerConfig {
            shutdown_grace: Duration::from_millis(650),
            ..ServerConfig::default()
        },
        async {
            let _ = stop_rx.await;
        },
    ));
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
    .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(&hello).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), peer.read_u8())
            .await
            .unwrap()
            .unwrap(),
        0x16
    );
    let started = tokio::time::Instant::now();
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(500));
    let mut tail = Vec::new();
    if let Err(error) = timeout(Duration::from_secs(1), peer.read_to_end(&mut tail))
        .await
        .unwrap()
    {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
        ));
    }
}

#[tokio::test]
async fn zero_grace_closes_listener_and_aborts_admitted_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        test_acceptor(),
        |_| async { future::pending::<Reply>().await },
        ServerConfig {
            shutdown_grace: Duration::ZERO,
            ..ServerConfig::default()
        },
        async {
            let _ = stop_rx.await;
        },
    ));
    let mut peer = tls_client(address).await;
    peer.write_all(b"gemini://localhost/hang\r\n")
        .await
        .unwrap();
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), server)
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
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn dropping_serve_cancels_owned_connection_tasks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(
        listener,
        test_acceptor(),
        |_| async { future::pending::<Reply>().await },
        ServerConfig::default(),
        future::pending(),
    ));
    let mut peer = tls_client(address).await;
    peer.write_all(b"gemini://localhost/hang\r\n")
        .await
        .unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert_peer_closed(
        timeout(Duration::from_secs(2), peer.read_u8())
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

#[tokio::test(start_paused = true)]
async fn fixed_deadline_aborts_and_joins_remaining_children() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        let _ = started_tx.send(());
        tokio::time::sleep(Duration::from_secs(4)).await;
    });
    let (pending_tx, pending_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        let _ = pending_tx.send(());
        future::pending::<()>().await;
    });
    started_rx.await.unwrap();
    pending_rx.await.unwrap();
    let began = tokio::time::Instant::now();
    let deadline = began + Duration::from_secs(5);
    let finish_drops = drops.clone();
    let finish = tokio::spawn(async move {
        finish_connections(&mut tasks, deadline).await;
        assert_eq!(finish_drops.load(Ordering::SeqCst), 2);
    });
    tokio::task::yield_now().await;
    advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(!finish.is_finished(), "the fixed deadline has not elapsed");
    advance(Duration::from_secs(1)).await;
    finish.await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(began.elapsed(), Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn immediate_join_reaps_panics_and_delayed_poll_does_not_renew_grace() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (panic_tx, panic_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        let _ = panic_tx.send(());
        panic!("controlled child panic");
    });
    let (pending_tx, pending_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        let _ = pending_tx.send(());
        future::pending::<()>().await;
    });
    panic_rx.await.unwrap();
    pending_rx.await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    advance(Duration::from_secs(6)).await;
    let before = tokio::time::Instant::now();
    finish_connections(&mut tasks, deadline).await;
    assert_eq!(tokio::time::Instant::now(), before);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}
