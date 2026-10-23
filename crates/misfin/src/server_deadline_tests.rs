//! Deadline behavior for the Misfin receive path.
//!
//! This is a child of `server`, so it can exercise the private budget and
//! receive functions without widening the production API.

use std::future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, advance};

use super::{
    DEFAULT_RECEIVE_STEP_TIMEOUT, DEFAULT_RECEIVE_TIMEOUT, MisfinServerConfig, ReceiveBudget,
    handle_connection, receive,
};
use crate::server::tests::{cert_der, dispatcher_for};
use crate::{MailboxStore, MisfinAddress, MisfinIdentitySpec, deterministic_identity};
use rustls::pki_types::CertificateDer;

fn assert_timeout(error: io::Error, message: &str) {
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), message);
}

struct PendingShutdown<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for PendingShutdown<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PendingShutdown<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn whole_receive_budget_is_fixed_at_acceptance_across_steps() {
    let accepted_at = Instant::now();
    let budget =
        ReceiveBudget::new(accepted_at, Duration::from_secs(8), Duration::from_secs(10)).unwrap();

    budget
        .step("request read", async {
            advance(Duration::from_secs(6)).await;
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap();
    budget
        .step("response write", async {
            advance(Duration::from_secs(3)).await;
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap();

    // The two phases consumed nine seconds of the same ten-second epoch.
    assert!(budget.check().is_ok());
    advance(Duration::from_secs(1)).await;
    assert_timeout(budget.check().unwrap_err(), "misfin receive timed out");
}

#[tokio::test(start_paused = true)]
async fn each_receive_step_has_its_own_limit() {
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(4),
        Duration::from_secs(20),
    )
    .unwrap();

    let error = budget
        .step("request read", async {
            future::pending::<io::Result<()>>().await
        })
        .await
        .unwrap_err();
    assert_timeout(error, "misfin request read timed out");
}

#[tokio::test(start_paused = true)]
async fn a_step_is_clamped_to_the_remaining_whole_budget() {
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(8),
        Duration::from_secs(5),
    )
    .unwrap();

    budget
        .step("request read", async {
            advance(Duration::from_secs(3)).await;
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap();
    let error = budget
        .step("response write", async {
            future::pending::<io::Result<()>>().await
        })
        .await
        .unwrap_err();
    assert_timeout(error, "misfin receive timed out");
}

#[tokio::test(start_paused = true)]
async fn already_expired_acceptance_is_rejected_before_running_a_step() {
    let accepted_at = Instant::now();
    advance(Duration::from_secs(3)).await;
    let budget =
        ReceiveBudget::new(accepted_at, Duration::from_secs(5), Duration::from_secs(2)).unwrap();

    let error = budget
        .step("TLS handshake", async { Ok::<_, io::Error>(()) })
        .await
        .unwrap_err();
    assert_timeout(error, "misfin receive timed out");
}

#[tokio::test(start_paused = true)]
async fn late_ready_step_result_is_refused() {
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(10),
    )
    .unwrap();

    let error = budget
        .step("request read", async {
            advance(Duration::from_secs(2)).await;
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap_err();
    assert_timeout(error, "misfin request read timed out");
}

#[test]
fn constructor_defaults_and_rejects_invalid_receive_budgets_before_tls_setup() {
    let mut config = MisfinServerConfig::new(Vec::new(), Vec::new(), Vec::new());
    assert_eq!(config.timeout, DEFAULT_RECEIVE_STEP_TIMEOUT);
    assert_eq!(config.receive_timeout, DEFAULT_RECEIVE_TIMEOUT);

    for (step, whole, expected) in [
        (
            Duration::ZERO,
            Duration::from_secs(120),
            "invalid misfin per-step timeout",
        ),
        (
            Duration::from_secs(30),
            Duration::ZERO,
            "invalid misfin whole-receive timeout",
        ),
        (
            Duration::MAX,
            Duration::from_secs(120),
            "invalid misfin per-step timeout",
        ),
        (
            Duration::from_secs(30),
            Duration::MAX,
            "invalid misfin whole-receive timeout",
        ),
    ] {
        config = MisfinServerConfig::new(Vec::new(), Vec::new(), Vec::new());
        config.timeout = step;
        config.receive_timeout = whole;
        match super::MisfinServer::new(config, MailboxStore::in_memory().unwrap()) {
            Err(super::MisfinServerError::Config(message)) => assert_eq!(message, expected),
            _ => panic!("invalid timeout must refuse before malformed TLS material is inspected"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn expired_receive_never_dispatches_or_stores_mail() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let accepted_at = Instant::now();
    advance(Duration::from_secs(3)).await;
    let budget =
        ReceiveBudget::new(accepted_at, Duration::from_secs(10), Duration::from_secs(2)).unwrap();
    let (mut server_stream, _client_stream) = tokio::io::duplex(64);

    assert_timeout(
        receive(&mut server_stream, &dispatcher, Some(&cert), &budget)
            .await
            .unwrap_err(),
        "misfin receive timed out",
    );
    assert!(
        dispatcher
            .store
            .list("mark@example.test")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(start_paused = true)]
async fn blocked_response_write_times_out_after_delivery_is_committed_once() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let store = dispatcher.store.clone();
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(10),
    )
    .unwrap();
    // The request fits in the pipe, while the complete reply does not.
    let (mut server_stream, mut client_stream) = tokio::io::duplex(64);
    client_stream
        .write_all(b"misfin://mark@example.test hello\r\n")
        .await
        .unwrap();

    let receiving = tokio::spawn(async move {
        receive(&mut server_stream, &dispatcher, Some(&cert), &budget).await
    });
    tokio::task::yield_now().await;
    advance(Duration::from_secs(2)).await;
    let error = receiving.await.unwrap().unwrap_err();
    assert_timeout(error, "misfin response write timed out");
    let inbox = store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "hello");
}

#[tokio::test(start_paused = true)]
async fn pending_tls_close_is_bounded_after_one_delivery() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let store = dispatcher.store.clone();
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(10),
    )
    .unwrap();
    let (server_stream, mut client_stream) = tokio::io::duplex(64);
    let mut server_stream = PendingShutdown(server_stream);
    client_stream
        .write_all(b"misfin://mark@example.test close\r\n")
        .await
        .unwrap();
    let receiving = tokio::spawn(async move {
        receive(&mut server_stream, &dispatcher, Some(&cert), &budget).await
    });

    let mut response = Vec::new();
    loop {
        let mut byte = [0];
        client_stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&response).starts_with("20 "));
    tokio::task::yield_now().await;
    advance(Duration::from_secs(2)).await;
    assert_timeout(
        receiving.await.unwrap().unwrap_err(),
        "misfin TLS close timed out",
    );
    let inbox = store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "close");
}

#[test]
fn synchronous_dispatch_that_crosses_expiry_keeps_its_single_committed_delivery() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(1),
        Duration::from_millis(700),
    )
    .unwrap();

    let error = budget
        .dispatch(|| {
            let response = dispatcher.dispatch(
                "misfin://mark@example.test committed",
                Some(&cert),
                1_750_000_000,
            );
            std::thread::sleep(Duration::from_millis(750));
            response
        })
        .unwrap_err();
    assert_timeout(error, "misfin receive timed out");
    let inbox = dispatcher.store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "committed");
}

#[test]
fn expired_dispatch_budget_does_not_invoke_the_commit_callback() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let budget = ReceiveBudget::new(
        Instant::now() - Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap();
    let invoked = std::cell::Cell::new(false);

    assert_timeout(
        budget
            .dispatch(|| {
                invoked.set(true);
                dispatcher.dispatch("misfin://mark@example.test no", None, 1_750_000_000)
            })
            .unwrap_err(),
        "misfin receive timed out",
    );
    assert!(!invoked.get());
    assert!(
        dispatcher
            .store
            .list("mark@example.test")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(start_paused = true)]
async fn drip_bytes_do_not_restart_the_request_read_step() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let store = dispatcher.store.clone();
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(10),
    )
    .unwrap();
    let (mut server_stream, mut client_stream) = tokio::io::duplex(64);
    let receiving = tokio::spawn(async move {
        receive(&mut server_stream, &dispatcher, Some(&cert), &budget).await
    });
    tokio::task::yield_now().await;

    for byte in b"mi" {
        client_stream.write_all(&[*byte]).await.unwrap();
        tokio::task::yield_now().await;
        advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }

    assert_timeout(
        receiving.await.unwrap().unwrap_err(),
        "misfin request read timed out",
    );
    assert!(store.list("mark@example.test").unwrap().is_empty());
}

#[tokio::test]
async fn a_complete_request_at_the_2048_byte_wire_limit_is_delivered() {
    use super::MAX_REQUEST_BYTES;

    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let base = "misfin://mark@example.test ";
    let message = "x".repeat(MAX_REQUEST_BYTES - base.len() - 2);
    let wire = format!("{base}{message}\r\n");
    assert_eq!(wire.len(), MAX_REQUEST_BYTES);
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap();
    let (mut server_stream, mut client_stream) = tokio::io::duplex(4096);
    client_stream.write_all(wire.as_bytes()).await.unwrap();
    receive(&mut server_stream, &dispatcher, Some(&cert), &budget)
        .await
        .unwrap();

    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("20 "));
    let inbox = dispatcher.store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, message);
}

#[tokio::test]
async fn truncated_eof_gets_59_without_delivering() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap();
    let (mut server_stream, mut client_stream) = tokio::io::duplex(128);
    client_stream
        .write_all(b"misfin://mark@example.test incomplete")
        .await
        .unwrap();
    client_stream.shutdown().await.unwrap();

    receive(&mut server_stream, &dispatcher, Some(&cert), &budget)
        .await
        .unwrap();
    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("59 "));
    assert!(
        dispatcher
            .store
            .list("mark@example.test")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn bare_lf_eof_gets_59_without_delivering() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap();
    let (mut server_stream, mut client_stream) = tokio::io::duplex(128);
    client_stream
        .write_all(b"misfin://mark@example.test incomplete\n")
        .await
        .unwrap();
    client_stream.shutdown().await.unwrap();

    receive(&mut server_stream, &dispatcher, Some(&cert), &budget)
        .await
        .unwrap();
    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("59 "));
    assert!(
        dispatcher
            .store
            .list("mark@example.test")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn embedded_bare_lf_in_message_is_preserved_when_crlf_terminates_request() {
    let (dispatcher, _) = dispatcher_for("mark@example.test");
    let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap();
    let (mut server_stream, mut client_stream) = tokio::io::duplex(128);
    client_stream
        .write_all(b"misfin://mark@example.test hello\nworld\n\r\n")
        .await
        .unwrap();

    receive(&mut server_stream, &dispatcher, Some(&cert), &budget)
        .await
        .unwrap();
    let mut response = Vec::new();
    client_stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("20 "));
    let inbox = dispatcher.store.list("mark@example.test").unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "hello\nworld\n");
}

#[tokio::test]
async fn native_tcp_peer_stalling_during_tls_handshake_is_closed_at_phase_deadline() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let server = super::MisfinServer::new(
        MisfinServerConfig::new(
            identity.certificate_der,
            identity.private_key_pkcs8_der,
            Vec::new(),
        ),
        MailboxStore::in_memory().unwrap(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_millis(700),
        Duration::from_secs(3),
    )
    .unwrap();
    let handler = tokio::spawn(handle_connection(
        server.acceptor,
        server.dispatcher,
        tcp,
        budget,
    ));

    assert_timeout(
        handler.await.unwrap().unwrap_err(),
        "misfin TLS handshake timed out",
    );
    let mut client = client;
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read_u8())
        .await
        .expect("timed-out server handler closes the accepted TCP peer");
    assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn expired_acceptance_deadline_stops_native_handshake_before_it_starts() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let server = super::MisfinServer::new(
        MisfinServerConfig::new(
            identity.certificate_der,
            identity.private_key_pkcs8_der,
            Vec::new(),
        ),
        MailboxStore::in_memory().unwrap(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let budget = ReceiveBudget::new(
        Instant::now() - Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(1),
    )
    .unwrap();
    let handler = tokio::spawn(handle_connection(
        server.acceptor,
        server.dispatcher,
        tcp,
        budget,
    ));

    assert_timeout(
        handler.await.unwrap().unwrap_err(),
        "misfin receive timed out",
    );
    let mut client = client;
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read_u8())
        .await
        .expect("expired acceptance budget closes the TCP peer");
    assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn native_tls_client_stalling_after_handshake_is_closed_without_mail() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let store = MailboxStore::in_memory().unwrap();
    let server = super::MisfinServer::new(
        MisfinServerConfig::new(
            identity.certificate_der,
            identity.private_key_pkcs8_der,
            Vec::new(),
        ),
        store.clone(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = server.acceptor.clone();
    let dispatcher = server.dispatcher.clone();
    let accepted = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let budget = ReceiveBudget::new(
            Instant::now(),
            Duration::from_millis(700),
            Duration::from_secs(3),
        )
        .unwrap();
        handle_connection(acceptor, dispatcher, tcp, budget).await
    });
    let mut client = super::tests::test_tls_client(address).await;

    assert_timeout(
        accepted.await.unwrap().unwrap_err(),
        "misfin request read timed out",
    );
    let mut response = Vec::new();
    let read_result =
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("timed-out TLS handler closes its peer");
    assert_eq!(
        read_result.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof,
        "TCP close without TLS close_notify is the expected deadline outcome"
    );
    assert!(response.is_empty());
    assert!(store.list("mark@example.test").unwrap().is_empty());
}

#[tokio::test]
async fn public_listener_passes_configured_deadlines_and_gives_each_accept_a_fresh_budget() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let mut config = MisfinServerConfig::new(
        identity.certificate_der,
        identity.private_key_pkcs8_der,
        Vec::new(),
    );
    // The whole allowance wins; neither listener idle time nor earlier peers
    // consume the next accepted transaction's allowance.
    config.timeout = Duration::from_secs(3);
    config.receive_timeout = Duration::from_millis(700);
    let bound = super::MisfinServer::new(config, MailboxStore::in_memory().unwrap())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let listener = tokio::spawn(bound.serve(async {
        let _ = stopped.await;
    }));
    tokio::time::sleep(Duration::from_millis(800)).await;
    for _ in 0..2 {
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        let started = Instant::now();
        let closed = tokio::time::timeout(Duration::from_secs(2), peer.read_u8())
            .await
            .expect("configured whole receive budget must close the stalled peer");
        assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "a fresh accept must receive its own budget"
        );
    }
    stop.send(()).unwrap();
    listener.await.unwrap().unwrap();
    // This observes the completed peers and accept-loop result only. It makes
    // no claim that serve() joins still-running connection tasks on shutdown.
}
