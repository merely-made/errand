use super::*;
use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn recipient() -> MisfinAddress {
    MisfinAddress::parse("target@localhost").unwrap()
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("pure preflight unexpectedly waited"),
    }
}
fn tls_fixture() -> (TlsAcceptor, String) {
    let material = crate::deterministic_identity(
        &[0x51; 32],
        &crate::MisfinIdentitySpec {
            address: recipient(),
            blurb: None,
        },
    )
    .unwrap();
    let fingerprint = sha256_hex(&material.certificate_der);
    let config = rustls::ServerConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(material.certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.private_key_pkcs8_der)),
        )
        .unwrap();
    (TlsAcceptor::from(Arc::new(config)), fingerprint)
}
fn listener() -> (Arc<TcpListener>, Arc<TcpListener>, std::net::SocketAddr) {
    let raw = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    raw.set_nonblocking(true).unwrap();
    let address = raw.local_addr().unwrap();
    let listener = Arc::new(TcpListener::from_std(raw).unwrap());
    (listener.clone(), listener, address)
}

fn options(address: std::net::SocketAddr, step: Duration, whole: Duration) -> SendOptions {
    SendOptions {
        connect_addr: Some(address),
        timeout: Some(step),
        send_timeout: Some(whole),
        ..SendOptions::default()
    }
}
async fn no_second_connection(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "send must not reconnect or resend"
    );
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut request = Vec::new();
    loop {
        request.push(stream.read_u8().await.unwrap());
        assert!(request.len() <= MAX_REQUEST_BYTES);
        if request.ends_with(b"\r\n") {
            return request;
        }
    }
}
async fn assert_closed_without_more_application_data<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        stream.take(4096).read_to_end(&mut bytes),
    )
    .await
    .expect("peer transport must close");
    if let Err(error) = result {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ),
            "unexpected TLS/transport error: {error}"
        );
    }
    assert!(
        bytes.is_empty(),
        "no duplicate application request after timeout/cancellation"
    );
}

#[test]
fn preflight_zero_and_unrepresentable_budgets_do_not_need_a_runtime() {
    assert_eq!(DEFAULT_STEP_TIMEOUT, Duration::from_secs(30));
    assert_eq!(DEFAULT_SEND_TIMEOUT, Duration::from_secs(120));
    let target = recipient();
    assert!(matches!(
        ready(send(&target, "bad\rmessage", &SendOptions::default())),
        Err(SendError::MessageContainsCarriageReturn)
    ));
    assert!(matches!(
        ready(send(
            &target,
            &"x".repeat(MAX_REQUEST_BYTES),
            &SendOptions::default()
        )),
        Err(SendError::MessageTooLong { .. })
    ));
    let invalid = MisfinAddress {
        mailbox: "target".into(),
        host: "invalid host".into(),
    };
    assert!(matches!(
        ready(send(&invalid, "one message", &SendOptions::default())),
        Err(SendError::InvalidHost(_))
    ));
    let whole_zero = SendOptions {
        send_timeout: Some(Duration::ZERO),
        identity: Some(MisfinIdentityMaterial {
            certificate_der: vec![0],
            private_key_pkcs8_der: vec![0],
        }),
        ..SendOptions::default()
    };
    assert!(matches!(
        ready(send(&target, "one message", &whole_zero)),
        Err(SendError::WholeSendTimeout { receipt: None })
    ));
    let step_zero = SendOptions {
        timeout: Some(Duration::ZERO),
        ..SendOptions::default()
    };
    assert!(matches!(
        ready(send(&target, "one message", &step_zero)),
        Err(SendError::Timeout("connect"))
    ));
    for policy in [
        SendOptions {
            timeout: Some(Duration::MAX),
            ..SendOptions::default()
        },
        SendOptions {
            send_timeout: Some(Duration::MAX),
            ..SendOptions::default()
        },
    ] {
        assert!(matches!(
            ready(send(&target, "one message", &policy)),
            Err(SendError::InvalidTimeout(_))
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn one_whole_budget_spans_multiple_individually_valid_steps() {
    let budget = SendBudget::new(Duration::from_millis(100), Duration::from_millis(150)).unwrap();
    let start = tokio::time::Instant::now();
    budget
        .step("TLS handshake", async {
            tokio::time::sleep(Duration::from_millis(90)).await;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        budget
            .step("response read", async {
                tokio::time::sleep(Duration::from_millis(90)).await;
                Ok(())
            })
            .await,
        Err(SendError::WholeSendTimeout { receipt: None })
    ));
    assert_eq!(start.elapsed(), Duration::from_millis(150));
    assert!(matches!(
        budget.check(),
        Err(SendError::WholeSendTimeout { receipt: None })
    ));
}

#[tokio::test(start_paused = true)]
async fn partial_request_write_distinguishes_step_and_whole_expiry() {
    for whole_wins in [false, true] {
        let (mut client, mut server) = tokio::io::duplex(1);
        let (step, whole) = if whole_wins {
            (Duration::from_millis(100), Duration::from_millis(40))
        } else {
            (Duration::from_millis(40), Duration::from_millis(100))
        };
        let budget = SendBudget::new(step, whole).unwrap();
        let result = budget
            .step("request write", async {
                client
                    .write_all(b"misfin request")
                    .await
                    .map_err(|error| SendError::Io(error.to_string()))
            })
            .await;
        if whole_wins {
            assert!(matches!(
                result,
                Err(SendError::WholeSendTimeout { receipt: None })
            ));
        } else {
            assert!(matches!(result, Err(SendError::Timeout("request write"))));
        }
        drop(client);
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        assert_eq!(
            sent, b"m",
            "one partial write, never an automatic second attempt"
        );
    }
}

#[tokio::test]
async fn stalled_native_handshake_distinguishes_step_and_whole_and_closes_tcp() {
    for whole_wins in [false, true] {
        let (listener, monitor, address) = listener();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(2),
                (&mut stream).take(16384).read_to_end(&mut hello),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!hello.is_empty());
            assert!(hello.len() < 16384);
        });
        let (step, whole) = if whole_wins {
            (Duration::from_secs(2), Duration::from_millis(500))
        } else {
            (Duration::from_millis(500), Duration::from_secs(2))
        };
        let result = send(&recipient(), "one message", &options(address, step, whole)).await;
        if whole_wins {
            assert!(
                matches!(&result, Err(SendError::WholeSendTimeout { receipt: None })),
                "expected whole-send expiry in stalled handshake, actual: {result:?}"
            );
        } else {
            assert!(
                matches!(&result, Err(SendError::Timeout("TLS handshake"))),
                "expected handshake step timeout, actual: {result:?}"
            );
        }
        server.await.unwrap();
        no_second_connection(&monitor).await;
    }
}

#[tokio::test]
async fn native_tls_and_reply_share_budget_after_exactly_one_transmission() {
    let (listener, monitor, address) = listener();
    let (acceptor, _) = tls_fixture();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(
            read_request(&mut stream).await,
            b"misfin://target@localhost one message\r\n"
        );
        observed.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _ = stream.write_all(b"20 known-mailbox-fingerprint\r\n").await;
        let _ = stream.shutdown().await;
    });
    let result = send(
        &recipient(),
        "one message",
        &options(address, Duration::from_secs(1), Duration::from_millis(400)),
    )
    .await;
    assert!(matches!(
        result,
        Err(SendError::WholeSendTimeout { receipt: None })
    ));
    server.await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    no_second_connection(&monitor).await;
}

#[tokio::test]
async fn native_dripping_reply_cannot_renew_whole_send_allowance() {
    let (listener, monitor, address) = listener();
    let (acceptor, _) = tls_fixture();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(
            read_request(&mut stream).await,
            b"misfin://target@localhost one message\r\n"
        );
        for byte in b"20 delayed-mailbox-fingerprint\r\n" {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if stream.write_all(&[*byte]).await.is_err() {
                break;
            }
        }
    });
    let result = send(
        &recipient(),
        "one message",
        &options(address, Duration::from_secs(1), Duration::from_millis(120)),
    )
    .await;
    assert!(matches!(
        result,
        Err(SendError::WholeSendTimeout { receipt: None })
    ));
    server.await.unwrap();
    no_second_connection(&monitor).await;
}

#[tokio::test]
async fn cancelling_after_request_closes_transport_and_does_not_resend() {
    let (listener, monitor, address) = listener();
    let (acceptor, _) = tls_fixture();
    let (sent, observed) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(
            read_request(&mut stream).await,
            b"misfin://target@localhost one message\r\n"
        );
        sent.send(()).unwrap();
        assert_closed_without_more_application_data(&mut stream).await;
    });
    let sending = tokio::spawn(async move {
        send(
            &recipient(),
            "one message",
            &options(address, Duration::from_secs(1), Duration::from_secs(2)),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), observed)
        .await
        .unwrap()
        .unwrap();
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    server.await.unwrap();
    no_second_connection(&monitor).await;
}

#[tokio::test]
async fn fingerprint_mismatch_precedes_application_write_and_preserves_primary_error() {
    let (listener, monitor, address) = listener();
    let (acceptor, fingerprint) = tls_fixture();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_closed_without_more_application_data(&mut stream).await;
    });
    let mut policy = options(address, Duration::from_secs(1), Duration::from_secs(2));
    policy.expected_fingerprint = Some("00".repeat(32));
    match send(&recipient(), "must not be sent", &policy).await {
        Err(SendError::FingerprintMismatch { expected, found }) => {
            assert_eq!(expected, "00".repeat(32));
            assert_eq!(found, fingerprint);
        }
        other => panic!("expected primary fingerprint mismatch, got {other:?}"),
    }
    server.await.unwrap();
    no_second_connection(&monitor).await;
}

#[tokio::test]
async fn native_status_receipts_are_preserved_without_redirect_or_temporary_error_resend() {
    for code in [20, 30, 31, 40] {
        let (listener, monitor, address) = listener();
        let (acceptor, fingerprint) = tls_fixture();
        let meta = if code == 20 {
            "mailbox-certificate-fingerprint"
        } else {
            "misfin://other@elsewhere.test"
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            assert_eq!(
                read_request(&mut stream).await,
                b"misfin://target@localhost one message\r\n"
            );
            stream
                .write_all(format!("{code} {meta}\r\n").as_bytes())
                .await
                .unwrap();
            assert_closed_without_more_application_data(&mut stream).await;
        });
        let receipt = send(
            &recipient(),
            "one message",
            &options(address, Duration::from_secs(1), Duration::from_secs(2)),
        )
        .await
        .unwrap();
        assert_eq!(receipt.status, MisfinStatus::from_code(code));
        assert_eq!(receipt.meta, meta);
        assert_eq!(receipt.server_fingerprint, fingerprint);
        server.await.unwrap();
        no_second_connection(&monitor).await;
    }
}

#[derive(Clone, Copy)]
enum Close {
    Pending,
    Error,
    Ready,
}
struct Reply {
    bytes: Vec<u8>,
    cursor: usize,
    close: Close,
    shutdown_polled: bool,
    written: Vec<u8>,
}
impl Reply {
    fn new(bytes: &[u8], close: Close) -> Self {
        Self {
            bytes: bytes.to_vec(),
            cursor: 0,
            close,
            shutdown_polled: false,
            written: Vec::new(),
        }
    }
}
impl AsyncRead for Reply {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let count = output
            .remaining()
            .min(self.bytes.len() - self.cursor)
            .min(1);
        output.put_slice(&self.bytes[self.cursor..self.cursor + count]);
        self.cursor += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Reply {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shutdown_polled = true;
        match self.close {
            Close::Pending => Poll::Pending,
            Close::Error => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Close::Ready => Poll::Ready(Ok(())),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn whole_expiry_during_close_retains_exact_observed_receipt() {
    for code in [20, 40] {
        let mut stream = Reply::new(
            format!("{code} mailbox-fingerprint\r\n").as_bytes(),
            Close::Pending,
        );
        let budget = SendBudget::new(Duration::from_secs(1), Duration::from_millis(50)).unwrap();
        match finish_response(&mut stream, &budget, "server-tls-fingerprint".into()).await {
            Err(SendError::WholeSendTimeout {
                receipt: Some(receipt),
            }) => {
                assert_eq!(
                    receipt,
                    SendReceipt {
                        status: MisfinStatus::from_code(code),
                        meta: "mailbox-fingerprint".into(),
                        server_fingerprint: "server-tls-fingerprint".into()
                    }
                );
            }
            other => panic!("known response must survive whole-send expiry at close: {other:?}"),
        }
        assert!(stream.shutdown_polled);
    }
}

#[tokio::test(start_paused = true)]
async fn step_close_timeout_or_io_error_keeps_existing_best_effort_receipt() {
    for close in [Close::Pending, Close::Error] {
        let mut stream = Reply::new(b"20 mailbox-fingerprint\r\n", close);
        let budget = SendBudget::new(Duration::from_millis(40), Duration::from_secs(1)).unwrap();
        let receipt = finish_response(&mut stream, &budget, "server-tls-fingerprint".into())
            .await
            .unwrap();
        assert_eq!(receipt.status, MisfinStatus::Delivered);
        assert_eq!(receipt.meta, "mailbox-fingerprint");
        assert_eq!(receipt.server_fingerprint, "server-tls-fingerprint");
        assert!(stream.shutdown_polled);
    }
}

#[tokio::test]
async fn incomplete_or_overlong_reply_never_becomes_an_observed_receipt() {
    for bytes in [
        b"20 partial".to_vec(),
        b"20 bare LF\n".to_vec(),
        [b"20 ".as_slice(), &[b'x'; MAX_REQUEST_BYTES], b"\r\n"].concat(),
    ] {
        let mut stream = Reply::new(&bytes, Close::Ready);
        let budget = SendBudget::new(Duration::from_secs(1), Duration::from_secs(2)).unwrap();
        assert!(matches!(
            finish_response(&mut stream, &budget, "server-fingerprint".into()).await,
            Err(SendError::BadResponse(_))
        ));
    }
    let mut stream = Reply::new(
        &[b"20 ".as_slice(), &[b'x'; MAX_REQUEST_BYTES - 5], b"\r\n"].concat(),
        Close::Ready,
    );
    let budget = SendBudget::new(Duration::from_secs(1), Duration::from_secs(2)).unwrap();
    assert_eq!(
        finish_response(&mut stream, &budget, "server-fingerprint".into())
            .await
            .unwrap()
            .meta
            .len(),
        MAX_REQUEST_BYTES - 5
    );
}

#[tokio::test]
async fn stalled_native_response_retains_the_existing_per_step_timeout() {
    let (listener, monitor, address) = listener();
    let (acceptor, _) = tls_fixture();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(
            read_request(&mut stream).await,
            b"misfin://target@localhost one message\r\n"
        );
        assert_closed_without_more_application_data(&mut stream).await;
    });
    let result = send(
        &recipient(),
        "one message",
        &options(address, Duration::from_millis(500), Duration::from_secs(2)),
    )
    .await;
    assert!(
        matches!(&result, Err(SendError::Timeout("response read"))),
        "expected response-read step timeout after TLS setup, actual: {result:?}"
    );
    server.await.unwrap();
    no_second_connection(&monitor).await;
}

#[tokio::test(start_paused = true)]
async fn pending_cleanup_preserves_fingerprint_refusal_when_step_or_whole_expires() {
    for whole_wins in [false, true] {
        let mut stream = Reply::new(b"", Close::Pending);
        let (step, whole) = if whole_wins {
            (Duration::from_secs(1), Duration::from_millis(40))
        } else {
            (Duration::from_millis(40), Duration::from_secs(1))
        };
        let budget = SendBudget::new(step, whole).unwrap();
        let start = tokio::time::Instant::now();
        let refusal = SendError::FingerprintMismatch {
            expected: "00".repeat(32),
            found: "11".repeat(32),
        };
        match close_after_refusal(&mut stream, &budget, refusal).await {
            SendError::FingerprintMismatch { expected, found } => {
                assert_eq!(expected, "00".repeat(32));
                assert_eq!(found, "11".repeat(32));
            }
            other => panic!("cleanup replaced definite trust refusal: {other:?}"),
        }
        assert_eq!(start.elapsed(), Duration::from_millis(40));
        assert!(stream.shutdown_polled);
        assert!(
            stream.written.is_empty(),
            "no application bytes after trust refusal"
        );
    }
}

#[tokio::test]
async fn always_ready_step_cannot_return_success_after_whole_deadline() {
    let budget = SendBudget::new(Duration::from_secs(1), Duration::from_millis(10)).unwrap();
    let polled = std::cell::Cell::new(false);
    let result = budget
        .step("response read", async {
            polled.set(true);
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        })
        .await;
    assert!(
        polled.get(),
        "fixture must actually poll the ready operation"
    );
    assert!(matches!(
        result,
        Err(SendError::WholeSendTimeout { receipt: None })
    ));
}
