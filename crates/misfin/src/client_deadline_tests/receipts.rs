use super::*;

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
