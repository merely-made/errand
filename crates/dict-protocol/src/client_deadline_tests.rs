use super::*;
use std::future::{Future, poll_fn};
use std::task::Poll;
use tokio::io::AsyncReadExt;

fn options() -> Options {
    Options {
        operation_timeout: Duration::from_millis(100),
        ..Options::default()
    }
}

#[test]
fn defaults_preserve_byte_limits_and_select_finite_operation_time() {
    assert_eq!(Options::default().limits, Limits::default());
    assert_eq!(
        Options::default().operation_timeout,
        Duration::from_secs(30)
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_and_dripping_banners_share_one_deadline() {
    for drip in [false, true] {
        let (client, mut server) = tokio::io::duplex(128);
        let sender = tokio::spawn(async move {
            if drip {
                for byte in b"220 slow\r\n" {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    if server.write_all(&[*byte]).await.is_err() {
                        return;
                    }
                }
            }
            std::future::pending::<()>().await;
        });
        let start = Instant::now();
        assert!(matches!(
            Session::over_with_options(client, options()).await,
            Err(ClientError::TimedOut)
        ));
        assert_eq!(start.elapsed(), Duration::from_millis(100));
        sender.abort();
        let _ = sender.await;
    }
}

#[tokio::test(start_paused = true)]
async fn define_deadline_spans_all_definitions_and_final_trailer() {
    let (client, server) = tokio::io::duplex(4096);
    let sender = tokio::spawn(async move {
        let mut server = BufReader::new(server);
        server.write_all(b"220 x\r\n").await.unwrap();
        let mut command = String::new();
        server.read_line(&mut command).await.unwrap();
        assert_eq!(command, "DEFINE db word\r\n");
        server
            .write_all(b"150 2 definitions\r\n151 first db name\r\n..one\r\n.\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        server
            .write_all(b"151 second db name\r\ntwo\r\n.\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        server.write_all(b"250 ok\r\n").await.unwrap();
        command.clear();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), server.read_line(&mut command))
                .await
                .is_err()
        );
        assert!(
            command.is_empty(),
            "poisoned session must not issue another command"
        );
    });
    let mut session = Session::over_with_options(client, options()).await.unwrap();
    let start = Instant::now();
    assert_eq!(
        session.define("db", "word").await,
        Err(ClientError::TimedOut)
    );
    assert_eq!(start.elapsed(), Duration::from_millis(100));
    assert!(session.command("STATUS").await.is_err());
    assert!(session.unusable);
    sender.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn dripping_definition_text_cannot_renew_the_deadline() {
    let (client, server) = tokio::io::duplex(4096);
    let sender = tokio::spawn(async move {
        let mut server = BufReader::new(server);
        server.write_all(b"220 x\r\n").await.unwrap();
        let mut command = String::new();
        server.read_line(&mut command).await.unwrap();
        server
            .write_all(b"150 1 definition\r\n151 word db name\r\n")
            .await
            .unwrap();
        for byte in b"slow text\r\n.\r\n250 ok\r\n" {
            tokio::time::sleep(Duration::from_millis(40)).await;
            if server.write_all(&[*byte]).await.is_err() {
                break;
            }
        }
    });
    let mut session = Session::over_with_options(client, options()).await.unwrap();
    assert_eq!(
        session.define("db", "word").await,
        Err(ClientError::TimedOut)
    );
    assert!(session.unusable);
    sender.abort();
    let _ = sender.await;
}

#[tokio::test(start_paused = true)]
async fn successful_and_terminal_refused_commands_get_fresh_budgets_after_idle() {
    let (client, server) = tokio::io::duplex(4096);
    let sender = tokio::spawn(async move {
        let mut server = BufReader::new(server);
        server.write_all(b"220 x\r\n").await.unwrap();
        for reply in [
            b"550 bad database\r\n".as_slice(),
            b"552 no match\r\n",
            b"250 ok\r\n",
        ] {
            let mut command = String::new();
            server.read_line(&mut command).await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            server.write_all(reply).await.unwrap();
        }
    });
    let mut session = Session::over_with_options(client, options()).await.unwrap();
    assert!(matches!(
        session.define("bad", "word").await,
        Err(ClientError::Refused { code: 550, .. })
    ));
    assert!(!session.unusable);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(session.define("db", "word").await.unwrap().is_empty());
    tokio::time::sleep(Duration::from_secs(1)).await;
    session.announce("test").await.unwrap();
    assert!(!session.unusable);
    sender.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn timeout_during_partial_write_prevents_further_writes() {
    let (client, mut server) = tokio::io::duplex(1);
    let greeting = tokio::spawn(async move {
        server.write_all(b"220 x\r\n").await.unwrap();
        server
    });
    let mut session = Session::over_with_options(client, options()).await.unwrap();
    let mut server = greeting.await.unwrap();
    assert_eq!(session.command("STATUS").await, Err(ClientError::TimedOut));
    let mut byte = [0];
    server.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, *b"S");
    assert!(session.command("STATUS").await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(1), server.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dropping_polled_partial_write_future_prevents_further_writes() {
    let (client, mut server) = tokio::io::duplex(1);
    let greeting = tokio::spawn(async move {
        server.write_all(b"220 x\r\n").await.unwrap();
        server
    });
    let mut session = Session::over(client).await.unwrap();
    let mut server = greeting.await.unwrap();
    {
        let mut command = Box::pin(session.command("STATUS"));
        poll_fn(|cx| {
            assert!(command.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert!(session.unusable);
    let mut byte = [0];
    server.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, *b"S");
    assert!(session.command("QUIT").await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(10), server.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dropping_polled_partial_response_future_prevents_stream_reuse() {
    let (client, mut server) = tokio::io::duplex(4096);
    server
        .write_all(b"220 x\r\n150 1 definition\r\n151 word db name\r\npartial")
        .await
        .unwrap();
    let mut session = Session::over(client).await.unwrap();
    {
        let mut command = Box::pin(session.define("db", "word"));
        poll_fn(|cx| {
            assert!(command.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert!(session.unusable);
    let mut first = vec![0; b"DEFINE db word\r\n".len()];
    server.read_exact(&mut first).await.unwrap();
    assert_eq!(first, b"DEFINE db word\r\n");
    server.write_all(b" text\r\n.\r\n250 ok\r\n").await.unwrap();
    assert!(session.command("STATUS").await.is_err());
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(10), server.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unpolled_drop_and_preflight_errors_leave_session_usable() {
    let (client, mut server) = tokio::io::duplex(4096);
    server
        .write_all(b"220 x\r\n552 no match\r\n")
        .await
        .unwrap();
    let mut session = Session::over(client).await.unwrap();
    drop(session.define("db", "unpolled"));
    assert!(!session.unusable);
    // This internal seam proves request preflight precedes timer construction.
    session.operation_timeout = Duration::ZERO;
    assert!(matches!(
        session.define("db", "bad\r\nword").await,
        Err(ClientError::Protocol(_))
    ));
    assert!(!session.unusable);
    session.operation_timeout = Duration::from_secs(30);
    assert!(session.define("db", "safe").await.unwrap().is_empty());
    let mut request = vec![0; b"DEFINE db safe\r\n".len()];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(request, b"DEFINE db safe\r\n");
}

#[tokio::test]
async fn native_connect_options_refuse_zero_and_overflow_before_contact() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    for timeout in [Duration::ZERO, Duration::MAX] {
        let options = Options {
            operation_timeout: timeout,
            ..Options::default()
        };
        let result =
            Session::connect_with_options("127.0.0.1", Some(address.port()), options).await;
        if timeout.is_zero() {
            assert!(matches!(result, Err(ClientError::TimedOut)));
        } else {
            assert!(matches!(result, Err(ClientError::Protocol(_))));
        }
        let (client, mut server) = tokio::io::duplex(128);
        server.write_all(b"220 x\r\n").await.unwrap();
        let result = Session::over_with_options(client, options).await;
        if timeout.is_zero() {
            assert!(matches!(result, Err(ClientError::TimedOut)));
        } else {
            assert!(matches!(result, Err(ClientError::Protocol(_))));
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(10), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_connect_deadline_includes_stalled_banner_and_drops_carrier() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sender = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        peer.write_all(b"220 partial").await.unwrap();
        let mut byte = [0];
        peer.read(&mut byte).await.unwrap()
    });
    let result = Session::connect_with_options(
        "127.0.0.1",
        Some(address.port()),
        Options {
            operation_timeout: Duration::from_millis(100),
            ..Options::default()
        },
    )
    .await;
    assert!(matches!(result, Err(ClientError::TimedOut)));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), sender)
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
