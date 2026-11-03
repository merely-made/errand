use super::*;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

async fn asked(server: &UdpSocket) -> (Packet, std::net::SocketAddr) {
    let mut bytes = [0; 4096];
    let (read, peer) = tokio::time::timeout(Duration::from_secs(3), server.recv_from(&mut bytes))
        .await
        .expect("fixture request")
        .unwrap();
    (
        decode(&bytes[..read], Direction::ClientToServer).unwrap(),
        peer,
    )
}

async fn answer(
    server: &UdpSocket,
    peer: std::net::SocketAddr,
    request: &Packet,
    command: Command,
    key: u16,
    data: Vec<u8>,
) {
    let packet = Packet {
        header: Header {
            command: command.code(),
            key,
            sequence: request.header.sequence,
            data_length: u16::try_from(data.len()).unwrap(),
            file_position: request.header.file_position,
        },
        data,
        extra: vec![],
    };
    server
        .send_to(&encode(&packet, Direction::ServerToClient), peer)
        .await
        .unwrap();
}

async fn session(server: &UdpSocket, timeout: Duration, limits: Limits) -> Session {
    Session::connect_with_options(
        "127.0.0.1",
        Some(server.local_addr().unwrap().port()),
        Options {
            limits,
            operation_timeout: timeout,
        },
    )
    .await
    .unwrap()
}

#[test]
fn zero_and_overflow_connect_policy_refuse_without_a_runtime_or_network() {
    for (timeout, expected) in [
        (Duration::ZERO, ClientError::OperationTimedOut),
        (
            Duration::MAX,
            ClientError::Protocol("operation timeout overflows the clock".into()),
        ),
    ] {
        let operation = Session::connect_with_options(
            "must-not-resolve.invalid",
            None,
            Options {
                operation_timeout: timeout,
                ..Default::default()
            },
        );
        let mut operation = pin!(operation);
        match operation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(Err(error)) => assert_eq!(error, expected),
            _ => panic!("invalid policy must refuse before runtime/timer/connection work"),
        }
    }
    assert_eq!(
        Options::default().operation_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(Options::default().limits, Limits::default());
}

#[tokio::test]
async fn full_file_and_directory_share_one_allowance_across_blocks() {
    for command in [Command::GetFile, Command::GetDir] {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(&server, Duration::from_millis(500), Limits::default()).await;
        let task = tokio::spawn(async move {
            for index in 0..2 {
                let (request, peer) = asked(&server).await;
                assert_eq!(request.header.command, command.code());
                assert_eq!(request.header.key, index);
                let expected_offset = if command == Command::GetFile {
                    u32::from(index) * MAX_PAYLOAD as u32
                } else {
                    u32::from(index) * 12
                };
                assert_eq!(request.header.file_position, expected_offset);
                tokio::time::sleep(Duration::from_millis(300)).await;
                let data = if command == Command::GetFile {
                    vec![b'x'; MAX_PAYLOAD]
                } else {
                    let mut entry = vec![0; 12];
                    entry[8] = crate::wire::RDTYPE_FILE;
                    entry[9] = b'x';
                    entry
                };
                answer(&server, peer, &request, command, index + 1, data).await;
            }
            let mut bytes = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(50), server.recv_from(&mut bytes))
                    .await
                    .is_err(),
                "expired operation must not send another request"
            );
        });
        let error = if command == Command::GetFile {
            session.get_file("/").await.unwrap_err()
        } else {
            session.list("/").await.unwrap_err()
        };
        assert_eq!(error, ClientError::OperationTimedOut);
        task.await.unwrap(); // the delayed old-sequence reply is now queued
        assert!(session.in_flight);
        let sequence = session.sequence;
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::SessionUnusable
        );
        assert_eq!(session.sequence, sequence);
        assert_eq!(
            session.set_operation_timeout(Duration::from_secs(3)),
            Err(ClientError::SessionUnusable)
        );
    }
}

#[tokio::test]
async fn operation_allowance_clips_retries_without_restarting_the_budget() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = session(&server, Duration::from_millis(350), Limits::default()).await;
    session.timeout = Duration::from_millis(200);
    let task = tokio::spawn(async move {
        let (first, _) = asked(&server).await;
        let (second, _) = asked(&server).await;
        assert_eq!(first, second, "retry keeps the same sequence/key/request");
        let mut bytes = [0; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(250), server.recv_from(&mut bytes))
                .await
                .is_err(),
            "a third retry would exceed the whole allowance"
        );
    });
    assert_eq!(
        session.version().await.unwrap_err(),
        ClientError::OperationTimedOut
    );
    assert_eq!(session.attempts, 3);
    assert_eq!(session.timeout, Duration::from_millis(200));
    assert_eq!(
        session.version().await.unwrap_err(),
        ClientError::SessionUnusable
    );
    task.await.unwrap();
}

#[tokio::test]
async fn each_completed_operation_gets_a_fresh_allowance_after_idle_time() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = session(&server, Duration::from_millis(200), Limits::default()).await;
    let task = tokio::spawn(async move {
        let (first, peer) = asked(&server).await;
        answer(
            &server,
            peer,
            &first,
            Command::Version,
            41,
            b"first".to_vec(),
        )
        .await;
        let (second, peer) = asked(&server).await;
        assert_eq!(second.header.key, 41);
        assert_ne!(first.header.sequence, second.header.sequence);
        // A queued old reply must not satisfy the next successful operation.
        answer(
            &server,
            peer,
            &first,
            Command::Version,
            41,
            b"stale".to_vec(),
        )
        .await;
        answer(
            &server,
            peer,
            &second,
            Command::Version,
            42,
            b"second".to_vec(),
        )
        .await;
    });
    assert_eq!(session.version().await.unwrap(), "first");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(session.version().await.unwrap(), "second");
    assert_eq!(session.key, 42);
    assert!(!session.in_flight);
    task.await.unwrap();
}

#[tokio::test]
async fn caller_cancellation_retires_the_uncertain_key_session() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = session(&server, Duration::from_secs(2), Limits::default()).await;
    let (seen, received) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let (sent, delivered) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (request, peer) = asked(&server).await;
        seen.send(()).unwrap();
        released.await.unwrap();
        answer(
            &server,
            peer,
            &request,
            Command::Version,
            99,
            b"late".to_vec(),
        )
        .await;
        sent.send(()).unwrap();
        let mut bytes = [0; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), server.recv_from(&mut bytes))
                .await
                .is_err()
        );
    });
    let mut operation = Box::pin(session.version());
    tokio::select! { result = &mut operation => panic!("unexpected completion: {result:?}"), _ = received => {} }
    drop(operation);
    release.send(()).unwrap();
    delivered.await.unwrap();
    assert_eq!(
        session.version().await.unwrap_err(),
        ClientError::SessionUnusable
    );
    assert_eq!(
        session.set_operation_timeout(Duration::from_secs(3)),
        Err(ClientError::SessionUnusable)
    );
    task.await.unwrap();
}

#[tokio::test]
async fn zero_budget_and_local_preflight_can_be_changed_without_reviving_interruption() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = session(
        &server,
        Duration::from_secs(1),
        Limits {
            max_request_bytes: HEADER_LEN + 3,
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(
        session.get_file_block("/too-long", 0).await,
        Err(ClientError::LimitExceeded { .. })
    ));
    session.set_operation_timeout(Duration::ZERO).unwrap();
    assert_eq!(
        session.version().await.unwrap_err(),
        ClientError::OperationTimedOut
    );
    let mut bytes = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut bytes))
            .await
            .is_err()
    );
    assert!(matches!(
        session.set_operation_timeout(Duration::MAX),
        Err(ClientError::Protocol(_))
    ));
    assert_eq!(session.operation_timeout(), Duration::ZERO);
    session
        .set_operation_timeout(Duration::from_secs(1))
        .unwrap();
    let task = tokio::spawn(async move {
        let (request, peer) = asked(&server).await;
        answer(&server, peer, &request, Command::GetFile, 1, b"ok".to_vec()).await;
    });
    assert_eq!(session.get_file_block("/x", 0).await.unwrap(), b"ok");
    task.await.unwrap();
}

#[tokio::test]
async fn accepted_error_and_aggregate_refusal_keep_the_server_key_known() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = session(
        &server,
        Duration::from_secs(1),
        Limits {
            max_file_bytes: 0,
            ..Default::default()
        },
    )
    .await;
    let task = tokio::spawn(async move {
        let (first, peer) = asked(&server).await;
        answer(&server, peer, &first, Command::Err, 10, b"refused".to_vec()).await;
        let (second, peer) = asked(&server).await;
        assert_eq!(second.header.key, 10);
        answer(&server, peer, &second, Command::GetFile, 11, b"x".to_vec()).await;
        let (third, peer) = asked(&server).await;
        assert_eq!(third.header.key, 11);
        answer(
            &server,
            peer,
            &third,
            Command::Version,
            12,
            b"healthy".to_vec(),
        )
        .await;
    });
    assert_eq!(
        session.version().await.unwrap_err(),
        ClientError::Refused("refused".into())
    );
    assert!(matches!(
        session.get_file("/").await,
        Err(ClientError::LimitExceeded {
            what: "file bytes",
            ..
        })
    ));
    assert_eq!(session.version().await.unwrap(), "healthy");
    task.await.unwrap();
}

#[tokio::test]
async fn expired_absolute_budget_refuses_before_a_ready_inner_request() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut session = session(&server, Duration::from_secs(1), Limits::default()).await;
    let deadline = tokio::time::Instant::now();
    assert_eq!(
        session
            .request_until(Command::Version, &[], 0, deadline)
            .await
            .unwrap_err(),
        ClientError::OperationTimedOut
    );
    assert!(!session.in_flight);
    assert_eq!(session.sequence, 1);
    let mut bytes = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut bytes))
            .await
            .is_err()
    );
}
