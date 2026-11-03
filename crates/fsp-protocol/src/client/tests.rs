use super::*;

#[test]
fn a_path_is_nul_terminated() {
    assert_eq!(nul_terminated("/pub"), b"/pub\0");
    assert_eq!(nul_terminated(""), b"\0");
}

#[tokio::test]
async fn a_stale_sequence_is_ignored_and_the_right_reply_accepted() {
    // A fake server that answers the wrong sequence first.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (read, peer) = server.recv_from(&mut buf).await.unwrap();
        let asked = decode(&buf[..read], Direction::ClientToServer).unwrap();

        let stale = Packet {
            header: Header {
                command: Command::GetFile.code(),
                key: 0x1111,
                sequence: asked.header.sequence.wrapping_sub(7),
                data_length: 5,
                file_position: 0,
            },
            data: b"stale".to_vec(),
            extra: Vec::new(),
        };
        server
            .send_to(&encode(&stale, Direction::ServerToClient), peer)
            .await
            .unwrap();

        let good = Packet {
            header: Header {
                command: Command::GetFile.code(),
                key: 0x2222,
                sequence: asked.header.sequence,
                data_length: 5,
                file_position: 0,
            },
            data: b"right".to_vec(),
            extra: Vec::new(),
        };
        server
            .send_to(&encode(&good, Direction::ServerToClient), peer)
            .await
            .unwrap();
    });

    let mut session = Session::connect("127.0.0.1", Some(addr.port()))
        .await
        .unwrap();
    session.timeout = Duration::from_secs(3);
    let block = session.get_file_block("/x", 0).await.unwrap();

    assert_eq!(block, b"right", "the stale sequence must not be accepted");
    assert_eq!(
        session.key, 0x2222,
        "the server's key is adopted for next time"
    );
}

#[tokio::test]
async fn a_server_error_surfaces_with_its_message() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (read, peer) = server.recv_from(&mut buf).await.unwrap();
        let asked = decode(&buf[..read], Direction::ClientToServer).unwrap();
        let error = Packet {
            header: Header {
                command: Command::Err.code(),
                key: 9,
                sequence: asked.header.sequence,
                data_length: 13,
                file_position: 0,
            },
            data: b"no such file\0".to_vec(),
            extra: Vec::new(),
        };
        server
            .send_to(&encode(&error, Direction::ServerToClient), peer)
            .await
            .unwrap();
    });

    let mut session = Session::connect("127.0.0.1", Some(addr.port()))
        .await
        .unwrap();
    session.timeout = Duration::from_secs(3);
    let error = session.get_file_block("/nope", 0).await.unwrap_err();
    assert_eq!(error, ClientError::Refused("no such file".into()));
}

#[tokio::test]
async fn silence_times_out_rather_than_hanging() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    // Never answer. The same request/sequence must be retried exactly twice.
    let task = tokio::spawn(async move {
        let mut buf = [0; 64];
        let mut first = None;
        for _ in 0..2 {
            let (read, _) =
                tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            if let Some(first) = &first {
                assert_eq!(&buf[..read], first);
            } else {
                first = Some(buf[..read].to_vec());
            }
        }
    });

    let mut session = Session::connect("127.0.0.1", Some(addr.port()))
        .await
        .unwrap();
    session.timeout = Duration::from_millis(60);
    session.attempts = 2;
    assert_eq!(
        session.get_file_block("/x", 0).await.unwrap_err(),
        ClientError::TimedOut
    );
    assert_eq!(
        session.version().await.unwrap_err(),
        ClientError::SessionUnusable
    );
    task.await.unwrap();
}
