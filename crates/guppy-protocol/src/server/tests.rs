use super::*;
use crate::client::{FetchOptions, fetch};

async fn spawn(
    handler: impl Handler,
    config: ServerConfig,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = serve(socket, handler, config, async {
            let _ = rx.await;
        })
        .await;
    });
    (addr, tx)
}

fn options_for(addr: SocketAddr) -> FetchOptions {
    FetchOptions {
        connect_addr: Some(addr),
        timeout: Duration::from_secs(5),
        retransmit_after: Duration::from_millis(200),
        ..Default::default()
    }
}

#[tokio::test]
async fn single_packet_round_trip() {
    let (addr, _stop) = spawn(
        |_request: Request| async move {
            GuppyResponse::Success {
                mime: "text/gemini".to_string(),
                body: b"# Title 1\n".to_vec(),
            }
        },
        ServerConfig::default(),
    )
    .await;
    let response = fetch("guppy://example.test/a", &options_for(addr))
        .await
        .unwrap();
    assert_eq!(
        response,
        GuppyResponse::Success {
            mime: "text/gemini".to_string(),
            body: b"# Title 1\n".to_vec()
        }
    );
}

#[tokio::test]
async fn multi_chunk_bodies_reassemble_in_order() {
    let body: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
    let expected = body.clone();
    let (addr, _stop) = spawn(
        move |_request: Request| {
            let body = body.clone();
            async move {
                GuppyResponse::Success {
                    mime: "application/octet-stream".to_string(),
                    body,
                }
            }
        },
        ServerConfig {
            chunk_size: 64,
            window: 4,
            ..Default::default()
        },
    )
    .await;
    let response = fetch("guppy://example.test/big", &options_for(addr))
        .await
        .unwrap();
    match response {
        GuppyResponse::Success { body, .. } => assert_eq!(body, expected),
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn prompt_redirect_and_error_round_trip() {
    let (addr, _stop) = spawn(
        |request: Request| async move {
            match (request.path.as_str(), request.input) {
                ("/greet", None) => GuppyResponse::Prompt {
                    text: "Your name".to_string(),
                },
                ("/greet", Some(name)) => GuppyResponse::Success {
                    mime: "text/gemini".to_string(),
                    body: format!("Hello {name}\n").into_bytes(),
                },
                ("/old", _) => GuppyResponse::Redirect {
                    target: "/new".to_string(),
                },
                _ => GuppyResponse::Error {
                    message: "not found".to_string(),
                },
            }
        },
        ServerConfig::default(),
    )
    .await;

    assert_eq!(
        fetch("guppy://example.test/greet", &options_for(addr))
            .await
            .unwrap(),
        GuppyResponse::Prompt {
            text: "Your name".to_string()
        }
    );
    assert_eq!(
        fetch("guppy://example.test/greet?Guppy", &options_for(addr))
            .await
            .unwrap(),
        GuppyResponse::Success {
            mime: "text/gemini".to_string(),
            body: b"Hello Guppy\n".to_vec()
        }
    );
    assert_eq!(
        fetch("guppy://example.test/old", &options_for(addr))
            .await
            .unwrap(),
        GuppyResponse::Redirect {
            target: "/new".to_string()
        }
    );
    assert_eq!(
        fetch("guppy://example.test/ghost", &options_for(addr))
            .await
            .unwrap(),
        GuppyResponse::Error {
            message: "not found".to_string()
        }
    );
}

/// Drive the client against a raw socket that delivers packets out of
/// order and duplicated — the spec's unreliable-network examples.
#[tokio::test]
async fn client_survives_out_of_order_and_duplicate_delivery() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        // Wait for the request.
        let (_count, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let first = encode_first(100, "text/plain", b"AA");
        let second = encode_continuation(101, b"BB");
        let eof = encode_continuation(102, b"");
        // Out of order, with duplicates: 101, 100, 101, 102(eof), 100.
        for wire in [&second, &first, &second, &eof, &first] {
            socket.send_to(wire, peer).await.unwrap();
        }
        // Absorb acks so the test socket doesn't fill any queue.
        loop {
            if socket.recv_from(&mut buffer).await.is_err() {
                break;
            }
        }
    });

    let response = fetch("guppy://example.test/x", &options_for(addr))
        .await
        .unwrap();
    assert_eq!(
        response,
        GuppyResponse::Success {
            mime: "text/plain".to_string(),
            body: b"AABB".to_vec()
        }
    );
}

#[tokio::test]
async fn file_handler_serves_and_refuses_traversal() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("index.gmi"), "# Hi\n").unwrap();
    let (addr, _stop) = spawn(FileHandler::new(dir.path()), ServerConfig::default()).await;

    assert_eq!(
        fetch("guppy://example.test/", &options_for(addr))
            .await
            .unwrap(),
        GuppyResponse::Success {
            mime: "text/gemini".to_string(),
            body: b"# Hi\n".to_vec()
        }
    );

    // URL parsing normalizes ".."; hostile selectors arrive raw.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(addr).await.unwrap();
    socket
        .send(b"guppy://example.test/%2e%2e/secret\r\n")
        .await
        .unwrap();
    let mut buffer = vec![0u8; 4096];
    let count = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert!(
        buffer[..count].starts_with(b"4 "),
        "traversal answered with an error"
    );
}

#[test]
fn build_session_chunks_and_terminates() {
    let session = build_session("text/plain", b"0123456789", 4);
    assert_eq!(session.packets.len(), 4, "3 data chunks + EOF");
    let seqs: Vec<u32> = session.packets.iter().map(|(seq, _)| *seq).collect();
    assert!(seqs.windows(2).all(|pair| pair[1] == pair[0] + 1));
    assert!(seqs[0] >= MIN_SEQ);
    // EOF packet is header-only.
    let (_, eof_wire) = session.packets.last().unwrap();
    assert!(eof_wire.ends_with(b"\r\n"));
}

#[test]
fn random_seq_stays_in_range() {
    for _ in 0..100 {
        let seq = random_seq(1000);
        assert!((MIN_SEQ..=MAX_SEQ - 1000).contains(&seq));
    }
}
