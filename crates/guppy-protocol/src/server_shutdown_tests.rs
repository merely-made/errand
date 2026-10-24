//! Shutdown cancellation and native UDP session regression controls.

use std::future;
use std::io;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;

use super::{Handler, Request, ServerConfig, run_until_shutdown, serve};
use crate::packet::encode_ack;
use crate::{GuppyResponse, Packet, parse_packet};

type Running = (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<io::Result<()>>,
);

async fn start(handler: impl Handler, config: ServerConfig) -> Running {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(serve(socket, handler, config, async {
        let _ = stopped.await;
    }));
    (address, stop, task)
}

async fn stop_server((address, stop, task): Running) {
    stop.send(()).unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The supplied socket is owned by serve, with no other server handles.
    let rebound = UdpSocket::bind(address).await.unwrap();
    drop(rebound);
}

async fn client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn request(socket: &UdpSocket, address: SocketAddr, path: &str) {
    socket
        .send_to(
            format!("guppy://example.test{path}\r\n").as_bytes(),
            address,
        )
        .await
        .unwrap();
}

async fn wire(socket: &UdpSocket) -> Vec<u8> {
    let mut bytes = [0; 4096];
    let size = timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap()
        .0;
    bytes[..size].to_vec()
}

async fn quiet(socket: &UdpSocket, duration: Duration) {
    let mut bytes = [0; 4096];
    assert!(
        timeout(duration, socket.recv_from(&mut bytes))
            .await
            .is_err(),
        "unexpected datagram"
    );
}

async fn ack(socket: &UdpSocket, address: SocketAddr, seq: u32) {
    socket.send_to(&encode_ack(seq), address).await.unwrap();
}

struct DropMark(Arc<AtomicUsize>);
impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn ready_shutdown_wins_before_queued_request_and_releases_socket() {
    let socket = client().await;
    let address = socket.local_addr().unwrap();
    let peer = client().await;
    request(&peer, address, "/queued").await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    serve(
        socket,
        move |_: Request| {
            observed.fetch_add(1, Ordering::SeqCst);
            async {
                GuppyResponse::Error {
                    message: "unexpected".into(),
                }
            }
        },
        ServerConfig::default(),
        async {},
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let rebound = UdpSocket::bind(address).await.unwrap();
    quiet(&peer, Duration::from_millis(150)).await;
    drop(rebound);
}

#[tokio::test]
async fn pending_inline_handler_is_dropped_without_parallel_peer_work_or_rollback() {
    let entered = Arc::new(Notify::new());
    let effects = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let signal = entered.clone();
    let changed = effects.clone();
    let guards = drops.clone();
    let running = start(
        move |_: Request| {
            let signal = signal.clone();
            let changed = changed.clone();
            let guards = guards.clone();
            async move {
                let _guard = DropMark(guards);
                changed.fetch_add(1, Ordering::SeqCst);
                signal.notify_one();
                future::pending::<GuppyResponse>().await
            }
        },
        ServerConfig::default(),
    )
    .await;
    let first = client().await;
    let second = client().await;
    request(&first, running.0, "/held").await;
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    request(&second, running.0, "/later").await;
    assert!(
        timeout(Duration::from_millis(200), entered.notified())
            .await
            .is_err()
    );
    stop_server(running).await;
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "current handler drops before serve returns"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "cancellation does not undo an existing effect or admit another handler"
    );
    quiet(&first, Duration::from_millis(100)).await;
    quiet(&second, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn whole_engine_guard_cancels_pending_io_and_preserves_existing_partial_output() {
    // UDP kernel send backpressure is not forced here. This exercises the same
    // outer guard with deterministic, genuinely pending AsyncWrite I/O.
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let drops = Arc::new(AtomicUsize::new(0));
    let guards = drops.clone();
    let (entered, ready) = oneshot::channel();
    let (stop, stopped) = oneshot::channel();
    let operation = async move {
        let _guard = DropMark(guards);
        writer.write_all(b"a").await?;
        entered.send(()).unwrap();
        writer.write_all(b"b").await?;
        Ok(())
    };
    let task = tokio::spawn(run_until_shutdown(operation, async {
        let _ = stopped.await;
    }));
    ready.await.unwrap();
    stop.send(()).unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let mut received = Vec::new();
    timeout(Duration::from_secs(1), reader.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"a");

    let error = run_until_shutdown(
        async { Err(io::Error::other("operation failed")) },
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "operation failed");
}

#[tokio::test]
async fn shutdown_remains_responsive_under_continuous_ready_datagrams() {
    let entered = Arc::new(Notify::new());
    let observed = entered.clone();
    let running = start(
        move |_: Request| {
            observed.notify_one();
            async {
                GuppyResponse::Error {
                    message: "busy".into(),
                }
            }
        },
        ServerConfig::default(),
    )
    .await;
    let address = running.0;
    let peer = client().await;
    let sender = tokio::spawn(async move {
        loop {
            if peer
                .send_to(b"guppy://example.test/flood\r\n", address)
                .await
                .is_err()
            {
                break;
            }
        }
    });
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    stop_server(running).await;
    sender.abort();
    let _ = sender.await;
}

#[tokio::test]
async fn window_ack_duplicates_retransmission_and_completed_linger_keep_native_semantics() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let running = start(
        move |request: Request| {
            observed.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(request.path, "/data");
                assert_eq!(request.input.as_deref(), Some("hello world"));
                GuppyResponse::Success {
                    mime: "application/octet-stream".into(),
                    body: b"abcdef".to_vec(),
                }
            }
        },
        ServerConfig {
            chunk_size: 2,
            window: 2,
            retransmit_after: Duration::from_millis(800),
            session_timeout: Duration::from_secs(20),
            max_sessions: 1,
        },
    )
    .await;
    let peer = client().await;
    request(&peer, running.0, "/data?hello%20world").await;
    let initial = [wire(&peer).await, wire(&peer).await];
    let first = initial
        .iter()
        .find_map(|wire| match parse_packet(wire).unwrap() {
            Packet::First { seq, mime, data } => {
                assert_eq!(mime, "application/octet-stream");
                assert_eq!(data, b"ab");
                Some(seq)
            }
            _ => None,
        })
        .unwrap();
    assert!(initial.iter().any(|wire| parse_packet(wire).unwrap()
        == Packet::Continuation {
            seq: first + 1,
            data: b"cd".to_vec()
        }));
    // A live duplicate request does not dispatch a second handler or reset seq.
    request(&peer, running.0, "/data?hello%20world").await;
    quiet(&peer, Duration::from_millis(150)).await;
    let resent = [wire(&peer).await, wire(&peer).await];
    for packet in &initial {
        assert!(resent.contains(packet));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    ack(&peer, running.0, first).await;
    assert_eq!(
        parse_packet(&wire(&peer).await).unwrap(),
        Packet::Continuation {
            seq: first + 2,
            data: b"ef".to_vec()
        }
    );
    ack(&peer, running.0, first).await; // Duplicate ACK, still a full window.
    ack(&peer, running.0, 1).await; // Unknown in-session ACK.
    quiet(&peer, Duration::from_millis(150)).await;
    ack(&peer, running.0, first + 1).await;
    assert_eq!(
        parse_packet(&wire(&peer).await).unwrap(),
        Packet::Continuation {
            seq: first + 3,
            data: Vec::new()
        }
    );
    ack(&peer, running.0, first + 2).await;
    ack(&peer, running.0, first + 3).await;
    request(&peer, running.0, "/data?hello%20world").await;
    quiet(&peer, Duration::from_millis(150)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "completed session still suppresses duplicates"
    );
    tokio::time::sleep(Duration::from_millis(5800)).await;
    request(&peer, running.0, "/data?hello%20world").await;
    let _ = wire(&peer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "completed linger eventually frees this peer"
    );
    stop_server(running).await;
}

#[tokio::test]
async fn session_cap_and_creation_based_expiry_survive_progress() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let running = start(
        move |_: Request| {
            observed.fetch_add(1, Ordering::SeqCst);
            async {
                GuppyResponse::Success {
                    mime: "text/plain".into(),
                    body: b"abcdef".to_vec(),
                }
            }
        },
        ServerConfig {
            chunk_size: 2,
            window: 1,
            retransmit_after: Duration::from_millis(600),
            session_timeout: Duration::from_secs(1),
            max_sessions: 1,
        },
    )
    .await;
    let first_peer = client().await;
    let second_peer = client().await;
    request(&first_peer, running.0, "/first").await;
    let first_seq = match parse_packet(&wire(&first_peer).await).unwrap() {
        Packet::First { seq, .. } => seq,
        other => panic!("unexpected {other:?}"),
    };
    request(&second_peer, running.0, "/blocked").await;
    quiet(&second_peer, Duration::from_millis(500)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    ack(&first_peer, running.0, first_seq).await;
    assert_eq!(
        parse_packet(&wire(&first_peer).await).unwrap(),
        Packet::Continuation {
            seq: first_seq + 1,
            data: b"cd".to_vec()
        }
    );
    tokio::time::sleep(Duration::from_millis(900)).await;
    request(&second_peer, running.0, "/new").await;
    assert!(matches!(
        parse_packet(&wire(&second_peer).await).unwrap(),
        Packet::First { .. }
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "ACK progress must not renew creation-based expiry"
    );
    stop_server(running).await;
}

#[tokio::test]
async fn zero_window_keeps_silent_session_and_cap_until_shutdown() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let entered = Arc::new(Notify::new());
    let signal = entered.clone();
    let running = start(
        move |_: Request| {
            observed.fetch_add(1, Ordering::SeqCst);
            signal.notify_one();
            async {
                GuppyResponse::Success {
                    mime: "text/plain".into(),
                    body: b"silent".to_vec(),
                }
            }
        },
        ServerConfig {
            window: 0,
            max_sessions: 1,
            ..ServerConfig::default()
        },
    )
    .await;
    let peer = client().await;
    let other = client().await;
    request(&peer, running.0, "/silent").await;
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    request(&peer, running.0, "/duplicate").await;
    request(&other, running.0, "/capped").await;
    quiet(&peer, Duration::from_millis(150)).await;
    quiet(&other, Duration::from_millis(150)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop_server(running).await;
}

#[tokio::test]
async fn shutdown_discards_unacked_session_without_waiting_for_eof_ack() {
    let running = start(
        |_: Request| async {
            GuppyResponse::Success {
                mime: "text/plain".into(),
                body: b"pending".to_vec(),
            }
        },
        ServerConfig {
            retransmit_after: Duration::from_millis(600),
            window: 1,
            ..ServerConfig::default()
        },
    )
    .await;
    let peer = client().await;
    request(&peer, running.0, "/pending").await;
    let first = wire(&peer).await;
    assert_eq!(
        wire(&peer).await,
        first,
        "unacknowledged packet retransmits before stop"
    );
    stop_server(running).await;
    // Sent UDP datagrams cannot be recalled; drain any already queued packet.
    let mut bytes = [0; 4096];
    while timeout(Duration::from_millis(50), peer.recv_from(&mut bytes))
        .await
        .is_ok()
    {}
    quiet(&peer, Duration::from_millis(900)).await;
}
