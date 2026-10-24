//! Native connection admission and joined-shutdown checks for Nex.

use std::future;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::{advance, timeout};

use super::{Request, ServerConfig, finish_connections, serve};

#[tokio::test]
async fn lifecycle_defaults_and_invalid_config_are_reported_before_accept() {
    let config = ServerConfig::default();
    assert_eq!(config.max_connections, 32);
    assert_eq!(config.shutdown_grace, Duration::from_secs(5));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = ServerConfig {
        max_connections: 0,
        ..ServerConfig::default()
    };
    let error = serve(
        listener,
        |_request: Request| async { Vec::new() },
        config,
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "invalid nex connection limit");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = ServerConfig {
        shutdown_grace: Duration::MAX,
        ..ServerConfig::default()
    };
    let error = serve(
        listener,
        |_request: Request| async { Vec::new() },
        config,
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "invalid nex shutdown grace");
}

#[tokio::test]
async fn one_connection_slot_queues_the_next_peer_then_reuses_the_slot() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, mut entered_rx) =
        tokio::sync::mpsc::unbounded_channel::<(String, tokio::sync::oneshot::Sender<Vec<u8>>)>();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let config = ServerConfig {
        max_connections: 1,
        shutdown_grace: Duration::ZERO,
        ..ServerConfig::default()
    };
    let server = tokio::spawn(serve(
        listener,
        move |request: Request| {
            let entered_tx = entered_tx.clone();
            async move {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                entered_tx.send((request.path, reply_tx)).unwrap();
                reply_rx.await.unwrap()
            }
        },
        config,
        async {
            let _ = stop_rx.await;
        },
    ));

    let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
    first.write_all(b"first\n").await.unwrap();
    let (first_path, first_reply) = timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_path, "first");

    let mut second = tokio::net::TcpStream::connect(address).await.unwrap();
    second.write_all(b"second\n").await.unwrap();
    assert!(
        timeout(Duration::from_millis(500), entered_rx.recv())
            .await
            .is_err()
    );

    first_reply.send(vec![0, 255, b'\n']).unwrap();
    let mut first_body = Vec::new();
    first.read_to_end(&mut first_body).await.unwrap();
    assert_eq!(first_body, [0, 255, b'\n']);
    let (second_path, second_reply) = timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_path, "second");
    second_reply.send(b"second body".to_vec()).unwrap();
    let mut second_body = Vec::new();
    second.read_to_end(&mut second_body).await.unwrap();
    assert_eq!(second_body, b"second body");

    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn graceful_shutdown_preserves_bare_lf_selector_and_exact_opaque_reply() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, mut entered_rx) =
        tokio::sync::mpsc::unbounded_channel::<tokio::sync::oneshot::Sender<Vec<u8>>>();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let config = ServerConfig {
        shutdown_grace: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = tokio::spawn(serve(
        listener,
        move |request: Request| {
            let entered_tx = entered_tx.clone();
            async move {
                assert_eq!(request.path, "opaque");
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                entered_tx.send(reply_tx).unwrap();
                reply_rx.await.unwrap()
            }
        },
        config,
        async {
            let _ = stop_rx.await;
        },
    ));
    let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
    peer.write_all(b"opaque\n").await.unwrap();
    let reply = timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    stop_tx.send(()).unwrap();
    reply.send(vec![0, 255, 1, b'\r', b'\n']).unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(2), peer.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw, [0, 255, 1, b'\r', b'\n']);
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

struct DropMark(Arc<AtomicUsize>);
impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn zero_and_expired_grace_cancel_and_join_held_handlers() {
    for grace in [Duration::ZERO, Duration::from_millis(500)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let child_drops = drops.clone();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let config = ServerConfig {
            shutdown_grace: grace,
            ..ServerConfig::default()
        };
        let server = tokio::spawn(serve(
            listener,
            move |_request: Request| {
                let child_drops = child_drops.clone();
                let entered_tx = entered_tx.clone();
                async move {
                    let _mark = DropMark(child_drops);
                    let _ = entered_tx.send(());
                    future::pending::<Vec<u8>>().await
                }
            },
            config,
            async {
                let _ = stop_rx.await;
            },
        ));
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        peer.write_all(b"held\n").await.unwrap();
        timeout(Duration::from_secs(2), entered_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let start = tokio::time::Instant::now();
        stop_tx.send(()).unwrap();
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if grace.is_zero() {
            assert!(start.elapsed() < Duration::from_millis(500));
        } else {
            assert!(start.elapsed() >= grace);
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let mut byte = [0];
        assert!(
            timeout(Duration::from_secs(1), peer.read(&mut byte))
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn dropping_serve_requests_child_cancellation_but_join_requires_awaiting_shutdown() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let child_drops = drops.clone();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(serve(
        listener,
        move |_request: Request| {
            let child_drops = child_drops.clone();
            let entered_tx = entered_tx.clone();
            async move {
                let _mark = DropMark(child_drops);
                let _ = entered_tx.send(());
                future::pending::<Vec<u8>>().await
            }
        },
        ServerConfig::default(),
        future::pending(),
    ));
    let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
    peer.write_all(b"held\n").await.unwrap();
    timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(2), peer.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn drain_uses_one_fixed_deadline_and_reaps_panics_and_cancellations() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _mark = DropMark(child_drops);
        let _ = started_tx.send(());
        tokio::time::sleep(Duration::from_secs(4)).await;
    });
    let (panic_tx, panic_rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _ = panic_tx.send(());
        panic!("controlled connection panic");
    });
    started_rx.await.unwrap();
    panic_rx.await.unwrap();
    let (pending_tx, pending_rx) = tokio::sync::oneshot::channel();
    let pending_drops = drops.clone();
    tasks.spawn(async move {
        let _mark = DropMark(pending_drops);
        pending_tx.send(()).unwrap();
        future::pending::<()>().await;
    });
    pending_rx.await.unwrap();
    let began = tokio::time::Instant::now();
    let deadline = began + Duration::from_secs(5);
    let drain = tokio::spawn(async move {
        finish_connections(&mut tasks, deadline).await;
    });
    tokio::task::yield_now().await;
    advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    advance(Duration::from_secs(1)).await;
    drain.await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(began.elapsed(), Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn drain_first_polled_after_deadline_does_not_restart_grace() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let child_drops = drops.clone();
    tasks.spawn(async move {
        let _mark = DropMark(child_drops);
        let _ = started_tx.send(());
        future::pending::<()>().await;
    });
    started_rx.await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    advance(Duration::from_secs(6)).await;
    let polled_at = tokio::time::Instant::now();
    finish_connections(&mut tasks, deadline).await;
    assert_eq!(tokio::time::Instant::now(), polled_at);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
