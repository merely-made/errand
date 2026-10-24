//! Native connection admission and joined-shutdown checks for Spartan.

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

use super::{Request, ServerConfig, SpartanResponse, finish_connections, serve};

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
        |_request: Request| async {
            SpartanResponse::ServerError {
                message: String::new(),
            }
        },
        config,
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "invalid spartan connection limit");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = ServerConfig {
        shutdown_grace: Duration::MAX,
        ..ServerConfig::default()
    };
    let error = serve(
        listener,
        |_request: Request| async {
            SpartanResponse::ServerError {
                message: String::new(),
            }
        },
        config,
        future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "invalid spartan shutdown grace");
}

#[tokio::test]
async fn queued_upload_keeps_native_request_and_exact_response_through_grace() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel::<(
        Request,
        tokio::sync::oneshot::Sender<SpartanResponse>,
    )>();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let config = ServerConfig {
        max_connections: 1,
        shutdown_grace: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = tokio::spawn(serve(
        listener,
        move |request: Request| {
            let entered_tx = entered_tx.clone();
            let effects = handler_effects.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                entered_tx.send((request, reply_tx)).unwrap();
                reply_rx.await.unwrap()
            }
        },
        config,
        async {
            let _ = stop_rx.await;
        },
    ));

    // Spartan's request carries a host, path, declared byte count, and the
    // complete upload body before the handler is called.
    let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
    first
        .write_all(b"upload.example /guestbook 5\r\nhello")
        .await
        .unwrap();
    let (request, first_reply) = timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.host, "upload.example");
    assert_eq!(request.path, "/guestbook");
    assert_eq!(request.data, b"hello");

    let mut second = tokio::net::TcpStream::connect(address).await.unwrap();
    second
        .write_all(b"upload.example /later 0\r\n")
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(500), entered_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);

    stop_tx.send(()).unwrap();
    first_reply
        .send(SpartanResponse::Success {
            mime: "application/octet-stream".to_string(),
            body: vec![0, 255, b'\r', b'\n'],
        })
        .unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(2), first.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw, b"2 application/octet-stream\r\n\0\xff\r\n");
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "shutdown does not undo a submitted handler effect"
    );
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
                    future::pending::<SpartanResponse>().await
                }
            },
            config,
            async {
                let _ = stop_rx.await;
            },
        ));
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        peer.write_all(b"example.test /held 0\r\n").await.unwrap();
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
                future::pending::<SpartanResponse>().await
            }
        },
        ServerConfig::default(),
        future::pending(),
    ));
    let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
    peer.write_all(b"example.test /held 0\r\n").await.unwrap();
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
async fn drain_started_after_deadline_aborts_immediately_and_joins_task() {
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
    finish_connections(&mut tasks, deadline).await;
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
