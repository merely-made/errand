use std::future;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{advance, timeout};

use super::{ServerConfig, finish_connections, serve};

#[tokio::test]
async fn defaults_and_new_lifecycle_fields_are_validated_before_accepting() {
    let config = ServerConfig::default();
    assert_eq!(config.max_connections, 32);
    assert_eq!(config.shutdown_grace, Duration::from_secs(5));
    for (config, expected) in [
        (
            ServerConfig {
                max_connections: 0,
                ..ServerConfig::default()
            },
            "invalid finger connection limit",
        ),
        (
            ServerConfig {
                shutdown_grace: Duration::MAX,
                ..ServerConfig::default()
            },
            "invalid finger shutdown grace",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = serve(
            listener,
            |_request| async { Vec::new() },
            config,
            future::pending(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), expected);
    }
    let config = ServerConfig {
        shutdown_grace: Duration::ZERO,
        ..ServerConfig::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        |_request| async { Vec::new() },
        config,
        async {
            let _ = stopped.await;
        },
    ));
    stop.send(()).unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn capacity_waits_on_a_real_finger_handler_then_reuses_the_slot() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (first_entered, mut entered) = tokio::sync::mpsc::unbounded_channel();
    let (release_first, release) = tokio::sync::oneshot::channel();
    let release = Arc::new(tokio::sync::Mutex::new(Some(release)));
    let (second_entered, mut second_seen) = tokio::sync::mpsc::unbounded_channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let config = ServerConfig {
        max_connections: 1,
        ..ServerConfig::default()
    };
    let server = tokio::spawn(serve(
        listener,
        move |request: super::Request| {
            let second_entered = second_entered.clone();
            let first_entered = first_entered.clone();
            let release = release.clone();
            async move {
                if request.query.user.as_deref() == Some("first") {
                    let _ = first_entered.send(());
                    let receiver = release.lock().await.take();
                    if let Some(release) = receiver {
                        let _ = release.await;
                    }
                    b"first response\r\n".to_vec()
                } else {
                    let _ = second_entered.send(());
                    b"second response\r\n".to_vec()
                }
            }
        },
        config,
        async {
            let _ = stopped.await;
        },
    ));
    let mut first = TcpStream::connect(address).await.unwrap();
    first.write_all(b"first\r\n").await.unwrap();
    timeout(Duration::from_secs(2), entered.recv())
        .await
        .unwrap()
        .unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    second.write_all(b"/W second\r\n").await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), second_seen.recv())
            .await
            .is_err()
    );

    release_first.send(()).unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), first.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"first response\r\n");
    timeout(Duration::from_secs(2), second_seen.recv())
        .await
        .unwrap()
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), second.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"second response\r\n");
    stop.send(()).unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_drains_the_native_finger_verbose_query_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let config = ServerConfig {
        shutdown_grace: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = tokio::spawn(serve(
        listener,
        move |request: super::Request| {
            let entered_tx = entered_tx.clone();
            let release_rx = release_rx.clone();
            async move {
                assert_eq!(request.query.user.as_deref(), Some("alice"));
                assert!(request.query.verbose);
                let _ = entered_tx.send(());
                let receiver = release_rx.lock().await.take();
                if let Some(release_rx) = receiver {
                    let _ = release_rx.await;
                }
                b"alice\r\n  mailbox is open\r\n".to_vec()
            }
        },
        config,
        async {
            let _ = stop_rx.await;
        },
    ));
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"/W alice\r\n").await.unwrap();
    timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    stop_tx.send(()).unwrap();
    release_tx.send(()).unwrap();
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), peer.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"alice\r\n  mailbox is open\r\n");
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn zero_grace_aborts_and_joins_an_admitted_finger_handler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let handler_drops = drops.clone();
    let config = ServerConfig {
        shutdown_grace: Duration::ZERO,
        ..ServerConfig::default()
    };
    let server = tokio::spawn(serve(
        listener,
        move |_request| {
            let entered_tx = entered_tx.clone();
            let drops = handler_drops.clone();
            async move {
                let _drop = DropMark(drops);
                let _ = entered_tx.send(());
                future::pending::<Vec<u8>>().await
            }
        },
        config,
        async {
            let _ = stop_rx.await;
        },
    ));
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"alice\r\n").await.unwrap();
    timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let mut ignored = Vec::new();
    let result = timeout(Duration::from_secs(1), peer.read_to_end(&mut ignored))
        .await
        .unwrap();
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ));
    }
}

#[tokio::test]
async fn grace_expiry_aborts_a_stalled_query_and_closes_the_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = ServerConfig {
        shutdown_grace: Duration::from_millis(700),
        ..ServerConfig::default()
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let handler_drops = drops.clone();
    let server = tokio::spawn(serve(
        listener,
        move |_request| {
            let entered_tx = entered_tx.clone();
            let drops = handler_drops.clone();
            async move {
                let _drop = DropMark(drops);
                let _ = entered_tx.send(());
                future::pending::<Vec<u8>>().await
            }
        },
        config,
        async {
            let _ = stopped.await;
        },
    ));
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"alice\r\n").await.unwrap();
    timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    stop.send(()).unwrap();
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let closed = timeout(Duration::from_secs(1), peer.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        closed.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    ));
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn dropping_serve_requests_cancellation_of_owned_handler_tasks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(serve(
        listener,
        move |_request| {
            let entered_tx = entered_tx.clone();
            async move {
                let _ = entered_tx.send(());
                future::pending::<Vec<u8>>().await
            }
        },
        ServerConfig::default(),
        future::pending(),
    ));
    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"alice\r\n").await.unwrap();
    timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let mut ignored = Vec::new();
    let result = timeout(Duration::from_secs(2), peer.read_to_end(&mut ignored))
        .await
        .unwrap();
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ));
    }
}

struct DropMark(Arc<AtomicUsize>);
impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn finish_connections_keeps_the_observed_grace_deadline_fixed() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let mut started = Vec::new();
    for wait in [Duration::from_secs(4), Duration::MAX] {
        let drops = drops.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        started.push(started_rx);
        tasks.spawn(async move {
            let _drop = DropMark(drops);
            let _ = started_tx.send(());
            if wait == Duration::MAX {
                future::pending::<()>().await
            } else {
                tokio::time::sleep(wait).await
            }
        });
    }
    for ready in started {
        ready.await.unwrap();
    }
    let start = tokio::time::Instant::now();
    let finish = tokio::spawn(async move {
        finish_connections(&mut tasks, start + Duration::from_secs(5)).await;
    });
    advance(Duration::from_secs(4)).await;
    tokio::task::yield_now().await;
    assert!(!finish.is_finished());
    advance(Duration::from_secs(1)).await;
    finish.await.unwrap();
    assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(5));
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn zero_deadline_aborts_and_joins_panicked_and_pending_children() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let panic_drop = drops.clone();
    let (panic_started_tx, panic_started_rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _drop = DropMark(panic_drop);
        let _ = panic_started_tx.send(());
        panic!("controlled child panic");
    });
    let pending_drop = drops.clone();
    let (pending_started_tx, pending_started_rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _drop = DropMark(pending_drop);
        let _ = pending_started_tx.send(());
        future::pending::<()>().await
    });
    panic_started_rx.await.unwrap();
    pending_started_rx.await.unwrap();
    finish_connections(&mut tasks, tokio::time::Instant::now()).await;
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn starting_the_drain_after_its_deadline_does_not_restart_grace() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let child_drops = drops.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _drop = DropMark(child_drops);
        let _ = started_tx.send(());
        future::pending::<()>().await;
    });
    started_rx.await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    advance(Duration::from_secs(6)).await;
    let before_drain = tokio::time::Instant::now();
    finish_connections(&mut tasks, deadline).await;
    assert_eq!(tokio::time::Instant::now(), before_drain);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
