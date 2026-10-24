use super::*;
use crate::SuccessHeader;
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, sync::oneshot, time::Instant};

const REQUEST: &[u8] = b"scroll://example.test/a%20b +fr-CA,fr,en\r\n";

#[derive(Clone, Copy, PartialEq)]
enum Block {
    None,
    Read,
    PartialRead,
    Write,
    PartialWrite,
    Flush,
}

#[derive(Default)]
struct State {
    polls: AtomicUsize,
    shutdowns: AtomicUsize,
    dropped: AtomicBool,
}

struct Carrier {
    input: Vec<u8>,
    read: usize,
    output: Vec<u8>,
    block: Block,
    started: Option<oneshot::Sender<()>>,
    read_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    state: Arc<State>,
}

impl Carrier {
    fn new(block: Block) -> (Self, oneshot::Receiver<()>) {
        let (started, waiting) = oneshot::channel();
        (
            Self {
                input: REQUEST.to_vec(),
                read: 0,
                output: Vec::new(),
                block,
                started: Some(started),
                read_delay: None,
                state: Arc::default(),
            },
            waiting,
        )
    }

    fn blocked(&mut self, stage: Block) -> bool {
        self.state.polls.fetch_add(1, Ordering::SeqCst);
        if self.block == stage {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            true
        } else {
            false
        }
    }
}

impl Drop for Carrier {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for Carrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.blocked(Block::Read) {
            return Poll::Pending;
        }
        if self.block == Block::PartialRead && self.read > 0 && self.blocked(Block::PartialRead) {
            return Poll::Pending;
        }
        if let Some(delay) = &mut self.read_delay {
            std::task::ready!(delay.as_mut().poll(cx));
            self.read_delay = None;
        }
        let count = buf.remaining().min(self.input.len() - self.read);
        buf.put_slice(&self.input[self.read..self.read + count]);
        self.read += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked(Block::Write) {
            return Poll::Pending;
        }
        if self.block == Block::PartialWrite {
            if self.output.is_empty() {
                self.output.extend_from_slice(&bytes[..3]);
                return Poll::Ready(Ok(3));
            }
            self.blocked(Block::PartialWrite);
            return Poll::Pending;
        }
        self.output.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.blocked(Block::Flush) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.shutdowns.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

struct Active(Arc<AtomicBool>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn reply() -> Reply {
    Reply {
        header: Header::Success(SuccessHeader {
            code: 28,
            mimetype: "text/scroll;charset=utf-8;lang=fr-CA".into(),
            author: Some("Écrivain".into()),
            published: Some("2026-10-23T10:00:00Z".into()),
            modified: Some("2026-10-23T10:00:01Z".into()),
        }),
        body: b"# Abstract\r\n\0\xff".to_vec(),
    }
}

fn assert_borrowed(carrier: &Carrier) {
    assert_eq!(carrier.state.shutdowns.load(Ordering::SeqCst), 0);
    assert!(!carrier.state.dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn ready_shutdown_precedes_ready_exchange_without_io_or_handler() {
    let (mut stream, _) = Carrier::new(Block::None);
    let handler = |_: Request| async { panic!("shutdown polled handler") };
    let error = serve_connection_until_shutdown(
        &mut stream,
        &handler,
        &ServerConfig::default(),
        std::future::ready(()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(stream.state.polls.load(Ordering::SeqCst), 0);
    assert_borrowed(&stream);
}

#[tokio::test]
async fn shutdown_cancels_started_read_write_and_flush_without_closing_carrier() {
    for stage in [
        Block::Read,
        Block::PartialRead,
        Block::Write,
        Block::PartialWrite,
        Block::Flush,
    ] {
        let (mut stream, started) = Carrier::new(stage);
        let handler = |_: Request| async { reply() };
        let error = serve_connection_until_shutdown(
            &mut stream,
            &handler,
            &ServerConfig::default(),
            async { started.await.unwrap() },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_borrowed(&stream);
        assert_eq!(
            stream.read,
            match stage {
                Block::Read => 0,
                Block::PartialRead => 1,
                _ => REQUEST.len(),
            }
        );
        assert_eq!(
            stream.output,
            match stage {
                Block::Flush => reply().encode(ResponseLimits::default()).unwrap(),
                Block::PartialWrite => b"28 ".to_vec(),
                _ => Vec::new(),
            }
        );
    }
}

#[tokio::test]
async fn signalled_shutdown_drops_started_handler_before_return() {
    let active = Arc::new(AtomicBool::new(false));
    let started = Arc::new(tokio::sync::Notify::new());
    let handler = |_: Request| {
        let active = active.clone();
        let started = started.clone();
        async move {
            active.store(true, Ordering::SeqCst);
            let _guard = Active(active);
            started.notify_one();
            std::future::pending::<Reply>().await
        }
    };
    let (mut stream, _) = Carrier::new(Block::None);
    let error = serve_connection_until_shutdown(
        &mut stream,
        &handler,
        &ServerConfig::default(),
        started.notified(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(!active.load(Ordering::SeqCst));
    assert!(stream.output.is_empty());
    assert_borrowed(&stream);
}

#[tokio::test]
async fn dropping_companion_drops_handler_and_releases_borrow() {
    let active = Arc::new(AtomicBool::new(false));
    let started = Arc::new(tokio::sync::Notify::new());
    let handler = |_: Request| {
        let active = active.clone();
        let started = started.clone();
        async move {
            active.store(true, Ordering::SeqCst);
            let _guard = Active(active);
            started.notify_one();
            std::future::pending::<Reply>().await
        }
    };
    let (mut stream, _) = Carrier::new(Block::None);
    let config = ServerConfig::default();
    {
        let exchange =
            serve_connection_until_shutdown(&mut stream, &handler, &config, std::future::pending());
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => panic!("unexpected result: {result:?}"),
            _ = started.notified() => assert!(active.load(Ordering::SeqCst)),
        }
    }
    assert!(!active.load(Ordering::SeqCst));
    assert_borrowed(&stream);
    stream.write_all(b"caller owns retirement").await.unwrap();
    assert_eq!(stream.output, b"caller owns retirement");
}

#[tokio::test(start_paused = true)]
async fn native_deadline_spans_read_handler_write_and_flush_without_renewal() {
    let (mut stream, _) = Carrier::new(Block::Flush);
    stream.read_delay = Some(Box::pin(tokio::time::sleep(Duration::from_secs(4))));
    let handler = |_: Request| async {
        tokio::time::sleep(Duration::from_secs(4)).await;
        reply()
    };
    let config = ServerConfig {
        timeout: Duration::from_secs(10),
        ..ServerConfig::default()
    };
    let begin = Instant::now();
    let error =
        serve_connection_until_shutdown(&mut stream, &handler, &config, std::future::pending())
            .await
            .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(Instant::now() - begin, config.timeout);
    assert!(stream.started.is_none(), "flush must actually be reached");
    assert_eq!(
        stream.output,
        reply().encode(config.response_limits).unwrap()
    );
    assert_borrowed(&stream);
}

#[tokio::test]
async fn success_preserves_native_request_metadata_bytes_and_unread_input() {
    let (mut stream, _) = Carrier::new(Block::None);
    stream.input.extend_from_slice(b"caller next phase");
    let handler = |request: Request| async move {
        assert_eq!(request.uri, "scroll://example.test/a%20b");
        assert_eq!(request.languages, ["fr-CA", "fr", "en"]);
        assert!(request.metadata);
        reply()
    };
    serve_connection_until_shutdown(
        &mut stream,
        &handler,
        &ServerConfig::default(),
        std::future::pending(),
    )
    .await
    .unwrap();
    assert_eq!(
        stream.output,
        reply().encode(ResponseLimits::default()).unwrap()
    );
    assert_eq!(&stream.input[stream.read..], b"caller next phase");
    assert_borrowed(&stream);
}

#[tokio::test]
async fn native_refusal_and_configuration_errors_survive_companion() {
    let (mut stream, _) = Carrier::new(Block::None);
    let handler = |_: Request| async { panic!("invalid request/config reached handler") };
    stream.input = b"http://example.test/ en\r\n".to_vec();
    serve_connection_until_shutdown(
        &mut stream,
        &handler,
        &ServerConfig::default(),
        std::future::pending(),
    )
    .await
    .unwrap();
    assert_eq!(stream.output, b"59 Invalid request\r\n");
    let (mut stream, _) = Carrier::new(Block::None);
    let config = ServerConfig {
        timeout: Duration::ZERO,
        ..ServerConfig::default()
    };
    let error =
        serve_connection_until_shutdown(&mut stream, &handler, &config, std::future::pending())
            .await
            .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(stream.state.polls.load(Ordering::SeqCst), 0);
    assert_borrowed(&stream);
}
