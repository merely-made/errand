use super::*;
use std::future::{Future, pending};
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

#[derive(Default)]
struct Calls(AtomicUsize);

impl Source for Calls {
    async fn receive(&self, _: &str, _: Option<Range>) -> Reply {
        self.0.fetch_add(1, Ordering::SeqCst);
        Reply::text("R")
    }
}

struct CountIo {
    polls: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

impl AsyncRead for CountIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

impl AsyncWrite for CountIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ready_shutdown_polls_neither_exchange_nor_source() {
    let polls = Arc::new(AtomicUsize::new(0));
    let source = Calls::default();
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = CountIo {
        polls: polls.clone(),
        closes: closes.clone(),
    };
    let error = serve_connection_until_shutdown(&mut io, &source, async {})
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(error.to_string(), "Scorpion exchange interrupted");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
}

#[derive(Clone, Copy)]
enum BlockAt {
    Read,
    Write,
    Flush,
}

struct BlockIo {
    at: BlockAt,
    input: &'static [u8],
    read: usize,
    started: Option<oneshot::Sender<()>>,
    drops: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

impl Drop for BlockIo {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for BlockIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if matches!(self.at, BlockAt::Read) {
            if let Some(tx) = self.started.take() {
                let _ = tx.send(());
            }
            return Poll::Pending;
        }
        let end = self.input.len().min(self.read + buf.remaining());
        buf.put_slice(&self.input[self.read..end]);
        self.read = end;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BlockIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.at, BlockAt::Write) {
            if let Some(tx) = self.started.take() {
                let _ = tx.send(());
            }
            return Poll::Pending;
        }
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.at, BlockAt::Flush) {
            if let Some(tx) = self.started.take() {
                let _ = tx.send(());
            }
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn shutdown_cancels_started_read_and_keeps_borrowed_carrier_alive() {
    assert_blocked_carrier_cancels(BlockAt::Read).await;
}

#[tokio::test]
async fn shutdown_cancels_started_write_and_keeps_borrowed_carrier_alive() {
    assert_blocked_carrier_cancels(BlockAt::Write).await;
}

#[tokio::test]
async fn shutdown_cancels_started_flush_and_keeps_borrowed_carrier_alive() {
    assert_blocked_carrier_cancels(BlockAt::Flush).await;
}

async fn assert_blocked_carrier_cancels(at: BlockAt) {
    let (started_tx, started_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = BlockIo {
        at,
        input: b"R scorpion://x/\r\n",
        read: 0,
        started: Some(started_tx),
        drops: drops.clone(),
        closes: closes.clone(),
    };
    let source = Calls::default();
    let mut exchange = Box::pin(serve_connection_until_shutdown(&mut io, &source, async {
        let _ = shutdown_rx.await;
    }));
    tokio::select! {
        _ = started_rx => {},
        result = &mut exchange => panic!("exchange ended before shutdown: {result:?}"),
    }
    shutdown_tx.send(()).unwrap();
    assert_eq!(
        (&mut exchange).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "borrowed stream was dropped"
    );
    assert_eq!(
        source.0.load(Ordering::SeqCst),
        usize::from(!matches!(at, BlockAt::Read))
    );
    assert_eq!(
        closes.load(Ordering::SeqCst),
        0,
        "wrapper closed the borrowed carrier"
    );
    drop(exchange);
    drop(io);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

struct PendingSource {
    started: Mutex<Option<oneshot::Sender<()>>>,
    dropped: Arc<AtomicUsize>,
}
struct PendingReply(Arc<AtomicUsize>);
impl Drop for PendingReply {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Source for PendingSource {
    fn receive(&self, _: &str, _: Option<Range>) -> impl Future<Output = Reply> + Send {
        let tx = self.started.lock().unwrap().take();
        let dropped = self.dropped.clone();
        async move {
            let _guard = PendingReply(dropped);
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
            pending().await
        }
    }
}

#[tokio::test]
async fn shutdown_drops_started_source_future_without_dropping_stream() {
    let (started_tx, started_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let source = PendingSource {
        started: Mutex::new(Some(started_tx)),
        dropped: drops.clone(),
    };
    let stream_drops = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = BlockIo {
        at: BlockAt::Flush,
        input: b"R scorpion://x/\r\n",
        read: 0,
        started: None,
        drops: stream_drops.clone(),
        closes: closes.clone(),
    };
    let mut exchange = Box::pin(serve_connection_until_shutdown(&mut io, &source, async {
        let _ = shutdown_rx.await;
    }));
    tokio::select! {
        _ = started_rx => {},
        result = &mut exchange => panic!("exchange ended before shutdown: {result:?}"),
    }
    shutdown_tx.send(()).unwrap();
    assert_eq!(
        (&mut exchange).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(stream_drops.load(Ordering::SeqCst), 0);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropping_wrapper_cancels_source_and_does_not_drop_borrowed_stream() {
    let (started_tx, started_rx) = oneshot::channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let source = PendingSource {
        started: Mutex::new(Some(started_tx)),
        dropped: drops.clone(),
    };
    let stream_drops = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = BlockIo {
        at: BlockAt::Flush,
        input: b"R scorpion://x/\r\n",
        read: 0,
        started: None,
        drops: stream_drops.clone(),
        closes: closes.clone(),
    };
    let mut exchange = Box::pin(serve_connection_until_shutdown(
        &mut io,
        &source,
        pending::<()>(),
    ));
    tokio::select! { _ = started_rx => {}, _ = &mut exchange => panic!("exchange completed") }
    drop(exchange);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(stream_drops.load(Ordering::SeqCst), 0);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
}

struct MemoryIo {
    input: &'static [u8],
    read: usize,
    output: Vec<u8>,
    closes: Arc<AtomicUsize>,
}
impl AsyncRead for MemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let end = self.input.len().min(self.read + buf.remaining());
        buf.put_slice(&self.input[self.read..end]);
        self.read = end;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for MemoryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.output.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Dispatch(Mutex<Vec<String>>);
impl Source for Dispatch {
    async fn receive(&self, url: &str, range: Option<Range>) -> Reply {
        self.0.lock().unwrap().push(format!("R:{url}:{range:?}"));
        match range {
            Some(_) => Reply::Partial {
                body: vec![0, 255],
                total: 9,
                media_type: "x/test".into(),
            },
            None => Reply::text("r"),
        }
    }
    async fn meta(&self, url: &str, kind: Option<&str>) -> Reply {
        self.0.lock().unwrap().push(format!("M:{url}:{kind:?}"));
        Reply::text("m")
    }
    async fn send(&self, url: &str, _: &Parameter) -> Reply {
        self.0.lock().unwrap().push(format!("S:{url}"));
        Reply::Status(Status::READY_NEW, "ready".into())
    }
    async fn interactive(&self, url: &str, caps: &str) -> Reply {
        self.0.lock().unwrap().push(format!("I:{url}:{caps}"));
        Reply::Status(Status::INTERACTIVE, "abc".into())
    }
}

#[tokio::test]
async fn success_preserves_native_dispatch_framing_and_borrowed_stream_handoff() {
    let input = b"R3-5 scorpion://x/r\r\nMtext/plain scorpion://x/m\r\nS1 scorpion://x/s\r\nIabc scorpion://x/i\r\nNEXT";
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = MemoryIo {
        input,
        read: 0,
        output: Vec::new(),
        closes: closes.clone(),
    };
    let source = Dispatch::default();
    let wires = [
        b"R3-5 scorpion://x/r\r\n".as_slice(),
        b"Mtext/plain scorpion://x/m\r\n".as_slice(),
        b"S1 scorpion://x/s\r\n".as_slice(),
        b"Iabc scorpion://x/i\r\n".as_slice(),
    ];
    for wire in wires {
        let result = serve_connection_until_shutdown(&mut io, &source, pending::<()>())
            .await
            .unwrap();
        assert_eq!(result.unwrap().to_wire(), wire);
    }
    assert_eq!(&io.input[io.read..], b"NEXT");
    let expected = [
        b"21 9 x/test\r\n".as_slice(),
        &[0, 255],
        b"20 1 text/plain;charset=utf-8\r\nm".as_slice(),
        b"70 ready\r\n".as_slice(),
        b"00 abc\r\n".as_slice(),
    ]
    .concat();
    assert_eq!(io.output, expected);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
    assert_eq!(
        *source.0.lock().unwrap(),
        vec![
            "R:scorpion://x/r:Some(Range { start: 3, end: Some(5) })",
            "M:scorpion://x/m:Some(\"text/plain\")",
            "S:scorpion://x/s",
            "I:scorpion://x/i:abc",
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn wrapper_does_not_change_a_callers_absolute_deadline() {
    let drops = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = BlockIo {
        at: BlockAt::Read,
        input: b"",
        read: 0,
        started: None,
        drops: drops.clone(),
        closes: closes.clone(),
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(7);
    let source = Calls::default();
    let result = tokio::time::timeout_at(
        deadline,
        serve_connection_until_shutdown(&mut io, &source, pending::<()>()),
    )
    .await;
    assert!(
        result.is_err(),
        "the caller's absolute deadline should expire"
    );
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(closes.load(Ordering::SeqCst), 0);
}

struct SlowSource;
impl Source for SlowSource {
    async fn receive(&self, _: &str, _: Option<Range>) -> Reply {
        tokio::time::sleep(std::time::Duration::from_secs(31)).await;
        Reply::text("after 30 seconds")
    }
}

#[tokio::test(start_paused = true)]
async fn wrapper_adds_no_native_server_deadline() {
    let closes = Arc::new(AtomicUsize::new(0));
    let mut io = MemoryIo {
        input: b"R scorpion://x/slow\r\n",
        read: 0,
        output: Vec::new(),
        closes: closes.clone(),
    };
    let start = tokio::time::Instant::now();
    let outer_deadline = start + std::time::Duration::from_secs(40);
    let result = tokio::time::timeout_at(
        outer_deadline,
        serve_connection_until_shutdown(&mut io, &SlowSource, pending::<()>()),
    )
    .await
    .expect("the caller's 40-second budget should contain the 31-second source");
    assert!(result.is_ok());
    assert_eq!(
        tokio::time::Instant::now() - start,
        std::time::Duration::from_secs(31)
    );
    assert!(io.output.ends_with(b"after 30 seconds"));
    assert_eq!(closes.load(Ordering::SeqCst), 0);
}
