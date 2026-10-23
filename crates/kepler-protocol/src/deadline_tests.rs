use super::*;
use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const REQUEST: &[u8] = b"kepler://x/ 0 en\r\n";

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("pure request preflight unexpectedly waited"),
    }
}
struct NoIo;
impl AsyncRead for NoIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        panic!("preflight read transport")
    }
}
impl AsyncWrite for NoIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        panic!("preflight wrote transport")
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("preflight flushed transport")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("preflight closed transport")
    }
}
fn options(timeout: Duration) -> Options {
    Options {
        operation_timeout: timeout,
        ..Options::default()
    }
}
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut prior = 0;
    for _ in 0..4096 {
        let byte = stream.read_u8().await.unwrap();
        if prior == b'\r' && byte == b'\n' {
            return;
        }
        prior = byte;
    }
    panic!("unbounded fixture request");
}
// An always-ready carrier can block between polls. Its final LF completes a
// valid bodyless response after the timer has expired, without yielding.
struct LateCompletion {
    bytes: &'static [u8],
    cursor: usize,
}
impl AsyncRead for LateCompletion {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.cursor == self.bytes.len() {
            return Poll::Ready(Ok(()));
        }
        let byte = self.bytes[self.cursor];
        if self.cursor + 1 == self.bytes.len() {
            std::thread::sleep(Duration::from_millis(60));
        }
        out.put_slice(&[byte]);
        self.cursor += 1;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for LateCompletion {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn preflight_and_zero_timeout_need_no_runtime_or_transport() {
    assert_eq!(
        Options::default().operation_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(Options::default().limits, Limits::default());
    assert!(matches!(
        ready(fetch_with_options(
            "gemini://x/",
            0,
            "en",
            &Options::default()
        )),
        Err(ClientError::BadUrl(_))
    ));
    #[cfg(not(feature = "tls"))]
    assert!(matches!(
        ready(fetch_with_options(
            "keplers://x/",
            0,
            "en",
            &Options::default()
        )),
        Err(ClientError::Connect(_))
    ));
    let mut client = NoIo;
    let policy = options(Duration::ZERO);
    assert!(matches!(
        ready(exchange_with_options(&mut client, REQUEST, &policy)),
        Err(ClientError::TimedOut)
    ));
    assert!(matches!(
        ready(fetch_with_options(
            "kepler://127.0.0.1:9/",
            0,
            "en",
            &policy
        )),
        Err(ClientError::TimedOut)
    ));
    let policy = options(Duration::MAX);
    assert!(matches!(
        ready(exchange_with_options(&mut client, REQUEST, &policy)),
        Err(ClientError::Protocol(_))
    ));
    let policy = Options {
        limits: Limits {
            max_request_bytes: 0,
            ..Limits::default()
        },
        ..Options::default()
    };
    assert!(matches!(
        ready(exchange_with_options(&mut client, REQUEST, &policy)),
        Err(ClientError::Limit(_))
    ));
}
#[tokio::test(start_paused = true)]
async fn one_budget_covers_stalled_write_header_and_body() {
    for stage in ["write", "header", "body"] {
        let (mut client, mut server) = tokio::io::duplex(if stage == "write" { 1 } else { 4096 });
        if stage == "body" {
            server
                .write_all(b"20 -1 12 34 text/plain\r\na")
                .await
                .unwrap();
        }
        let policy = options(Duration::from_millis(50));
        let started = tokio::time::Instant::now();
        assert!(
            matches!(
                exchange_with_options(&mut client, REQUEST, &policy).await,
                Err(ClientError::TimedOut)
            ),
            "{stage}"
        );
        assert_eq!(started.elapsed(), policy.operation_timeout);
        drop(server);
    }
}
#[tokio::test(start_paused = true)]
async fn convenience_exchange_has_a_finite_default_deadline() {
    let (mut client, server) = tokio::io::duplex(1);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        exchange(&mut client, REQUEST).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(started.elapsed(), Options::default().operation_timeout);
    drop(server);
}
#[tokio::test(start_paused = true)]
async fn header_and_body_share_the_original_deadline() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        read_request(&mut server).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        server
            .write_all(b"20 -1 12 34 text/plain\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let _ = server.write_all(b"done").await;
    });
    let policy = options(Duration::from_millis(60));
    let started = tokio::time::Instant::now();
    assert!(matches!(
        exchange_with_options(&mut client, REQUEST, &policy).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(started.elapsed(), policy.operation_timeout);
    server.abort();
    let _ = server.await;
}
#[tokio::test(start_paused = true)]
async fn continuous_body_activity_cannot_renew_the_deadline() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        read_request(&mut server).await;
        server
            .write_all(b"20 -1 12 34 text/plain\r\n")
            .await
            .unwrap();
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if server.write_all(b"x").await.is_err() {
                break;
            }
        }
    });
    let policy = options(Duration::from_millis(45));
    let started = tokio::time::Instant::now();
    assert!(matches!(
        exchange_with_options(&mut client, REQUEST, &policy).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(started.elapsed(), policy.operation_timeout);
    server.abort();
    let _ = server.await;
}
#[tokio::test]
async fn late_always_ready_completion_is_not_a_success() {
    let mut client = LateCompletion {
        bytes: b"70 123\r\n",
        cursor: 0,
    };
    let policy = options(Duration::from_millis(30));
    assert!(matches!(
        exchange_with_options(&mut client, REQUEST, &policy).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(client.cursor, client.bytes.len(), "fixture reached late completion");
}
#[tokio::test]
async fn tcp_fetch_timeout_drops_owned_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("kepler://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(b"20 -1 12 34 text/plain\r\na")
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let policy = options(Duration::from_millis(40));
    assert!(matches!(
        fetch_with_options(&url, 123, "en", &policy).await,
        Err(ClientError::TimedOut)
    ));
    server.await.unwrap();
}
#[cfg(feature = "tls")]
fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use std::sync::Arc;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
    )
    .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_handshake_and_body_share_the_whole_operation_budget() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("keplers://{}/", listener.local_addr().unwrap());
    let entered_body = Arc::new(AtomicBool::new(false));
    let observed = entered_body.clone();
    let acceptor = tls_acceptor();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let mut stream = acceptor.accept(stream).await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(b"20 -1 12 34 text/plain\r\n")
            .await
            .unwrap();
        observed.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _ = stream.write_all(b"done").await;
        let _ = stream.shutdown().await;
    });
    let policy = options(Duration::from_millis(400));
    assert!(matches!(
        fetch_with_options(&url, 123, "en", &policy).await,
        Err(ClientError::TimedOut)
    ));
    assert!(
        entered_body.load(Ordering::SeqCst),
        "fixture must reach body stage before timing out"
    );
    server.await.unwrap();
}
#[cfg(feature = "tls")]
#[tokio::test]
async fn stalled_tls_handshake_is_bounded_and_owned_tcp_is_closed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("keplers://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            stream.take(16384).read_to_end(&mut data),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!data.is_empty());
        assert!(data.len() < 16384);
    });
    let policy = options(Duration::from_millis(40));
    assert!(matches!(
        fetch_with_options(&url, 123, "en", &policy).await,
        Err(ClientError::TimedOut)
    ));
    server.await.unwrap();
}
