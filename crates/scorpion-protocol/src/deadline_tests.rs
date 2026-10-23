use super::*;
use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, duplex};
use tokio::time::{Instant, sleep};

fn options(milliseconds: u64) -> Options {
    Options {
        operation_timeout: Duration::from_millis(milliseconds),
        ..Options::default()
    }
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("pure preflight waited for I/O"),
    }
}

#[derive(Default)]
struct Carrier {
    written: usize,
}
impl AsyncRead for Carrier {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Carrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written += bytes.len();
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn zero_overflow_expired_and_bad_url_preflight_need_no_runtime() {
    let request = Request::receive("scorpion://example.net/");
    let mut carrier = Carrier::default();
    assert!(matches!(
        ready(exchange_with_options(&mut carrier, &request, options(0))),
        Err(ClientError::TimedOut)
    ));
    assert!(matches!(
        ready(exchange_with_options(
            &mut carrier,
            &request,
            Options {
                operation_timeout: Duration::MAX,
                ..Options::default()
            }
        )),
        Err(ClientError::InvalidTimeout)
    ));
    assert!(matches!(
        ready(exchange_until(
            &mut carrier,
            &request,
            Limits::default(),
            Instant::now() - Duration::from_secs(1)
        )),
        Err(ClientError::TimedOut)
    ));
    assert_eq!(carrier.written, 0);
    for url in ["not a URL", "scorpions://example.net/"] {
        assert!(matches!(
            ready(fetch_with_options(&Request::receive(url), options(0))),
            Err(ClientError::Url(_))
        ));
    }
    #[cfg(feature = "tls")]
    assert!(matches!(
        ready(crate::tls::connect_with_deadline(
            "not a URL",
            crate::tls::accept_any_verifier(),
            Instant::now()
        )),
        Err(ClientError::Url(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn default_response_reader_has_a_finite_operation_budget() {
    let (mut client, _server) = duplex(32);
    let start = Instant::now();
    assert!(matches!(
        read_response(&mut client, Limits::default(), None).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(Instant::now() - start, DEFAULT_OPERATION_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn stalled_write_and_header_obey_the_selected_budget() {
    let request = Request::receive("scorpion://example.net/");
    for capacity in [1, 128] {
        let (mut client, _server) = duplex(capacity);
        let start = Instant::now();
        assert!(matches!(
            exchange_with_options(&mut client, &request, options(20)).await,
            Err(ClientError::TimedOut)
        ));
        assert_eq!(Instant::now() - start, Duration::from_millis(20));
    }
}

#[tokio::test(start_paused = true)]
async fn body_progress_does_not_renew_the_deadline() {
    let (mut client, mut server) = duplex(256);
    let task = tokio::spawn(async move {
        server.write_all(b"20 3 text/plain\r\n").await.unwrap();
        for _ in 0..3 {
            sleep(Duration::from_millis(8)).await;
            if server.write_all(b"x").await.is_err() {
                break;
            }
        }
    });
    let start = Instant::now();
    assert!(matches!(
        read_response_with_options(&mut client, options(20), None).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(Instant::now() - start, Duration::from_millis(20));
    task.abort();
    let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn one_absolute_deadline_spans_two_responses_without_losing_framing() {
    let (mut client, mut server) = duplex(256);
    let task = tokio::spawn(async move {
        sleep(Duration::from_millis(12)).await;
        server.write_all(b"20 2 text/plain\r\nok").await.unwrap();
        sleep(Duration::from_millis(12)).await;
        let _ = server.write_all(b"80 saved\r\n").await;
    });
    let start = Instant::now();
    let deadline = start + Duration::from_millis(20);
    let first = read_response_until(&mut client, Limits::default(), None, deadline)
        .await
        .unwrap();
    assert_eq!(first.body, b"ok");
    assert!(matches!(
        read_response_until(&mut client, Limits::default(), None, deadline).await,
        Err(ClientError::TimedOut)
    ));
    assert_eq!(Instant::now() - start, Duration::from_millis(20));
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn a_late_ready_completion_is_not_success() {
    let deadline = Instant::now() + Duration::from_millis(10);
    let mut ran = false;
    let result = within_deadline(deadline, async {
        ran = true;
        std::thread::sleep(Duration::from_millis(20));
        Ok(())
    })
    .await;
    assert!(ran);
    assert!(matches!(result, Err(ClientError::TimedOut)));
}

#[tokio::test]
async fn native_tcp_fetch_times_out_and_drops_the_owned_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let request = Request::receive(format!("scorpion://{}/", listener.local_addr().unwrap()));
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(!bytes.is_empty());
    });
    assert!(matches!(
        fetch_with_options(&request, options(100)).await,
        Err(ClientError::TimedOut)
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn native_tcp_success_preserves_body_and_status_metadata() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let request = Request::receive(format!("scorpion://{}/", listener.local_addr().unwrap()));
    let expected = request.to_wire();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut line = vec![0; expected.len()];
        stream.read_exact(&mut line).await.unwrap();
        assert_eq!(line, expected);
        stream.write_all(b"20 2 text/plain\r\nok").await.unwrap();
    });
    let response = fetch_with_options(&request, options(1000)).await.unwrap();
    assert_eq!(response.body, b"ok");
    assert_eq!(response.header.status, crate::Status::OK);
    task.await.unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn native_tls_handshake_obeys_the_caller_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("scorpions://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    assert!(matches!(
        crate::tls::connect_with_deadline(
            &url,
            crate::tls::accept_any_verifier(),
            Instant::now() + Duration::from_millis(100)
        )
        .await,
        Err(ClientError::TimedOut)
    ));
    task.abort();
    let _ = task.await;
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn native_tls_and_two_framed_responses_share_one_deadline() {
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
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("scorpions://{}/", listener.local_addr().unwrap());
    let request = Request::send(url.clone(), None);
    let expected = request.to_wire();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut line = vec![0; expected.len()];
        stream.read_exact(&mut line).await.unwrap();
        assert_eq!(line, expected);
        stream
            .write_all(b"20 2 text/plain\r\nok80 saved\r\n")
            .await
            .unwrap();
        let _ = stream.shutdown().await;
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut stream =
        crate::tls::connect_with_deadline(&url, crate::tls::accept_any_verifier(), deadline)
            .await
            .unwrap();
    let first = exchange_until(&mut stream, &request, Limits::default(), deadline)
        .await
        .unwrap();
    assert_eq!(first.body, b"ok");
    let second = read_response_until(&mut stream, Limits::default(), None, deadline)
        .await
        .unwrap();
    assert_eq!(second.header.status, crate::Status::ACCEPTED_NEW);
    task.await.unwrap();
}
