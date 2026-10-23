use super::*;
use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

struct Probe {
    input: Vec<u8>,
    cursor: usize,
    written: Vec<u8>,
    hold: bool,
}
impl Probe {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            cursor: 0,
            written: Vec::new(),
            hold: false,
        }
    }
}
impl AsyncRead for Probe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.cursor == self.input.len() {
            return if self.hold {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            };
        }
        // Fragment every header and body down to one-byte reads.
        out.put_slice(&self.input[self.cursor..self.cursor + 1]);
        self.cursor += 1;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Probe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("operation waited for body bytes or EOF instead of refusing"),
    }
}
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        result.push(byte);
        assert!(result.len() <= 8192);
        if result.ends_with(b"\r\n") {
            return result;
        }
    }
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

const REQUEST: &[u8] = b"kepler://x/ 0 en\r\n";
#[tokio::test]
async fn supplied_limits_are_exact_and_never_return_a_prefix() {
    let mut empty = Probe::new(b"");
    assert!(matches!(
        ready(exchange_with_limits(
            &mut empty,
            b"",
            &Limits {
                max_request_bytes: 0,
                ..Limits::default()
            }
        )),
        Err(ClientError::Limit(_))
    ));
    assert!(empty.written.is_empty());
    let header = b"20 -1 12 34 text/plain;charset=utf-8\r\n";
    for body in [b"".as_slice(), b"abcd", b"abcde"] {
        let mut stream = Probe::new(&[header.as_slice(), body].concat());
        let limits = Limits {
            max_request_bytes: REQUEST.len(),
            max_header_line_bytes: header.len(),
            max_body_bytes: 4,
        };
        let result = ready(exchange_with_limits(&mut stream, REQUEST, &limits));
        if body.len() <= 4 {
            let response = result.unwrap();
            assert_eq!(response.body, body);
            assert_eq!(response.cache().unwrap().last_updated, 12);
            assert_eq!(response.cache().unwrap().expires, 34);
            assert_eq!(response.mime(), Some("text/plain;charset=utf-8"));
        } else {
            assert!(matches!(result, Err(ClientError::Limit(_))));
        }
        assert_eq!(stream.written, REQUEST);
    }
    for limits in [
        Limits {
            max_request_bytes: REQUEST.len() - 1,
            ..Limits::default()
        },
        Limits {
            max_request_bytes: 0,
            ..Limits::default()
        },
        Limits {
            max_header_line_bytes: 0,
            ..Limits::default()
        },
    ] {
        let mut stream = Probe::new(b"");
        assert!(matches!(
            ready(exchange_with_limits(&mut stream, REQUEST, &limits)),
            Err(ClientError::Limit(_))
        ));
        assert!(stream.written.is_empty());
    }
    for body in [b"".as_slice(), b"x"] {
        let mut stream = Probe::new(&[header.as_slice(), body].concat());
        let result = ready(exchange_with_limits(
            &mut stream,
            REQUEST,
            &Limits {
                max_body_bytes: 0,
                ..Limits::default()
            },
        ));
        assert_eq!(result.is_ok(), body.is_empty());
    }
}
#[tokio::test]
async fn header_budget_includes_crlf_and_missing_terminators_fail() {
    let header = b"70 123\r\n";
    for cap in [header.len() - 1, header.len()] {
        let mut stream = Probe::new(header);
        let result = ready(exchange_with_limits(
            &mut stream,
            REQUEST,
            &Limits {
                max_header_line_bytes: cap,
                ..Limits::default()
            },
        ));
        assert_eq!(result.is_ok(), cap == header.len());
        if let Ok(response) = result {
            assert_eq!(
                response.header,
                Header::Unchanged {
                    code: 70,
                    expires: 123
                }
            );
        }
    }
    for header in [b"70 123".as_slice(), b"70 123\n", b"70 123\r"] {
        assert!(matches!(
            ready(exchange(Probe::new(header), REQUEST)),
            Err(ClientError::Protocol(_))
        ));
    }
}
#[tokio::test]
async fn known_length_rejects_short_eof_and_leaves_following_bytes_unread() {
    let mut stream = Probe::new(b"20 4 12 34 text/plain\r\nabcdNEXT");
    let response = ready(exchange_with_limits(
        &mut stream,
        REQUEST,
        &Limits {
            max_body_bytes: 4,
            ..Limits::default()
        },
    ))
    .unwrap();
    assert_eq!(response.body, b"abcd");
    assert_eq!(&stream.input[stream.cursor..], b"NEXT");
    assert!(matches!(
        ready(exchange(
            Probe::new(b"20 5 12 34 text/plain\r\nabcd"),
            REQUEST
        )),
        Err(ClientError::Protocol(_))
    ));
    let mut zero = Probe::new(b"20 0 -1 -1 text/plain\r\nNEXT");
    assert!(
        ready(exchange_with_limits(
            &mut zero,
            REQUEST,
            &Limits {
                max_body_bytes: 0,
                ..Limits::default()
            }
        ))
        .unwrap()
        .body
        .is_empty()
    );
    assert_eq!(&zero.input[zero.cursor..], b"NEXT");
}
#[tokio::test]
async fn declared_oversize_refuses_before_any_body_or_eof_arrives() {
    let mut stream = Probe::new(b"20 5 -1 -1 text/plain\r\n");
    stream.hold = true;
    assert!(matches!(
        ready(exchange_with_limits(
            &mut stream,
            REQUEST,
            &Limits {
                max_body_bytes: 4,
                ..Limits::default()
            }
        )),
        Err(ClientError::Limit(_))
    ));
}
#[tokio::test]
async fn default_header_preserves_old_counter_and_caller_can_raise_it() {
    assert_eq!(Limits::default().max_header_line_bytes, MAX_URI + 1);
    for extra in [0, 1] {
        let header = format!("51 {}\r\n", "x".repeat(MAX_URI + 1 - 5 + extra));
        assert_eq!(header.len(), MAX_URI + 1 + extra);
        assert_eq!(
            ready(exchange(Probe::new(header.as_bytes()), REQUEST)).is_ok(),
            extra == 0
        );
        assert!(
            ready(exchange_with_limits(
                Probe::new(header.as_bytes()),
                REQUEST,
                &Limits {
                    max_header_line_bytes: header.len(),
                    ..Limits::default()
                }
            ))
            .is_ok()
        );
    }
}
#[tokio::test]
async fn request_budgets_and_uri_ceiling_refuse_before_connect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("kepler://{}/", listener.local_addr().unwrap());
    let line = request_line(&url, i64::MIN, "en-GB");
    assert!(matches!(
        fetch_with_limits(
            &url,
            i64::MIN,
            "en-GB",
            &Limits {
                max_request_bytes: line.len() - 1,
                ..Limits::default()
            }
        )
        .await,
        Err(ClientError::Limit(_))
    ));
    assert!(matches!(
        fetch_with_limits(&url, 0, "en\r\nrequest", &Limits::default()).await,
        Err(ClientError::BadUrl(_))
    ));
    let oversized = format!("{url}{}", "x".repeat(MAX_URI));
    assert!(matches!(
        fetch_with_limits(
            &oversized,
            0,
            "en",
            &Limits {
                max_request_bytes: usize::MAX,
                ..Limits::default()
            }
        )
        .await,
        Err(ClientError::BadUrl(_))
    ));
    assert!(matches!(listener.accept(), Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
}
#[tokio::test]
async fn tcp_adapter_passes_exact_request_header_and_body_budgets() {
    for rejected in [None, Some("header"), Some("body")] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("kepler://{}/", listener.local_addr().unwrap());
        let request = request_line(&url, 123, "en-GB,en;q=0.8");
        let expected = request.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(read_request(&mut stream).await, expected.as_bytes());
            stream
                .write_all(b"20 4 12 34 text/plain\r\nabcd")
                .await
                .unwrap();
        });
        let result = fetch_with_limits(
            &url,
            123,
            "en-GB,en;q=0.8",
            &Limits {
                max_request_bytes: request.len(),
                max_header_line_bytes: b"20 4 12 34 text/plain\r\n".len()
                    - usize::from(rejected == Some("header")),
                max_body_bytes: 4 - usize::from(rejected == Some("body")),
            },
        )
        .await;
        assert_eq!(result.is_ok(), rejected.is_none());
        if let Ok(response) = result {
            assert_eq!(response.body, b"abcd");
        }
        server.await.unwrap();
    }
}
#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_adapter_passes_explicit_header_and_body_budgets() {
    for rejected in [None, Some("header"), Some("body")] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("keplers://{}/", listener.local_addr().unwrap());
        let request = request_line(&url, 123, "en");
        let expected = request.clone();
        let acceptor = tls_acceptor();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            assert_eq!(read_request(&mut stream).await, expected.as_bytes());
            stream
                .write_all(b"20 4 12 34 text/plain\r\nabcd")
                .await
                .unwrap();
            let _ = stream.shutdown().await;
        });
        let result = fetch_with_limits(
            &url,
            123,
            "en",
            &Limits {
                max_request_bytes: request.len(),
                max_header_line_bytes: b"20 4 12 34 text/plain\r\n".len()
                    - usize::from(rejected == Some("header")),
                max_body_bytes: 4 - usize::from(rejected == Some("body")),
            },
        )
        .await;
        assert_eq!(result.is_ok(), rejected.is_none());
        if let Ok(response) = result {
            assert_eq!(response.body, b"abcd");
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn caller_can_raise_full_request_budget_without_relaxing_uri_ceiling() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("kepler://{}/", listener.local_addr().unwrap());
    let language = "x".repeat(5000);
    let expected = request_line(&url, 0, &language);
    let request_bytes = expected.len();
    assert!(request_bytes > Limits::default().max_request_bytes);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_request(&mut stream).await, expected.as_bytes());
        stream
            .write_all(b"20 5 -1 -1 text/plain\r\nabcde")
            .await
            .unwrap();
    });
    let response = fetch_with_limits(
        &url,
        0,
        &language,
        &Limits {
            max_request_bytes: request_bytes,
            max_body_bytes: 5,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(response.body, b"abcde");
    server.await.unwrap();
}

#[tokio::test]
async fn unknown_body_overflow_refuses_without_waiting_for_eof() {
    let mut stream = Probe::new(b"20 -1 -1 -1 text/plain\r\nabcde");
    stream.hold = true;
    assert!(matches!(
        ready(exchange_with_limits(
            &mut stream,
            REQUEST,
            &Limits {
                max_body_bytes: 4,
                ..Limits::default()
            }
        )),
        Err(ClientError::Limit(_))
    ));
}
