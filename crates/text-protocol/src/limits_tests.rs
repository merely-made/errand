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

const IRI: &str = "text://x/";
#[tokio::test]
async fn supplied_limits_are_exact_and_never_return_a_prefix() {
    let header = b"20 text/plain;charset=utf-8\r\n";
    for body in [b"".as_slice(), b"abcd", b"abcde"] {
        let mut stream = Probe::new(&[header.as_slice(), body].concat());
        let result = ready(exchange_with_limits(
            IRI,
            &mut stream,
            &Limits {
                max_request_bytes: IRI.len() + 2,
                max_header_line_bytes: header.len(),
                max_body_bytes: 4,
            },
        ));
        assert_eq!(result.is_ok(), body.len() <= 4);
        if let Ok(response) = result {
            assert_eq!(response.body, body);
            assert_eq!(response.header.meta, "text/plain;charset=utf-8");
        }
        assert_eq!(stream.written, request_line(IRI).as_bytes());
    }
    for limits in [
        Limits {
            max_request_bytes: IRI.len() + 1,
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
            ready(exchange_with_limits(IRI, &mut stream, &limits)),
            Err(ClientError::Limit(_))
        ));
        assert!(stream.written.is_empty());
    }
    for body in [b"".as_slice(), b"x"] {
        let mut stream = Probe::new(&[header.as_slice(), body].concat());
        let result = ready(exchange_with_limits(
            IRI,
            &mut stream,
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
    let header = b"30 text://next/\r\n";
    for cap in [header.len() - 1, header.len()] {
        let mut stream = Probe::new(header);
        let result = ready(exchange_with_limits(
            IRI,
            &mut stream,
            &Limits {
                max_header_line_bytes: cap,
                ..Limits::default()
            },
        ));
        assert_eq!(result.is_ok(), cap == header.len());
        if let Ok(response) = result {
            assert_eq!(response.header.status, Status::Redirect);
            assert_eq!(response.header.meta, "text://next/");
            assert!(response.body.is_empty());
        }
    }
    for header in [b"40 failure".as_slice(), b"40 failure\n", b"40 failure\r"] {
        assert!(matches!(
            ready(exchange(IRI, &mut Probe::new(header))),
            Err(ClientError::Protocol(_))
        ));
    }
}
#[tokio::test]
async fn overflow_refuses_while_response_is_still_open() {
    let mut stream = Probe::new(b"20 text/plain\r\nabcde");
    stream.hold = true;
    assert!(matches!(
        ready(exchange_with_limits(
            IRI,
            &mut stream,
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
    assert_eq!(Limits::default().max_header_line_bytes, 4097);
    for extra in [0, 1] {
        let header = format!("40 {}\r\n", "x".repeat(4097 - 5 + extra));
        assert_eq!(header.len(), 4097 + extra);
        assert_eq!(
            ready(exchange(IRI, &mut Probe::new(header.as_bytes()))).is_ok(),
            extra == 0
        );
        assert!(
            ready(exchange_with_limits(
                IRI,
                &mut Probe::new(header.as_bytes()),
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
async fn request_limits_and_injected_line_breaks_refuse_before_connect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let iri = format!("text://{}/", listener.local_addr().unwrap());
    assert!(matches!(
        fetch_with_limits(
            &iri,
            &Limits {
                max_request_bytes: iri.len() + 1,
                ..Limits::default()
            }
        )
        .await,
        Err(ClientError::Limit(_))
    ));
    let injected = iri.clone() + "\r\nrequest";
    assert!(matches!(
        fetch_with_limits(&injected, &Limits::default()).await,
        Err(ClientError::BadUrl(_))
    ));
    let mut stream = Probe::new(b"");
    assert!(matches!(
        ready(exchange_with_limits(
            &injected,
            &mut stream,
            &Limits::default()
        )),
        Err(ClientError::BadUrl(_))
    ));
    assert!(stream.written.is_empty());
    #[cfg(feature = "tls")]
    assert!(matches!(
        fetch_tls_with_limits(
            &iri,
            &Limits {
                max_request_bytes: iri.len() + 1,
                ..Limits::default()
            }
        )
        .await,
        Err(ClientError::Limit(_))
    ));
    assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
}
#[tokio::test]
async fn tcp_adapter_passes_exact_request_header_and_body_budgets() {
    for rejected in [None, Some("header"), Some("body")] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let iri = format!("text://{}/", listener.local_addr().unwrap());
        let expected = request_line(&iri);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(read_request(&mut stream).await, expected.as_bytes());
            stream.write_all(b"20 text/plain\r\nabcd").await.unwrap();
        });
        let result = fetch_with_limits(
            &iri,
            &Limits {
                max_request_bytes: iri.len() + 2,
                max_header_line_bytes: b"20 text/plain\r\n".len()
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
        let iri = format!("text://{}/", listener.local_addr().unwrap());
        let expected = request_line(&iri);
        let acceptor = tls_acceptor();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            assert_eq!(read_request(&mut stream).await, expected.as_bytes());
            stream.write_all(b"20 text/plain\r\nabcd").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let result = fetch_tls_with_limits(
            &iri,
            &Limits {
                max_request_bytes: iri.len() + 2,
                max_header_line_bytes: b"20 text/plain\r\n".len()
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
async fn caller_can_raise_request_and_body_budgets() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let iri = format!(
        "text://{}/{}",
        listener.local_addr().unwrap(),
        "x".repeat(5000)
    );
    let expected = request_line(&iri);
    assert!(expected.len() > Limits::default().max_request_bytes);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_request(&mut stream).await, expected.as_bytes());
        stream.write_all(b"20 text/plain\r\nabcde").await.unwrap();
    });
    let response = fetch_with_limits(
        &iri,
        &Limits {
            max_request_bytes: iri.len() + 2,
            max_body_bytes: 5,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(response.body, b"abcde");
    server.await.unwrap();
}
