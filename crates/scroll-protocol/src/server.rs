//! One native Scroll exchange over a caller-owned connection.
//!
//! The caller owns addressing, TLS, certificates, admission, storage and task
//! lifetime. No listener is opened and no task is spawned here. The handler
//! receives language preferences and the abstract flag unchanged; selecting a
//! language or deciding authority is its responsibility.

use std::{future::Future, io, time::Duration};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Header, Reply, Request, ResponseLimits, Status, parse_request};

/// Resolve one native request. Implemented for async closures.
pub trait Handler: Send + Sync {
    fn handle(&self, request: Request) -> impl Future<Output = Reply> + Send;
}

impl<F, Fut> Handler for F
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: Future<Output = Reply> + Send,
{
    fn handle(&self, request: Request) -> impl Future<Output = Reply> + Send {
        self(request)
    }
}

/// Bounds supplied by the host. Request size includes its terminating CRLF.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    pub max_request_bytes: usize,
    pub response_limits: ResponseLimits,
    /// One deadline covering request read, handler, response write and flush.
    /// Synchronous work within a handler must arrange its own preemption.
    pub timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 4096,
            response_limits: ResponseLimits::default(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Read one request and write/flush one validated reply. The stream remains
/// borrowed: the caller closes it after completion, refusal or cancellation.
/// Dropping this future stops all of its work; no background work survives it.
/// Invalid request envelopes receive `59`; invalid handler responses return an
/// error before writing any response bytes. Host policy validates authority and
/// decides which requested language, if any, it can serve.
pub async fn serve_connection<S>(
    stream: &mut S,
    handler: &impl Handler,
    config: &ServerConfig,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if config.max_request_bytes < 2
        || config.response_limits.max_header_line_bytes < 2
        || config.timeout.is_zero()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Scroll server limits",
        ));
    }
    tokio::time::timeout(config.timeout, async {
        let reply = match read_request(stream, config.max_request_bytes).await? {
            Some(request) => handler.handle(request).await,
            None => Reply {
                header: Header::Meta {
                    code: 59,
                    status: Status::PermanentFailure,
                    meta: "Invalid request".into(),
                },
                body: Vec::new(),
            },
        };
        let bytes = reply
            .encode(config.response_limits)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Scroll exchange deadline"))?
}

async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_request_bytes: usize,
) -> io::Result<Option<Request>> {
    let mut line = Vec::with_capacity(max_request_bytes.min(256));
    let mut byte = [0u8; 1];
    while line.len() < max_request_bytes {
        if stream.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            let Ok(line) = std::str::from_utf8(&line) else {
                return Ok(None);
            };
            let envelope = &line[..line.len() - 2];
            if !envelope.contains(' ') || envelope.chars().any(char::is_control) {
                return Ok(None);
            }
            let Some(request) = parse_request(line) else {
                return Ok(None);
            };
            let Ok(uri) = url::Url::parse(&request.uri) else {
                return Ok(None);
            };
            if uri.scheme() != "scroll" || uri.host_str().is_none() || uri.fragment().is_some() {
                return Ok(None);
            }
            return Ok(Some(request));
        }
        // A bare LF can never become a valid CRLF envelope.
        if byte[0] == b'\n' {
            return Ok(None);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SuccessHeader;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    fn reply(body: &[u8]) -> Reply {
        Reply {
            header: Header::Success(SuccessHeader {
                code: 28,
                mimetype: "text/scroll;charset=utf-8;lang=en".into(),
                author: Some("A writer".into()),
                published: None,
                modified: Some("2026-10-21T12:00:00Z".into()),
            }),
            body: body.to_vec(),
        }
    }

    async fn raw_exchange(
        bytes: &[u8],
        handler: &impl Handler,
        config: ServerConfig,
    ) -> (io::Result<()>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let (outcome, response) = tokio::join!(
            async {
                let result = serve_connection(&mut server, handler, &config).await;
                server.shutdown().await.unwrap();
                result
            },
            async {
                client.write_all(bytes).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                response
            }
        );
        (outcome, response)
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn native_full_and_abstract_round_trip_preserves_preferences() {
        let handler = |request: Request| async move {
            assert_eq!(request.languages, ["fr-CA", "fr", "en"]);
            assert_eq!(request.uri, "scroll://example.test/index.scroll");
            reply(if request.metadata {
                b"# Abstract\r\n"
            } else {
                b"# Saved\r\n"
            })
        };
        for metadata in [false, true] {
            let (mut client, mut server) = tokio::io::duplex(4096);
            let config = ServerConfig::default();
            let (_, response) = tokio::join!(
                async {
                    serve_connection(&mut server, &handler, &config)
                        .await
                        .unwrap();
                    server.shutdown().await.unwrap();
                },
                crate::exchange(
                    "scroll://example.test/index.scroll",
                    &["fr-CA", "fr", "en"],
                    metadata,
                    &mut client
                )
            );
            let response = response.unwrap();
            let expected = reply(if metadata {
                b"# Abstract\r\n"
            } else {
                b"# Saved\r\n"
            });
            assert_eq!(response.header, expected.header);
            assert_eq!(response.body, expected.body);
        }
    }

    #[tokio::test]
    async fn strict_request_envelope_refuses_before_handler() {
        let handler = |_request: Request| async { panic!("invalid request reached handler") };
        for line in [
            &b"scroll://example.test/ en\n"[..],
            b"scroll://example.test/\r\n",
            b"scroll://example.test/ en\0\r\n",
            b"http://example.test/ en\r\n",
            b"scroll://example.test/#fragment en\r\n",
            b"not-a-uri en\r\n",
            b"scroll://example.test/ \xff\r\n",
            b"scroll://example.test/ en",
        ] {
            let (outcome, response) = raw_exchange(line, &handler, ServerConfig::default()).await;
            outcome.unwrap();
            assert_eq!(response, b"59 Invalid request\r\n", "{line:?}");
        }
    }

    #[tokio::test]
    async fn request_limit_counts_crlf_and_no_bytes_are_decoded() {
        let line = b"scroll://example.test/a%20b.scroll +en,en-US\r\n";
        let handler = |request: Request| async move {
            assert_eq!(request.uri, "scroll://example.test/a%20b.scroll");
            assert_eq!(request.languages, ["en", "en-US"]);
            assert!(request.metadata);
            reply(b"exact")
        };
        let config = ServerConfig {
            max_request_bytes: line.len(),
            ..ServerConfig::default()
        };
        let (outcome, response) = raw_exchange(line, &handler, config).await;
        outcome.unwrap();
        assert_eq!(
            response,
            reply(b"exact").encode(config.response_limits).unwrap()
        );
        let (outcome, response) = raw_exchange(
            line,
            &handler,
            ServerConfig {
                max_request_bytes: line.len() - 1,
                ..config
            },
        )
        .await;
        outcome.unwrap();
        assert_eq!(response, b"59 Invalid request\r\n");
    }

    #[tokio::test]
    async fn invalid_or_oversized_handler_reply_writes_nothing() {
        for inject in [false, true] {
            let handler = move |_request: Request| async move {
                let mut reply = reply(b"too large");
                if inject {
                    let Header::Success(header) = &mut reply.header else {
                        unreachable!()
                    };
                    header.author = Some("writer\r\nInjected".into());
                }
                reply
            };
            let config = ServerConfig {
                response_limits: ResponseLimits {
                    max_body_bytes: if inject { 100 } else { 1 },
                    ..ResponseLimits::default()
                },
                ..ServerConfig::default()
            };
            let (outcome, response) =
                raw_exchange(b"scroll://example.test/ en\r\n", &handler, config).await;
            assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(response.is_empty());
        }
    }

    #[tokio::test]
    async fn deadline_covers_request_handler_and_blocked_write() {
        let config = ServerConfig {
            timeout: Duration::from_millis(10),
            ..ServerConfig::default()
        };
        let ready = |_request: Request| async { reply(&[b'x'; 4096]) };
        let (mut client, mut server) = tokio::io::duplex(128);
        assert_eq!(
            serve_connection(&mut server, &ready, &config)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        client
            .write_all(b"scroll://example.test/ en\r\n")
            .await
            .unwrap();
        let pending = |_request: Request| std::future::pending::<Reply>();
        assert_eq!(
            serve_connection(&mut server, &pending, &config)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        client
            .write_all(b"scroll://example.test/ en\r\n")
            .await
            .unwrap();
        assert_eq!(
            serve_connection(&mut server, &ready, &config)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    struct FlushBlocked(tokio::io::DuplexStream);

    impl AsyncRead for FlushBlocked {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for FlushBlocked {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(context, bytes)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    #[tokio::test]
    async fn deadline_includes_flush_after_all_bytes_are_written() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut server = FlushBlocked(server);
        let config = ServerConfig {
            timeout: Duration::from_millis(10),
            ..ServerConfig::default()
        };
        let handler = |_request: Request| async { reply(b"saved bytes") };
        client
            .write_all(b"scroll://example.test/ en\r\n")
            .await
            .unwrap();
        let result = serve_connection(&mut server, &handler, &config).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        drop(server);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(
            bytes,
            reply(b"saved bytes")
                .encode(config.response_limits)
                .unwrap()
        );
    }

    struct Active(Arc<AtomicBool>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn dropping_exchange_drops_inline_handler_and_releases_stream() {
        let active = Arc::new(AtomicBool::new(false));
        let state = active.clone();
        let handler = move |_request: Request| {
            let state = state.clone();
            async move {
                let _active = Active(state.clone());
                state.store(true, Ordering::SeqCst);
                std::future::pending::<Reply>().await
            }
        };
        let (mut client, mut server) = tokio::io::duplex(128);
        client
            .write_all(b"scroll://example.test/ en\r\n")
            .await
            .unwrap();
        let config = ServerConfig::default();
        {
            let exchange = serve_connection(&mut server, &handler, &config);
            tokio::pin!(exchange);
            tokio::select! {
                result = &mut exchange => panic!("unexpected completion: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(10)) => assert!(active.load(Ordering::SeqCst)),
            }
        }
        assert!(!active.load(Ordering::SeqCst));
        server.write_all(b"host still owns stream").await.unwrap();
        let mut bytes = [0u8; 22];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"host still owns stream");
    }
}
