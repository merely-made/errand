//! The kepler client.
//!
//! `kepler://` is plaintext on port 2009; `keplers://` is the same exchange
//! inside TLS on port 10009. Unlike gemini, encryption is not mandatory, so
//! which one you get is the scheme's choice rather than the protocol's.
//!
//! The exchange is one line out and one header back, and the body's length is
//! declared rather than implied by the connection closing, which is the whole
//! reason kepler exists.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::wire::{CacheInfo, Header, MAX_URI, parse_header, request_line};

/// Plaintext kepler.
pub const DEFAULT_PORT: u16 = 2009;
/// Kepler inside TLS.
pub const DEFAULT_TLS_PORT: u16 = 10009;

/// Per-exchange wire budgets. Request and header limits include their CRLF.
/// A zero body budget accepts only an empty body; zero line budgets refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_request_bytes: usize,
    pub max_header_line_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: 4096,
            // The old 1024-byte guard counted CR but not the final LF.
            max_header_line_bytes: 1025,
            max_body_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Size limits and one deadline for the complete operation, after request preflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub limits: Limits,
    pub operation_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            operation_timeout: Duration::from_secs(30),
        }
    }
}

fn operation_deadline(timeout: Duration) -> Result<tokio::time::Instant, ClientError> {
    if timeout.is_zero() {
        return Err(ClientError::TimedOut);
    }
    let deadline = tokio::time::Instant::now()
        .into_std()
        .checked_add(timeout)
        .ok_or_else(|| ClientError::Protocol("operation timeout exceeds the clock range".into()))?;
    Ok(tokio::time::Instant::from_std(deadline))
}

pub(crate) fn check_deadline(deadline: tokio::time::Instant) -> Result<(), ClientError> {
    if tokio::time::Instant::now() >= deadline {
        Err(ClientError::TimedOut)
    } else {
        Ok(())
    }
}

fn check_request(request_bytes: usize, limits: &Limits) -> Result<(), ClientError> {
    if limits.max_request_bytes == 0
        || request_bytes > limits.max_request_bytes
        || limits.max_header_line_bytes == 0
    {
        return Err(ClientError::Limit(
            "request or header line budget exceeded".into(),
        ));
    }
    Ok(())
}

/// What can go wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    BadUrl(String),
    /// The complete operation exceeded its configured deadline.
    TimedOut,
    /// A caller-supplied wire budget was exceeded.
    Limit(String),
    Connect(String),
    Io(String),
    /// The reply did not obey the grammar.
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut => write!(f, "operation timed out"),
            Self::Limit(m) => write!(f, "limit: {m}"),
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// One kepler reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: Header,
    /// The body, for a `2x`. Empty for every other class, none of which
    /// carries one.
    pub body: Vec<u8>,
}

impl Response {
    /// The cache metadata, for a success.
    pub fn cache(&self) -> Option<CacheInfo> {
        match &self.header {
            Header::Success { cache, .. } => Some(*cache),
            _ => None,
        }
    }

    /// The MIME type, for a success.
    pub fn mime(&self) -> Option<&str> {
        match &self.header {
            Header::Success { mimetype, .. } => Some(mimetype),
            _ => None,
        }
    }
}

/// Fetch a `kepler://` or `keplers://` URL.
///
/// `last_cached` is the epoch second of the copy you already hold, or `0` if
/// you hold none. A server may answer `7x` to say it has not changed, which is
/// the exchange kepler adds over its relatives.
pub async fn fetch(url: &str, last_cached: i64, language: &str) -> Result<Response, ClientError> {
    fetch_with_limits(url, last_cached, language, &Limits::default()).await
}

/// Fetch using explicit size budgets and the default 30-second operation deadline.
pub async fn fetch_with_limits(
    url: &str,
    last_cached: i64,
    language: &str,
    limits: &Limits,
) -> Result<Response, ClientError> {
    fetch_with_options(
        url,
        last_cached,
        language,
        &Options {
            limits: *limits,
            ..Options::default()
        },
    )
    .await
}

/// Fetch with a single deadline covering DNS, connect, TLS, request and response.
pub async fn fetch_with_options(
    url: &str,
    last_cached: i64,
    language: &str,
    options: &Options,
) -> Result<Response, ClientError> {
    let limits = &options.limits;
    if url.len() > MAX_URI {
        return Err(ClientError::BadUrl(format!("URI exceeds {MAX_URI} bytes")));
    }
    if url.contains(['\r', '\n']) || language.contains(['\r', '\n']) {
        return Err(ClientError::BadUrl(
            "request field contains a line break".into(),
        ));
    }
    let request_bytes = url
        .len()
        .checked_add(language.len())
        .and_then(|n| n.checked_add(last_cached.to_string().len()))
        .and_then(|n| n.checked_add(4))
        .ok_or_else(|| ClientError::Limit("request length overflow".into()))?;
    check_request(request_bytes, limits)?;
    let parsed = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    if parsed.fragment().is_some() {
        return Err(ClientError::BadUrl("kepler URIs carry no fragment".into()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("kepler URL has no host".into()))?;

    let secure = match parsed.scheme() {
        "kepler" => false,
        "keplers" => true,
        other => return Err(ClientError::BadUrl(format!("scheme {other} is not kepler"))),
    };
    let port = parsed.port().unwrap_or(if secure {
        DEFAULT_TLS_PORT
    } else {
        DEFAULT_PORT
    });

    let line = request_line(url, last_cached, language);

    #[cfg(not(feature = "tls"))]
    if secure {
        return Err(ClientError::Connect(
            "keplers:// needs the `tls` feature".into(),
        ));
    }
    let deadline = operation_deadline(options.operation_timeout)?;
    let result = tokio::time::timeout_at(deadline, async {
        check_deadline(deadline)?;
        #[cfg(feature = "tls")]
        if secure {
            return crate::tls::exchange_tls(host, port, line.as_bytes(), limits, deadline).await;
        }
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
        exchange_inner(stream, line.as_bytes(), limits, deadline).await
    })
    .await
    .map_err(|_| ClientError::TimedOut)?;
    check_deadline(deadline)?;
    result
}

/// Run the exchange over any connected stream.
///
/// Transport-independent, like gemini's: an already-encrypted carrier needs
/// no TLS of its own.
pub async fn exchange<S>(mut stream: S, request: &[u8]) -> Result<Response, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    exchange_with_limits(&mut stream, request, &Limits::default()).await
}

/// Exchange over a supplied carrier using explicit wire budgets.
pub async fn exchange_with_limits<S>(
    mut stream: S,
    request: &[u8],
    limits: &Limits,
) -> Result<Response, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    exchange_with_options(
        &mut stream,
        request,
        &Options {
            limits: *limits,
            ..Options::default()
        },
    )
    .await
}

/// Exchange with one deadline. Discard a borrowed carrier after timeout or cancellation.
pub async fn exchange_with_options<S>(
    mut stream: S,
    request: &[u8],
    options: &Options,
) -> Result<Response, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    check_request(request.len(), &options.limits)?;
    let deadline = operation_deadline(options.operation_timeout)?;
    let result = tokio::time::timeout_at(
        deadline,
        exchange_inner(&mut stream, request, &options.limits, deadline),
    )
    .await
    .map_err(|_| ClientError::TimedOut)?;
    check_deadline(deadline)?;
    result
}

pub(crate) async fn exchange_inner<S>(
    mut stream: S,
    request: &[u8],
    limits: &Limits,
    deadline: tokio::time::Instant,
) -> Result<Response, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    check_deadline(deadline)?;
    stream
        .write_all(request)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        check_deadline(deadline)?;
        if stream
            .read(&mut byte)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?
            == 0
        {
            return Err(ClientError::Protocol("header ended without CRLF".into()));
        }
        if line.len() >= limits.max_header_line_bytes {
            return Err(ClientError::Limit(
                "response header line budget exceeded".into(),
            ));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            if !line.ends_with(b"\r\n") {
                return Err(ClientError::Protocol("header ended without CRLF".into()));
            }
            break;
        }
    }
    let text = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| ClientError::Protocol("header is not UTF-8".into()))?;
    let header = parse_header(text).map_err(|e| ClientError::Protocol(e.0))?;
    let mut body = Vec::new();
    if let Header::Success { cache, .. } = &header {
        let known_length = if cache.has_length() {
            let length = usize::try_from(cache.length)
                .map_err(|_| ClientError::Limit("declared body exceeds platform size".into()))?;
            if length > limits.max_body_bytes {
                return Err(ClientError::Limit("declared body budget exceeded".into()));
            }
            Some(length)
        } else {
            None
        };
        let mut chunk = [0u8; 8192];
        loop {
            check_deadline(deadline)?;
            let remaining = known_length.unwrap_or(limits.max_body_bytes) - body.len();
            if known_length.is_some() && remaining == 0 {
                break;
            }
            let read_size = remaining
                .saturating_add(usize::from(known_length.is_none()))
                .min(chunk.len());
            let count = stream
                .read(&mut chunk[..read_size])
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if count == 0 {
                if known_length.is_some() {
                    return Err(ClientError::Protocol("declared body ended early".into()));
                }
                break;
            }
            if count > remaining {
                return Err(ClientError::Limit("response body budget exceeded".into()));
            }
            body.extend_from_slice(&chunk[..count]);
        }
    }
    Ok(Response { header, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Status;

    #[tokio::test]
    async fn a_declared_length_is_read_exactly() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).ends_with("\r\n"));
            // Five bytes declared, then trailing bytes that must NOT be read.
            server
                .write_all(b"20 5 -1 -1 text/plain\r\nhellotrailing-garbage")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 0 en\r\n").await.unwrap();
        assert_eq!(response.body, b"hello", "stopped at the declared length");
        assert_eq!(response.mime(), Some("text/plain"));
    }

    #[tokio::test]
    async fn an_unknown_length_reads_to_the_end_of_the_stream() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"20 -1 -1 -1 text/gemini\r\n# All of it\n")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 0 en\r\n").await.unwrap();
        assert_eq!(response.body, b"# All of it\n");
    }

    #[tokio::test]
    async fn a_cache_hit_carries_no_body() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"70 1777759482\r\n").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 100 en\r\n").await.unwrap();
        assert_eq!(response.header.status(), Status::Unchanged);
        assert!(response.body.is_empty());
        assert_eq!(response.cache(), None, "a 7x carries no cache block");
    }

    #[tokio::test]
    async fn a_failure_carries_its_message_and_no_body() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"51 not found\r\nignored").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 0 en\r\n").await.unwrap();
        assert_eq!(response.header.status(), Status::PermanentFailure);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn a_fragment_is_refused_before_connecting() {
        let error = fetch("kepler://example.net/a#frag", 0, "en")
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }

    #[tokio::test]
    async fn another_scheme_is_refused() {
        let error = fetch("gemini://example.net/", 0, "en").await.unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }
}
