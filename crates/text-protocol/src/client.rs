use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{DEFAULT_PORT, Header, parse_header, request_line};

/// Per-exchange wire budgets. Line budgets include CRLF; zero body permits only empty responses.
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
            max_header_line_bytes: 4097,
            max_body_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Size limits and one deadline for the complete operation after request preflight.
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
pub(super) fn operation_deadline(timeout: Duration) -> Result<tokio::time::Instant, ClientError> {
    if timeout.is_zero() {
        return Err(ClientError::TimedOut);
    }
    let deadline = tokio::time::Instant::now()
        .into_std()
        .checked_add(timeout)
        .ok_or_else(|| ClientError::Protocol("operation timeout exceeds the clock range".into()))?;
    Ok(tokio::time::Instant::from_std(deadline))
}
pub(super) fn check_deadline(deadline: tokio::time::Instant) -> Result<(), ClientError> {
    if tokio::time::Instant::now() >= deadline {
        Err(ClientError::TimedOut)
    } else {
        Ok(())
    }
}

pub(super) fn check_request(iri: &str, limits: &Limits) -> Result<(), ClientError> {
    if iri.contains(['\r', '\n']) {
        return Err(ClientError::BadUrl(
            "IRI contains a request line break".into(),
        ));
    }
    if iri
        .len()
        .checked_add(2)
        .is_none_or(|n| n > limits.max_request_bytes)
        || limits.max_header_line_bytes == 0
    {
        return Err(ClientError::Limit(
            "request or header line budget exceeded".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    BadUrl(String),
    /// The complete operation exceeded its configured deadline.
    TimedOut,
    /// A caller-supplied wire budget was exceeded.
    Limit(String),
    Connect(String),
    Io(String),
    /// The reply's first line was not one of the three the protocol has.
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

/// One response: the header, and the body for a `20`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: Header,
    pub body: Vec<u8>,
}

/// Fetch a `text://` IRI over plain TCP (the Mercury port).
pub async fn fetch(iri: &str) -> Result<Response, ClientError> {
    fetch_with_limits(iri, &Limits::default()).await
}

/// Fetch over TCP with caller-owned size budgets.
pub async fn fetch_with_limits(iri: &str, limits: &Limits) -> Result<Response, ClientError> {
    fetch_with_options(
        iri,
        &Options {
            limits: *limits,
            ..Options::default()
        },
    )
    .await
}

/// Fetch with one budget across DNS, connect, request and response.
pub async fn fetch_with_options(iri: &str, options: &Options) -> Result<Response, ClientError> {
    let limits = &options.limits;
    check_request(iri, limits)?;
    let parsed = url::Url::parse(iri).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    if parsed.scheme() != "text" {
        return Err(ClientError::BadUrl(format!(
            "scheme {} is not text",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("text IRI has no host".into()))?;
    let port = parsed.port().unwrap_or(DEFAULT_PORT);
    let deadline = operation_deadline(options.operation_timeout)?;
    let result = tokio::time::timeout_at(deadline, async {
        check_deadline(deadline)?;
        let mut stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
        exchange_inner(iri, &mut stream, limits, deadline).await
    })
    .await
    .map_err(|_| ClientError::TimedOut)?;
    check_deadline(deadline)?;
    result
}

/// Run the exchange over any connected stream, so an encrypted carrier
/// needs no TLS of its own.
pub async fn exchange<S>(iri: &str, stream: &mut S) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_with_limits(iri, stream, &Limits::default()).await
}

/// Run a supplied-carrier exchange with explicit wire budgets.
pub async fn exchange_with_limits<S>(
    iri: &str,
    stream: &mut S,
    limits: &Limits,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_with_options(
        iri,
        stream,
        &Options {
            limits: *limits,
            ..Options::default()
        },
    )
    .await
}

/// Exchange with one deadline. Discard the borrowed carrier after timeout or cancellation.
pub async fn exchange_with_options<S>(
    iri: &str,
    stream: &mut S,
    options: &Options,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    check_request(iri, &options.limits)?;
    let deadline = operation_deadline(options.operation_timeout)?;
    let result = tokio::time::timeout_at(
        deadline,
        exchange_inner(iri, stream, &options.limits, deadline),
    )
    .await
    .map_err(|_| ClientError::TimedOut)?;
    check_deadline(deadline)?;
    result
}

pub(super) async fn exchange_inner<S>(
    iri: &str,
    stream: &mut S,
    limits: &Limits,
    deadline: tokio::time::Instant,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    check_deadline(deadline)?;
    stream
        .write_all(request_line(iri).as_bytes())
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
    let header = parse_header(text)
        .ok_or_else(|| ClientError::Protocol(format!("not a text-protocol status: {text:?}")))?;
    let mut body = Vec::new();
    if header.status == super::Status::Ok {
        let mut chunk = [0u8; 8192];
        loop {
            check_deadline(deadline)?;
            let remaining = limits.max_body_bytes - body.len();
            let read_size = remaining.saturating_add(1).min(chunk.len());
            let count = stream
                .read(&mut chunk[..read_size])
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if count == 0 {
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
