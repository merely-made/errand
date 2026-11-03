//! An async Scorpion client.
//!
//! [`exchange`] runs one request over **any** stream, so it works over TCP,
//! over a TLS session from [`crate::tls`], or over anything else that carries
//! bytes. [`fetch`] is the convenience that dials TCP first.
//!
//! ## Reading a body
//!
//! A `2x` response declares its size, and that size decides how the body is
//! read: a known length is read exactly, and `?` -- which the specification
//! allows for dynamic files -- is read to end of stream. Reading to EOF
//! unconditionally would work for a single request but breaks the `S`
//! subprotocol, where the connection stays open for the server's second status
//! line.

use std::io;
use std::time::Duration;

#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::request::Request;
use crate::response::{Header, ResponseError};
use crate::{DEFAULT_PORT, MAX_REQUEST_LINE};

mod body;
use body::read_response_inner;

/// Why an exchange failed.
#[derive(Debug)]
pub enum ClientError {
    /// The complete operation exceeded its caller-selected deadline.
    TimedOut,
    /// The requested duration cannot be represented by the monotonic clock.
    InvalidTimeout,
    /// The socket failed.
    Io(io::Error),
    /// The server's status line could not be read.
    Response(ResponseError),
    /// The URL could not be parsed, or named no host.
    Url(String),
    /// The server declared or sent a body larger than the caller allowed.
    BodyTooLarge {
        /// The declared length, or the minimum observed length for an unknown body.
        declared: u64,
        /// What the caller permitted.
        limit: u64,
    },
    /// The server closed before sending the bytes it declared.
    Truncated {
        /// What the server declared.
        declared: u64,
        /// What actually arrived.
        received: u64,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut => write!(f, "scorpion: operation deadline expired"),
            Self::InvalidTimeout => write!(f, "scorpion: operation timeout is too large"),
            Self::Io(error) => write!(f, "scorpion: {error}"),
            Self::Response(error) => write!(f, "scorpion: {error}"),
            Self::Url(detail) => write!(f, "scorpion: {detail}"),
            Self::BodyTooLarge { declared, limit } => write!(
                f,
                "scorpion: body requires at least {declared} bytes, over the {limit}-byte limit"
            ),
            Self::Truncated { declared, received } => write!(
                f,
                "scorpion: server declared {declared} bytes but sent {received}"
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Response(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ResponseError> for ClientError {
    fn from(error: ResponseError) -> Self {
        Self::Response(error)
    }
}

/// One server response: its status line, and its body when it has one.
#[derive(Clone, Debug)]
pub struct Response {
    /// The status line.
    pub header: Header,
    /// The body. Empty for every class but `2x`, which is the only one that
    /// carries file data.
    pub body: Vec<u8>,
}

impl Response {
    /// The body as text, when it is valid UTF-8.
    ///
    /// Deliberately fallible: Scorpion documents are binary, and its text
    /// encodings are not UTF-8, so a lossy conversion would quietly corrupt
    /// exactly the content this protocol exists to carry.
    pub fn text(&self) -> Option<&str> {
        core::str::from_utf8(&self.body).ok()
    }
}

/// How much a client is willing to read.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The largest body to accept. A server declaring more is refused before
    /// a single byte of it is buffered.
    pub max_body: u64,
    /// The largest status line to accept.
    pub max_header: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body: 32 * 1024 * 1024,
            max_header: MAX_REQUEST_LINE,
        }
    }
}

/// The convenience helpers' complete-operation allowance.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Native size policy and a single budget for the complete operation.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Existing native header and body limits.
    pub limits: Limits,
    /// Includes connection setup, writes, status and body reads.
    pub operation_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
        }
    }
}

pub(crate) fn deadline_after(timeout: Duration) -> Result<tokio::time::Instant, ClientError> {
    if timeout.is_zero() {
        return Err(ClientError::TimedOut);
    }
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ClientError::InvalidTimeout)
}

pub(crate) async fn within_deadline<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(ClientError::TimedOut);
    }
    let result = tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| ClientError::TimedOut)?;
    // An always-ready carrier can complete while the timeout's inner future
    // is being polled. It must not turn a late completion into success.
    if tokio::time::Instant::now() >= deadline {
        return Err(ClientError::TimedOut);
    }
    result
}

/// Run one request over an already-open stream.
pub async fn exchange<S>(
    stream: &mut S,
    request: &Request,
    limits: Limits,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_with_options(
        stream,
        request,
        Options {
            limits,
            ..Options::default()
        },
    )
    .await
}

/// Exchange using one caller-selected operation budget.
///
/// Discard a borrowed carrier after timeout or cancellation: it may contain a
/// partially written request or unread response. This is not an idle timeout.
pub async fn exchange_with_options<S>(
    stream: &mut S,
    request: &Request,
    options: Options,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = deadline_after(options.operation_timeout)?;
    exchange_until(stream, request, options.limits, deadline).await
}

/// Exchange before an absolute caller deadline, shared with other session phases.
/// Discard the carrier after timeout or cancellation.
pub async fn exchange_until<S>(
    stream: &mut S,
    request: &Request,
    limits: Limits,
    deadline: tokio::time::Instant,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    within_deadline(deadline, exchange_inner(stream, request, limits)).await
}

async fn exchange_inner<S>(
    stream: &mut S,
    request: &Request,
    limits: Limits,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&request.to_wire()).await?;
    stream.flush().await?;
    let range = match &request.parameter {
        crate::request::Parameter::Range(range) => Some(*range),
        _ => None,
    };
    read_response_inner(stream, limits, range).await
}

/// Read one status line and, if the class carries one, its body.
///
/// `requested_range` is what the client asked for, and it is **required** to
/// read a `21` correctly. On a partial response the declared size is the size
/// of the whole file, not of the bytes being sent, so a reader that trusted it
/// would block waiting for data the server was never going to send. Pass
/// `None` when the request carried no range.
pub async fn read_response<S>(
    stream: &mut S,
    limits: Limits,
    requested_range: Option<crate::request::Range>,
) -> Result<Response, ClientError>
where
    S: AsyncRead + Unpin,
{
    read_response_with_options(
        stream,
        Options {
            limits,
            ..Options::default()
        },
        requested_range,
    )
    .await
}

/// Read a framed response within one operation budget. Discard the carrier
/// after timeout or cancellation, rather than reusing a partial frame.
pub async fn read_response_with_options<S>(
    stream: &mut S,
    options: Options,
    requested_range: Option<crate::request::Range>,
) -> Result<Response, ClientError>
where
    S: AsyncRead + Unpin,
{
    let deadline = deadline_after(options.operation_timeout)?;
    read_response_until(stream, options.limits, requested_range, deadline).await
}

/// Read before the same absolute deadline used for connection setup or an
/// earlier interactive response. This never renews the caller's allowance.
pub async fn read_response_until<S>(
    stream: &mut S,
    limits: Limits,
    requested_range: Option<crate::request::Range>,
    deadline: tokio::time::Instant,
) -> Result<Response, ClientError>
where
    S: AsyncRead + Unpin,
{
    within_deadline(
        deadline,
        read_response_inner(stream, limits, requested_range),
    )
    .await
}

/// Dial the host in `request`'s URL and run one exchange over plain TCP.
///
/// For `scorpions://`, use [`crate::tls`] instead: this sends the request in
/// the clear, and a client must never treat the two schemes as equivalent.
pub async fn fetch(request: &Request, limits: Limits) -> Result<Response, ClientError> {
    fetch_with_options(
        request,
        Options {
            limits,
            ..Options::default()
        },
    )
    .await
}

/// Dial TCP and exchange under one deadline, including name resolution and all
/// response bytes. The owned socket is dropped on timeout or cancellation.
pub async fn fetch_with_options(
    request: &Request,
    options: Options,
) -> Result<Response, ClientError> {
    let (host, port) = authority(&request.url)?;
    if !request
        .url
        .split(':')
        .next()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(crate::SCHEME))
    {
        return Err(ClientError::Url(
            "plain TCP fetch requires scorpion://; use the TLS carrier for scorpions://".into(),
        ));
    }
    let deadline = deadline_after(options.operation_timeout)?;
    within_deadline(deadline, async {
        let mut stream = TcpStream::connect((host.as_str(), port)).await?;
        exchange_inner(&mut stream, request, options.limits).await
    })
    .await
}

#[cfg(test)]
#[path = "deadline_tests.rs"]
mod deadline_tests;

/// The host and port a URL names, defaulting to [`DEFAULT_PORT`].
pub fn authority(url: &str) -> Result<(String, u16), ClientError> {
    let parsed = url::Url::parse(url).map_err(|error| ClientError::Url(error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::Url(format!("{url} names no host")))?
        .to_string();
    Ok((host, parsed.port().unwrap_or(DEFAULT_PORT)))
}

#[cfg(test)]
mod tests;
