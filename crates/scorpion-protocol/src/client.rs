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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::request::Request;
use crate::response::{Header, ResponseError, Size};
use crate::status::Major;
use crate::{DEFAULT_PORT, MAX_REQUEST_LINE};

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

async fn read_response_inner<S>(
    stream: &mut S,
    limits: Limits,
    requested_range: Option<crate::request::Range>,
) -> Result<Response, ClientError>
where
    S: AsyncRead + Unpin,
{
    let line = read_line(stream, limits.max_header).await?;
    let header = Header::parse(&line)?;

    if header.status.major() != Major::Success {
        return Ok(Response {
            header,
            body: Vec::new(),
        });
    }

    // `success()` is Some here because the class was just checked.
    let declared = match header.success() {
        Some(Ok(success)) => success.size,
        Some(Err(error)) => return Err(error.into()),
        None => Size::Unknown,
    };

    let body = if header.status == crate::Status::PARTIAL {
        // A range response: the declared size describes the file, so the
        // range decides how much to read. Read *up to* that much rather than
        // exactly, because a range running past the end of the file is
        // answered with what exists, which is fewer bytes than were asked for
        // and is not an error.
        match requested_range.and_then(|range| range.len()) {
            Some(length) if length <= limits.max_body => {
                // The range is a frame boundary: probing beyond it would eat
                // the next status line on an interactive connection.
                let mut body = Vec::new();
                stream.take(length).read_to_end(&mut body).await?;
                body
            }
            _ => read_to_end_capped(stream, limits.max_body).await?,
        }
    } else {
        match declared {
            Size::Known(size) => {
                if size > limits.max_body {
                    return Err(ClientError::BodyTooLarge {
                        declared: size,
                        limit: limits.max_body,
                    });
                }
                let length = usize::try_from(size).map_err(|_| ClientError::BodyTooLarge {
                    declared: size,
                    limit: usize::MAX as u64,
                })?;
                let mut body = vec![0u8; length];
                match stream.read_exact(&mut body).await {
                    Ok(_) => body,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        return Err(ClientError::Truncated {
                            declared: size,
                            received: 0,
                        });
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            // The server does not know either, so end of stream is the end of
            // the file. The cap keeps a server that never stops from filling
            // memory.
            Size::Unknown => read_to_end_capped(stream, limits.max_body).await?,
        }
    };

    Ok(Response { header, body })
}

/// Read to end of stream, refusing to buffer more than `cap` bytes.
async fn read_to_end_capped<S>(stream: &mut S, cap: u64) -> Result<Vec<u8>, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // One sentinel byte distinguishes exact-fit EOF from overflow. It is
        // never appended, and a peer cannot force cap+1 body storage.
        let remaining = cap.saturating_sub(body.len() as u64);
        let count = remaining.saturating_add(1).min(chunk.len() as u64) as usize;
        let read = stream.read(&mut chunk[..count]).await?;
        if read == 0 {
            return Ok(body);
        }
        if read as u64 > remaining {
            return Err(ClientError::BodyTooLarge {
                declared: (body.len() as u64).saturating_add(read as u64),
                limit: cap,
            });
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

/// Read one CRLF-terminated line, refusing anything over `max`.
async fn read_line<S>(stream: &mut S, max: usize) -> Result<String, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            if line.is_empty() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= max {
            return Err(ResponseError::TooLong.into());
        }
        line.push(byte[0]);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| ClientError::Response(ResponseError::Malformed))
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
mod tests {
    use super::*;
    use crate::request::Range;
    use tokio::io::duplex;

    /// Serve one canned response over an in-memory pipe and return what the
    /// client sent.
    async fn round_trip(
        request: &Request,
        canned: &[u8],
    ) -> (Vec<u8>, Result<Response, ClientError>) {
        let (mut client_side, mut server_side) = duplex(64 * 1024);
        let canned = canned.to_vec();
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut byte = [0u8; 1];
            // Read exactly the request line, then answer.
            loop {
                let read = server_side.read(&mut byte).await.unwrap();
                if read == 0 {
                    break;
                }
                seen.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            server_side.write_all(&canned).await.unwrap();
            server_side.flush().await.unwrap();
            drop(server_side);
            seen
        });

        let response = exchange(&mut client_side, request, Limits::default()).await;
        (server.await.unwrap(), response)
    }

    #[tokio::test]
    async fn a_declared_length_is_read_exactly() {
        let (sent, response) = round_trip(
            &Request::receive("scorpion://example.com/"),
            b"20 5 text/plain\r\nhello",
        )
        .await;
        assert_eq!(sent, b"R scorpion://example.com/\r\n");
        let response = response.unwrap();
        assert_eq!(response.header.status, crate::Status::OK);
        assert_eq!(response.text(), Some("hello"));
    }

    #[tokio::test]
    async fn an_unknown_length_is_read_to_end_of_stream() {
        let (_, response) = round_trip(
            &Request::receive("scorpion://example.com/dynamic"),
            b"20 ? text/plain\r\ngenerated on the fly",
        )
        .await;
        assert_eq!(response.unwrap().text(), Some("generated on the fly"));
    }

    #[tokio::test]
    async fn unknown_bodies_accept_exact_fit_and_refuse_the_next_byte() {
        for (payload, cap, accepted) in [
            (&b""[..], 0, true),
            (&b"a"[..], 0, false),
            (&b"abc"[..], 3, true),
            (&b"abcd"[..], 3, false),
        ] {
            let mut wire = b"20 ? text/plain\r\n".to_vec();
            wire.extend_from_slice(payload);
            let response = read_response(
                &mut wire.as_slice(),
                Limits {
                    max_body: cap,
                    ..Limits::default()
                },
                None,
            )
            .await;
            if accepted {
                assert_eq!(response.unwrap().body, payload);
            } else {
                assert!(
                    matches!(response, Err(ClientError::BodyTooLarge { limit, .. }) if limit == cap)
                );
            }
        }
    }

    #[tokio::test]
    async fn partial_response_refuses_policy_overflow_but_preserves_range_framing() {
        let limits = Limits {
            max_body: 3,
            ..Limits::default()
        };
        let mut oversized = &b"21 100 text/plain\r\nabcd"[..];
        assert!(matches!(
            read_response(&mut oversized, limits, Some(Range::new(0, 10))).await,
            Err(ClientError::BodyTooLarge { limit: 3, .. })
        ));

        // A following status line is not part of the requested three bytes.
        let mut framed = &b"21 100 text/plain\r\nabc70 ready\r\n"[..];
        let response = read_response(&mut framed, limits, Some(Range::new(0, 3)))
            .await
            .unwrap();
        assert_eq!(response.body, b"abc");
        assert_eq!(framed, b"70 ready\r\n");
    }

    #[tokio::test]
    async fn a_non_success_class_reads_no_body() {
        // The property that keeps the S subprotocol working: a 7x must not
        // consume the stream looking for a body that is not there.
        let (_, response) = round_trip(
            &Request::receive("scorpion://example.com/missing"),
            b"51 no such file\r\n",
        )
        .await;
        let response = response.unwrap();
        assert_eq!(response.header.status, crate::Status::NOT_FOUND);
        assert!(response.body.is_empty());
        assert_eq!(response.header.message(), Some("no such file"));
    }

    #[tokio::test]
    async fn a_truncated_body_is_an_error_not_a_short_read() {
        let (_, response) = round_trip(
            &Request::receive("scorpion://example.com/"),
            b"20 100 text/plain\r\nonly this much",
        )
        .await;
        assert!(
            matches!(response, Err(ClientError::Truncated { declared: 100, .. })),
            "a server that under-delivers must not look like a successful short file"
        );
    }

    #[tokio::test]
    async fn an_oversized_declaration_is_refused_before_buffering() {
        let (mut client_side, mut server_side) = duplex(1024);
        tokio::spawn(async move {
            let mut byte = [0u8; 1];
            while server_side.read(&mut byte).await.unwrap() != 0 && byte[0] != b'\n' {}
            server_side
                .write_all(b"20 999999999 text/plain\r\n")
                .await
                .unwrap();
            // Deliberately never send the body.
            std::future::pending::<()>().await;
        });

        let limits = Limits {
            max_body: 1024,
            ..Limits::default()
        };
        let error = exchange(
            &mut client_side,
            &Request::receive("scorpion://example.com/"),
            limits,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ClientError::BodyTooLarge { limit: 1024, .. }
        ));
    }

    #[tokio::test]
    async fn a_partial_response_is_bounded_by_the_range_not_the_declared_size() {
        // The trap, from the reading side. A 21 declares the whole file's
        // size (10) while sending only the requested range (6). A client that
        // read the declared size would block forever waiting for four bytes
        // the server was never going to send.
        let (_, response) = round_trip(
            &Request::receive_range("scorpion://example.com/file", Range::new(3, 9)),
            b"21 10 text/plain\r\n345678",
        )
        .await;
        let response = response.unwrap();
        assert_eq!(response.text(), Some("345678"), "the range, not the file");
        assert_eq!(
            response.header.success().unwrap().unwrap().size,
            crate::Size::Known(10),
            "and the header still reports the whole file's size"
        );
    }

    #[tokio::test]
    async fn a_range_running_past_the_end_of_a_file_is_not_an_error() {
        // A server answers what exists. Fewer bytes than asked for is normal
        // here, unlike a short 20, so it must not read as truncation.
        let (_, response) = round_trip(
            &Request::receive_range("scorpion://example.com/file", Range::new(8, 100)),
            b"21 10 text/plain\r\n89",
        )
        .await;
        assert_eq!(response.unwrap().text(), Some("89"));
    }

    #[test]
    fn the_default_port_applies_when_a_url_omits_one() {
        assert_eq!(
            authority("scorpion://example.com/page").unwrap(),
            ("example.com".to_string(), 1517)
        );
        assert_eq!(
            authority("scorpion://example.com:1234/page").unwrap(),
            ("example.com".to_string(), 1234)
        );
    }
}
