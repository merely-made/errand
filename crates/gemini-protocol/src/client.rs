//! The gemini request/response.
//!
//! The exchange is small: send the absolute URL followed by `\r\n`, then read
//! a `<status> <meta>\r\n` header and, for a `2x` success, the body that
//! follows. The server closes the connection at the end, so the body is
//! whatever remains after the header line.
//!
//! [`exchange`] runs that over **any** `AsyncRead + AsyncWrite` and needs no
//! TLS. [`fetch`] is the ordinary internet client: TCP, plus rustls with real
//! trust-on-first-use pinning (see [`crate::tofu`]), and it rides the `tls`
//! feature.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

#[cfg(feature = "tls")]
mod connection;
#[cfg(feature = "tls")]
pub(crate) use connection::tofu_connect_inner;
#[cfg(feature = "tls")]
pub use connection::{
    fetch, fetch_url, fetch_url_streaming, fetch_url_streaming_with_identity,
    fetch_url_streaming_with_options, fetch_url_with_identity, fetch_url_with_options,
    tofu_connect,
};

/// Caller-owned bounds for one complete exchange, including connection setup.
/// Byte budgets include CRLF for request/header lines; body bytes are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchOptions {
    pub timeout: std::time::Duration,
    pub max_request_bytes: usize,
    pub max_header_line_bytes: usize,
    pub max_body_bytes: usize,
}
impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            max_request_bytes: 1024,
            max_header_line_bytes: 1024,
            max_body_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Gemini's well-known port.
pub const DEFAULT_PORT: u16 = 1965;

/// The largest request line gemini permits, in bytes (the spec caps the URL at
/// 1024; the trailing CRLF rides within that budget here).
const MAX_REQUEST: usize = 1024;

/// Gemini caps the complete response header, including its trailing CRLF, at
/// 1024 bytes. Enforcing that while reading keeps a peer from turning header
/// discovery into an unbounded buffer.
const MAX_RESPONSE_HEADER: usize = 1024;

/// Borrowed client-certificate material for one Gemini TLS connection.
///
/// Storage, minting, capsule assignment, and rotation belong to the host's
/// identity layer. This protocol type only presents the selected self-signed
/// certificate during the handshake. The private key must be PKCS#8 DER.
#[cfg(feature = "tls")]
#[derive(Clone, Copy)]
pub struct ClientIdentity<'a> {
    pub certificate_der: &'a [u8],
    pub private_key_pkcs8_der: &'a [u8],
}

// ── Vocabulary ─────────────────────────────────────────────────────────────

/// Gemini's status classes, one per leading digit of the two-digit code.
///
/// Temporary and permanent failure are kept **apart**, unlike a client that
/// flattens both to "it failed": retrying a `4x` is reasonable and retrying a
/// `5x` is not, and a caller should not have to rediscover that from the raw
/// code. The code itself stays on [`Response::code`], because the second digit
/// carries detail the class does not (`44` is a rate limit, `51` is not-found,
/// `53` is proxy-request-refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `1x`: the server wants input; `meta` is the prompt.
    Input,
    /// `2x`: success; `meta` is the MIME type and the body follows.
    Success,
    /// `3x`: redirect; `meta` is the target. Following it is the caller's call.
    Redirect,
    /// `4x`: temporary failure; the same request may work later.
    TemporaryFailure,
    /// `5x`: permanent failure; it will not.
    PermanentFailure,
    /// `6x`: a client certificate is required.
    CertificateRequired,
}

impl Status {
    /// The class of a two-digit code, or `None` if the leading digit is not one
    /// gemini defines.
    pub fn from_code(code: u8) -> Option<Self> {
        match code / 10 {
            1 => Some(Self::Input),
            2 => Some(Self::Success),
            3 => Some(Self::Redirect),
            4 => Some(Self::TemporaryFailure),
            5 => Some(Self::PermanentFailure),
            6 => Some(Self::CertificateRequired),
            _ => None,
        }
    }
}

/// One gemini response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status class.
    pub status: Status,
    /// The literal two-digit code, e.g. `20`, `31`, `51`.
    pub code: u8,
    /// The header's meta field: the MIME type on success, otherwise the prompt,
    /// redirect target, or reason. May be empty.
    pub meta: String,
    /// The body. Empty for anything but a success, where `meta` is the payload.
    pub body: Vec<u8>,
}

/// The parsed facts available before a successful response body completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: Status,
    pub code: u8,
    pub meta: String,
}

impl ResponseHead {
    /// The MIME type of a successful response, without parameters.
    pub fn mime(&self) -> Option<&str> {
        if self.status != Status::Success {
            return None;
        }
        let mime = self.meta.split(';').next().unwrap_or("").trim();
        (!mime.is_empty()).then_some(mime)
    }
}

impl Response {
    /// The MIME type of a successful response: `meta` up to the first `;`
    /// parameter, trimmed. `None` for a non-success or an empty meta.
    pub fn mime(&self) -> Option<&str> {
        if self.status != Status::Success {
            return None;
        }
        let mime = self.meta.split(';').next().unwrap_or("").trim();
        (!mime.is_empty()).then_some(mime)
    }
}

/// What can go wrong running a gemini exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The URL could not be parsed, or it lacks a host.
    BadUrl(String),
    /// The TCP or TLS connection could not be established.
    Connect(String),
    /// A read or write failed mid-exchange.
    Io(String),
    /// The whole exchange deadline expired.
    Timeout,
    /// The response violated the grammar (no CRLF, a non-numeric status, an
    /// undefined status class, an over-long request).
    Protocol(String),
    /// The host's pinned certificate changed. Raised before the request is
    /// sent, so nothing was disclosed to whoever answered.
    CertificateChanged {
        host: String,
        pinned: String,
        seen: String,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Timeout => write!(f, "exchange timed out"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::CertificateChanged { host, pinned, seen } => write!(
                f,
                "certificate for {host} changed: pinned {pinned}, saw {seen}"
            ),
        }
    }
}

impl std::error::Error for ClientError {}

// ── The exchange ───────────────────────────────────────────────────────────

/// Run a gemini request/response over an already-connected, ready stream.
///
/// This is the transport-independent half of the protocol: nothing here
/// assumes TCP, TLS, or IP. An already-encrypted carrier needs no TLS at all,
/// so a Reticulum link, where the destination hash *is* the peer identity and
/// there is no certificate to pin, drives this same code with the TLS and TOFU
/// layer simply absent.
pub async fn exchange<S>(url: &Url, stream: &mut S) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_streaming(url, stream, |_, _| {}).await
}

/// Run a Gemini exchange and report each successful body chunk as it arrives.
///
/// The returned [`Response`] still contains the exact complete body. This
/// keeps custody and compatibility callers on the buffered contract while a
/// presentation host can act on bytes before connection close.
pub async fn exchange_streaming<S, F>(
    url: &Url,
    stream: &mut S,
    on_chunk: F,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&ResponseHead, &[u8]),
{
    exchange_streaming_with_options(url, stream, &FetchOptions::default(), on_chunk).await
}

/// Exchange with caller bounds; native 1024-byte request/header ceilings remain.
pub async fn exchange_with_options<S>(
    url: &Url,
    stream: &mut S,
    options: &FetchOptions,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_streaming_with_options(url, stream, options, |_, _| {}).await
}

/// Bounded streaming exchange. Overflow is refused before append or callback.
pub async fn exchange_streaming_with_options<S, F>(
    url: &Url,
    stream: &mut S,
    options: &FetchOptions,
    on_chunk: F,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&ResponseHead, &[u8]),
{
    tokio::time::timeout(options.timeout, async {
        let max = options.max_request_bytes.min(MAX_REQUEST);
        if url.as_str().len().saturating_add(2) > max {
            return Err(ClientError::Protocol(format!(
                "request exceeds {max} bytes"
            )));
        }
        let request = format!("{url}\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        read_response_streaming(stream, options, on_chunk).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

pub(crate) async fn read_response_streaming<S, F>(
    stream: &mut S,
    options: &FetchOptions,
    mut on_chunk: F,
) -> Result<Response, ClientError>
where
    S: AsyncRead + Unpin,
    F: FnMut(&ResponseHead, &[u8]),
{
    let max = options.max_header_line_bytes.min(MAX_RESPONSE_HEADER);
    let mut header = Vec::new();
    loop {
        let mut byte = [0];
        if stream
            .read(&mut byte)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?
            == 0
        {
            return Err(ClientError::Protocol("response header has no CRLF".into()));
        }
        if header.len() == max {
            return Err(ClientError::Protocol(format!(
                "response header exceeds {max} bytes"
            )));
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n") {
            break;
        }
    }
    let head = parse_response_head(&header[..header.len() - 2])?;
    let mut body = Vec::new();
    if head.status == Status::Success {
        let mut chunk = [0; 16 * 1024];
        loop {
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if count == 0 {
                break;
            }
            if count > options.max_body_bytes.saturating_sub(body.len()) {
                return Err(ClientError::Protocol(format!(
                    "response body exceeds {} bytes",
                    options.max_body_bytes
                )));
            }
            on_chunk(&head, &chunk[..count]);
            body.extend_from_slice(&chunk[..count]);
        }
    }
    Ok(Response {
        status: head.status,
        code: head.code,
        meta: head.meta,
        body,
    })
}

/// Split a gemini response into its `<status> <meta>\r\n` header and body.
pub fn parse_response(raw: &[u8]) -> Result<Response, ClientError> {
    let split = raw
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| ClientError::Protocol("response header has no CRLF".into()))?;
    let body = raw[split + 2..].to_vec();
    let head = parse_response_head(&raw[..split])?;
    Ok(Response {
        status: head.status,
        code: head.code,
        meta: head.meta,
        body: if head.status == Status::Success {
            body
        } else {
            Vec::new()
        },
    })
}

fn parse_response_head(header: &[u8]) -> Result<ResponseHead, ClientError> {
    let header = std::str::from_utf8(header)
        .map_err(|_| ClientError::Protocol("response header is not UTF-8".into()))?;
    let bytes = header.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(ClientError::Protocol(format!(
            "bad gemini status: {header:?}"
        )));
    }
    let code = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    let meta = header.get(2..).unwrap_or("").trim_start().to_string();
    let status = Status::from_code(code)
        .ok_or_else(|| ClientError::Protocol(format!("unknown gemini status class: {code}")))?;

    Ok(ResponseHead { status, code, meta })
}

#[cfg(test)]
mod tests;
