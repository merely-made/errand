//! The gopher client (`gopher://`, port 70).
//!
//! A gopher URL is `gopher://host/<type><selector>`: the first path character is
//! the item type, the rest is the selector sent verbatim. The request is just
//! the selector and a CRLF; a type-7 search appends the query after a TAB.
//!
//! Gopher has no status line. Every reply is a body, and the item type is the
//! only hint about what the bytes are, so the client reports a best-effort
//! MIME alongside them rather than inventing a status the protocol lacks.
//!
//! ```no_run
//! # async fn run() -> Result<(), gopher_protocol::ClientError> {
//! let reply = gopher_protocol::fetch("gopher://gopher.floodgap.com/1/").await?;
//! if reply.mime == "application/gopher-menu" {
//!     for item in gopher_protocol::parse_menu(&String::from_utf8_lossy(&reply.body)) {
//!         println!("{:?} {}", item.kind, item.display);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::plus::{AttributeBlock, MalformedHeader, PlusHeader, parse_attributes, parse_header};

// Re-exported so `client::PlusRequest` remains a valid path after the type
// moved to `plus`, where it belongs: a request form is protocol vocabulary,
// not client machinery, and the server needs it too.
pub use crate::plus::PlusRequest;

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
            max_request_bytes: 4096,
            max_header_line_bytes: 4096,
            max_body_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Gopher's well-known port.
pub const DEFAULT_PORT: u16 = 70;

/// What can go wrong fetching a gopher resource. Server refusals remain error
/// items in the native menu body; `Protocol` reports local byte-budget failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The URL could not be parsed, or it lacks a host.
    BadUrl(String),
    /// The TCP connection could not be established.
    Connect(String),
    /// A read or write failed mid-exchange.
    Io(String),
    /// The whole exchange deadline expired.
    Timeout,
    /// A configured byte budget was exceeded.
    Protocol(String),
    /// A Gopher+ reply did not begin with a well-formed header. Only Gopher+
    /// transactions can produce this; plain RFC 1436 replies have no header.
    BadPlusHeader(String),
    /// A Gopher+ server answered `--1`. The string is the error text it sent.
    PlusError(String),
}

impl From<MalformedHeader> for ClientError {
    fn from(error: MalformedHeader) -> Self {
        Self::BadPlusHeader(error.0)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Timeout => write!(f, "exchange timed out"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::BadPlusHeader(m) => write!(f, "malformed gopher+ header: {m}"),
            Self::PlusError(m) => write!(f, "gopher+ error: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// One gopher reply: the body, plus the MIME inferred from the item type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// A best-effort MIME type from the requested item type. Menus report
    /// `application/gopher-menu` so a consumer can route them to
    /// [`crate::menu::parse`].
    pub mime: String,
    /// The reply body, read to EOF.
    pub body: Vec<u8>,
}

/// Fetch a `gopher://` URL.
///
/// The URL is taken as a string so this signature does not carry a `url`
/// major version into the public API.
pub async fn fetch(url: &str) -> Result<Response, ClientError> {
    fetch_with_options(url, &FetchOptions::default()).await
}

/// Fetch with a whole deadline and caller request/body budgets.
pub async fn fetch_with_options(
    url: &str,
    options: &FetchOptions,
) -> Result<Response, ClientError> {
    tokio::time::timeout(options.timeout, async {
        let url = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("gopher URL has no host".into()))?;
        let port = url.port().unwrap_or(DEFAULT_PORT);
        let path = url.path().strip_prefix('/').unwrap_or(url.path());
        let selector_len = path
            .len()
            .saturating_sub(path.chars().next().map_or(0, char::len_utf8));
        if selector_len > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let (item_type, selector) = split_path(&url);

        let size = selector
            .len()
            .saturating_add(url.query().map_or(0, |q| q.len().saturating_add(1)))
            .saturating_add(2);
        if size > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let mut request = selector;
        // A type-7 item is a search server: the query rides after a TAB.
        if let Some(query) = url.query() {
            request.push('\t');
            request.push_str(query);
        }
        request.push_str("\r\n");

        let body = exchange(&url, host, port, request.as_bytes(), options).await?;
        Ok(Response {
            mime: mime_for_item_type(item_type).to_string(),
            body,
        })
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Open a connection (plaintext for `gopher://`, TLS for `gophers://`), send
/// `request`, and read the whole reply to EOF (gopher servers close the
/// stream when done).
async fn exchange(
    url: &Url,
    host: &str,
    port: u16,
    request: &[u8],
    options: &FetchOptions,
) -> Result<Vec<u8>, ClientError> {
    if request.len() > options.max_request_bytes {
        return Err(ClientError::Protocol(
            "request exceeds configured limit".into(),
        ));
    }
    if url.scheme() == "gophers" {
        #[cfg(feature = "tls")]
        {
            let mut stream = crate::tls::connect(host, port).await?;
            return send_and_read(&mut stream, request, options).await;
        }
        #[cfg(not(feature = "tls"))]
        {
            // Refusing beats silently sending a gophers:// request in the
            // clear, which is what ignoring the scheme would do.
            return Err(ClientError::BadUrl(
                "gophers:// needs the `tls` feature".into(),
            ));
        }
    }
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    send_and_read(&mut stream, request, options).await
}

/// Send a request over an already-connected stream and read the reply to EOF.
async fn send_and_read<S>(
    stream: &mut S,
    request: &[u8],
    options: &FetchOptions,
) -> Result<Vec<u8>, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    let mut body = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if count == 0 {
            break;
        }
        if count > options.max_body_bytes.saturating_sub(body.len()) {
            return Err(ClientError::Protocol(
                "body exceeds configured limit".into(),
            ));
        }
        body.extend_from_slice(&chunk[..count]);
    }
    Ok(body)
}

/// Split a gopher path into its item-type character and selector. An empty path
/// is the root menu (type `1`, empty selector).
fn split_path(url: &Url) -> (char, String) {
    let path = url.path();
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let mut chars = trimmed.chars();
    match chars.next() {
        Some(item_type) => (item_type, chars.as_str().to_string()),
        None => ('1', String::new()),
    }
}

/// A best-effort MIME type for a gopher item type. Menus get an
/// `application/gopher-menu` type so a consumer can route them to a gophermap
/// renderer; unknown types fall back to opaque bytes.
///
/// This is a client convention, not part of RFC 1436 — gopher carries no MIME.
pub fn mime_for_item_type(item_type: char) -> &'static str {
    match item_type {
        '0' => "text/plain",
        '1' | '7' => "application/gopher-menu",
        'h' => "text/html",
        'g' => "image/gif",
        'I' | ':' => "image/*",
        's' | '<' => "audio/*",
        _ => "application/octet-stream",
    }
}

// ── Gopher+ ────────────────────────────────────────────────────────────────

/// A Gopher+ reply: the header the server declared, and the body with any
/// period terminator removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlusReply {
    pub header: PlusHeader,
    pub body: Vec<u8>,
}

/// Run a Gopher+ transaction against a `gopher://` URL.
///
/// A Gopher+ request is the RFC 1436 request with a second TAB and a token:
/// `selector <TAB> search <TAB> token`. The search field is present but empty
/// for a non-search item, which is why the spec's own examples show two tabs.
pub async fn fetch_plus(url: &str, request: PlusRequest) -> Result<PlusReply, ClientError> {
    fetch_plus_with_options(url, request, &FetchOptions::default()).await
}

/// Bounded Gopher+ transaction; native header/count semantics are preserved.
pub async fn fetch_plus_with_options(
    url: &str,
    request: PlusRequest,
    options: &FetchOptions,
) -> Result<PlusReply, ClientError> {
    tokio::time::timeout(options.timeout, async {
        let url = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("gopher URL has no host".into()))?;
        let port = url.port().unwrap_or(DEFAULT_PORT);
        let path = url.path().strip_prefix('/').unwrap_or(url.path());
        let selector_len = path
            .len()
            .saturating_sub(path.chars().next().map_or(0, char::len_utf8));
        if selector_len > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let (_, selector) = split_path(&url);
        let search = url.query().unwrap_or("");

        let token_len = match &request {
            PlusRequest::Item(Some(view)) => 1_usize.saturating_add(view.len()),
            _ => 1,
        };
        let size = selector
            .len()
            .saturating_add(search.len())
            .saturating_add(token_len)
            .saturating_add(4);
        if size > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let token = request.token();
        let line = format!("{selector}\t{search}\t{token}\r\n");
        let (header, body) = plus_exchange(&url, host, port, line.as_bytes(), options).await?;

        if header == PlusHeader::Error {
            return Err(ClientError::PlusError(
                String::from_utf8_lossy(&body).trim().to_string(),
            ));
        }
        Ok(PlusReply { header, body })
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Fetch and parse an item's Gopher+ attribute blocks (`!`).
pub async fn fetch_attributes(url: &str) -> Result<Vec<AttributeBlock>, ClientError> {
    fetch_attributes_with_options(url, &FetchOptions::default()).await
}

/// Attribute blocks with caller bounds.
pub async fn fetch_attributes_with_options(
    url: &str,
    options: &FetchOptions,
) -> Result<Vec<AttributeBlock>, ClientError> {
    let reply = fetch_plus_with_options(url, PlusRequest::Attributes, options).await?;
    Ok(parse_attributes(&String::from_utf8_lossy(&reply.body)))
}

/// Fetch and parse the attribute blocks of every item in a directory (`$`).
pub async fn fetch_directory_attributes(url: &str) -> Result<Vec<AttributeBlock>, ClientError> {
    fetch_directory_attributes_with_options(url, &FetchOptions::default()).await
}

/// Directory attribute blocks with caller bounds.
pub async fn fetch_directory_attributes_with_options(
    url: &str,
    options: &FetchOptions,
) -> Result<Vec<AttributeBlock>, ClientError> {
    let reply = fetch_plus_with_options(url, PlusRequest::DirectoryAttributes, options).await?;
    Ok(parse_attributes(&String::from_utf8_lossy(&reply.body)))
}

/// Send a Gopher+ request and read the reply according to its header, rather
/// than always reading to EOF: a counted body stops at its count.
async fn plus_exchange(
    url: &Url,
    host: &str,
    port: u16,
    request: &[u8],
    options: &FetchOptions,
) -> Result<(PlusHeader, Vec<u8>), ClientError> {
    if request.len() > options.max_request_bytes {
        return Err(ClientError::Protocol(
            "request exceeds configured limit".into(),
        ));
    }
    if url.scheme() == "gophers" {
        #[cfg(feature = "tls")]
        {
            let stream = crate::tls::connect(host, port).await?;
            return plus_over(stream, request, options).await;
        }
        #[cfg(not(feature = "tls"))]
        {
            return Err(ClientError::BadUrl(
                "gophers:// needs the `tls` feature".into(),
            ));
        }
    }
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    plus_over(stream, request, options).await
}

/// The Gopher+ transaction over an already-connected stream.
async fn plus_over<S>(
    mut stream: S,
    request: &[u8],
    options: &FetchOptions,
) -> Result<(PlusHeader, Vec<u8>), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;

    let mut header_bytes = Vec::new();
    loop {
        let mut byte = [0];
        if stream
            .read(&mut byte)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?
            == 0
        {
            return Err(ClientError::BadPlusHeader("unterminated header".into()));
        }
        if header_bytes.len() == options.max_header_line_bytes {
            return Err(ClientError::Protocol(
                "header exceeds configured limit".into(),
            ));
        }
        header_bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let header_line = std::str::from_utf8(&header_bytes)
        .map_err(|_| ClientError::BadPlusHeader("header is not UTF-8".into()))?;
    let header = parse_header(header_line)?;
    let mut body = Vec::new();
    if let PlusHeader::Length(count) = header {
        if count > options.max_body_bytes as u64 {
            return Err(ClientError::Protocol(
                "body exceeds configured limit".into(),
            ));
        }
        let mut remaining = count;
        let mut chunk = [0; 8192];
        while remaining != 0 {
            let capacity = remaining.min(chunk.len() as u64) as usize;
            let count = stream
                .read(&mut chunk[..capacity])
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if count == 0 {
                return Err(ClientError::Protocol("truncated counted body".into()));
            }
            body.extend_from_slice(&chunk[..count]);
            remaining -= count as u64;
        }
    } else {
        let mut chunk = [0; 8192];
        loop {
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if count == 0 {
                break;
            }
            if count > options.max_body_bytes.saturating_sub(body.len()) {
                return Err(ClientError::Protocol(
                    "body exceeds configured limit".into(),
                ));
            }
            body.extend_from_slice(&chunk[..count]);
        }
    }

    if matches!(header, PlusHeader::PeriodTerminated | PlusHeader::Error) {
        body = strip_period_terminator(body);
    }
    Ok((header, body))
}

/// Remove a trailing `.` line. The newline before it belongs to the last data
/// line, so only the terminator line itself goes.
fn strip_period_terminator(mut body: Vec<u8>) -> Vec<u8> {
    for terminator in [
        b"\r\n.\r\n".as_slice(),
        b"\n.\n".as_slice(),
        b"\r\n.".as_slice(),
        b"\n.".as_slice(),
    ] {
        if body.ends_with(terminator) {
            let keep = if terminator.starts_with(b"\r\n") {
                2
            } else {
                1
            };
            body.truncate(body.len() - terminator.len() + keep);
            return body;
        }
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(u: &str) -> (char, String) {
        split_path(&Url::parse(u).unwrap())
    }

    #[test]
    fn root_path_is_a_menu() {
        assert_eq!(split("gopher://example.org/"), ('1', String::new()));
        assert_eq!(split("gopher://example.org"), ('1', String::new()));
    }

    #[test]
    fn type_and_selector_split_at_the_first_char() {
        assert_eq!(
            split("gopher://example.org/0/about.txt"),
            ('0', "/about.txt".into())
        );
        assert_eq!(split("gopher://example.org/1/dir"), ('1', "/dir".into()));
    }

    #[test]
    fn mime_inference() {
        assert_eq!(mime_for_item_type('0'), "text/plain");
        assert_eq!(mime_for_item_type('1'), "application/gopher-menu");
        assert_eq!(mime_for_item_type('9'), "application/octet-stream");
    }

    #[tokio::test]
    async fn a_url_without_a_host_is_refused_before_connecting() {
        let error = fetch("gopher:///0/x").await.unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }

    #[test]
    fn plus_tokens_match_the_spec() {
        assert_eq!(PlusRequest::Item(None).token(), "+");
        assert_eq!(
            PlusRequest::Item(Some("text/plain".into())).token(),
            "+text/plain"
        );
        assert_eq!(PlusRequest::Attributes.token(), "!");
        assert_eq!(PlusRequest::DirectoryAttributes.token(), "$");
    }

    #[test]
    fn the_period_terminator_goes_but_the_last_newline_stays() {
        assert_eq!(
            strip_period_terminator(b"one\r\ntwo\r\n.\r\n".to_vec()),
            b"one\r\ntwo\r\n".to_vec()
        );
        assert_eq!(
            strip_period_terminator(b"one\ntwo\n.\n".to_vec()),
            b"one\ntwo\n".to_vec()
        );
    }

    #[test]
    fn a_body_that_merely_ends_in_a_period_is_left_alone() {
        assert_eq!(
            strip_period_terminator(b"see fig. 1.".to_vec()),
            b"see fig. 1.".to_vec()
        );
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    async fn plus(raw: &[u8], max: usize) -> Result<(PlusHeader, Vec<u8>), ClientError> {
        let (client, mut server) = tokio::io::duplex(128);
        let raw = raw.to_vec();
        let server = tokio::spawn(async move {
            let mut request = [0; 256];
            let _ = server.read(&mut request).await.unwrap();
            let _ = server.write_all(&raw).await;
        });
        let result = plus_over(
            client,
            b"/\t\t+\r\n",
            &FetchOptions {
                max_body_bytes: max,
                ..Default::default()
            },
        )
        .await;
        server.await.unwrap();
        result
    }
    #[tokio::test]
    async fn counted_and_uncounted_plus_replies_have_exact_body_bounds() {
        assert_eq!(plus(b"+4\r\nABCD", 4).await.unwrap().1, b"ABCD");
        assert!(plus(b"+5\r\nABCDE", 4).await.is_err());
        assert!(plus(b"+4\r\nABC", 4).await.is_err());
        assert_eq!(plus(b"+-1\r\nABCD", 4).await.unwrap().1, b"ABCD");
        assert!(plus(b"+-1\r\nABCDE", 4).await.is_err());
    }
    #[tokio::test]
    async fn oversized_plus_representation_is_refused_before_connecting() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("gopher://{}/1/", listener.local_addr().unwrap());
        let options = FetchOptions {
            max_request_bytes: 8,
            ..Default::default()
        };
        let error =
            fetch_plus_with_options(&url, PlusRequest::Item(Some("x".repeat(8192))), &options)
                .await
                .unwrap_err();
        assert!(matches!(error, ClientError::Protocol(_)));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}
