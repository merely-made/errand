//! The scroll client.
//!
//! One request per connection, like gemini: send the URI and language list,
//! read the header, read the body to EOF. TLS is mandatory and the trust
//! posture is the spec's own words, "TOFU is used, similarly to Gemini" — so
//! the TLS half rides [`gemini_protocol::tofu_connect`], and a host that
//! installs one [`TofuStore`](gemini_protocol::TofuStore) has installed it
//! for both protocols.
//!
//! ```no_run
//! # #[cfg(feature = "tls")]
//! # async fn run() -> Result<(), scroll_protocol::ClientError> {
//! let page = scroll_protocol::fetch("scroll://example.net/", &["en"], false).await?;
//!
//! if let scroll_protocol::Header::Success(header) = &page.header {
//!     println!("{} by {:?}", header.mimetype, header.author);
//!     for line in scroll_protocol::scrolltext::parse(&String::from_utf8_lossy(&page.body)) {
//!         println!("{line:?}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "tls")]
use crate::wire::DEFAULT_PORT;
use crate::wire::{Header, Status, finish_success, parse_status_line, request_line};

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

/// What can go wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    BadUrl(String),
    Connect(String),
    Io(String),
    /// The whole exchange deadline expired.
    Timeout,
    Protocol(String),
    /// The host's pinned certificate changed; nothing was sent.
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
            Self::CertificateChanged { host, pinned, seen } => {
                write!(
                    f,
                    "certificate for {host} changed: pinned {pinned}, saw {seen}"
                )
            }
        }
    }
}

impl std::error::Error for ClientError {}

#[cfg(feature = "tls")]
impl From<gemini_protocol::ClientError> for ClientError {
    fn from(error: gemini_protocol::ClientError) -> Self {
        use gemini_protocol::ClientError as Gemini;
        match error {
            Gemini::BadUrl(m) => Self::BadUrl(m),
            Gemini::Connect(m) => Self::Connect(m),
            Gemini::Io(m) => Self::Io(m),
            Gemini::Timeout => Self::Timeout,
            Gemini::Protocol(m) => Self::Protocol(m),
            Gemini::CertificateChanged { host, pinned, seen } => {
                Self::CertificateChanged { host, pinned, seen }
            }
        }
    }
}

/// One scroll response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: Header,
    /// The body for a success (or the abstract, for a metadata request).
    /// Empty for every other class.
    pub body: Vec<u8>,
}

/// Fetch a `scroll://` URL over TLS with TOFU pinning.
///
/// `languages` are BCP47 tags, most preferred first. `metadata` asks for the
/// resource's abstract rather than its body.
#[cfg(feature = "tls")]
pub async fn fetch(url: &str, languages: &[&str], metadata: bool) -> Result<Response, ClientError> {
    fetch_with_options(url, languages, metadata, &FetchOptions::default()).await
}

/// Fetch with caller-owned bounds, retaining all native metadata.
#[cfg(feature = "tls")]
pub async fn fetch_with_options(
    url: &str,
    languages: &[&str],
    metadata: bool,
    options: &FetchOptions,
) -> Result<Response, ClientError> {
    tokio::time::timeout(options.timeout, async {
        if request_size(url, languages, metadata) > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let parsed = url::Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
        if parsed.scheme() != "scroll" {
            return Err(ClientError::BadUrl(format!(
                "scheme {} is not scroll",
                parsed.scheme()
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("scroll URL has no host".into()))?;
        let port = parsed.port().unwrap_or(DEFAULT_PORT);

        let mut stream = gemini_protocol::tofu_connect(host, port).await?;
        exchange_with_options(url, languages, metadata, &mut stream, options).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Run the exchange over any connected stream.
///
/// Transport-independent, like gemini's: an already-encrypted carrier needs
/// no TLS of its own.
pub async fn exchange<S>(
    url: &str,
    languages: &[&str],
    metadata: bool,
    stream: &mut S,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_with_options(url, languages, metadata, stream, &FetchOptions::default()).await
}

/// Stream exchange with independently bounded request, metadata lines, and body.
pub async fn exchange_with_options<S>(
    url: &str,
    languages: &[&str],
    metadata: bool,
    stream: &mut S,
    options: &FetchOptions,
) -> Result<Response, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(options.timeout, async {
        if request_size(url, languages, metadata) > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let request = request_line(url, languages, metadata);
        if request.len() > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;

        let status_line = read_line(stream, options.max_header_line_bytes).await?;
        let (code, status, meta) =
            parse_status_line(&status_line).map_err(|e| ClientError::Protocol(e.0))?;

        if status != Status::Success {
            return Ok(Response {
                header: Header::Meta { code, status, meta },
                body: Vec::new(),
            });
        }

        // A success carries three metadata lines before the body.
        let author = read_line(stream, options.max_header_line_bytes).await?;
        let published = read_line(stream, options.max_header_line_bytes).await?;
        let modified = read_line(stream, options.max_header_line_bytes).await?;

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

        Ok(Response {
            header: Header::Success(finish_success(code, meta, &author, &published, &modified)),
            body,
        })
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Read one CRLF-terminated header line, byte-wise so the body that follows
/// is never swallowed by a buffered reader.
async fn read_line<S>(stream: &mut S, max: usize) -> Result<String, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let count = stream
            .read(&mut byte)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if count == 0 {
            return Err(ClientError::Protocol("unterminated header line".into()));
        }
        if line.len() == max {
            return Err(ClientError::Protocol(
                "header line exceeds configured limit".into(),
            ));
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            break;
        }
    }
    String::from_utf8(line).map_err(|_| ClientError::Protocol("header is not UTF-8".into()))
}

fn request_size(url: &str, languages: &[&str], metadata: bool) -> usize {
    languages.iter().fold(
        url.len()
            .saturating_add(3 + usize::from(metadata))
            .saturating_add(languages.len().saturating_sub(1)),
        |size, tag| size.saturating_add(tag.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::UdcClass;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn a_success_reads_its_three_metadata_lines_then_the_body() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(
                String::from_utf8_lossy(&buf[..n]),
                "scroll://example.net/spec.scroll en-US,en\r\n"
            );
            server
                .write_all(
                    b"20 text/scroll\r\n\
                      Christian Lee Seibold\r\n\
                      2025-07-23T20:50:51Z\r\n\
                      2024-08-03T14:11:29Z\r\n\
                      # Scroll Protocol Speculative Specification\n",
                )
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(
            "scroll://example.net/spec.scroll",
            &["en-US", "en"],
            false,
            &mut client,
        )
        .await
        .unwrap();

        let Header::Success(header) = &response.header else {
            panic!("expected success, got {:?}", response.header);
        };
        assert_eq!(header.mimetype, "text/scroll");
        assert_eq!(header.author.as_deref(), Some("Christian Lee Seibold"));
        assert_eq!(header.published.as_deref(), Some("2025-07-23T20:50:51Z"));
        assert_eq!(header.modified.as_deref(), Some("2024-08-03T14:11:29Z"));
        assert_eq!(header.class(), Some(UdcClass::Science));
        assert_eq!(
            response.body,
            b"# Scroll Protocol Speculative Specification\n"
        );
    }

    #[tokio::test]
    async fn blank_metadata_lines_arrive_as_none() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"24 text/plain\r\n\r\n\r\n\r\nhello\n")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange("scroll://x/", &["en"], false, &mut client)
            .await
            .unwrap();
        let Header::Success(header) = &response.header else {
            panic!("expected success");
        };
        assert_eq!(header.author, None);
        assert_eq!(header.published, None);
        assert_eq!(header.modified, None);
        assert_eq!(header.class(), Some(UdcClass::General));
        assert_eq!(response.body, b"hello\n");
    }

    #[tokio::test]
    async fn a_metadata_request_carries_the_plus_flag() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(String::from_utf8_lossy(&buf[..n]), "scroll://x/doc +en\r\n");
            server
                .write_all(b"20 text/scroll\r\nAuthor\r\n\r\n\r\n# Title\n")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange("scroll://x/doc", &["en"], true, &mut client)
            .await
            .unwrap();
        assert_eq!(response.body, b"# Title\n", "the abstract is the body");
    }

    #[tokio::test]
    async fn an_input_status_carries_its_prompt_and_no_metadata_lines() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"11 Passphrase?\r\n").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange("scroll://x/", &["en"], false, &mut client)
            .await
            .unwrap();
        assert_eq!(
            response.header,
            Header::Meta {
                code: 11,
                status: Status::Input,
                meta: "Passphrase?".into()
            }
        );
        assert!(response.body.is_empty());
    }
}
