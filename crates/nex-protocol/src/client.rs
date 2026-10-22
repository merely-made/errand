//! The nex client: send a path, read until close.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use super::NEX_PORT;

/// Options for a [`fetch`].
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Whole-exchange deadline, including connection setup. Default 30s.
    pub timeout: Duration,
    /// Refuse responses larger than this. Default 16 MiB.
    pub max_body: usize,
    /// Complete request line, including CRLF. Default 4096 bytes.
    pub max_request_bytes: usize,
    /// Connect here instead of resolving the URL's host. For tests and odd
    /// deployments.
    pub connect_addr: Option<std::net::SocketAddr>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_body: 16 * 1024 * 1024,
            max_request_bytes: 4096,
            connect_addr: None,
        }
    }
}

/// Why a fetch failed. Nex has no protocol-level errors: a successful
/// exchange is whatever bytes the server sent.
#[derive(Debug)]
pub enum ClientError {
    BadUrl(String),
    Io(String),
    Timeout(&'static str),
    BodyTooLarge { max: usize },
    RequestTooLarge { max: usize },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(message) => write!(formatter, "bad nex URL: {message}"),
            Self::Io(message) => write!(formatter, "nex IO error: {message}"),
            Self::Timeout(step) => write!(formatter, "nex {step} timed out"),
            Self::RequestTooLarge { max } => write!(formatter, "nex request exceeds {max} bytes"),
            Self::BodyTooLarge { max } => {
                write!(formatter, "nex response exceeds {max} bytes")
            }
        }
    }
}

impl std::error::Error for ClientError {}

/// Fetch a `nex://` URL and return the raw response bytes.
pub async fn fetch(url: &str, options: &FetchOptions) -> Result<Vec<u8>, ClientError> {
    let url = Url::parse(url).map_err(|error| ClientError::BadUrl(error.to_string()))?;
    if url.scheme() != "nex" {
        return Err(ClientError::BadUrl(format!(
            "expected nex:// scheme, got {}://",
            url.scheme()
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("URL has no host".to_string()))?;
    let port = url.port().unwrap_or(NEX_PORT);
    fetch_path(host, port, url.path(), options).await
}

/// Fetch by explicit host/port/path. The path may be empty (the spec allows
/// an empty selector for the root).
pub async fn fetch_path(
    host: &str,
    port: u16,
    path: &str,
    options: &FetchOptions,
) -> Result<Vec<u8>, ClientError> {
    tokio::time::timeout(options.timeout, async {
        if path.len().saturating_add(2) > options.max_request_bytes {
            return Err(ClientError::RequestTooLarge {
                max: options.max_request_bytes,
            });
        }
        let connect = async {
            match options.connect_addr {
                Some(addr) => TcpStream::connect(addr).await,
                None => TcpStream::connect((host, port)).await,
            }
        };
        let mut stream = tokio::time::timeout(options.timeout, connect)
            .await
            .map_err(|_| ClientError::Timeout("connect"))?
            .map_err(|error| ClientError::Io(error.to_string()))?;

        let request = format!("{path}\r\n");
        tokio::time::timeout(options.timeout, stream.write_all(request.as_bytes()))
            .await
            .map_err(|_| ClientError::Timeout("request write"))?
            .map_err(|error| ClientError::Io(error.to_string()))?;

        let read = async {
            let mut body = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let count = stream.read(&mut chunk).await?;
                if count == 0 {
                    break;
                }
                if count > options.max_body.saturating_sub(body.len()) {
                    return Ok::<_, std::io::Error>(None);
                }
                body.extend_from_slice(&chunk[..count]);
            }
            Ok(Some(body))
        };
        tokio::time::timeout(options.timeout, read)
            .await
            .map_err(|_| ClientError::Timeout("response read"))?
            .map_err(|error| ClientError::Io(error.to_string()))?
            .ok_or(ClientError::BodyTooLarge {
                max: options.max_body,
            })
    })
    .await
    .map_err(|_| ClientError::Timeout("exchange"))?
}
