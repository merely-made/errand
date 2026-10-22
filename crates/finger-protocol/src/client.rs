//! The classic finger client (`finger://`, port 79, RFC 1288).
//!
//! The request is a username and a CRLF; the reply is free-form text meant for
//! a human. There is no status line, no MIME type, and no structure: whatever
//! the remote `fingerd` felt like printing is the answer. That looseness is
//! why [WebFinger](crate::webfinger) exists.
//!
//! An empty username asks for a listing of everyone logged in, which most
//! modern hosts refuse or answer emptily.
//!
//! ```no_run
//! # async fn run() -> Result<(), finger_protocol::ClientError> {
//! let reply = finger_protocol::fetch("finger://example.org/alice").await?;
//! println!("{}", reply.text());
//! # Ok(())
//! # }
//! ```

// `Query` lives at the crate root: it is protocol vocabulary that the server
// needs too, so it must not sit behind the `client` feature.
pub use crate::Query;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

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

/// Finger's well-known port.
pub const DEFAULT_PORT: u16 = 79;

/// What can go wrong fingering a host.
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
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Timeout => write!(f, "exchange timed out"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A finger reply: free-form text, as bytes.
///
/// Kept as bytes rather than a `String` because RFC 1288 fixes no encoding and
/// real servers answer in whatever the host's locale was in 1994.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub body: Vec<u8>,
}

impl Response {
    /// The reply as text, replacing anything that is not valid UTF-8.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// Fetch a `finger://` URL.
///
/// Both `finger://host/user` and `finger://user@host` name a user; a bare
/// `finger://host/` asks for the listing.
pub async fn fetch(url: &str) -> Result<Response, ClientError> {
    fetch_with_options(url, &FetchOptions::default()).await
}

/// Fetch with a whole deadline and request/body bounds.
pub async fn fetch_with_options(
    url: &str,
    options: &FetchOptions,
) -> Result<Response, ClientError> {
    let url = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("finger URL has no host".into()))?;
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let user = if url.path().trim_start_matches('/').is_empty() {
        url.username()
    } else {
        url.path().trim_start_matches('/')
    };
    if user.len().saturating_add(2) > options.max_request_bytes {
        return Err(ClientError::Protocol(
            "request exceeds configured limit".into(),
        ));
    }
    query_with_options(host, port, &query_from_url(&url), options).await
}

/// Run a finger query against a host directly.
pub async fn query(host: &str, port: u16, request: &Query) -> Result<Response, ClientError> {
    query_with_options(host, port, request, &FetchOptions::default()).await
}

/// Query with caller bounds. Finger has no response header.
pub async fn query_with_options(
    host: &str,
    port: u16,
    request: &Query,
    options: &FetchOptions,
) -> Result<Response, ClientError> {
    tokio::time::timeout(options.timeout, async {
        let size = request
            .user
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(if request.verbose {
                2 + usize::from(request.user.as_deref().is_some_and(|user| !user.is_empty()))
            } else {
                0
            })
            .saturating_add(2);
        if size > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let wire = request.wire();
        if wire.len() > options.max_request_bytes {
            return Err(ClientError::Protocol(
                "request exceeds configured limit".into(),
            ));
        }
        let mut stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        stream
            .write_all(wire.as_bytes())
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
        Ok(Response { body })
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// The user a finger URL names: the path if present, else the userinfo, else
/// none for a host listing.
fn query_from_url(url: &Url) -> Query {
    let from_path = url.path().trim_start_matches('/');
    let user = if !from_path.is_empty() {
        Some(from_path.to_string())
    } else if !url.username().is_empty() {
        Some(url.username().to_string())
    } else {
        None
    };
    Query {
        user,
        verbose: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(u: &str) -> Option<String> {
        query_from_url(&Url::parse(u).unwrap()).user
    }

    #[test]
    fn user_from_path_or_userinfo_or_listing() {
        assert_eq!(
            target("finger://example.org/alice").as_deref(),
            Some("alice")
        );
        assert_eq!(target("finger://bob@example.org").as_deref(), Some("bob"));
        assert_eq!(target("finger://example.org/"), None);
    }

    #[test]
    fn the_verbose_switch_rides_before_the_user() {
        assert_eq!(Query::user("alice").verbose().wire(), "/W alice\r\n");
        assert_eq!(Query::default().verbose().wire(), "/W\r\n");
    }

    #[tokio::test]
    async fn a_url_without_a_host_is_refused_before_connecting() {
        let error = fetch("finger:///alice").await.unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }
}
