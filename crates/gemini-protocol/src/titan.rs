//! The Titan protocol (`titan://`, port 1965, <https://transjovian.org/titan>).
//!
//! Titan is the upload/write companion to Gemini. The client opens a TLS
//! connection (same TOFU verifier as Gemini), sends a request line of the form
//!
//!   `<titan-url>;size=<n>[;mime=<type>][;token=<token>]\r\n`
//!
//! immediately followed by `<n>` bytes of body, then reads a Gemini-format
//! response header (`<code> <meta>\r\n`) and optional body.
//!
//! ## Navigation (`fetch`)
//!
//! When the host navigates to a `titan://` URL without a payload (e.g. the user
//! clicks a titan:// link), `fetch` sends a zero-byte upload. The server
//! typically replies with a redirect (`30`/`31`) to the read location or a
//! failure; whatever it returns is parsed as a Gemini response.
//!
//! ## Upload (`upload`)
//!
//! For actual writes, call [`upload`] directly with the body bytes, MIME type,
//! and optional token.

use tokio::io::AsyncWriteExt;
use url::Url;

use crate::client::{
    ClientError, ClientIdentity, FetchOptions, Response, read_response_streaming,
    tofu_connect_inner,
};

/// Titan shares gemini's port.
pub const DEFAULT_PORT: u16 = 1965;

/// Default cap for a Titan server's Gemini response body. Callers that expect
/// larger receipts can use [`upload_with_options`].
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Bounds applied while reading a Titan response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadOptions {
    pub max_response_bytes: usize,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Navigate to a `titan://` URL by sending a zero-byte upload and returning the
/// server's Gemini-format response.
pub async fn fetch(url: &Url) -> Result<Response, ClientError> {
    upload_inner(url, &[], "", None, None, UploadOptions::default()).await
}

/// Upload `body` to `url` with the given `mime` type and optional `token`.
/// Returns the server's Gemini-format response.
///
/// The request line is `<url>;size=<n>[;mime=<type>][;token=<token>]\r\n`
/// followed immediately by the body bytes.
pub async fn upload(
    url: &Url,
    body: &[u8],
    mime: &str,
    token: Option<&str>,
) -> Result<Response, ClientError> {
    upload_inner(url, body, mime, token, None, UploadOptions::default()).await
}

/// Upload with an explicit response-body bound.
pub async fn upload_with_options(
    url: &Url,
    body: &[u8],
    mime: &str,
    token: Option<&str>,
    options: UploadOptions,
) -> Result<Response, ClientError> {
    upload_inner(url, body, mime, token, None, options).await
}

/// Upload while presenting one caller-selected Gemini-family client identity.
///
/// The caller remains responsible for capsule scoping. Server trust still
/// passes through the installed Gemini TOFU store before request bytes leave
/// the process.
pub async fn upload_with_identity(
    url: &Url,
    body: &[u8],
    mime: &str,
    token: Option<&str>,
    identity: ClientIdentity<'_>,
) -> Result<Response, ClientError> {
    upload_inner(
        url,
        body,
        mime,
        token,
        Some(identity),
        UploadOptions::default(),
    )
    .await
}

async fn upload_inner(
    url: &Url,
    body: &[u8],
    mime: &str,
    token: Option<&str>,
    identity: Option<ClientIdentity<'_>>,
    options: UploadOptions,
) -> Result<Response, ClientError> {
    validate_request(url, body.len(), mime, token, options)?;
    let max_request_bytes = body
        .len()
        .checked_add(1024)
        .ok_or_else(|| ClientError::Protocol("Titan request size overflows".into()))?;
    let bounds = FetchOptions {
        max_request_bytes,
        max_body_bytes: options.max_response_bytes,
        ..FetchOptions::default()
    };
    upload_with_fetch_options(url, body, mime, token, identity, &bounds).await
}

/// Upload with separate total request, response header/body, and whole deadline bounds.
/// The Titan request line still cannot exceed its native 1024-byte ceiling.
pub async fn upload_with_fetch_options(
    url: &Url,
    body: &[u8],
    mime: &str,
    token: Option<&str>,
    identity: Option<ClientIdentity<'_>>,
    options: &FetchOptions,
) -> Result<Response, ClientError> {
    tokio::time::timeout(options.timeout, async {
        validate_request(
            url,
            body.len(),
            mime,
            token,
            UploadOptions {
                max_response_bytes: options.max_body_bytes.max(1),
            },
        )?;
        let size = request_size(url, body.len(), mime, token);
        if size > options.max_request_bytes
            || body.len() > options.max_request_bytes.saturating_sub(size)
        {
            return Err(ClientError::Protocol(
                "Titan request exceeds configured limit".into(),
            ));
        }
        let request = request_line(url, body.len(), mime, token);
        let host = url
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("titan URL has no host".into()))?;
        let port = url.port().unwrap_or(DEFAULT_PORT);
        let mut tls = tofu_connect_inner(host, port, identity).await?;
        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        tls.write_all(body)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        read_response_streaming(&mut tls, options, |_, _| {}).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

fn validate_request(
    url: &Url,
    body_len: usize,
    mime: &str,
    token: Option<&str>,
    options: UploadOptions,
) -> Result<(), ClientError> {
    if url.scheme() != "titan"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path().contains(';')
    {
        return Err(ClientError::Protocol("invalid titan URL".into()));
    }
    if options.max_response_bytes == 0 {
        return Err(ClientError::Protocol(
            "Titan response limit must be non-zero".into(),
        ));
    }
    if !field_is_safe(mime) || token.is_some_and(|value| !field_is_safe(value)) {
        return Err(ClientError::Protocol(
            "Titan MIME and token fields contain a forbidden delimiter or control byte".into(),
        ));
    }
    if request_size(url, body_len, mime, token) > 1024 {
        return Err(ClientError::Protocol(
            "Titan request line exceeds 1024 bytes".into(),
        ));
    }
    Ok(())
}

fn field_is_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b';')
}

fn request_size(url: &Url, body_len: usize, mime: &str, token: Option<&str>) -> usize {
    url.as_str()
        .len()
        .saturating_add(6)
        .saturating_add(body_len.to_string().len())
        .saturating_add(if mime.is_empty() {
            0
        } else {
            6_usize.saturating_add(mime.len())
        })
        .saturating_add(token.map_or(0, |value| 7_usize.saturating_add(value.len())))
        .saturating_add(2)
}

/// Build titan's request line:
/// `<url>;size=<n>[;mime=<type>][;token=<token>]\r\n`.
fn request_line(url: &Url, size: usize, mime: &str, token: Option<&str>) -> String {
    let mut request = format!("{url};size={size}");
    if !mime.is_empty() {
        request.push_str(";mime=");
        request.push_str(mime);
    }
    if let Some(token) = token {
        request.push_str(";token=");
        request.push_str(token);
    }
    request.push_str("\r\n");
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titan_shares_gemini_port() {
        assert_eq!(DEFAULT_PORT, crate::client::DEFAULT_PORT);
    }

    #[test]
    fn the_request_line_carries_size_mime_and_token_in_order() {
        let url = Url::parse("titan://example.org/raw/page").unwrap();
        assert_eq!(
            request_line(&url, 12, "text/gemini", Some("hunter2")),
            "titan://example.org/raw/page;size=12;mime=text/gemini;token=hunter2\r\n"
        );
    }

    #[test]
    fn an_empty_mime_and_no_token_leave_only_the_size() {
        let url = Url::parse("titan://example.org/raw/page").unwrap();
        assert_eq!(
            request_line(&url, 0, "", None),
            "titan://example.org/raw/page;size=0\r\n"
        );
    }

    #[test]
    fn request_validation_rejects_injection_and_wrong_urls_before_connect() {
        let good = Url::parse("titan://example.org/page").unwrap();
        assert!(
            validate_request(
                &good,
                0,
                "text/gemini\r\n20",
                None,
                UploadOptions::default()
            )
            .is_err()
        );
        assert!(
            validate_request(
                &good,
                0,
                "text/gemini",
                Some("x;y"),
                UploadOptions::default()
            )
            .is_err()
        );
        assert!(
            validate_request(
                &Url::parse("gemini://example.org/page#frag").unwrap(),
                0,
                "",
                None,
                UploadOptions::default()
            )
            .is_err()
        );
        assert!(
            validate_request(
                &Url::parse("titan://user:pass@example.org/page").unwrap(),
                0,
                "",
                None,
                UploadOptions::default()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn response_reader_refuses_oversize_without_truncating() {
        let (mut reader, mut writer) = tokio::io::duplex(32);
        tokio::spawn(async move {
            writer.write_all(b"20 text/plain\r\n12345").await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let options = FetchOptions {
            max_body_bytes: 4,
            ..Default::default()
        };
        let error = read_response_streaming(&mut reader, &options, |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::Protocol(message) if message.contains("exceeds")));
    }

    #[tokio::test]
    async fn public_upload_refuses_before_connect_for_invalid_fields() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("titan://127.0.0.1:{port}/page")).unwrap();
        let error = upload(&url, b"body", "text/gemini\r\n20", None)
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::Protocol(message) if message.contains("delimiter")));
        assert!(
            matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ),
            "invalid request must not connect"
        );
    }
    #[tokio::test]
    async fn legacy_zero_response_limit_refuses_before_mutation_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = Url::parse(&format!("titan://{}/write", listener.local_addr().unwrap())).unwrap();
        let error = upload_with_options(
            &url,
            b"mutation",
            "text/plain",
            None,
            UploadOptions {
                max_response_bytes: 0,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ClientError::Protocol(_)));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}
