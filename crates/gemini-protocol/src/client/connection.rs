//! Native TCP/TLS fetch setup and shared TOFU connection establishment.

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use url::Url;

use super::{
    ClientError, ClientIdentity, DEFAULT_PORT, FetchOptions, MAX_REQUEST, Response, ResponseHead,
    exchange_streaming_with_options,
};

/// Fetch a `gemini://` URL over TCP and TLS, with trust-on-first-use pinning.
///
/// The host's pinned fingerprint is checked during the handshake, a first
/// contact is pinned once it completes, and a changed certificate surfaces as
/// [`ClientError::CertificateChanged`] before the request is ever sent.
#[cfg(feature = "tls")]
pub async fn fetch(url: &str) -> Result<Response, ClientError> {
    let url = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    fetch_url(&url).await
}

/// [`fetch`], for a caller that already has a parsed [`Url`].
#[cfg(feature = "tls")]
pub async fn fetch_url(url: &Url) -> Result<Response, ClientError> {
    fetch_url_inner(url, None).await
}

/// [`fetch_url`], reporting each successful body chunk as it arrives.
#[cfg(feature = "tls")]
pub async fn fetch_url_streaming<F>(url: &Url, on_chunk: F) -> Result<Response, ClientError>
where
    F: FnMut(&ResponseHead, &[u8]),
{
    fetch_url_streaming_inner(url, None, on_chunk).await
}

/// [`fetch_url`], presenting one caller-selected client certificate.
///
/// The caller remains responsible for capsule scoping. This function sends
/// the supplied identity to exactly the host named by `url`.
#[cfg(feature = "tls")]
pub async fn fetch_url_with_identity(
    url: &Url,
    identity: ClientIdentity<'_>,
) -> Result<Response, ClientError> {
    fetch_url_inner(url, Some(identity)).await
}

/// [`fetch_url_with_identity`], reporting body chunks as they arrive.
#[cfg(feature = "tls")]
pub async fn fetch_url_streaming_with_identity<F>(
    url: &Url,
    identity: ClientIdentity<'_>,
    on_chunk: F,
) -> Result<Response, ClientError>
where
    F: FnMut(&ResponseHead, &[u8]),
{
    fetch_url_streaming_inner(url, Some(identity), on_chunk).await
}

#[cfg(feature = "tls")]
async fn fetch_url_inner(
    url: &Url,
    identity: Option<ClientIdentity<'_>>,
) -> Result<Response, ClientError> {
    fetch_url_streaming_inner(url, identity, |_, _| {}).await
}

#[cfg(feature = "tls")]
async fn fetch_url_streaming_inner<F>(
    url: &Url,
    identity: Option<ClientIdentity<'_>>,
    on_chunk: F,
) -> Result<Response, ClientError>
where
    F: FnMut(&ResponseHead, &[u8]),
{
    fetch_url_streaming_with_options(url, identity, &FetchOptions::default(), on_chunk).await
}

/// TLS fetch with caller limits and an optional host-selected certificate.
#[cfg(feature = "tls")]
pub async fn fetch_url_with_options(
    url: &Url,
    identity: Option<ClientIdentity<'_>>,
    options: &FetchOptions,
) -> Result<Response, ClientError> {
    fetch_url_streaming_with_options(url, identity, options, |_, _| {}).await
}

/// TLS streaming fetch; the deadline includes DNS, TCP, TOFU, and TLS.
#[cfg(feature = "tls")]
pub async fn fetch_url_streaming_with_options<F>(
    url: &Url,
    identity: Option<ClientIdentity<'_>>,
    options: &FetchOptions,
    on_chunk: F,
) -> Result<Response, ClientError>
where
    F: FnMut(&ResponseHead, &[u8]),
{
    tokio::time::timeout(options.timeout, async {
        let max = options.max_request_bytes.min(MAX_REQUEST);
        if url.as_str().len().saturating_add(2) > max {
            return Err(ClientError::Protocol(format!(
                "request exceeds {max} bytes"
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("gemini URL has no host".into()))?;
        let port = url.port().unwrap_or(DEFAULT_PORT);
        let mut stream = tofu_connect_inner(host, port, identity).await?;
        exchange_streaming_with_options(url, &mut stream, options, on_chunk).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

/// Open a TLS connection with trust-on-first-use pinning, without speaking
/// any protocol over it.
///
/// This is gemini's trust posture offered as a building block: the host's
/// pinned fingerprint is checked during the handshake, a first contact is
/// pinned once it completes, and a changed certificate surfaces as
/// [`ClientError::CertificateChanged`] before a single application byte is
/// written. Protocols that declare "TOFU, as in gemini" (scroll does, in so
/// many words) ride this seam and share the same installed
/// [`TofuStore`](crate::TofuStore), so a host that pins a certificate once
/// has pinned it for every protocol that trusts this way.
#[cfg(feature = "tls")]
pub async fn tofu_connect(
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ClientError> {
    tofu_connect_inner(host, port, None).await
}

#[cfg(feature = "tls")]
pub(crate) async fn tofu_connect_inner(
    host: &str,
    port: u16,
    identity: Option<ClientIdentity<'_>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ClientError> {
    use crate::{tls, tofu};

    // No installed store, no connection: refuse before any socket is opened.
    // Look the capsule target's pin up before connecting (so the verifier stays
    // 'static), then wrap TCP in a pinning TLS handshake.
    let store =
        tofu::trust_store().ok_or_else(|| ClientError::Connect(tofu::NO_TRUST_STORE.into()))?;
    let target = tofu::target(host, port);
    let pinned = store.fingerprint(&target);
    let (connector, seen) =
        tls::pinning_connector(pinned, identity).map_err(ClientError::Connect)?;

    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| ClientError::Connect(format!("server name {host}: {e}")))?;
    let stream = match connector.connect(server_name, tcp).await {
        Ok(tls) => tls,
        Err(e) => {
            // A pin mismatch surfaces richly; the verifier recorded what it
            // saw before rejecting the handshake.
            if let (Some(pinned), Some(seen)) = (pinned, *seen.lock().unwrap())
                && pinned != seen
            {
                return Err(ClientError::CertificateChanged {
                    host: target,
                    pinned: tofu::hex(&pinned),
                    seen: tofu::hex(&seen),
                });
            }
            return Err(ClientError::Connect(format!("tls handshake: {e}")));
        }
    };

    // Clean handshake: pin the fingerprint on first contact.
    if pinned.is_none()
        && let Some(fingerprint) = *seen.lock().unwrap()
    {
        store
            .try_pin(&target, fingerprint)
            .map_err(|error| ClientError::Io(format!("trust store: {error}")))?;
    }

    Ok(stream)
}
