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

#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(feature = "tls")]
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

    // Look the capsule target's pin up before connecting (so the verifier stays
    // 'static), then wrap TCP in a pinning TLS handshake.
    let store = tofu::trust_store();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tls")]
    #[derive(Debug)]
    struct AcceptAnyClient;

    #[cfg(feature = "tls")]
    impl rustls::server::danger::ClientCertVerifier for AcceptAnyClient {
        fn offer_client_auth(&self) -> bool {
            true
        }

        fn client_auth_mandatory(&self) -> bool {
            true
        }

        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
            ]
        }
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn caller_identity_is_presented_in_the_tls_handshake() {
        use std::sync::Arc;

        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let server_key = KeyPair::generate().unwrap();
        let server_cert = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&server_key)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&client_key)
            .unwrap();
        let expected_client_cert = client_cert.der().to_vec();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(Arc::new(AcceptAnyClient))
            .with_single_cert(
                vec![CertificateDer::from(server_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let presented = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .expect("the client presented its certificate")
                .as_ref()
                .to_vec();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 256];
                let read = tls.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before the Gemini request");
                request.extend_from_slice(&chunk[..read]);
                if request.ends_with(b"\r\n") {
                    break;
                }
            }
            tls.write_all(b"20 text/gemini\r\n# identity received\n")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
            presented
        };
        let url = Url::parse(&format!("gemini://localhost:{port}/private")).unwrap();
        let client_key_der = client_key.serialize_der();
        let client = fetch_url_with_identity(
            &url,
            ClientIdentity {
                certificate_der: client_cert.der().as_ref(),
                private_key_pkcs8_der: &client_key_der,
            },
        );
        let (presented, response) = tokio::join!(server, client);

        assert_eq!(presented, expected_client_cert);
        assert_eq!(response.unwrap().body, b"# identity received\n");
    }

    #[test]
    fn parses_success_header_and_body() {
        let r = parse_response(b"20 text/gemini; charset=utf-8\r\n# Hello\nworld\n").unwrap();
        assert_eq!(r.status, Status::Success);
        assert_eq!(r.code, 20);
        assert_eq!(r.mime(), Some("text/gemini"));
        assert_eq!(r.body, b"# Hello\nworld\n");
    }

    #[test]
    fn redirect_meta_is_the_target_and_body_is_dropped() {
        let r = parse_response(b"31 gemini://example.org/moved\r\nignored").unwrap();
        assert_eq!(r.status, Status::Redirect);
        assert_eq!(r.meta, "gemini://example.org/moved");
        assert!(r.body.is_empty());
    }

    #[test]
    fn temporary_and_permanent_failure_stay_apart() {
        // The distinction a client needs in order to know whether retrying is
        // sensible, and the one a flattened `Failure` throws away.
        let temporary = parse_response(b"44 slow down\r\n").unwrap();
        assert_eq!(temporary.status, Status::TemporaryFailure);
        assert_eq!(temporary.code, 44);

        let permanent = parse_response(b"51 not found\r\n").unwrap();
        assert_eq!(permanent.status, Status::PermanentFailure);
        assert_eq!(permanent.code, 51);
    }

    #[test]
    fn cert_required_class() {
        let r = parse_response(b"60 client cert required\r\n").unwrap();
        assert_eq!(r.status, Status::CertificateRequired);
    }

    #[test]
    fn empty_meta_is_fine() {
        let r = parse_response(b"20 \r\nbody").unwrap();
        assert_eq!(r.mime(), None);
        assert_eq!(r.body, b"body");
    }

    #[test]
    fn a_non_success_has_no_mime_even_with_a_meta() {
        let r = parse_response(b"31 gemini://example.org/\r\n").unwrap();
        assert_eq!(r.mime(), None);
    }

    #[test]
    fn missing_crlf_is_a_protocol_error() {
        assert!(matches!(
            parse_response(b"20 text/gemini"),
            Err(ClientError::Protocol(_))
        ));
    }

    #[test]
    fn non_numeric_status_is_a_protocol_error() {
        assert!(matches!(
            parse_response(b"xx nope\r\n"),
            Err(ClientError::Protocol(_))
        ));
    }

    #[test]
    fn an_undefined_status_class_is_refused() {
        assert!(matches!(
            parse_response(b"90 what\r\n"),
            Err(ClientError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn exchange_runs_over_any_stream() {
        // A mock capsule over an in-memory duplex: no TCP, no TLS. This is the
        // proof the exchange is transport-independent, and the exact code path
        // a Reticulum `LinkStream` (also `AsyncRead + AsyncWrite`) drives.
        let (client, mut server) = tokio::io::duplex(4096);
        let url = Url::parse("gemini://capsule.example/hello").unwrap();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"gemini://capsule.example/hello\r\n");
            server
                .write_all(b"20 text/gemini\r\n# Hello over an arbitrary stream\n")
                .await
                .unwrap();
            // Close so the client's read-to-EOF completes.
            server.shutdown().await.unwrap();
        });

        let mut client = client;
        let response = exchange(&url, &mut client).await.unwrap();
        server.await.unwrap();

        assert_eq!(response.status, Status::Success);
        assert_eq!(response.mime(), Some("text/gemini"));
        assert_eq!(response.body, b"# Hello over an arbitrary stream\n");
    }

    #[tokio::test]
    async fn streaming_exchange_reports_a_prefix_before_the_tail_arrives() {
        let (client, mut server) = tokio::io::duplex(4096);
        let url = Url::parse("gemini://capsule.example/live").unwrap();
        let prefix_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_release = prefix_seen.clone();
        let server = tokio::spawn(async move {
            let mut request = [0_u8; 1024];
            let _ = server.read(&mut request).await.unwrap();
            server
                .write_all(b"20 text/gemini\r\n# Prefix\n")
                .await
                .unwrap();
            while !server_release.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            server.write_all(b"Tail\n").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let mut client = client;
        let mut chunks = Vec::new();
        let response = exchange_streaming(&url, &mut client, |head, chunk| {
            assert_eq!(head.mime(), Some("text/gemini"));
            chunks.push(chunk.to_vec());
            prefix_seen.store(true, std::sync::atomic::Ordering::Release);
        })
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(chunks, [b"# Prefix\n".to_vec(), b"Tail\n".to_vec()]);
        assert_eq!(response.body, b"# Prefix\nTail\n");
    }

    #[tokio::test]
    async fn an_over_long_request_never_reaches_the_wire() {
        let (mut client, _server) = tokio::io::duplex(64);
        let url = Url::parse(&format!("gemini://example.org/{}", "x".repeat(1100))).unwrap();
        assert!(matches!(
            exchange(&url, &mut client).await,
            Err(ClientError::Protocol(_))
        ));
    }
}
