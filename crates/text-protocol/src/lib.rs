//! # text-protocol
//!
//! An implementation of the [Text Protocol](https://textprotocol.org/)
//! (`text://`): the deliberately minimal one. Requests are an IRI and a CRLF;
//! responses are one of **exactly three** status codes; every document is
//! `text/plain;charset=utf-8`.
//!
//! The protocol advertises three transports, named after the crewed-flight
//! programs, via DNS Service Discovery:
//!
//! | Port | Name | Carrier | Here |
//! |---|---|---|---|
//! | 1961 | Mercury | plain TCP | [`fetch`] (feature `client`) |
//! | 1965 | Gemini | TLS | [`fetch_tls`] (feature `tls`) |
//! | 1968 | Apollo | Noise (XX, Curve25519, ChaCha20-Poly1305, BLAKE2b) | **not implemented** |
//!
//! The Noise transport is not implemented because it would pull a Noise
//! stack this crate does not otherwise need; the port and pattern are
//! recorded so nobody has to rediscover them.
//!
//! ## The whole grammar
//!
//! ```text
//! request  = IRI CRLF                      (UTF-8, NFC, absolute)
//! response = "20" SP mimetype CRLF body    (success)
//!          / "30" SP IRI CRLF              (redirect)
//!          / "40" SP description CRLF      (error)
//! ```
//!
//! A body is plain text whose only structure is the optional link line:
//!
//! ```text
//! => text://textprotocol.org/license.txt rel=license CC0-1.0
//! ```
//!
//! Tokens after the IRI are attributes when they contain `=` (`rel=license`)
//! and label text otherwise; [`LinkLine`] carries both.
//!
//! ```
//! use text_protocol::{Line, parse_body};
//!
//! let body = "hello\n=> text://example.org/a.txt rel=license CC0-1.0\n";
//! let lines = parse_body(body);
//!
//! assert_eq!(lines[0], Line::Text("hello".into()));
//! let Line::Link(link) = &lines[1] else { panic!() };
//! assert_eq!(link.url, "text://example.org/a.txt");
//! assert_eq!(link.attributes[0], ("rel".into(), "license".into()));
//! assert_eq!(link.label.as_deref(), Some("CC0-1.0"));
//! ```

#![forbid(unsafe_code)]

/// Plain TCP, the port the spec names Mercury.
pub const DEFAULT_PORT: u16 = 1961;
/// TLS, the port the spec names Gemini.
pub const DEFAULT_TLS_PORT: u16 = 1965;
/// Noise, the port the spec names Apollo. Recorded, not implemented.
pub const NOISE_PORT: u16 = 1968;

/// The three status codes. There are no others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `20`: success; the meta is the mimetype and a body follows.
    Ok,
    /// `30`: redirect; the meta is the target IRI.
    Redirect,
    /// `40`: error; the meta is a description.
    Nok,
}

impl Status {
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "20" => Some(Self::Ok),
            "30" => Some(Self::Redirect),
            "40" => Some(Self::Nok),
            _ => None,
        }
    }
}

/// A parsed response header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub status: Status,
    /// Mimetype, redirect target, or error description, by status.
    pub meta: String,
}

/// Parse a response header line (without its CRLF). `None` if it is not one
/// of the three the protocol defines.
pub fn parse_header(line: &str) -> Option<Header> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (code, meta) = match line.split_once(' ') {
        Some((code, meta)) => (code, meta),
        None => (line, ""),
    };
    Some(Header {
        status: Status::from_code(code)?,
        meta: meta.trim().to_string(),
    })
}

/// Build a request line: the IRI and a CRLF, nothing else.
pub fn request_line(iri: &str) -> String {
    format!("{iri}\r\n")
}

// ── The body ───────────────────────────────────────────────────────────────

/// One line of a text-protocol body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// Ordinary text, verbatim.
    Text(String),
    /// A `=>` link line.
    Link(LinkLine),
}

/// A link line: the IRI, its `key=value` attributes, and any label text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkLine {
    pub url: String,
    /// Tokens containing `=`, split at the first one, in order.
    pub attributes: Vec<(String, String)>,
    /// The remaining tokens joined by single spaces, or `None` if there were
    /// none.
    pub label: Option<String>,
}

/// Parse a body into lines. Only `=>` is structural; everything else is text.
pub fn parse_body(body: &str) -> Vec<Line> {
    body.lines()
        .map(|line| match line.strip_prefix("=>") {
            Some(rest) => Line::Link(parse_link(rest)),
            None => Line::Text(line.to_string()),
        })
        .collect()
}

fn parse_link(rest: &str) -> LinkLine {
    let mut tokens = rest.split_whitespace();
    let url = tokens.next().unwrap_or("").to_string();
    let mut attributes = Vec::new();
    let mut label_parts = Vec::new();
    for token in tokens {
        match token.split_once('=') {
            // An attribute, unless the label has already started: a label
            // containing `=` stays label text.
            Some((key, value)) if label_parts.is_empty() && !key.is_empty() => {
                attributes.push((key.to_string(), value.to_string()));
            }
            _ => label_parts.push(token),
        }
    }
    LinkLine {
        url,
        attributes,
        label: (!label_parts.is_empty()).then(|| label_parts.join(" ")),
    }
}

// ── Client ─────────────────────────────────────────────────────────────────

#[cfg(feature = "client")]
mod client {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::{DEFAULT_PORT, Header, parse_header, request_line};

    /// Per-exchange wire budgets. Line budgets include CRLF; zero body permits only empty responses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Limits {
        pub max_request_bytes: usize,
        pub max_header_line_bytes: usize,
        pub max_body_bytes: usize,
    }

    impl Default for Limits {
        fn default() -> Self {
            Self {
                max_request_bytes: 4096,
                max_header_line_bytes: 4097,
                max_body_bytes: 64 * 1024 * 1024,
            }
        }
    }

    pub(super) fn check_request(iri: &str, limits: &Limits) -> Result<(), ClientError> {
        if iri.contains(['\r', '\n']) {
            return Err(ClientError::BadUrl(
                "IRI contains a request line break".into(),
            ));
        }
        if iri
            .len()
            .checked_add(2)
            .is_none_or(|n| n > limits.max_request_bytes)
            || limits.max_header_line_bytes == 0
        {
            return Err(ClientError::Limit(
                "request or header line budget exceeded".into(),
            ));
        }
        Ok(())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ClientError {
        BadUrl(String),
        /// A caller-supplied wire budget was exceeded.
        Limit(String),
        Connect(String),
        Io(String),
        /// The reply's first line was not one of the three the protocol has.
        Protocol(String),
    }

    impl std::fmt::Display for ClientError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Limit(m) => write!(f, "limit: {m}"),
                Self::BadUrl(m) => write!(f, "bad url: {m}"),
                Self::Connect(m) => write!(f, "connect: {m}"),
                Self::Io(m) => write!(f, "io: {m}"),
                Self::Protocol(m) => write!(f, "protocol: {m}"),
            }
        }
    }

    impl std::error::Error for ClientError {}

    /// One response: the header, and the body for a `20`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Response {
        pub header: Header,
        pub body: Vec<u8>,
    }

    /// Fetch a `text://` IRI over plain TCP (the Mercury port).
    pub async fn fetch(iri: &str) -> Result<Response, ClientError> {
        fetch_with_limits(iri, &Limits::default()).await
    }

    /// Fetch over TCP with caller-owned size budgets.
    pub async fn fetch_with_limits(iri: &str, limits: &Limits) -> Result<Response, ClientError> {
        check_request(iri, limits)?;
        let parsed = url::Url::parse(iri).map_err(|e| ClientError::BadUrl(e.to_string()))?;
        if parsed.scheme() != "text" {
            return Err(ClientError::BadUrl(format!(
                "scheme {} is not text",
                parsed.scheme()
            )));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("text IRI has no host".into()))?;
        let port = parsed.port().unwrap_or(DEFAULT_PORT);
        let mut stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
        exchange_with_limits(iri, &mut stream, limits).await
    }

    /// Run the exchange over any connected stream, so an encrypted carrier
    /// needs no TLS of its own.
    pub async fn exchange<S>(iri: &str, stream: &mut S) -> Result<Response, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        exchange_with_limits(iri, stream, &Limits::default()).await
    }

    /// Run a supplied-carrier exchange with explicit wire budgets.
    pub async fn exchange_with_limits<S>(
        iri: &str,
        stream: &mut S,
        limits: &Limits,
    ) -> Result<Response, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        check_request(iri, limits)?;
        stream
            .write_all(request_line(iri).as_bytes())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if stream
                .read(&mut byte)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?
                == 0
            {
                return Err(ClientError::Protocol("header ended without CRLF".into()));
            }
            if line.len() >= limits.max_header_line_bytes {
                return Err(ClientError::Limit(
                    "response header line budget exceeded".into(),
                ));
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                if !line.ends_with(b"\r\n") {
                    return Err(ClientError::Protocol("header ended without CRLF".into()));
                }
                break;
            }
        }
        let text = std::str::from_utf8(&line[..line.len() - 2])
            .map_err(|_| ClientError::Protocol("header is not UTF-8".into()))?;
        let header = parse_header(text).ok_or_else(|| {
            ClientError::Protocol(format!("not a text-protocol status: {text:?}"))
        })?;
        let mut body = Vec::new();
        if header.status == super::Status::Ok {
            let mut chunk = [0u8; 8192];
            loop {
                let remaining = limits.max_body_bytes - body.len();
                let read_size = remaining.saturating_add(1).min(chunk.len());
                let count = stream
                    .read(&mut chunk[..read_size])
                    .await
                    .map_err(|e| ClientError::Io(e.to_string()))?;
                if count == 0 {
                    break;
                }
                if count > remaining {
                    return Err(ClientError::Limit("response body budget exceeded".into()));
                }
                body.extend_from_slice(&chunk[..count]);
            }
        }
        Ok(Response { header, body })
    }
}

#[cfg(feature = "client")]
pub use client::{
    ClientError, Limits, Response, exchange, exchange_with_limits, fetch, fetch_with_limits,
};

/// Fetch over TLS (the port the spec names Gemini). Certificates are accepted
/// without verification, stated rather than hidden: the protocol's own
/// plain-TCP transport shows encryption is optional here, so TLS is
/// confidentiality, not peer authentication.
#[cfg(feature = "tls")]
pub async fn fetch_tls(iri: &str) -> Result<Response, ClientError> {
    fetch_tls_with_limits(iri, &Limits::default()).await
}

/// Fetch over TLS with caller-owned size budgets and existing certificate policy.
#[cfg(feature = "tls")]
pub async fn fetch_tls_with_limits(iri: &str, limits: &Limits) -> Result<Response, ClientError> {
    client::check_request(iri, limits)?;
    let parsed = url::Url::parse(iri).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    if parsed.scheme() != "text" {
        return Err(ClientError::BadUrl(format!(
            "scheme {} is not text",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("text IRI has no host".into()))?
        .to_string();
    let port = parsed.port().unwrap_or(DEFAULT_TLS_PORT);
    let mut stream = tls::connect(&host, port).await?;
    client::exchange_with_limits(iri, &mut stream, limits).await
}

#[cfg(feature = "tls")]
mod tls {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use super::ClientError;

    pub(crate) async fn connect(
        host: &str,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ClientError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ClientError::Connect(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_no_client_auth();
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| ClientError::Connect(format!("server name {host}: {e}")))?;
        TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|e| ClientError::Connect(format!("tls handshake: {e}")))
    }

    #[derive(Debug)]
    struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_statuses_parse_and_a_fourth_does_not() {
        assert_eq!(
            parse_header("20 text/plain;charset=utf-8"),
            Some(Header {
                status: Status::Ok,
                meta: "text/plain;charset=utf-8".into()
            })
        );
        assert_eq!(
            parse_header("30 text://textprotocol.org/").unwrap().status,
            Status::Redirect
        );
        assert_eq!(parse_header("40 NOK").unwrap().status, Status::Nok);
        assert_eq!(
            parse_header("51 not found"),
            None,
            "the protocol has three codes"
        );
        assert_eq!(parse_header("garbage"), None);
    }

    #[test]
    fn the_request_is_an_iri_and_a_crlf_and_nothing_else() {
        assert_eq!(
            request_line("text://textprotocol.org/"),
            "text://textprotocol.org/\r\n"
        );
    }

    #[test]
    fn the_specs_own_link_example_parses() {
        let lines = parse_body("=> text://textprotocol.org/license.txt rel=license CC0-1.0\n");
        let Line::Link(link) = &lines[0] else {
            panic!("expected a link");
        };
        assert_eq!(link.url, "text://textprotocol.org/license.txt");
        assert_eq!(
            link.attributes,
            vec![("rel".to_string(), "license".to_string())]
        );
        assert_eq!(link.label.as_deref(), Some("CC0-1.0"));
    }

    #[test]
    fn a_bare_link_has_no_attributes_and_no_label() {
        let Line::Link(link) = &parse_body("=> text://example.org/\n")[0] else {
            panic!();
        };
        assert!(link.attributes.is_empty());
        assert_eq!(link.label, None);
    }

    #[test]
    fn an_equals_inside_a_label_stays_label_text() {
        let Line::Link(link) = &parse_body("=> text://x/ rel=next E = mc squared\n")[0] else {
            panic!();
        };
        assert_eq!(link.attributes.len(), 1);
        assert_eq!(link.label.as_deref(), Some("E = mc squared"));
    }

    #[test]
    fn everything_else_is_verbatim_text() {
        let lines = parse_body("# not a heading\n* not a list\nplain\n");
        assert!(lines.iter().all(|l| matches!(l, Line::Text(_))));
    }

    #[cfg(feature = "client")]
    mod client_tests {
        use super::super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn a_success_reads_its_body_and_a_redirect_does_not() {
            let (mut client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                let n = server.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"text://example.org/\r\n");
                server
                    .write_all(b"20 text/plain;charset=utf-8\r\nhello\n")
                    .await
                    .unwrap();
                server.shutdown().await.unwrap();
            });
            let response = exchange("text://example.org/", &mut client).await.unwrap();
            assert_eq!(response.header.status, Status::Ok);
            assert_eq!(response.body, b"hello\n");

            let (mut client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                let _ = server.read(&mut buf).await.unwrap();
                server
                    .write_all(b"30 text://example.org/moved\r\nignored")
                    .await
                    .unwrap();
                server.shutdown().await.unwrap();
            });
            let response = exchange("text://example.org/", &mut client).await.unwrap();
            assert_eq!(response.header.status, Status::Redirect);
            assert!(response.body.is_empty(), "a redirect carries no body");
        }

        #[tokio::test]
        async fn another_scheme_is_refused() {
            let error = fetch("gemini://example.org/").await.unwrap_err();
            assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
        }
    }
}

#[cfg(all(test, feature = "client"))]
mod limits_tests;
