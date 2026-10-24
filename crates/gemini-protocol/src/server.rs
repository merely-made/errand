//! The gemini server: accept TLS, read one URL line, answer with a status
//! header and a body, close.
//!
//! Gemini's server side is small. The whole request is an absolute URL and a
//! CRLF, capped at 1024 bytes, and the whole response is `<code> <meta>\r\n`
//! followed by a body that only a `2x` carries. The connection close *is* the
//! end of the body, so there is no length header and no keep-alive.
//!
//! ## Certificates
//!
//! The caller supplies the server certificate and key. This crate does not
//! generate them: a self-signed certificate is the gemini norm, but minting
//! one is an application's decision (and its lifetime, and its storage), not a
//! protocol library's.
//!
//! **Client certificates are not requested.** A handler may answer `6x` to say
//! one is required, but this server will not ask for or verify one, which
//! matches the client half's documented gap. Until both sides gain it, the
//! `6x` path is a thing you can say and not a thing you can complete.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use url::Url;

use crate::client::{DEFAULT_PORT, Status};

const DEFAULT_MAX_CONNECTIONS: usize = 32;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// One gemini request: the absolute URL the client asked for.
#[derive(Debug, Clone)]
pub struct Request {
    pub url: Url,
    pub peer: SocketAddr,
}

impl Request {
    /// The path, with a leading `/` and percent-decoding left alone (a server
    /// that decodes before routing invites traversal).
    pub fn path(&self) -> &str {
        self.url.path()
    }

    /// The query string, which is how gemini carries user input after a `1x`.
    pub fn query(&self) -> Option<&str> {
        self.url.query()
    }
}

/// What a handler answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The two-digit status code, e.g. `20`, `31`, `51`.
    pub code: u8,
    /// The meta field: the MIME type on success, otherwise the prompt,
    /// redirect target, or reason.
    pub meta: String,
    /// The body. Ignored for anything but a `2x`, because gemini defines no
    /// body for other statuses.
    pub body: Vec<u8>,
}

impl Reply {
    /// `20`, with a MIME type and a body.
    pub fn success(mime: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            code: 20,
            meta: mime.into(),
            body: body.into(),
        }
    }

    /// `20 text/gemini`, the common case.
    pub fn gemtext(body: impl Into<Vec<u8>>) -> Self {
        Self::success("text/gemini", body)
    }

    /// `10`, asking the user for input; `meta` is the prompt.
    pub fn input(prompt: impl Into<String>) -> Self {
        Self::header(10, prompt)
    }

    /// `30`, a temporary redirect to `target`.
    pub fn redirect(target: impl Into<String>) -> Self {
        Self::header(30, target)
    }

    /// `51`, not found.
    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::header(51, reason)
    }

    /// Any status that carries no body.
    pub fn header(code: u8, meta: impl Into<String>) -> Self {
        Self {
            code,
            meta: meta.into(),
            body: Vec::new(),
        }
    }

    /// The status class, or `None` if the code is not one gemini defines.
    pub fn status(&self) -> Option<Status> {
        Status::from_code(self.code)
    }

    /// The wire form of the header line, including its CRLF.
    fn header_line(&self) -> String {
        format!("{} {}\r\n", self.code, self.meta)
    }
}

/// The application seam.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> impl Future<Output = Reply> + Send;
}

impl<F, Fut> Handler for F
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Reply> + Send,
{
    fn handle(&self, request: Request) -> impl Future<Output = Reply> + Send {
        self(request)
    }
}

/// Server limits and timeouts.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Maximum request-line length. The spec caps a gemini URL at 1024 bytes,
    /// and this is that cap, not a policy choice.
    pub max_request_line: usize,
    /// Per-connection IO timeout. Default 30s.
    pub timeout: Duration,
    /// Maximum accepted connection tasks, including TLS handshakes. Default 32.
    /// Must be nonzero. At capacity, accept pauses and pending peers are
    /// subject to OS backlog limits.
    pub max_connections: usize,
    /// One graceful-drain allowance after shutdown is observed. Default 5s.
    /// Zero aborts immediately.
    pub shutdown_grace: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_request_line: 1024,
            timeout: Duration::from_secs(30),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

/// Build a TLS acceptor from a certificate chain and private key, both DER.
///
/// Self-signed is normal for gemini; nothing here checks the certificate's
/// provenance, because the client's trust-on-first-use is what does.
pub fn acceptor(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Accept connections on the caller-bound `listener` and serve them through
/// `handler` until `shutdown` resolves. Invalid lifecycle settings are rejected
/// before accepting a connection or calling the handler.
///
/// At most [`ServerConfig::max_connections`] tasks run at once; when full,
/// accepting pauses and waiting peers remain subject to the operating system's
/// listener backlog. Shutdown closes the listener and gives admitted tasks one
/// fixed [`ServerConfig::shutdown_grace`] window to finish, then aborts and
/// joins the remaining tasks. Signal shutdown and await this future for that
/// joined guarantee. Dropping the future cancels its owned task set but cannot
/// await termination. Cancellation cannot undo synchronous handler side
/// effects already performed.
pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: impl Handler,
    config: ServerConfig,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    validate_lifecycle(config.max_connections, config.shutdown_grace)?;
    let handler = Arc::new(handler);
    let config = Arc::new(config);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    let stopped_at = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break Instant::now(),
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(result) = joined {
                    report_connection_join(result);
                }
            }
            accepted = listener.accept(), if connections.len() < config.max_connections => match accepted {
                Ok((stream, peer)) => {
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();
                    let config = config.clone();
                    connections.spawn(async move {
                        if let Err(error) =
                            handle_connection(stream, peer, acceptor, handler, &config).await
                        {
                            log::debug!("gemini: connection from {peer} failed: {error}");
                        }
                    });
                }
                Err(error) => log::warn!("gemini: accept failed: {error}"),
            },
        }
    };
    let grace_deadline = stopped_at
        .checked_add(config.shutdown_grace)
        .unwrap_or(stopped_at);
    drop(listener);
    finish_connections(&mut connections, grace_deadline).await;
    Ok(())
}

fn validate_lifecycle(max_connections: usize, shutdown_grace: Duration) -> std::io::Result<()> {
    if max_connections == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gemini connection limit",
        ));
    }
    if std::time::Instant::now()
        .checked_add(shutdown_grace)
        .is_none()
        || Instant::now().checked_add(shutdown_grace).is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gemini shutdown grace",
        ));
    }
    Ok(())
}

fn report_connection_join(result: Result<(), JoinError>) {
    if let Err(error) = result {
        if error.is_panic() {
            log::warn!("gemini: connection task panicked: {error}");
        } else {
            log::debug!("gemini: connection task cancelled: {error}");
        }
    }
}

async fn finish_connections(connections: &mut JoinSet<()>, deadline: Instant) {
    if Instant::now() < deadline {
        let drained = tokio::time::timeout_at(deadline, async {
            while let Some(result) = connections.join_next().await {
                report_connection_join(result);
            }
        })
        .await;
        if drained.is_ok() {
            return;
        }
    }
    connections.abort_all();
    while let Some(result) = connections.join_next().await {
        report_connection_join(result);
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    handler: Arc<impl Handler>,
    config: &ServerConfig,
) -> std::io::Result<()> {
    let mut tls = tokio::time::timeout(config.timeout, acceptor.accept(stream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tls handshake"))??;

    // The request is one line, and the spec's 1024-byte cap is what stops a
    // client streaming forever before we have anything to route on.
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let count = tokio::time::timeout(config.timeout, tls.read(&mut byte))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request read"))??;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > config.max_request_line {
            return write_reply(
                &mut tls,
                &Reply::header(59, "request exceeds 1024 bytes"),
            )
            .await;
        }
    }

    let reply = match parse_request(&line) {
        Ok(url) => handler.handle(Request { url, peer }).await,
        // 59 is "bad request", which is the right answer to something that is
        // not a gemini URL at all.
        Err(reason) => Reply::header(59, reason),
    };
    write_reply(&mut tls, &reply).await
}

/// Parse a request line into the absolute URL gemini requires.
pub fn parse_request(line: &[u8]) -> Result<Url, String> {
    let text = std::str::from_utf8(line).map_err(|_| "request is not UTF-8".to_string())?;
    let text = text.trim_end_matches(['\r', '\n']);
    let url = Url::parse(text).map_err(|error| error.to_string())?;

    if url.scheme() != "gemini" {
        return Err(format!("scheme {} is not gemini", url.scheme()));
    }
    if url.host_str().is_none() {
        return Err("request has no host".to_string());
    }
    if url.fragment().is_some() {
        // Fragments are a client-side concept and must never reach a server.
        return Err("request carries a fragment".to_string());
    }
    Ok(url)
}

async fn write_reply<S>(stream: &mut S, reply: &Reply) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write_all(reply.header_line().as_bytes()).await?;
    // Only a success carries a body; for anything else meta is the payload.
    if reply.status() == Some(Status::Success) {
        stream.write_all(&reply.body).await?;
    }
    stream.shutdown().await
}

/// Gemini's well-known port, re-exported so a server can bind without
/// reaching into the client module.
pub const PORT: u16 = DEFAULT_PORT;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_gemini_url_parses() {
        let url = parse_request(b"gemini://example.org/path?q\r\n").unwrap();
        assert_eq!(url.host_str(), Some("example.org"));
        assert_eq!(url.path(), "/path");
        assert_eq!(url.query(), Some("q"));
    }

    #[test]
    fn a_relative_request_is_refused() {
        // Gemini requires an absolute URL, unlike gopher's bare selector.
        assert!(parse_request(b"/path\r\n").is_err());
    }

    #[test]
    fn another_scheme_is_refused() {
        assert!(parse_request(b"https://example.org/\r\n").is_err());
        assert!(parse_request(b"spartan://example.org/\r\n").is_err());
    }

    #[test]
    fn a_fragment_never_belongs_on_the_wire() {
        assert!(parse_request(b"gemini://example.org/p#frag\r\n").is_err());
    }

    #[test]
    fn invalid_utf8_is_refused_rather_than_lossily_accepted() {
        assert!(parse_request(&[0xFF, 0xFE, b'\r', b'\n']).is_err());
    }

    #[test]
    fn reply_constructors_carry_the_right_codes() {
        assert_eq!(Reply::gemtext("hi").code, 20);
        assert_eq!(Reply::gemtext("hi").meta, "text/gemini");
        assert_eq!(Reply::input("name?").code, 10);
        assert_eq!(Reply::redirect("gemini://x/").code, 30);
        assert_eq!(Reply::not_found("gone").code, 51);
    }

    #[test]
    fn the_header_line_is_the_spec_shape() {
        assert_eq!(
            Reply::gemtext("body").header_line(),
            "20 text/gemini\r\n"
        );
        assert_eq!(
            Reply::not_found("no such page").header_line(),
            "51 no such page\r\n"
        );
    }

    #[test]
    fn what_the_server_writes_the_client_parses_back() {
        // The receipt that both halves of the crate agree on the wire.
        let reply = Reply::gemtext("# Hello\n");
        let mut raw = reply.header_line().into_bytes();
        raw.extend_from_slice(&reply.body);

        let parsed = crate::client::parse_response(&raw).unwrap();
        assert_eq!(parsed.status, Status::Success);
        assert_eq!(parsed.code, 20);
        assert_eq!(parsed.mime(), Some("text/gemini"));
        assert_eq!(parsed.body, b"# Hello\n");
    }

    #[test]
    fn a_non_success_round_trips_without_a_body() {
        let reply = Reply::redirect("gemini://example.org/moved");
        let parsed = crate::client::parse_response(reply.header_line().as_bytes()).unwrap();
        assert_eq!(parsed.status, Status::Redirect);
        assert_eq!(parsed.meta, "gemini://example.org/moved");
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn an_undefined_code_has_no_status_class() {
        assert_eq!(Reply::header(90, "?").status(), None);
    }
}

#[cfg(test)]
#[path = "server_lifecycle_tests.rs"]
mod server_lifecycle_tests;
