//! The gopher server: read one selector line, answer with bytes, close.
//!
//! RFC 1436 gives the server no status channel at all, so a server that
//! dislikes a request answers with an error *item* inside an ordinary menu
//! rather than with a code. That is why [`Handler`] returns plain bytes.
//!
//! The request line carries up to three tab-separated fields, and reading all
//! three is what lets one server answer both generations:
//!
//! ```text
//! selector                       an ordinary RFC 1436 request
//! selector <TAB> query           a type-7 search
//! selector <TAB> query <TAB> +   a Gopher+ request (the query may be empty)
//! ```
//!
//! When the third field is present the reply is framed with a Gopher+ header
//! carrying the body's length, which this server writes for the handler. A
//! handler therefore never has to know which generation asked.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;

use crate::plus::PlusRequest;

/// One gopher request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The selector, exactly as sent. Note this does **not** carry the item
    /// type: the type character lives in the URL a client resolved, not on the
    /// wire, so a server routes on the selector alone.
    pub selector: String,
    /// The search terms of a type-7 request, if any.
    pub search: Option<String>,
    /// The Gopher+ form asked for, if this was a Gopher+ request.
    pub plus: Option<PlusRequest>,
    pub peer: SocketAddr,
}

/// The application seam: turn a [`Request`] into response bytes.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> impl Future<Output = Vec<u8>> + Send;
}

impl<F, Fut> Handler for F
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Vec<u8>> + Send,
{
    fn handle(&self, request: Request) -> impl Future<Output = Vec<u8>> + Send {
        self(request)
    }
}

/// Server limits and timeouts.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Maximum request-line length. RFC 1436 does not cap it, so this is the
    /// server protecting itself. Default 2048.
    pub max_request_line: usize,
    /// Per-connection IO timeout. Default 30s.
    pub timeout: Duration,
    /// Maximum number of accepted connection tasks. Default 32. Must be
    /// nonzero. At capacity, accept pauses and pending peers are subject to OS
    /// backlog limits.
    pub max_connections: usize,
    /// One graceful-drain allowance after shutdown is observed. Default 5s.
    /// Zero aborts immediately.
    pub shutdown_grace: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_request_line: 2048,
            timeout: Duration::from_secs(30),
            max_connections: 32,
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Accept connections on `listener` and serve them through `handler` until
/// `shutdown` resolves. At most [`ServerConfig::max_connections`] tasks are
/// admitted; at capacity the listener stops accepting and the OS backlog
/// applies. When shutdown is observed, the listener closes and admitted work
/// drains for one fixed grace period before remaining tasks are aborted and
/// joined. Signal shutdown and await this future for that joined guarantee.
/// Dropping this future aborts its owned tasks but cannot await their joins.
/// Cancellation does not roll back synchronous side effects already performed
/// by a handler.
pub async fn serve(
    listener: TcpListener,
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
                    let handler = handler.clone();
                    let config = config.clone();
                    connections.spawn(async move {
                        if let Err(error) = handle_connection(stream, peer, handler, &config).await {
                            log::debug!("gopher: connection from {peer} failed: {error}");
                        }
                    });
                }
                Err(error) => log::warn!("gopher: accept failed: {error}"),
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

#[cfg(test)]
#[path = "server_lifecycle_tests.rs"]
mod lifecycle_tests;

fn validate_lifecycle(max_connections: usize, shutdown_grace: Duration) -> std::io::Result<()> {
    if max_connections == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gopher connection limit",
        ));
    }
    if std::time::Instant::now()
        .checked_add(shutdown_grace)
        .is_none()
        || Instant::now().checked_add(shutdown_grace).is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gopher shutdown grace",
        ));
    }
    Ok(())
}

fn report_connection_join(result: Result<(), JoinError>) {
    if let Err(error) = result {
        if error.is_panic() {
            log::warn!("gopher: connection task panicked: {error}");
        } else {
            log::debug!("gopher: connection task cancelled: {error}");
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
    mut stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<impl Handler>,
    config: &ServerConfig,
) -> std::io::Result<()> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let count = tokio::time::timeout(config.timeout, stream.read(&mut byte))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "selector read"))??;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() >= config.max_request_line {
            // No error channel exists in RFC 1436, so closing is the only
            // honest answer to an over-long selector.
            return stream.shutdown().await;
        }
    }

    let (selector, search, plus) = parse_request(&line);
    let is_plus = plus.is_some();
    let request = Request {
        selector,
        search,
        plus,
        peer,
    };
    let body = handler.handle(request).await;

    // A Gopher+ request is answered with a Gopher+ header. The handler does
    // not write it, because the length is the server's to count.
    if is_plus {
        stream
            .write_all(format!("+{}\r\n", body.len()).as_bytes())
            .await?;
    }
    stream.write_all(&body).await?;
    stream.shutdown().await
}

/// Split a request line into selector, search terms, and Gopher+ form.
///
/// The trailing CR is stripped; the fields are otherwise sent verbatim.
pub fn parse_request(line: &[u8]) -> (String, Option<String>, Option<PlusRequest>) {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end_matches(['\r', '\n']);

    let mut fields = text.split('\t');
    let selector = fields.next().unwrap_or("").to_string();
    let search = fields.next().and_then(|s| (!s.is_empty()).then(|| s.to_string()));
    let plus = fields.next().and_then(PlusRequest::from_token);
    (selector, search, plus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_selector_is_neither_a_search_nor_gopher_plus() {
        let (selector, search, plus) = parse_request(b"/about.txt\r\n");
        assert_eq!(selector, "/about.txt");
        assert_eq!(search, None);
        assert_eq!(plus, None);
    }

    #[test]
    fn a_type_seven_search_carries_its_terms() {
        let (selector, search, plus) = parse_request(b"/search\trust lang\r\n");
        assert_eq!(selector, "/search");
        assert_eq!(search.as_deref(), Some("rust lang"));
        assert_eq!(plus, None);
    }

    #[test]
    fn the_third_field_is_read_as_a_gopher_plus_form() {
        // The spec's own shape: selector, empty search, then the token.
        let (selector, search, plus) = parse_request(b"/arc\t\t+\r\n");
        assert_eq!(selector, "/arc");
        assert_eq!(search, None, "an empty search field is not a search");
        assert_eq!(plus, Some(PlusRequest::Item(None)));

        assert_eq!(
            parse_request(b"/arc\t\t!\r\n").2,
            Some(PlusRequest::Attributes)
        );
        assert_eq!(
            parse_request(b"/dir\t\t$\r\n").2,
            Some(PlusRequest::DirectoryAttributes)
        );
        assert_eq!(
            parse_request(b"/arc\t\t+text/plain\r\n").2,
            Some(PlusRequest::Item(Some("text/plain".into())))
        );
    }

    #[test]
    fn a_search_and_a_gopher_plus_form_can_arrive_together() {
        let (selector, search, plus) = parse_request(b"/find\tterms\t!\r\n");
        assert_eq!(selector, "/find");
        assert_eq!(search.as_deref(), Some("terms"));
        assert_eq!(plus, Some(PlusRequest::Attributes));
    }

    #[test]
    fn what_the_client_writes_the_server_reads_back() {
        // The client builds `{selector}\t{search}\t{token}`; this is the
        // receipt that both halves of the crate agree on the wire.
        for form in [
            PlusRequest::Item(None),
            PlusRequest::Item(Some("text/plain".into())),
            PlusRequest::Attributes,
            PlusRequest::DirectoryAttributes,
        ] {
            let line = format!("/sel\t\t{}\r\n", form.token());
            let (selector, _, parsed) = parse_request(line.as_bytes());
            assert_eq!(selector, "/sel");
            assert_eq!(parsed, Some(form));
        }
    }

    #[test]
    fn an_empty_selector_is_the_root_menu() {
        assert_eq!(parse_request(b"\r\n").0, "");
        assert_eq!(parse_request(b"").0, "");
    }

    #[test]
    fn an_unrecognised_third_field_is_not_a_gopher_plus_request() {
        assert_eq!(parse_request(b"/x\t\tnonsense\r\n").2, None);
    }

    #[test]
    fn a_bare_lf_is_accepted_as_well_as_crlf() {
        assert_eq!(parse_request(b"/about.txt\n").0, "/about.txt");
    }
}
