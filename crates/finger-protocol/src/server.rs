//! The finger server: read one query line, answer with free-form text, close.
//!
//! RFC 1288 gives the server almost no structure to work with. There is no
//! status code, no MIME type and no framing beyond the CRLF that ends the
//! request, so "no such user" is whatever text the handler chooses to write.
//!
//! The one piece of grammar is the `/W` switch, which asks for a longer
//! answer. A server may honour it or ignore it; this one parses it and hands
//! it to the handler to decide.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;

use crate::Query;

/// One finger request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// What was asked for. `user` is `None` for a listing request.
    pub query: Query,
    pub peer: SocketAddr,
}

/// The application seam: turn a [`Request`] into response bytes.
///
/// Bytes rather than a `String` because RFC 1288 fixes no encoding, and a
/// server that has to re-encode someone's `.plan` to satisfy a type is a
/// server that will mangle it.
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
    /// Maximum query-line length. RFC 1288 does not cap it, so this is the
    /// server protecting itself. Default 512.
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
            max_request_line: 512,
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
                            log::debug!("finger: connection from {peer} failed: {error}");
                        }
                    });
                }
                Err(error) => log::warn!("finger: accept failed: {error}"),
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
            "invalid finger connection limit",
        ));
    }
    if std::time::Instant::now()
        .checked_add(shutdown_grace)
        .is_none()
        || Instant::now().checked_add(shutdown_grace).is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid finger shutdown grace",
        ));
    }
    Ok(())
}

fn report_connection_join(result: Result<(), JoinError>) {
    if let Err(error) = result {
        if error.is_panic() {
            log::warn!("finger: connection task panicked: {error}");
        } else {
            log::debug!("finger: connection task cancelled: {error}");
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
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let count = tokio::time::timeout(config.timeout, stream.read(&mut byte))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "query read"))??;
        // A bare EOF is a legitimate empty query: some clients connect, send
        // nothing, and expect the host listing.
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() >= config.max_request_line {
            // No error channel exists, so the only honest response is to close.
            return stream.shutdown().await;
        }
    }

    let request = Request {
        query: parse_query(&line),
        peer,
    };
    let body = handler.handle(request).await;
    stream.write_all(&body).await?;
    // Finger has no length header; the close is what ends the response.
    stream.shutdown().await
}

/// Parse a finger query line, per RFC 1288's `{W}{S}{U}{C}` grammar.
pub fn parse_query(line: &[u8]) -> Query {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end_matches(['\r', '\n']);

    let (verbose, rest) = match text.strip_prefix("/W") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, text),
    };
    let user = rest.trim();
    Query {
        user: (!user.is_empty()).then(|| user.to_string()),
        verbose,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_username_is_a_plain_query() {
        let q = parse_query(b"alice\r\n");
        assert_eq!(q.user.as_deref(), Some("alice"));
        assert!(!q.verbose);
    }

    #[test]
    fn an_empty_line_is_a_listing_request() {
        assert_eq!(parse_query(b"\r\n").user, None);
        assert_eq!(parse_query(b"").user, None);
    }

    #[test]
    fn the_verbose_switch_is_recognised_with_and_without_a_user() {
        let q = parse_query(b"/W alice\r\n");
        assert_eq!(q.user.as_deref(), Some("alice"));
        assert!(q.verbose);

        let q = parse_query(b"/W\r\n");
        assert_eq!(q.user, None);
        assert!(q.verbose);
    }

    #[test]
    fn the_wire_form_and_the_parser_agree() {
        // What the client writes, the server must read back identically.
        for query in [
            Query::user("alice"),
            Query::user("bob").verbose(),
            Query::default(),
            Query::default().verbose(),
        ] {
            assert_eq!(parse_query(query.wire().as_bytes()), query);
        }
    }

    #[test]
    fn a_bare_lf_is_accepted_as_well_as_crlf() {
        assert_eq!(parse_query(b"alice\n").user.as_deref(), Some("alice"));
    }

    #[test]
    fn surrounding_whitespace_does_not_become_part_of_the_name() {
        assert_eq!(parse_query(b"  alice  \r\n").user.as_deref(), Some("alice"));
    }
}
