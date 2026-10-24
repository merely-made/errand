//! Serving Scorpion.
//!
//! A server answers requests from a [`Source`]: something that can turn a URL
//! and a subprotocol into a [`Reply`]. The trait is deliberately narrow and
//! says nothing about files, so a source can be a directory, a database, a
//! generated site, or a test fixture.
//!
//! [`serve_connection`] handles one already-accepted stream, which keeps this
//! module usable behind TLS without knowing anything about it: hand it the
//! plaintext side of a completed handshake and it neither knows nor cares.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::MAX_REQUEST_LINE;
use crate::document::Block;
use crate::request::{Parameter, Range, Request, Subprotocol};
use crate::response::{Header, Size};
use crate::status::Status;

/// What a source hands back for a request.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A file. `media_type` is a MIME or ULFI type.
    Content {
        /// The bytes.
        body: Vec<u8>,
        /// The declared type.
        media_type: String,
        /// An optional opaque version, for conflict detection on upload.
        version: Option<String>,
    },
    /// Part of a file, in answer to a range request. `total` is the size of
    /// the **whole** file, which is what a `21` line must report.
    Partial {
        /// The bytes of the requested range.
        body: Vec<u8>,
        /// The size of the entire file.
        total: u64,
        /// The declared type.
        media_type: String,
    },
    /// A redirect.
    Redirect {
        /// Where to.
        url: String,
        /// Whether a client may remember it.
        permanent: bool,
    },
    /// Ask the user for input, then retry with it as the query string.
    Input(String),
    /// Any other status, with its message.
    Status(Status, String),
}

impl Reply {
    /// A document, encoded and typed as Scorpion's own format.
    pub fn document(blocks: &[Block]) -> Result<Self, crate::document::DocumentError> {
        Ok(Self::Content {
            body: crate::document::encode(blocks)?,
            media_type: "application/x-scorpion".to_string(),
            version: None,
        })
    }

    /// Plain UTF-8 text.
    pub fn text(body: impl Into<String>) -> Self {
        Self::Content {
            body: body.into().into_bytes(),
            media_type: "text/plain;charset=utf-8".to_string(),
            version: None,
        }
    }

    /// A file was not found.
    pub fn not_found() -> Self {
        Self::Status(Status::NOT_FOUND, "not found".to_string())
    }

    /// The status line and body this reply becomes.
    fn render(&self) -> (Header, &[u8]) {
        match self {
            Self::Content {
                body,
                media_type,
                version,
            } => {
                let mut parameters = vec![Size::Known(body.len() as u64).to_string(), media_type.clone()];
                if let Some(version) = version {
                    parameters.push(version.clone());
                }
                (
                    Header {
                        status: Status::OK,
                        parameters,
                    },
                    body,
                )
            },
            Self::Partial {
                body,
                total,
                media_type,
            } => (
                Header {
                    status: Status::PARTIAL,
                    // The whole file's size, not the range's: the spec is
                    // explicit, and a client uses it to know the file's extent.
                    parameters: vec![total.to_string(), media_type.clone()],
                },
                body,
            ),
            Self::Redirect { url, permanent } => (
                Header {
                    status: if *permanent {
                        Status::PERMANENT_REDIRECT
                    } else {
                        Status::TEMPORARY_REDIRECT
                    },
                    parameters: vec![url.clone()],
                },
                &[],
            ),
            Self::Input(prompt) => (
                Header {
                    status: Status::INPUT,
                    parameters: vec![prompt.clone()],
                },
                &[],
            ),
            Self::Status(status, message) => (
                Header {
                    status: *status,
                    parameters: if message.is_empty() {
                        Vec::new()
                    } else {
                        vec![message.clone()]
                    },
                },
                &[],
            ),
        }
    }
}

/// Where a server's answers come from.
///
/// Only [`Source::receive`] is required, matching the specification: `R` is
/// the only mandatory subprotocol. The rest default to refusing in the way the
/// specification prescribes, so a minimal source is correct rather than merely
/// incomplete.
pub trait Source: Send + Sync {
    /// Answer an `R` request, optionally for one byte range.
    fn receive(
        &self,
        url: &str,
        range: Option<Range>,
    ) -> impl Future<Output = Reply> + Send;

    /// Answer an `M` request: information *about* the file.
    ///
    /// Defaults to `59 bad request`, which is what the specification names for
    /// a subprotocol feature a server has not implemented.
    fn meta(&self, _url: &str, _desired_type: Option<&str>) -> impl Future<Output = Reply> + Send {
        async { Reply::Status(Status::BAD_REQUEST, "meta is not implemented".into()) }
    }

    /// Answer an `S` request. Returning a `7x` means "ready to receive"; this
    /// crate does not yet drive the upload phase that follows, so the default
    /// refuses rather than half-implementing it.
    fn send(&self, _url: &str, _parameter: &Parameter) -> impl Future<Output = Reply> + Send {
        async { Reply::Status(Status::BAD_REQUEST, "send is not implemented".into()) }
    }

    /// Answer an `I` request. The default refuses; interactive mode is
    /// optional and needs the caller to own the stream afterwards.
    fn interactive(&self, _url: &str, _capabilities: &str) -> impl Future<Output = Reply> + Send {
        async { Reply::Status(Status::BAD_REQUEST, "interactive is not implemented".into()) }
    }
}

/// Serve one already-accepted connection: read a request, write a reply.
///
/// Returns the request that was served, so a caller can log it.
pub async fn serve_connection<S, Src>(
    stream: &mut S,
    source: &Src,
) -> Result<Option<Request>, io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Src: Source,
{
    let line = read_request_line(stream, MAX_REQUEST_LINE).await?;

    let request = match Request::parse(&line) {
        Ok(request) => request,
        Err(error) => {
            // A malformed request still gets a well-formed answer: 59 is the
            // code the specification names for a request the server cannot
            // make sense of, and closing the connection instead would leave
            // the client unable to tell a bad request from a dead server.
            write_reply(
                stream,
                &Reply::Status(Status::BAD_REQUEST, error.to_string()),
            )
            .await?;
            return Ok(None);
        },
    };

    let reply = match (&request.subprotocol, &request.parameter) {
        (Subprotocol::Receive, Parameter::Range(range)) => {
            source.receive(&request.url, Some(*range)).await
        },
        (Subprotocol::Receive, _) => source.receive(&request.url, None).await,
        (Subprotocol::Meta, Parameter::DesiredType(kind)) => {
            source.meta(&request.url, Some(kind)).await
        },
        (Subprotocol::Meta, _) => source.meta(&request.url, None).await,
        (Subprotocol::Send, parameter) => source.send(&request.url, parameter).await,
        (Subprotocol::Interactive, Parameter::Capabilities(codes)) => {
            source.interactive(&request.url, codes).await
        },
        (Subprotocol::Interactive, _) => source.interactive(&request.url, "").await,
    };

    write_reply(stream, &reply).await?;
    Ok(Some(request))
}

/// Serve one exchange until it completes or the caller's shutdown future wins.
///
/// Shutdown is checked before starting or polling the exchange. If it wins
/// after I/O or source work has begun, that work is cancelled and this returns
/// [`io::ErrorKind::Interrupted`]. The caller owns the carrier and must retire
/// it after an interrupted exchange, since a request or reply may be partial.
/// Already emitted bytes and source effects cannot be undone. The stream is
/// never closed or shut down here, including when this future is dropped.
/// All work stays inline; synchronous source/carrier work is cooperative.
/// Server deadlines remain caller-owned: this companion creates no timer,
/// task, or grace period. Successful exchanges return the served request and
/// leave later stream phases to the caller, as [`serve_connection`] does.
pub async fn serve_connection_until_shutdown<S, Src, Shutdown>(
    stream: &mut S,
    source: &Src,
    shutdown: Shutdown,
) -> Result<Option<Request>, io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Src: Source,
    Shutdown: Future<Output = ()>,
{
    tokio::select! {
        biased;
        _ = shutdown => Err(io::Error::new(io::ErrorKind::Interrupted, "Scorpion exchange interrupted")),
        result = serve_connection(stream, source) => result,
    }
}

/// Write one reply's status line and body.
pub async fn write_reply<S>(stream: &mut S, reply: &Reply) -> Result<(), io::Error>
where
    S: AsyncWrite + Unpin,
{
    let (header, body) = reply.render();
    stream.write_all(&header.to_wire()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await
}

/// Read one CRLF-terminated request line, refusing anything over `max`.
async fn read_request_line<S>(stream: &mut S, max: usize) -> Result<String, io::Error>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            if line.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= max {
            return Err(io::Error::other("request line exceeds the permitted length"));
        }
        line.push(byte[0]);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| io::Error::other("request line is not valid UTF-8"))
}

// These tests drive the server with this crate's own client, so they need
// both features. Without the second `cfg` a bare `--features server` build
// fails to compile its tests, which is the shape of bug that only ever shows
// up in a consumer's build.
#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::client::{Limits, exchange};
    use tokio::io::duplex;

    struct Fixture;

    impl Source for Fixture {
        async fn receive(&self, url: &str, range: Option<Range>) -> Reply {
            if url.ends_with("/missing") {
                return Reply::not_found();
            }
            let body = b"0123456789".to_vec();
            let Some(range) = range else {
                return Reply::Content {
                    body,
                    media_type: "text/plain".into(),
                    version: None,
                };
            };
            let end = range.end.map_or(body.len(), |e| e as usize).min(body.len());
            let start = (range.start as usize).min(end);
            Reply::Partial {
                body: body[start..end].to_vec(),
                total: body.len() as u64,
                media_type: "text/plain".into(),
            }
        }
    }

    async fn ask(request: Request) -> crate::client::Response {
        let (mut client_side, mut server_side) = duplex(64 * 1024);
        tokio::spawn(async move {
            serve_connection(&mut server_side, &Fixture).await.unwrap();
            drop(server_side);
        });
        exchange(&mut client_side, &request, Limits::default())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_plain_receive_is_served() {
        let response = ask(Request::receive("scorpion://example.com/file")).await;
        assert_eq!(response.header.status, Status::OK);
        assert_eq!(response.text(), Some("0123456789"));
    }

    #[tokio::test]
    async fn a_range_reply_reports_the_whole_file_size() {
        // End-to-end proof of the trap: the body is the six requested bytes,
        // but the declared size is the file's ten.
        let response = ask(Request::receive_range(
            "scorpion://example.com/file",
            Range::new(3, 9),
        ))
        .await;
        assert_eq!(response.header.status, Status::PARTIAL);
        assert_eq!(response.text(), Some("345678"), "end is exclusive");
        assert_eq!(
            response.header.success().unwrap().unwrap().size,
            Size::Known(10),
            "a 21 declares the entire file, not the range"
        );
    }

    #[tokio::test]
    async fn an_unimplemented_subprotocol_refuses_in_the_prescribed_way() {
        // The default trait bodies matter: a source that implements only the
        // mandatory R must still answer S and I correctly rather than hanging
        // or closing the connection.
        for request in [
            Request::send("scorpion://example.com/file", None),
            Request::interactive("scorpion://example.com/shell", None),
            Request::meta("scorpion://example.com/file"),
        ] {
            let response = ask(request.clone()).await;
            assert_eq!(
                response.header.status,
                Status::BAD_REQUEST,
                "{} should refuse cleanly",
                request.subprotocol
            );
            assert!(response.body.is_empty());
        }
    }

    #[tokio::test]
    async fn a_malformed_request_still_gets_a_well_formed_answer() {
        let (mut client_side, mut server_side) = duplex(4096);
        tokio::spawn(async move {
            let served = serve_connection(&mut server_side, &Fixture).await.unwrap();
            assert!(served.is_none(), "nothing valid was served");
            drop(server_side);
        });
        // No scheme, which the spec makes mandatory.
        client_side.write_all(b"R /relative/path\r\n").await.unwrap();
        client_side.flush().await.unwrap();

        let response = crate::client::read_response(&mut client_side, Limits::default(), None)
            .await
            .unwrap();
        assert_eq!(response.header.status, Status::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_source_can_answer_with_a_scorpion_document() {
        use crate::document::{BlockType, Encoding};
        let blocks = vec![
            Block {
                block_type: BlockType::Heading(1),
                encoding: Encoding::Pc,
                attribute: b"top".to_vec(),
                body: b"Title".to_vec(),
            },
            Block::new(BlockType::Paragraph, Encoding::Pc, b"Body text.".to_vec()),
        ];
        let reply = Reply::document(&blocks).unwrap();
        let (header, body) = reply.render();
        assert_eq!(header.status, Status::OK);
        assert_eq!(crate::document::parse(body).unwrap(), blocks);
    }
}

#[cfg(test)]
#[path = "server_shutdown_tests.rs"]
mod server_shutdown_tests;
