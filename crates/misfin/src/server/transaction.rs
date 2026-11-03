use super::{Dispatcher, MAX_REQUEST_BYTES, MisfinResponse, ReceiveBudget, unix_now};
use rustls::pki_types::CertificateDer;
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub(super) async fn handle_connection(
    acceptor: TlsAcceptor,
    dispatcher: Arc<Dispatcher>,
    tcp: TcpStream,
    budget: ReceiveBudget,
) -> io::Result<()> {
    let mut tls = budget.step("TLS handshake", acceptor.accept(tcp)).await?;
    let peer_cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned();
    receive(&mut tls, &dispatcher, peer_cert.as_ref(), &budget).await
}

// The same exchange runs over TLS and controlled carriers in deadline tests.
pub(super) async fn receive<S>(
    stream: &mut S,
    dispatcher: &Dispatcher,
    peer_cert: Option<&CertificateDer<'_>>,
    budget: &ReceiveBudget,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = budget.step("request read", read_request(stream)).await?;
    let response = budget.dispatch(|| match request {
        RequestRead::Line(request) => dispatcher.dispatch(&request, peer_cert, unix_now()),
        RequestRead::TooLong => MisfinResponse::new(59, "Request exceeds 2048 bytes."),
        RequestRead::NotUtf8 => MisfinResponse::new(59, "Request is not UTF-8."),
        RequestRead::Incomplete => MisfinResponse::new(59, "Request requires CRLF."),
    })?;
    budget
        .step(
            "response write",
            stream.write_all(response.encode().as_bytes()),
        )
        .await?;
    budget.step("TLS close", stream.shutdown()).await
}

/// The outcome of reading a request line: the request without its CRLF, or a
/// protocol violation the caller should answer with 59.
enum RequestRead {
    Line(String),
    TooLong,
    NotUtf8,
    Incomplete,
}

/// Read the complete request line; the caller times the entire read once.
/// A request that reaches the spec's 2048-byte ceiling without a CRLF is
/// over-long (the ceiling includes the terminator).
async fn read_request<S>(stream: &mut S) -> io::Result<RequestRead>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let count = stream.read(&mut byte).await?;
        if count == 0 {
            return Ok(RequestRead::Incomplete);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            return Ok(RequestRead::TooLong);
        }
    }
    match String::from_utf8(buf) {
        Ok(mut text) => {
            // Only the observed wire terminator is framing. Bare newlines,
            // including trailing message newlines, are valid message content.
            text.truncate(text.len() - 2);
            Ok(RequestRead::Line(text))
        }
        Err(_) => Ok(RequestRead::NotUtf8),
    }
}
