//! Bounded response framing for exact, unknown-length and partial bodies.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{ClientError, Limits, Response};
use crate::response::{Header, ResponseError, Size};
use crate::status::Major;

pub(super) async fn read_response_inner<S>(
    stream: &mut S,
    limits: Limits,
    requested_range: Option<crate::request::Range>,
) -> Result<Response, ClientError>
where
    S: AsyncRead + Unpin,
{
    let line = read_line(stream, limits.max_header).await?;
    let header = Header::parse(&line)?;

    if header.status.major() != Major::Success {
        return Ok(Response {
            header,
            body: Vec::new(),
        });
    }

    // `success()` is Some here because the class was just checked.
    let declared = match header.success() {
        Some(Ok(success)) => success.size,
        Some(Err(error)) => return Err(error.into()),
        None => Size::Unknown,
    };

    let body = if header.status == crate::Status::PARTIAL {
        // A range response: the declared size describes the file, so the
        // range decides how much to read. Read *up to* that much rather than
        // exactly, because a range running past the end of the file is
        // answered with what exists, which is fewer bytes than were asked for
        // and is not an error.
        match requested_range.and_then(|range| range.len()) {
            Some(length) if length <= limits.max_body => {
                // The range is a frame boundary: probing beyond it would eat
                // the next status line on an interactive connection.
                let mut body = Vec::new();
                stream.take(length).read_to_end(&mut body).await?;
                body
            }
            _ => read_to_end_capped(stream, limits.max_body).await?,
        }
    } else {
        match declared {
            Size::Known(size) => {
                if size > limits.max_body {
                    return Err(ClientError::BodyTooLarge {
                        declared: size,
                        limit: limits.max_body,
                    });
                }
                let length = usize::try_from(size).map_err(|_| ClientError::BodyTooLarge {
                    declared: size,
                    limit: usize::MAX as u64,
                })?;
                let mut body = vec![0u8; length];
                match stream.read_exact(&mut body).await {
                    Ok(_) => body,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        return Err(ClientError::Truncated {
                            declared: size,
                            received: 0,
                        });
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            // The server does not know either, so end of stream is the end of
            // the file. The cap keeps a server that never stops from filling
            // memory.
            Size::Unknown => read_to_end_capped(stream, limits.max_body).await?,
        }
    };

    Ok(Response { header, body })
}

/// Read to end of stream, refusing to buffer more than `cap` bytes.
async fn read_to_end_capped<S>(stream: &mut S, cap: u64) -> Result<Vec<u8>, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // One sentinel byte distinguishes exact-fit EOF from overflow. It is
        // never appended, and a peer cannot force cap+1 body storage.
        let remaining = cap.saturating_sub(body.len() as u64);
        let count = remaining.saturating_add(1).min(chunk.len() as u64) as usize;
        let read = stream.read(&mut chunk[..count]).await?;
        if read == 0 {
            return Ok(body);
        }
        if read as u64 > remaining {
            return Err(ClientError::BodyTooLarge {
                declared: (body.len() as u64).saturating_add(read as u64),
                limit: cap,
            });
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

/// Read one CRLF-terminated line, refusing anything over `max`.
async fn read_line<S>(stream: &mut S, max: usize) -> Result<String, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            if line.is_empty() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= max {
            return Err(ResponseError::TooLong.into());
        }
        line.push(byte[0]);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| ClientError::Response(ResponseError::Malformed))
}
