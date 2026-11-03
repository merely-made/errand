//! The FSP client: UDP, with FSP's own reliability on top.
//!
//! FSP carries its own sequencing and retransmission because UDP gives it
//! none. Two rules drive this client:
//!
//! - the client **echoes the server's last key** in every request, and
//! - the client **chooses the sequence** and the server echoes it back, which
//!   is how a lost or stale reply is detected.
//!
//! A reply whose sequence does not match is discarded and the read continues,
//! rather than being handed up as an answer to a question nobody asked.
//!
//! ```no_run
//! # async fn run() -> Result<(), fsp_protocol::ClientError> {
//! let mut session = fsp_protocol::Session::connect("fsp.example", None).await?;
//!
//! for entry in session.list("/pub").await? {
//!     println!("{:?} {} ({} bytes)", entry.kind, entry.name, entry.size);
//! }
//! let bytes = session.get_file("/pub/readme.txt").await?;
//! session.bye().await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use tokio::net::UdpSocket;

use crate::wire::{
    Command, DecodeError, DirEntry, HEADER_LEN, MAX_PAYLOAD, parse_directory_bounded,
};
#[cfg(test)]
use crate::wire::{Direction, Header, Packet, checksum, decode, encode};

mod exchange;

/// The specification's minimum wait before a resend.
pub const RESEND_AFTER: Duration = Duration::from_secs(1);

/// Caller-owned byte and entry budgets. `Session::attempts` and
/// `Session::timeout` retain their per-reply retry semantics. `MAX_PAYLOAD` is the client's block
/// completion threshold, not a hard reply-data ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Complete outgoing wire packet, including its 12-byte header.
    pub max_request_bytes: usize,
    /// Complete incoming UDP datagram, including header, data and extra area.
    pub max_datagram_bytes: usize,
    pub max_data_bytes: usize,
    pub max_extra_bytes: usize,
    pub max_file_bytes: usize,
    /// All directory reply data, including padding and end markers.
    pub max_directory_bytes: usize,
    pub max_directory_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: HEADER_LEN + MAX_PAYLOAD,
            max_datagram_bytes: HEADER_LEN + MAX_PAYLOAD * 2,
            max_data_bytes: MAX_PAYLOAD * 2,
            max_extra_bytes: MAX_PAYLOAD * 2,
            max_file_bytes: 64 * 1024 * 1024,
            max_directory_bytes: 8 * 1024 * 1024,
            max_directory_entries: 65_536,
        }
    }
}

/// Connection and operation policy. Every public operation receives a fresh
/// allowance; one file/list allowance spans every block and retry. This is not
/// an idle-session lifetime cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub limits: Limits,
    pub operation_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            operation_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    Connect(String),
    Io(String),
    /// The reply did not decode.
    Protocol(String),
    /// The server answered `CC_ERR`; the string is its message.
    Refused(String),
    /// No valid reply arrived within the retry budget.
    TimedOut,
    /// The complete operation exhausted its caller-selected allowance.
    OperationTimedOut,
    /// An interrupted request left the server key uncertain; reconnect.
    SessionUnusable,
    /// A configured byte or entry budget was exceeded; no prefix is returned.
    LimitExceeded {
        what: &'static str,
        max: usize,
    },
    /// The next block position cannot be represented by the native u32 offset.
    OffsetOverflow,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::Refused(m) => write!(f, "server refused: {m}"),
            Self::TimedOut => write!(f, "no reply within the retry budget"),
            Self::OperationTimedOut => write!(f, "operation timed out"),
            Self::SessionUnusable => {
                write!(f, "session has an interrupted request; reconnect required")
            }
            Self::LimitExceeded { what, max } => write!(f, "{what} exceeds configured limit {max}"),
            Self::OffsetOverflow => write!(f, "FSP block offset exceeds 32 bits"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<DecodeError> for ClientError {
    fn from(error: DecodeError) -> Self {
        Self::Protocol(error.to_string())
    }
}

/// An FSP session: a socket plus the key and sequence bookkeeping.
pub struct Session {
    socket: UdpSocket,
    /// The server's last key, echoed back on every request.
    key: u16,
    sequence: u16,
    limits: Limits,
    operation_timeout: Duration,
    /// Remains set when a request future is cancelled, expires, or fails before
    /// an accepted reply makes the next server key known.
    in_flight: bool,
    /// How many times a request is sent before giving up.
    pub attempts: u32,
    pub timeout: Duration,
}

impl Session {
    /// Open a session to an FSP server.
    pub async fn connect(host: &str, port: Option<u16>) -> Result<Self, ClientError> {
        Self::connect_with_limits(host, port, Limits::default()).await
    }

    /// Open a session with native byte/entry bounds and unchanged retry timing.
    pub async fn connect_with_limits(
        host: &str,
        port: Option<u16>,
        limits: Limits,
    ) -> Result<Self, ClientError> {
        Self::connect_with_options(
            host,
            port,
            Options {
                limits,
                ..Options::default()
            },
        )
        .await
    }

    /// Open with caller-selected operation and size policy. The connect
    /// allowance includes UDP setup and host resolution.
    pub async fn connect_with_options(
        host: &str,
        port: Option<u16>,
        options: Options,
    ) -> Result<Self, ClientError> {
        let deadline = operation_deadline(options.operation_timeout)?;
        let session = tokio::time::timeout_at(deadline, async {
            check_deadline(deadline)?;
            let port = port.unwrap_or(crate::wire::DEFAULT_PORT);
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            check_deadline(deadline)?;
            socket
                .connect((host, port))
                .await
                .map_err(|e| ClientError::Connect(format!("udp {host}:{port}: {e}")))?;
            check_deadline(deadline)?;
            Ok::<Self, ClientError>(Self {
                socket,
                key: 0,
                sequence: 1,
                limits: options.limits,
                operation_timeout: options.operation_timeout,
                in_flight: false,
                attempts: 3,
                timeout: RESEND_AFTER,
            })
        })
        .await
        .map_err(|_| ClientError::OperationTimedOut)??;
        check_deadline(deadline)?;
        Ok(session)
    }

    /// The immutable budget snapshot selected when this session was opened.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Select the allowance for later operations. Zero is a local refusal;
    /// changing policy cannot revive an interrupted session.
    pub fn set_operation_timeout(&mut self, timeout: Duration) -> Result<(), ClientError> {
        self.ensure_usable()?;
        validate_operation_timeout(timeout)?;
        self.operation_timeout = timeout;
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), ClientError> {
        if self.in_flight {
            Err(ClientError::SessionUnusable)
        } else {
            Ok(())
        }
    }

    fn start_operation(&self) -> Result<tokio::time::Instant, ClientError> {
        self.ensure_usable()?;
        operation_deadline(self.operation_timeout)
    }

    fn path_bytes(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        let size = path
            .len()
            .checked_add(1)
            .ok_or(ClientError::LimitExceeded {
                what: "request",
                max: self.limits.max_request_bytes,
            })?;
        self.check_request_size(size)?;
        Ok(nul_terminated(path))
    }

    fn check_request_size(&self, data_bytes: usize) -> Result<u16, ClientError> {
        let length = u16::try_from(data_bytes).map_err(|_| ClientError::LimitExceeded {
            what: "request data",
            max: usize::from(u16::MAX),
        })?;
        let size = HEADER_LEN
            .checked_add(data_bytes)
            .ok_or(ClientError::LimitExceeded {
                what: "request",
                max: self.limits.max_request_bytes,
            })?;
        if size > self.limits.max_request_bytes {
            return Err(ClientError::LimitExceeded {
                what: "request",
                max: self.limits.max_request_bytes,
            });
        }
        Ok(length)
    }

    /// The server version string.
    pub async fn version(&mut self) -> Result<String, ClientError> {
        let deadline = self.start_operation()?;
        let reply = self
            .request_until(Command::Version, &[], 0, deadline)
            .await?;
        let version = trim_nul(&reply.data);
        check_deadline(deadline)?;
        Ok(version)
    }

    /// Fetch one block of a file at `offset`. An empty block is end of file.
    pub async fn get_file_block(
        &mut self,
        path: &str,
        offset: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let deadline = self.start_operation()?;
        let data = self.path_bytes(path)?;
        let reply = self
            .request_until(Command::GetFile, &data, offset, deadline)
            .await?;
        check_deadline(deadline)?;
        Ok(reply.data)
    }

    /// Fetch a whole file, block by block.
    pub async fn get_file(&mut self, path: &str) -> Result<Vec<u8>, ClientError> {
        let deadline = self.start_operation()?;
        let data = self.path_bytes(path)?;
        let mut body = Vec::new();
        let mut offset = 0;
        loop {
            check_deadline(deadline)?;
            let block = self
                .request_until(Command::GetFile, &data, offset, deadline)
                .await?
                .data;
            check_deadline(deadline)?;
            if block.is_empty() {
                return Ok(body);
            }
            if block.len() > self.limits.max_file_bytes.saturating_sub(body.len()) {
                return Err(ClientError::LimitExceeded {
                    what: "file bytes",
                    max: self.limits.max_file_bytes,
                });
            }
            let next = advance_offset(offset, block.len())?;
            let short = block.len() < MAX_PAYLOAD;
            body.extend_from_slice(&block);
            check_deadline(deadline)?;
            if short {
                return Ok(body);
            }
            offset = next;
        }
    }

    /// List a directory. Raw block bytes (including padding/end markers) and
    /// decoded entry count are independently bounded. Native SKIP padding moves
    /// to the next packet; an explicit END marker completes the directory.
    pub async fn list(&mut self, path: &str) -> Result<Vec<DirEntry>, ClientError> {
        let deadline = self.start_operation()?;
        let data = self.path_bytes(path)?;
        let mut entries = Vec::new();
        let mut received = 0usize;
        let mut offset = 0;
        loop {
            check_deadline(deadline)?;
            let reply = self
                .request_until(Command::GetDir, &data, offset, deadline)
                .await?;
            check_deadline(deadline)?;
            if reply.data.is_empty() {
                return Ok(entries);
            }
            if reply.data.len() > self.limits.max_directory_bytes.saturating_sub(received) {
                return Err(ClientError::LimitExceeded {
                    what: "directory bytes",
                    max: self.limits.max_directory_bytes,
                });
            }
            let next = advance_offset(offset, reply.data.len())?;
            let block = parse_directory_bounded(
                &reply.data,
                self.limits
                    .max_directory_entries
                    .saturating_sub(entries.len()),
            )
            .map_err(|_| ClientError::LimitExceeded {
                what: "directory entries",
                max: self.limits.max_directory_entries,
            })?;
            received += reply.data.len();
            entries.extend(block.entries);
            check_deadline(deadline)?;
            if block.finished {
                return Ok(entries);
            }
            offset = next;
        }
    }

    /// End the session politely.
    pub async fn bye(mut self) -> Result<(), ClientError> {
        let deadline = self.start_operation()?;
        self.request_until(Command::Bye, &[], 0, deadline).await?;
        check_deadline(deadline)
    }
}

fn validate_operation_timeout(timeout: Duration) -> Result<(), ClientError> {
    if std::time::Instant::now().checked_add(timeout).is_none() {
        return Err(ClientError::Protocol(
            "operation timeout overflows the clock".into(),
        ));
    }
    Ok(())
}

fn operation_deadline(timeout: Duration) -> Result<tokio::time::Instant, ClientError> {
    validate_operation_timeout(timeout)?;
    if timeout.is_zero() {
        return Err(ClientError::OperationTimedOut);
    }
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ClientError::Protocol("operation timeout overflows the clock".into()))
}

fn check_deadline(deadline: tokio::time::Instant) -> Result<(), ClientError> {
    if tokio::time::Instant::now() >= deadline {
        Err(ClientError::OperationTimedOut)
    } else {
        Ok(())
    }
}

fn advance_offset(offset: u32, bytes: usize) -> Result<u32, ClientError> {
    let bytes = u32::try_from(bytes).map_err(|_| ClientError::OffsetOverflow)?;
    offset.checked_add(bytes).ok_or(ClientError::OffsetOverflow)
}

fn nul_terminated(path: &str) -> Vec<u8> {
    let mut out = path.as_bytes().to_vec();
    out.push(0);
    out
}

fn trim_nul(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.trim_end_matches('\0').to_string()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod limit_tests;

#[cfg(test)]
mod operation_tests;
