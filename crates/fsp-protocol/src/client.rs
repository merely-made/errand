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
    Command, DecodeError, DirEntry, Direction, HEADER_LEN, Header, MAX_PAYLOAD, Packet, checksum,
    decode, encode, parse_directory_bounded,
};

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

    /// Send a command and wait for the reply that echoes our sequence.
    pub async fn request(
        &mut self,
        command: Command,
        data: &[u8],
        file_position: u32,
    ) -> Result<Packet, ClientError> {
        let deadline = self.start_operation()?;
        self.request_until(command, data, file_position, deadline)
            .await
    }

    async fn request_until(
        &mut self,
        command: Command,
        data: &[u8],
        file_position: u32,
        deadline: tokio::time::Instant,
    ) -> Result<Packet, ClientError> {
        self.ensure_usable()?;
        check_deadline(deadline)?;
        let data_length = self.check_request_size(data.len())?;
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;

        let outgoing = Packet {
            header: Header {
                command: command.code(),
                key: self.key,
                sequence,
                data_length,
                file_position,
            },
            data: data.to_vec(),
            extra: Vec::new(),
        };
        let bytes = encode(&outgoing, Direction::ClientToServer);

        for _ in 0..self.attempts {
            check_deadline(deadline)?;
            self.in_flight = true;
            tokio::time::timeout_at(deadline, self.socket.send(&bytes))
                .await
                .map_err(|_| ClientError::OperationTimedOut)?
                .map_err(|e| ClientError::Io(e.to_string()))?;
            check_deadline(deadline)?;

            if let Some(reply) = self.await_reply(sequence, deadline).await? {
                check_deadline(deadline)?;
                // The server's key is echoed on our next request.
                self.key = reply.header.key;
                self.in_flight = false;
                check_deadline(deadline)?;
                if reply.header.command == Command::Err.code() {
                    return Err(ClientError::Refused(trim_nul(&reply.data)));
                }
                return Ok(reply);
            }
        }
        check_deadline(deadline)?;
        Err(ClientError::TimedOut)
    }

    /// Read until a reply with the expected sequence arrives, or the timeout
    /// expires. Mismatched replies are stale and are dropped.
    async fn await_reply(
        &mut self,
        sequence: u16,
        operation: tokio::time::Instant,
    ) -> Result<Option<Packet>, ClientError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.timeout)
            .unwrap_or(operation)
            .min(operation);
        // One sentinel beyond the configured cap detects successful truncating
        // receives. At most 65536 bytes cover every ordinary UDP datagram even
        // when the caller supplies a larger policy value.
        let capacity = self.limits.max_datagram_bytes.min(usize::from(u16::MAX)) + 1;
        let mut buffer = vec![0u8; capacity];

        loop {
            check_deadline(operation)?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let read = match tokio::time::timeout_at(deadline, self.socket.recv(&mut buffer)).await
            {
                Err(_) => {
                    check_deadline(operation)?;
                    return Ok(None);
                }
                Ok(Err(e)) if cfg!(windows) && e.raw_os_error() == Some(10040) => {
                    // WSAEMSGSIZE refuses a datagram larger than the receive
                    // buffer rather than returning its prefix.
                    return Err(ClientError::LimitExceeded {
                        what: "reply datagram",
                        max: self.limits.max_datagram_bytes,
                    });
                }
                Ok(Err(e)) => return Err(ClientError::Io(e.to_string())),
                Ok(Ok(read)) => read,
            };

            check_deadline(operation)?;
            if read > self.limits.max_datagram_bytes {
                return Err(ClientError::LimitExceeded {
                    what: "reply datagram",
                    max: self.limits.max_datagram_bytes,
                });
            }
            let bytes = &buffer[..read];
            // Validate the small fixed header and sequence before allocating
            // decoded data/extra vectors. Corrupt and stale replies retain the
            // existing discard-and-wait behavior under this same reply deadline.
            if bytes.len() < HEADER_LEN || checksum(bytes, Direction::ServerToClient) != bytes[1] {
                continue;
            }
            if u16::from_be_bytes([bytes[4], bytes[5]]) != sequence {
                continue;
            }
            let data_len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
            let available = bytes.len() - HEADER_LEN;
            if data_len > available {
                continue;
            }
            if data_len > self.limits.max_data_bytes {
                return Err(ClientError::LimitExceeded {
                    what: "reply data",
                    max: self.limits.max_data_bytes,
                });
            }
            if available - data_len > self.limits.max_extra_bytes {
                return Err(ClientError::LimitExceeded {
                    what: "reply extra data",
                    max: self.limits.max_extra_bytes,
                });
            }
            let packet = decode(bytes, Direction::ServerToClient)?;
            check_deadline(operation)?;
            return Ok(Some(packet));
        }
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
mod tests {
    use super::*;

    #[test]
    fn a_path_is_nul_terminated() {
        assert_eq!(nul_terminated("/pub"), b"/pub\0");
        assert_eq!(nul_terminated(""), b"\0");
    }

    #[tokio::test]
    async fn a_stale_sequence_is_ignored_and_the_right_reply_accepted() {
        // A fake server that answers the wrong sequence first.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (read, peer) = server.recv_from(&mut buf).await.unwrap();
            let asked = decode(&buf[..read], Direction::ClientToServer).unwrap();

            let stale = Packet {
                header: Header {
                    command: Command::GetFile.code(),
                    key: 0x1111,
                    sequence: asked.header.sequence.wrapping_sub(7),
                    data_length: 5,
                    file_position: 0,
                },
                data: b"stale".to_vec(),
                extra: Vec::new(),
            };
            server
                .send_to(&encode(&stale, Direction::ServerToClient), peer)
                .await
                .unwrap();

            let good = Packet {
                header: Header {
                    command: Command::GetFile.code(),
                    key: 0x2222,
                    sequence: asked.header.sequence,
                    data_length: 5,
                    file_position: 0,
                },
                data: b"right".to_vec(),
                extra: Vec::new(),
            };
            server
                .send_to(&encode(&good, Direction::ServerToClient), peer)
                .await
                .unwrap();
        });

        let mut session = Session::connect("127.0.0.1", Some(addr.port()))
            .await
            .unwrap();
        session.timeout = Duration::from_secs(3);
        let block = session.get_file_block("/x", 0).await.unwrap();

        assert_eq!(block, b"right", "the stale sequence must not be accepted");
        assert_eq!(
            session.key, 0x2222,
            "the server's key is adopted for next time"
        );
    }

    #[tokio::test]
    async fn a_server_error_surfaces_with_its_message() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (read, peer) = server.recv_from(&mut buf).await.unwrap();
            let asked = decode(&buf[..read], Direction::ClientToServer).unwrap();
            let error = Packet {
                header: Header {
                    command: Command::Err.code(),
                    key: 9,
                    sequence: asked.header.sequence,
                    data_length: 13,
                    file_position: 0,
                },
                data: b"no such file\0".to_vec(),
                extra: Vec::new(),
            };
            server
                .send_to(&encode(&error, Direction::ServerToClient), peer)
                .await
                .unwrap();
        });

        let mut session = Session::connect("127.0.0.1", Some(addr.port()))
            .await
            .unwrap();
        session.timeout = Duration::from_secs(3);
        let error = session.get_file_block("/nope", 0).await.unwrap_err();
        assert_eq!(error, ClientError::Refused("no such file".into()));
    }

    #[tokio::test]
    async fn silence_times_out_rather_than_hanging() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        // Never answer. The same request/sequence must be retried exactly twice.
        let task = tokio::spawn(async move {
            let mut buf = [0; 64];
            let mut first = None;
            for _ in 0..2 {
                let (read, _) =
                    tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                if let Some(first) = &first {
                    assert_eq!(&buf[..read], first);
                } else {
                    first = Some(buf[..read].to_vec());
                }
            }
        });

        let mut session = Session::connect("127.0.0.1", Some(addr.port()))
            .await
            .unwrap();
        session.timeout = Duration::from_millis(60);
        session.attempts = 2;
        assert_eq!(
            session.get_file_block("/x", 0).await.unwrap_err(),
            ClientError::TimedOut
        );
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::SessionUnusable
        );
        task.await.unwrap();
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    use crate::wire::{EntryKind, RDTYPE_END, RDTYPE_FILE, RDTYPE_SKIP};

    type Reply = (Command, u32, Vec<u8>, Vec<u8>);

    async fn fixture(
        limits: Limits,
        replies: Vec<Reply>,
    ) -> (Session, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0; 65_536];
            for (index, (command, offset, data, extra)) in replies.into_iter().enumerate() {
                let (read, peer) =
                    tokio::time::timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
                        .await
                        .expect("fixture request deadline")
                        .unwrap();
                let request = decode(&buffer[..read], Direction::ClientToServer).unwrap();
                assert_eq!(request.header.command, command.code());
                assert_eq!(request.header.file_position, offset);
                assert_eq!(
                    request.header.key, index as u16,
                    "server key must be echoed"
                );
                let packet = Packet {
                    header: Header {
                        command: command.code(),
                        key: (index + 1) as u16,
                        sequence: request.header.sequence,
                        data_length: u16::try_from(data.len()).unwrap(),
                        file_position: offset,
                    },
                    data,
                    extra,
                };
                server
                    .send_to(&encode(&packet, Direction::ServerToClient), peer)
                    .await
                    .unwrap();
            }
        });
        let session = Session::connect_with_limits("127.0.0.1", Some(address.port()), limits)
            .await
            .unwrap();
        (session, task)
    }

    fn entry(name: &str) -> Vec<u8> {
        let mut bytes = 123u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.push(RDTYPE_FILE);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.resize(bytes.len().div_ceil(4) * 4, 0);
        bytes
    }

    fn marker(kind: u8) -> Vec<u8> {
        let mut bytes = vec![0; 12];
        bytes[8] = kind;
        bytes
    }

    #[test]
    fn default_budgets_and_offset_arithmetic_are_explicit() {
        let limits = Limits::default();
        assert_eq!(limits.max_request_bytes, HEADER_LEN + MAX_PAYLOAD);
        assert_eq!(limits.max_datagram_bytes, HEADER_LEN + 2 * MAX_PAYLOAD);
        assert_eq!(limits.max_file_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_directory_bytes, 8 * 1024 * 1024);
        assert_eq!(limits.max_directory_entries, 65_536);
        assert_eq!(advance_offset(u32::MAX - 2, 2), Ok(u32::MAX));
        assert_eq!(
            advance_offset(u32::MAX - 2, 3),
            Err(ClientError::OffsetOverflow)
        );
        assert_eq!(
            advance_offset(0, usize::MAX),
            Err(ClientError::OffsetOverflow)
        );
    }

    #[tokio::test]
    async fn file_cap_accepts_full_block_then_eof_and_refuses_one_extra() {
        for extra in [false, true] {
            let replies = vec![
                (Command::GetFile, 0, vec![b'x'; MAX_PAYLOAD], vec![]),
                (
                    Command::GetFile,
                    MAX_PAYLOAD as u32,
                    if extra { vec![b'y'] } else { vec![] },
                    vec![],
                ),
            ];
            let limits = Limits {
                max_file_bytes: MAX_PAYLOAD,
                ..Default::default()
            };
            let (mut session, task) = fixture(limits, replies).await;
            assert_eq!(session.attempts, 3);
            assert_eq!(session.timeout, RESEND_AFTER);
            let result = session.get_file("/x").await;
            if extra {
                assert_eq!(
                    result.unwrap_err(),
                    ClientError::LimitExceeded {
                        what: "file bytes",
                        max: MAX_PAYLOAD
                    }
                );
            } else {
                assert_eq!(result.unwrap(), vec![b'x'; MAX_PAYLOAD]);
            }
            task.await.unwrap();
        }
        for data in [vec![], vec![b'x']] {
            let empty = data.is_empty();
            let (mut session, task) = fixture(
                Limits {
                    max_file_bytes: 0,
                    ..Default::default()
                },
                vec![(Command::GetFile, 0, data, vec![])],
            )
            .await;
            let result = session.get_file("/").await;
            if empty {
                assert_eq!(result.unwrap(), b"");
            } else {
                assert!(matches!(
                    result,
                    Err(ClientError::LimitExceeded {
                        what: "file bytes",
                        ..
                    })
                ));
            }
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn larger_than_minimum_blocks_remain_native_and_caller_bounded() {
        let size = MAX_PAYLOAD * 2;
        let (mut session, task) = fixture(
            Limits {
                max_file_bytes: size,
                ..Default::default()
            },
            vec![
                (Command::GetFile, 0, vec![b'x'; size], vec![]),
                (Command::GetFile, size as u32, vec![], vec![]),
            ],
        )
        .await;
        assert_eq!(session.get_file("/").await.unwrap().len(), size);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn directory_aggregate_bytes_and_entries_are_bounded_across_many_blocks() {
        let count = 32;
        let raw = entry("x");
        for max in [raw.len() * count, raw.len() * count - 1] {
            let mut replies = (0..count)
                .map(|index| {
                    (
                        Command::GetDir,
                        (index * raw.len()) as u32,
                        raw.clone(),
                        vec![],
                    )
                })
                .collect::<Vec<_>>();
            if max == raw.len() * count {
                replies.push((Command::GetDir, (count * raw.len()) as u32, vec![], vec![]));
            }
            let (mut session, task) = fixture(
                Limits {
                    max_directory_bytes: max,
                    max_directory_entries: count,
                    ..Default::default()
                },
                replies,
            )
            .await;
            let result = session.list("/").await;
            if max == raw.len() * count {
                let entries = result.unwrap();
                assert_eq!(entries.len(), count);
                assert_eq!(
                    entries[0].size,
                    u32::MAX,
                    "advertised file sizes remain inert metadata"
                );
                assert_eq!(entries[0].kind, EntryKind::File);
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ClientError::LimitExceeded {
                        what: "directory bytes",
                        max
                    }
                );
            }
            task.await.unwrap();
        }
        let replies = (0..3)
            .map(|index| {
                (
                    Command::GetDir,
                    (index * raw.len()) as u32,
                    raw.clone(),
                    vec![],
                )
            })
            .collect();
        let (mut session, task) = fixture(
            Limits {
                max_directory_entries: 2,
                ..Default::default()
            },
            replies,
        )
        .await;
        assert_eq!(
            session.list("/").await.unwrap_err(),
            ClientError::LimitExceeded {
                what: "directory entries",
                max: 2
            }
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn directory_skip_advances_and_end_stops_even_after_entries() {
        let mut final_block = entry("saved");
        final_block.extend(marker(RDTYPE_END));
        final_block.extend(entry("ignored"));
        let (mut session, task) = fixture(
            Limits::default(),
            vec![
                (Command::GetDir, 0, marker(RDTYPE_SKIP), vec![]),
                (Command::GetDir, 12, final_block, vec![]),
            ],
        )
        .await;
        let entries = session.list("/").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "saved");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn reply_data_and_extra_caps_are_checked_without_flattening_native_packet() {
        for (data, extra, expected) in [
            (4, 4, None),
            (5, 0, Some("reply data")),
            (0, 5, Some("reply extra data")),
        ] {
            let limits = Limits {
                max_data_bytes: 4,
                max_extra_bytes: 4,
                ..Default::default()
            };
            let (mut session, task) = fixture(
                limits,
                vec![(
                    Command::Version,
                    u32::MAX,
                    vec![b'd'; data],
                    vec![b'e'; extra],
                )],
            )
            .await;
            let result = session.request(Command::Version, &[], u32::MAX).await;
            if let Some(what) = expected {
                assert_eq!(
                    result.unwrap_err(),
                    ClientError::LimitExceeded { what, max: 4 }
                );
            } else {
                let packet = result.unwrap();
                assert_eq!(packet.data, b"dddd");
                assert_eq!(packet.extra, b"eeee");
                assert_eq!(packet.header.file_position, u32::MAX);
            }
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_datagram_cannot_be_a_valid_prefix_success() {
        for extra in [0, 1, 32] {
            // Zero extra bytes preserve the checksum of the valid first16 bytes,
            // so truncation to the old receive budget would decode successfully.
            let limits = Limits {
                max_datagram_bytes: HEADER_LEN + 4,
                ..Default::default()
            };
            let (mut session, task) = fixture(
                limits,
                vec![(Command::GetFile, 0, b"data".to_vec(), vec![0; extra])],
            )
            .await;
            let result = session.get_file_block("/x", 0).await;
            if extra == 0 {
                assert_eq!(result.unwrap(), b"data");
            } else {
                assert!(
                    matches!(
                        result,
                        Err(ClientError::LimitExceeded {
                            what: "reply datagram",
                            ..
                        })
                    ),
                    "{result:?}"
                );
            }
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_path_and_u16_data_limits_refuse_before_contact() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut session = Session::connect_with_limits(
            "127.0.0.1",
            Some(address.port()),
            Limits {
                max_request_bytes: HEADER_LEN + 3,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            session.get_file_block("/xx", 0).await.unwrap_err(),
            ClientError::LimitExceeded {
                what: "request",
                max: HEADER_LEN + 3
            }
        );
        assert_eq!(
            session.sequence, 1,
            "local refusal must not consume a sequence"
        );
        let mut buffer = [0; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut buffer))
                .await
                .is_err()
        );
        let mut session = Session::connect_with_limits(
            "127.0.0.1",
            Some(address.port()),
            Limits {
                max_request_bytes: usize::MAX,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            session
                .request(Command::Version, &vec![0; usize::from(u16::MAX) + 1], 0)
                .await
                .unwrap_err(),
            ClientError::LimitExceeded {
                what: "request data",
                max: usize::from(u16::MAX)
            }
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut buffer))
                .await
                .is_err()
        );
        let (mut session, task) = fixture(
            Limits {
                max_request_bytes: HEADER_LEN + 3,
                ..Default::default()
            },
            vec![(Command::GetFile, 0, b"ok".to_vec(), vec![])],
        )
        .await;
        assert_eq!(session.get_file_block("/x", 0).await.unwrap(), b"ok");
        task.await.unwrap();
    }
}

#[cfg(test)]
mod operation_tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    async fn asked(server: &UdpSocket) -> (Packet, std::net::SocketAddr) {
        let mut bytes = [0; 4096];
        let (read, peer) =
            tokio::time::timeout(Duration::from_secs(3), server.recv_from(&mut bytes))
                .await
                .expect("fixture request")
                .unwrap();
        (
            decode(&bytes[..read], Direction::ClientToServer).unwrap(),
            peer,
        )
    }

    async fn answer(
        server: &UdpSocket,
        peer: std::net::SocketAddr,
        request: &Packet,
        command: Command,
        key: u16,
        data: Vec<u8>,
    ) {
        let packet = Packet {
            header: Header {
                command: command.code(),
                key,
                sequence: request.header.sequence,
                data_length: u16::try_from(data.len()).unwrap(),
                file_position: request.header.file_position,
            },
            data,
            extra: vec![],
        };
        server
            .send_to(&encode(&packet, Direction::ServerToClient), peer)
            .await
            .unwrap();
    }

    async fn session(server: &UdpSocket, timeout: Duration, limits: Limits) -> Session {
        Session::connect_with_options(
            "127.0.0.1",
            Some(server.local_addr().unwrap().port()),
            Options {
                limits,
                operation_timeout: timeout,
            },
        )
        .await
        .unwrap()
    }

    #[test]
    fn zero_and_overflow_connect_policy_refuse_without_a_runtime_or_network() {
        for (timeout, expected) in [
            (Duration::ZERO, ClientError::OperationTimedOut),
            (
                Duration::MAX,
                ClientError::Protocol("operation timeout overflows the clock".into()),
            ),
        ] {
            let operation = Session::connect_with_options(
                "must-not-resolve.invalid",
                None,
                Options {
                    operation_timeout: timeout,
                    ..Default::default()
                },
            );
            let mut operation = pin!(operation);
            match operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(Err(error)) => assert_eq!(error, expected),
                _ => panic!("invalid policy must refuse before runtime/timer/connection work"),
            }
        }
        assert_eq!(
            Options::default().operation_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(Options::default().limits, Limits::default());
    }

    #[tokio::test]
    async fn full_file_and_directory_share_one_allowance_across_blocks() {
        for command in [Command::GetFile, Command::GetDir] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut session = session(&server, Duration::from_millis(500), Limits::default()).await;
            let task = tokio::spawn(async move {
                for index in 0..2 {
                    let (request, peer) = asked(&server).await;
                    assert_eq!(request.header.command, command.code());
                    assert_eq!(request.header.key, index);
                    let expected_offset = if command == Command::GetFile {
                        u32::from(index) * MAX_PAYLOAD as u32
                    } else {
                        u32::from(index) * 12
                    };
                    assert_eq!(request.header.file_position, expected_offset);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let data = if command == Command::GetFile {
                        vec![b'x'; MAX_PAYLOAD]
                    } else {
                        let mut entry = vec![0; 12];
                        entry[8] = crate::wire::RDTYPE_FILE;
                        entry[9] = b'x';
                        entry
                    };
                    answer(&server, peer, &request, command, index + 1, data).await;
                }
                let mut bytes = [0; 64];
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), server.recv_from(&mut bytes))
                        .await
                        .is_err(),
                    "expired operation must not send another request"
                );
            });
            let error = if command == Command::GetFile {
                session.get_file("/").await.unwrap_err()
            } else {
                session.list("/").await.unwrap_err()
            };
            assert_eq!(error, ClientError::OperationTimedOut);
            task.await.unwrap(); // the delayed old-sequence reply is now queued
            assert!(session.in_flight);
            let sequence = session.sequence;
            assert_eq!(
                session.version().await.unwrap_err(),
                ClientError::SessionUnusable
            );
            assert_eq!(session.sequence, sequence);
            assert_eq!(
                session.set_operation_timeout(Duration::from_secs(3)),
                Err(ClientError::SessionUnusable)
            );
        }
    }

    #[tokio::test]
    async fn operation_allowance_clips_retries_without_restarting_the_budget() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(&server, Duration::from_millis(350), Limits::default()).await;
        session.timeout = Duration::from_millis(200);
        let task = tokio::spawn(async move {
            let (first, _) = asked(&server).await;
            let (second, _) = asked(&server).await;
            assert_eq!(first, second, "retry keeps the same sequence/key/request");
            let mut bytes = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(250), server.recv_from(&mut bytes))
                    .await
                    .is_err(),
                "a third retry would exceed the whole allowance"
            );
        });
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::OperationTimedOut
        );
        assert_eq!(session.attempts, 3);
        assert_eq!(session.timeout, Duration::from_millis(200));
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::SessionUnusable
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn each_completed_operation_gets_a_fresh_allowance_after_idle_time() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(&server, Duration::from_millis(200), Limits::default()).await;
        let task = tokio::spawn(async move {
            let (first, peer) = asked(&server).await;
            answer(
                &server,
                peer,
                &first,
                Command::Version,
                41,
                b"first".to_vec(),
            )
            .await;
            let (second, peer) = asked(&server).await;
            assert_eq!(second.header.key, 41);
            assert_ne!(first.header.sequence, second.header.sequence);
            // A queued old reply must not satisfy the next successful operation.
            answer(
                &server,
                peer,
                &first,
                Command::Version,
                41,
                b"stale".to_vec(),
            )
            .await;
            answer(
                &server,
                peer,
                &second,
                Command::Version,
                42,
                b"second".to_vec(),
            )
            .await;
        });
        assert_eq!(session.version().await.unwrap(), "first");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(session.version().await.unwrap(), "second");
        assert_eq!(session.key, 42);
        assert!(!session.in_flight);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn caller_cancellation_retires_the_uncertain_key_session() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(&server, Duration::from_secs(2), Limits::default()).await;
        let (seen, received) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (sent, delivered) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (request, peer) = asked(&server).await;
            seen.send(()).unwrap();
            released.await.unwrap();
            answer(
                &server,
                peer,
                &request,
                Command::Version,
                99,
                b"late".to_vec(),
            )
            .await;
            sent.send(()).unwrap();
            let mut bytes = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(50), server.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        });
        let mut operation = Box::pin(session.version());
        tokio::select! { result = &mut operation => panic!("unexpected completion: {result:?}"), _ = received => {} }
        drop(operation);
        release.send(()).unwrap();
        delivered.await.unwrap();
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::SessionUnusable
        );
        assert_eq!(
            session.set_operation_timeout(Duration::from_secs(3)),
            Err(ClientError::SessionUnusable)
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn zero_budget_and_local_preflight_can_be_changed_without_reviving_interruption() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(
            &server,
            Duration::from_secs(1),
            Limits {
                max_request_bytes: HEADER_LEN + 3,
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(
            session.get_file_block("/too-long", 0).await,
            Err(ClientError::LimitExceeded { .. })
        ));
        session.set_operation_timeout(Duration::ZERO).unwrap();
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::OperationTimedOut
        );
        let mut bytes = [0; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut bytes))
                .await
                .is_err()
        );
        assert!(matches!(
            session.set_operation_timeout(Duration::MAX),
            Err(ClientError::Protocol(_))
        ));
        assert_eq!(session.operation_timeout(), Duration::ZERO);
        session
            .set_operation_timeout(Duration::from_secs(1))
            .unwrap();
        let task = tokio::spawn(async move {
            let (request, peer) = asked(&server).await;
            answer(&server, peer, &request, Command::GetFile, 1, b"ok".to_vec()).await;
        });
        assert_eq!(session.get_file_block("/x", 0).await.unwrap(), b"ok");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn accepted_error_and_aggregate_refusal_keep_the_server_key_known() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(
            &server,
            Duration::from_secs(1),
            Limits {
                max_file_bytes: 0,
                ..Default::default()
            },
        )
        .await;
        let task = tokio::spawn(async move {
            let (first, peer) = asked(&server).await;
            answer(&server, peer, &first, Command::Err, 10, b"refused".to_vec()).await;
            let (second, peer) = asked(&server).await;
            assert_eq!(second.header.key, 10);
            answer(&server, peer, &second, Command::GetFile, 11, b"x".to_vec()).await;
            let (third, peer) = asked(&server).await;
            assert_eq!(third.header.key, 11);
            answer(
                &server,
                peer,
                &third,
                Command::Version,
                12,
                b"healthy".to_vec(),
            )
            .await;
        });
        assert_eq!(
            session.version().await.unwrap_err(),
            ClientError::Refused("refused".into())
        );
        assert!(matches!(
            session.get_file("/").await,
            Err(ClientError::LimitExceeded {
                what: "file bytes",
                ..
            })
        ));
        assert_eq!(session.version().await.unwrap(), "healthy");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn expired_absolute_budget_refuses_before_a_ready_inner_request() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut session = session(&server, Duration::from_secs(1), Limits::default()).await;
        let deadline = tokio::time::Instant::now();
        assert_eq!(
            session
                .request_until(Command::Version, &[], 0, deadline)
                .await
                .unwrap_err(),
            ClientError::OperationTimedOut
        );
        assert!(!session.in_flight);
        assert_eq!(session.sequence, 1);
        let mut bytes = [0; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut bytes))
                .await
                .is_err()
        );
    }
}
