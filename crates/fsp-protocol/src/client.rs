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

/// Caller-owned byte and entry budgets. These do not add a session or whole-
/// operation deadline: `Session::attempts` and `Session::timeout` retain their
/// existing per-reply retry semantics. `MAX_PAYLOAD` is the client's block
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
        let port = port.unwrap_or(crate::wire::DEFAULT_PORT);
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        socket
            .connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("udp {host}:{port}: {e}")))?;
        Ok(Self {
            socket,
            key: 0,
            sequence: 1,
            limits,
            attempts: 3,
            timeout: RESEND_AFTER,
        })
    }

    /// The immutable budget snapshot selected when this session was opened.
    pub fn limits(&self) -> Limits {
        self.limits
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
        let reply = self.request(Command::Version, &[], 0).await?;
        Ok(trim_nul(&reply.data))
    }

    /// Fetch one block of a file at `offset`. An empty block is end of file.
    pub async fn get_file_block(
        &mut self,
        path: &str,
        offset: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let data = self.path_bytes(path)?;
        let reply = self.request(Command::GetFile, &data, offset).await?;
        Ok(reply.data)
    }

    /// Fetch a whole file, block by block.
    pub async fn get_file(&mut self, path: &str) -> Result<Vec<u8>, ClientError> {
        let data = self.path_bytes(path)?;
        let mut body = Vec::new();
        let mut offset = 0;
        loop {
            let block = self.request(Command::GetFile, &data, offset).await?.data;
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
        let data = self.path_bytes(path)?;
        let mut entries = Vec::new();
        let mut received = 0usize;
        let mut offset = 0;
        loop {
            let reply = self.request(Command::GetDir, &data, offset).await?;
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
            if block.finished {
                return Ok(entries);
            }
            offset = next;
        }
    }

    /// End the session politely.
    pub async fn bye(mut self) -> Result<(), ClientError> {
        self.request(Command::Bye, &[], 0).await.map(|_| ())
    }

    /// Send a command and wait for the reply that echoes our sequence.
    pub async fn request(
        &mut self,
        command: Command,
        data: &[u8],
        file_position: u32,
    ) -> Result<Packet, ClientError> {
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
            self.socket
                .send(&bytes)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;

            if let Some(reply) = self.await_reply(sequence).await? {
                // The server's key is echoed on our next request.
                self.key = reply.header.key;
                if reply.header.command == Command::Err.code() {
                    return Err(ClientError::Refused(trim_nul(&reply.data)));
                }
                return Ok(reply);
            }
        }
        Err(ClientError::TimedOut)
    }

    /// Read until a reply with the expected sequence arrives, or the timeout
    /// expires. Mismatched replies are stale and are dropped.
    async fn await_reply(&mut self, sequence: u16) -> Result<Option<Packet>, ClientError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        // One sentinel beyond the configured cap detects successful truncating
        // receives. At most 65536 bytes cover every ordinary UDP datagram even
        // when the caller supplies a larger policy value.
        let capacity = self.limits.max_datagram_bytes.min(usize::from(u16::MAX)) + 1;
        let mut buffer = vec![0u8; capacity];

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let read = match tokio::time::timeout(remaining, self.socket.recv(&mut buffer)).await {
                Err(_) => return Ok(None),
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
            return Ok(Some(decode(bytes, Direction::ServerToClient)?));
        }
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
