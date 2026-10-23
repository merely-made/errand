//! FSP v2 packets: the 12-byte header, its direction-dependent checksum, and
//! directory entries.
//!
//! Dependency-free and always compiled.
//!
//! FSP is the outlier of the small-web family in two ways. It runs over
//! **UDP** and carries its own reliability, and it is deliberately simple
//! enough to run on a serial line: "FSP datagram header has checksum and
//! payload size recorded... can be used as very simple raw-protocol... This
//! makes it very popular in embedded devices area."
//!
//! ```text
//! FSP v2 HEADER FORMAT (12 bytes)
//!  byte FSP_COMMAND
//!  byte MESSAGE_CHECKSUM
//!  word KEY
//!  word SEQUENCE
//!  word DATA_LENGTH
//!  long FILE_POSITION
//! ```
//!
//! Numbers are network byte order, high byte first.

/// FSP's default port when a URL omits one.
pub const DEFAULT_PORT: u16 = 21;

/// The fixed header width.
pub const HEADER_LEN: usize = 12;

/// The payload size every implementation must accept.
pub const MAX_PAYLOAD: usize = 1024;

/// FSP command codes.
///
/// Codes above `0x7F` are reserved for extended headers (`CC_LIMIT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Server version string and setup.
    Version = 0x10,
    /// Error response from the server.
    Err = 0x40,
    /// Get a directory listing.
    GetDir = 0x41,
    /// Get a file.
    GetFile = 0x42,
    /// Open a file for writing.
    UpLoad = 0x43,
    /// Close and install a file opened for writing.
    Install = 0x44,
    /// Delete a file.
    DelFile = 0x45,
    /// Delete a directory.
    DelDir = 0x46,
    /// Get directory protection.
    GetPro = 0x47,
    /// Set directory protection.
    SetPro = 0x48,
    /// Create a directory.
    MakeDir = 0x49,
    /// Finish a session.
    Bye = 0x4A,
    /// Atomic get-and-delete.
    GrabFile = 0x4B,
    /// Atomic get-and-delete, done.
    GrabDone = 0x4C,
    /// Information about a file or directory.
    Stat = 0x4D,
    /// Rename a file or directory.
    Rename = 0x4E,
    /// Change password.
    ChPassw = 0x4F,
}

impl Command {
    /// The code for a byte, or `None` if it is not one FSP defines.
    pub fn from_code(code: u8) -> Option<Self> {
        use Command::*;
        Some(match code {
            0x10 => Version,
            0x40 => Err,
            0x41 => GetDir,
            0x42 => GetFile,
            0x43 => UpLoad,
            0x44 => Install,
            0x45 => DelFile,
            0x46 => DelDir,
            0x47 => GetPro,
            0x48 => SetPro,
            0x49 => MakeDir,
            0x4A => Bye,
            0x4B => GrabFile,
            0x4C => GrabDone,
            0x4D => Stat,
            0x4E => Rename,
            0x4F => ChPassw,
            _ => return None,
        })
    }

    pub fn code(self) -> u8 {
        self as u8
    }
}

/// Which way a packet is travelling, which **changes how it is checksummed**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Initial checksum value is zero.
    ServerToClient,
    /// Initial checksum value is the packet size.
    ClientToServer,
}

/// The 12-byte header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub command: u8,
    /// The client echoes the server's previous key; the server checks it.
    pub key: u16,
    /// The client chooses this; the server echoes it back, which is how a
    /// client detects a lost or stale reply.
    pub sequence: u16,
    pub data_length: u16,
    /// A file offset, or the size of the extra-data area, depending on the
    /// command.
    pub file_position: u32,
}

/// A whole packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    /// The payload, `DATA_LENGTH` bytes.
    pub data: Vec<u8>,
    /// The optional extra-data area that follows the payload.
    pub extra: Vec<u8>,
}

/// Why a packet could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Shorter than a header.
    TooShort,
    /// `DATA_LENGTH` claims more than the datagram holds.
    LengthOverrun { claimed: usize, available: usize },
    /// The checksum did not match. Carries both values, since FSP's one-byte
    /// checksum exists to reject non-FSP traffic rather than to correct it.
    BadChecksum { expected: u8, found: u8 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "packet shorter than a 12-byte header"),
            Self::LengthOverrun { claimed, available } => {
                write!(f, "data length {claimed} exceeds {available} available")
            }
            Self::BadChecksum { expected, found } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#04x}, found {found:#04x}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Compute a packet's checksum.
///
/// **The method differs by direction**, which is the detail most worth getting
/// right: server-to-client starts from zero, client-to-server starts from the
/// packet's own size. The checksum byte itself is treated as zero while
/// summing.
///
/// ```
/// use fsp_protocol::wire::{Direction, checksum};
///
/// let packet = [0x41, 0x00, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0];
/// // The same bytes checksum differently depending on which way they go.
/// assert_ne!(
///     checksum(&packet, Direction::ServerToClient),
///     checksum(&packet, Direction::ClientToServer)
/// );
/// ```
pub fn checksum(packet: &[u8], direction: Direction) -> u8 {
    let mut sum: u32 = match direction {
        Direction::ServerToClient => 0,
        Direction::ClientToServer => packet.len() as u32,
    };
    for (index, byte) in packet.iter().enumerate() {
        // Position 1 is the checksum field, which counts as zero.
        if index != 1 {
            sum = sum.wrapping_add(u32::from(*byte));
        }
    }
    (sum + (sum >> 8)) as u8
}

/// Encode a packet, filling in its checksum for the given direction.
pub fn encode(packet: &Packet, direction: Direction) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + packet.data.len() + packet.extra.len());
    out.push(packet.header.command);
    out.push(0); // checksum, filled below
    out.extend_from_slice(&packet.header.key.to_be_bytes());
    out.extend_from_slice(&packet.header.sequence.to_be_bytes());
    out.extend_from_slice(&packet.header.data_length.to_be_bytes());
    out.extend_from_slice(&packet.header.file_position.to_be_bytes());
    out.extend_from_slice(&packet.data);
    out.extend_from_slice(&packet.extra);

    out[1] = checksum(&out, direction);
    out
}

/// Decode a packet, verifying its checksum for the given direction.
pub fn decode(bytes: &[u8], direction: Direction) -> Result<Packet, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    let found = bytes[1];
    let expected = checksum(bytes, direction);
    if found != expected {
        return Err(DecodeError::BadChecksum { expected, found });
    }

    let header = Header {
        command: bytes[0],
        key: u16::from_be_bytes([bytes[2], bytes[3]]),
        sequence: u16::from_be_bytes([bytes[4], bytes[5]]),
        data_length: u16::from_be_bytes([bytes[6], bytes[7]]),
        file_position: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
    };

    let data_length = usize::from(header.data_length);
    let available = bytes.len() - HEADER_LEN;
    if data_length > available {
        return Err(DecodeError::LengthOverrun {
            claimed: data_length,
            available,
        });
    }

    Ok(Packet {
        header,
        data: bytes[HEADER_LEN..HEADER_LEN + data_length].to_vec(),
        extra: bytes[HEADER_LEN + data_length..].to_vec(),
    })
}

// ── Directory entries ──────────────────────────────────────────────────────

/// An entry's type byte.
pub const RDTYPE_END: u8 = 0x00;
pub const RDTYPE_FILE: u8 = 0x01;
pub const RDTYPE_DIR: u8 = 0x02;
/// Padding to the end of a block: skip it and keep reading.
pub const RDTYPE_SKIP: u8 = 0x2A;

/// What a directory entry points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// Unix timestamp.
    pub time: u32,
    pub size: u32,
    pub kind: EntryKind,
    pub name: String,
}

/// Parse a directory block into entries.
///
/// Each entry is a 4-byte time, a 4-byte size, a type byte, a NUL-terminated
/// name, then padding to a 4-byte boundary. `RDTYPE_SKIP` is padding to the
/// end of the block and `RDTYPE_END` stops the walk; a block is never split
/// across packets, so a short read is the end rather than a continuation.
pub fn parse_directory(block: &[u8]) -> Vec<DirEntry> {
    parse_directory_bounded(block, usize::MAX)
        .expect("entry count cannot exceed usize::MAX")
        .entries
}

/// The bounded native walk also distinguishes padding from an explicit END.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryBlock {
    pub entries: Vec<DirEntry>,
    pub finished: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryLimitExceeded {
    pub max_entries: usize,
}

impl std::fmt::Display for DirectoryLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "directory block exceeds {} entries", self.max_entries)
    }
}
impl std::error::Error for DirectoryLimitExceeded {}

/// Parse with an entry budget, checking before name allocation. Unknown kinds,
/// native padding, verbatim fields and the original lossy UTF-8 name behavior
/// follow `parse_directory`; `finished` records an explicit END marker.
pub fn parse_directory_bounded(
    block: &[u8],
    max_entries: usize,
) -> Result<DirectoryBlock, DirectoryLimitExceeded> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    let mut finished = false;

    while at + 9 <= block.len() {
        let time = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        let size = u32::from_be_bytes([block[at + 4], block[at + 5], block[at + 6], block[at + 7]]);
        let kind_byte = block[at + 8];

        if kind_byte == RDTYPE_END {
            finished = true;
            break;
        }
        if kind_byte == RDTYPE_SKIP {
            // Padding to the end of this block.
            break;
        }

        // The name runs to a NUL.
        let name_start = at + 9;
        let Some(nul) = block[name_start..].iter().position(|b| *b == 0) else {
            break;
        };
        if let Some(kind) = match kind_byte {
            RDTYPE_FILE => Some(EntryKind::File),
            RDTYPE_DIR => Some(EntryKind::Directory),
            _ => None,
        } {
            if entries.len() == max_entries {
                return Err(DirectoryLimitExceeded { max_entries });
            }
            let name = String::from_utf8_lossy(&block[name_start..name_start + nul]).to_string();
            entries.push(DirEntry {
                time,
                size,
                kind,
                name,
            });
        }

        // Advance past the name's NUL, then pad to a 4-byte boundary.
        let end = name_start + nul + 1;
        at = end.div_ceil(4) * 4;
    }
    Ok(DirectoryBlock { entries, finished })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(command: Command, data: &[u8]) -> Packet {
        Packet {
            header: Header {
                command: command.code(),
                key: 0xBEEF,
                sequence: 0x1234,
                data_length: data.len() as u16,
                file_position: 0,
            },
            data: data.to_vec(),
            extra: Vec::new(),
        }
    }

    #[test]
    fn the_header_is_twelve_bytes_in_network_order() {
        let bytes = encode(&packet(Command::GetFile, b"hi"), Direction::ClientToServer);
        assert_eq!(bytes.len(), HEADER_LEN + 2);
        assert_eq!(bytes[0], 0x42, "command");
        assert_eq!(&bytes[2..4], &[0xBE, 0xEF], "key, high byte first");
        assert_eq!(&bytes[4..6], &[0x12, 0x34], "sequence, high byte first");
        assert_eq!(&bytes[6..8], &[0x00, 0x02], "data length");
    }

    #[test]
    fn the_checksum_differs_by_direction() {
        // The detail that silently breaks an implementation against a real
        // server: server-to-client starts from zero, client-to-server starts
        // from the packet size.
        let raw = [0x41u8, 0x00, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0];
        let to_client = checksum(&raw, Direction::ServerToClient);
        let to_server = checksum(&raw, Direction::ClientToServer);
        assert_ne!(to_client, to_server);
        assert_eq!(
            to_server.wrapping_sub(to_client),
            HEADER_LEN as u8,
            "the difference is the packet size"
        );
    }

    #[test]
    fn a_packet_round_trips_in_each_direction() {
        for direction in [Direction::ServerToClient, Direction::ClientToServer] {
            let original = packet(Command::GetDir, b"/pub");
            let bytes = encode(&original, direction);
            assert_eq!(decode(&bytes, direction).unwrap(), original);
        }
    }

    #[test]
    fn a_packet_checksummed_one_way_is_refused_the_other() {
        let bytes = encode(&packet(Command::GetDir, b"/pub"), Direction::ClientToServer);
        let error = decode(&bytes, Direction::ServerToClient).unwrap_err();
        assert!(
            matches!(error, DecodeError::BadChecksum { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn a_corrupted_byte_is_caught() {
        let mut bytes = encode(
            &packet(Command::GetFile, b"data"),
            Direction::ServerToClient,
        );
        bytes[HEADER_LEN] ^= 0xFF;
        assert!(matches!(
            decode(&bytes, Direction::ServerToClient),
            Err(DecodeError::BadChecksum { .. })
        ));
    }

    #[test]
    fn a_short_packet_is_refused_rather_than_panicking() {
        assert_eq!(
            decode(&[0u8; 5], Direction::ServerToClient),
            Err(DecodeError::TooShort)
        );
        assert_eq!(
            decode(&[], Direction::ServerToClient),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn a_lying_data_length_is_refused() {
        let mut original = packet(Command::GetFile, b"four");
        original.header.data_length = 9999;
        let bytes = encode(&original, Direction::ServerToClient);
        assert!(matches!(
            decode(&bytes, Direction::ServerToClient),
            Err(DecodeError::LengthOverrun { .. })
        ));
    }

    #[test]
    fn extra_data_after_the_payload_is_kept_and_checksummed() {
        let original = Packet {
            header: Header {
                command: Command::Version.code(),
                key: 1,
                sequence: 2,
                data_length: 3,
                file_position: 2,
            },
            data: b"abc".to_vec(),
            extra: b"xy".to_vec(),
        };
        let bytes = encode(&original, Direction::ServerToClient);
        let decoded = decode(&bytes, Direction::ServerToClient).unwrap();
        assert_eq!(decoded.data, b"abc");
        assert_eq!(decoded.extra, b"xy", "extra data survives");
    }

    #[test]
    fn every_defined_command_round_trips_its_code() {
        for code in [
            0x10u8, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
            0x4D, 0x4E, 0x4F,
        ] {
            assert_eq!(Command::from_code(code).unwrap().code(), code);
        }
        assert_eq!(Command::from_code(0x00), None);
        assert_eq!(
            Command::from_code(0x81),
            None,
            "extended headers are reserved"
        );
    }

    /// Build a directory entry the way a server would.
    fn entry(time: u32, size: u32, kind: u8, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&time.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.push(kind);
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn directory_entries_parse_with_their_padding() {
        let mut block = entry(1000, 42, RDTYPE_FILE, "readme.txt");
        block.extend(entry(2000, 0, RDTYPE_DIR, "pub"));
        block.extend(entry(0, 0, RDTYPE_END, ""));

        let entries = parse_directory(&block);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            DirEntry {
                time: 1000,
                size: 42,
                kind: EntryKind::File,
                name: "readme.txt".into()
            }
        );
        assert_eq!(entries[1].kind, EntryKind::Directory);
        assert_eq!(entries[1].name, "pub");
    }

    #[test]
    fn the_end_marker_stops_the_walk() {
        let mut block = entry(1, 1, RDTYPE_FILE, "a");
        block.extend(entry(0, 0, RDTYPE_END, ""));
        block.extend(entry(2, 2, RDTYPE_FILE, "never-read"));
        assert_eq!(parse_directory(&block).len(), 1);
    }

    #[test]
    fn a_skip_marker_ends_the_block() {
        let mut block = entry(1, 1, RDTYPE_FILE, "a");
        block.extend(entry(0, 0, RDTYPE_SKIP, ""));
        assert_eq!(parse_directory(&block).len(), 1);
    }

    #[test]
    fn a_truncated_entry_stops_cleanly() {
        let mut block = entry(1, 1, RDTYPE_FILE, "a");
        block.extend_from_slice(&[0, 0, 0, 5, 0, 0]); // not a whole entry
        assert_eq!(parse_directory(&block).len(), 1);
    }

    #[test]
    fn an_empty_block_yields_nothing() {
        assert!(parse_directory(&[]).is_empty());
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    fn entry(name: &[u8]) -> Vec<u8> {
        let mut bytes = 123u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&999u32.to_be_bytes());
        bytes.push(RDTYPE_FILE);
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.resize(bytes.len().div_ceil(4) * 4, 0);
        bytes
    }
    #[test]
    fn bounded_directory_walk_keeps_grammar_and_checks_entries_before_copy() {
        let mut bytes = entry(b"first");
        bytes.extend(entry(b"\xff"));
        let mut end = vec![0; 12];
        end[8] = RDTYPE_END;
        bytes.extend(end);
        bytes.extend(entry(b"ignored"));
        let result = parse_directory_bounded(&bytes, 2).unwrap();
        assert!(result.finished);
        assert_eq!(result.entries, parse_directory(&bytes));
        assert_eq!(result.entries[1].name, "\u{fffd}");
        assert_eq!(
            parse_directory_bounded(&bytes, 1),
            Err(DirectoryLimitExceeded { max_entries: 1 })
        );
        let mut skip = vec![0; 12];
        skip[8] = RDTYPE_SKIP;
        skip.extend(entry(b"padding"));
        let result = parse_directory_bounded(&skip, 0).unwrap();
        assert!(result.entries.is_empty());
        assert!(!result.finished);
    }
}
