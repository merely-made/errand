//! UDP request/reply sequencing, bounded retries and server-key settlement.

use super::{ClientError, Session, check_deadline, trim_nul};
use crate::wire::{Command, Direction, HEADER_LEN, Header, Packet, checksum, decode, encode};

impl Session {
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

    pub(super) async fn request_until(
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
