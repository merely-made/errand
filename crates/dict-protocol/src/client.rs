//! The DICT client: a session, not a fetch.
//!
//! The connection stays open across commands, so this is a [`Session`] you
//! hold rather than a function you call. That is the protocol's shape and
//! hiding it behind a one-shot `fetch` would mean reconnecting per word,
//! which is exactly what a command loop exists to avoid.
//!
//! ## Looking a word up
//!
//! ```no_run
//! # async fn run() -> Result<(), dict_protocol::ClientError> {
//! let mut session = dict_protocol::Session::connect("dict.org", None).await?;
//!
//! for definition in session.define("*", "smolweb").await? {
//!     println!("[{}] {}", definition.database, definition.text.join("\n"));
//! }
//! session.quit().await?;
//! # Ok(())
//! # }
//! ```
//!
//! `"*"` asks every database and `"!"` asks for the first that matches. A word
//! that is absent yields an **empty vector rather than an error**, because
//! `552 no match` is an answer.
//!

use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{Instant, error::Elapsed, timeout_at};

use crate::wire::{self, DEFAULT_PORT, MAX_LINE, Status};

mod commands;

/// What can go wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    Connect(String),
    Io(String),
    /// The server said something the grammar does not allow.
    Protocol(String),
    /// The whole connection/banner or command operation exhausted its budget.
    TimedOut,
    /// The server refused, with its own code and message.
    Refused {
        code: u16,
        text: String,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::TimedOut => write!(f, "operation timed out"),
            Self::Refused { code, text } => write!(f, "server refused: {code} {text}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Finite budgets for a banner or one complete high-level command response.
///
/// Bytes count the wire representation, including CRLF, status lines, text
/// terminators and trailers, before dot unstuffing. Every inbound line counts,
/// including empty lines, so this also bounds the number of returned items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Outgoing command bytes, including CRLF; [`MAX_LINE`] also applies.
    pub max_command_bytes: usize,
    /// Bytes in any single inbound line, including CRLF.
    pub max_line_bytes: usize,
    /// Total inbound bytes across the entire command response.
    pub max_response_bytes: usize,
    /// Total inbound lines across the entire command response.
    pub max_response_lines: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_command_bytes: MAX_LINE,
            max_line_bytes: 4096,
            max_response_bytes: 64 * 1024 * 1024,
            max_response_lines: 65_536,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<(), ClientError> {
        if self.max_command_bytes < 2
            || self.max_line_bytes == 0
            || self.max_response_bytes == 0
            || self.max_response_lines == 0
        {
            return Err(ClientError::Protocol(
                "invalid zero or undersized limits".into(),
            ));
        }
        Ok(())
    }
}

/// Session byte limits and a fresh whole-operation allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub limits: Limits,
    /// Covers connection plus banner, then independently each complete command.
    /// Idle time between commands does not consume this allowance.
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

impl Options {
    fn deadline(self) -> Result<Instant, ClientError> {
        self.limits.validate()?;
        operation_deadline(self.operation_timeout)
    }
}

fn operation_deadline(timeout: Duration) -> Result<Instant, ClientError> {
    if timeout.is_zero() {
        return Err(ClientError::TimedOut);
    }
    if std::time::Instant::now().checked_add(timeout).is_none() {
        return Err(ClientError::Protocol(
            "operation timeout is unrepresentable".into(),
        ));
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ClientError::Protocol("operation timeout is unrepresentable".into()))
}

fn check_deadline(deadline: Instant) -> Result<(), ClientError> {
    if Instant::now() >= deadline {
        Err(ClientError::TimedOut)
    } else {
        Ok(())
    }
}

fn timed_result<T>(
    deadline: Instant,
    result: Result<Result<T, ClientError>, Elapsed>,
) -> Result<T, ClientError> {
    check_deadline(deadline)?;
    result.map_err(|_| ClientError::TimedOut)?
}

#[derive(Default)]
struct Budget {
    bytes: usize,
    lines: usize,
}

/// An open DICT session.
pub struct Session<S> {
    stream: BufReader<S>,
    banner: Status,
    limits: Limits,
    budget: Budget,
    unusable: bool,
    operation_timeout: Duration,
    deadline: Instant,
}

impl Session<TcpStream> {
    /// Connect to a DICT server and read its banner.
    pub async fn connect(host: &str, port: Option<u16>) -> Result<Self, ClientError> {
        Self::connect_with_limits(host, port, Limits::default()).await
    }

    /// Connect using explicit byte/line budgets and the default 30-second deadline.
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

    /// One deadline covers DNS resolution, TCP connection and the entire banner.
    pub async fn connect_with_options(
        host: &str,
        port: Option<u16>,
        options: Options,
    ) -> Result<Self, ClientError> {
        let deadline = options.deadline()?;
        let port = port.unwrap_or(DEFAULT_PORT);
        let result = timeout_at(deadline, async {
            check_deadline(deadline)?;
            let stream = TcpStream::connect((host, port))
                .await
                .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
            Self::over_before_deadline(stream, options, deadline).await
        })
        .await;
        timed_result(deadline, result)
    }
}

impl<S> Session<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Start a session over an already-connected stream, reading the banner.
    ///
    /// Transport-independent, so DICT rides an encrypted carrier as readily as
    /// TCP.
    pub async fn over(stream: S) -> Result<Self, ClientError> {
        Self::over_with_limits(stream, Limits::default()).await
    }

    /// Start a session with explicit limits, also applied to the banner.
    ///
    /// A receive failure leaves the session unusable: a partial response is
    /// never drained without a budget. Request preflight failures do not do so.
    /// Uses the default 30-second deadline for the banner and each command.
    pub async fn over_with_limits(stream: S, limits: Limits) -> Result<Self, ClientError> {
        Self::over_with_options(
            stream,
            Options {
                limits,
                ..Options::default()
            },
        )
        .await
    }

    /// Start a supplied-carrier session with explicit byte and time budgets.
    /// Carrier establishment before this call remains the host's responsibility.
    pub async fn over_with_options(stream: S, options: Options) -> Result<Self, ClientError> {
        let deadline = options.deadline()?;
        let result = timeout_at(
            deadline,
            Self::over_before_deadline(stream, options, deadline),
        )
        .await;
        timed_result(deadline, result)
    }

    async fn over_before_deadline(
        stream: S,
        options: Options,
        deadline: Instant,
    ) -> Result<Self, ClientError> {
        let mut stream = BufReader::new(stream);
        let banner = read_status(
            &mut stream,
            options.limits,
            &mut Budget::default(),
            deadline,
        )
        .await?;
        if banner.code != wire::BANNER {
            return Err(ClientError::Protocol(format!(
                "expected a 220 banner, got {} {}",
                banner.code, banner.text
            )));
        }
        Ok(Self {
            stream,
            banner,
            limits: options.limits,
            budget: Budget::default(),
            unusable: false,
            operation_timeout: options.operation_timeout,
            deadline,
        })
    }

    /// The server's greeting, which carries its capabilities and message id.
    pub fn banner(&self) -> &Status {
        &self.banner
    }

    /// Send a command line and read its initial status response.
    ///
    /// This low-level method does not consume text blocks or later statuses.
    /// Use the high-level methods for complete, jointly budgeted responses.
    pub async fn command(&mut self, line: &str) -> Result<Status, ClientError> {
        let deadline = self.begin_operation(line)?;
        let result = timeout_at(deadline, self.send_command(line)).await;
        self.finish_operation(deadline, result)
    }

    fn begin_operation(&mut self, line: &str) -> Result<Instant, ClientError> {
        self.check_command_parts(&[line])?;
        if self.unusable {
            return Err(ClientError::Protocol(
                "session is unusable after an incomplete or failed operation".into(),
            ));
        }
        let deadline = operation_deadline(self.operation_timeout)?;
        self.deadline = deadline;
        // Set before the first I/O await. Dropping a polled operation future
        // leaves this flag set even though no error return executes.
        self.unusable = true;
        self.budget = Budget::default();
        Ok(deadline)
    }

    fn finish_operation<T>(
        &mut self,
        deadline: Instant,
        result: Result<Result<T, ClientError>, Elapsed>,
    ) -> Result<T, ClientError> {
        let result = timed_result(deadline, result);
        if result.is_ok()
            || matches!(
                &result,
                Err(ClientError::Refused {
                    code: 400..=599,
                    ..
                })
            )
        {
            self.unusable = false;
        }
        result
    }

    async fn send_command(&mut self, line: &str) -> Result<Status, ClientError> {
        check_deadline(self.deadline)?;
        let write = async {
            self.stream.get_mut().write_all(line.as_bytes()).await?;
            self.stream.get_mut().write_all(b"\r\n").await
        }
        .await;
        if let Err(error) = write {
            self.unusable = true;
            return Err(ClientError::Io(error.to_string()));
        }
        self.read_status().await
    }

    fn check_command_parts(&self, parts: &[&str]) -> Result<(), ClientError> {
        let cap = self.limits.max_command_bytes.min(MAX_LINE);
        let mut bytes = 2usize;
        for part in parts {
            if part.contains(['\r', '\n']) {
                return Err(ClientError::Protocol("command contains CR or LF".into()));
            }
            bytes = bytes
                .checked_add(part.len())
                .filter(|&n| n <= cap)
                .ok_or_else(|| ClientError::Protocol(format!("command exceeds {cap} bytes")))?;
        }
        Ok(())
    }

    fn parameter_command(&self, verb: &str, params: &[&str]) -> Result<String, ClientError> {
        // Check escaped lengths before constructing quoted caller input.
        let cap = self.limits.max_command_bytes.min(MAX_LINE);
        let mut bytes = verb.len() + 2;
        for param in params {
            if param.contains(['\r', '\n']) {
                return Err(ClientError::Protocol("parameter contains CR or LF".into()));
            }
            bytes = bytes
                .checked_add(1)
                .and_then(|n| n.checked_add(quoted_len(param)))
                .filter(|&n| n <= cap)
                .ok_or_else(|| ClientError::Protocol(format!("command exceeds {cap} bytes")))?;
        }
        let mut line = String::with_capacity(bytes - 2);
        line.push_str(verb);
        for param in params {
            line.push(' ');
            line.push_str(&quote(param));
        }
        Ok(line)
    }

    async fn read_status(&mut self) -> Result<Status, ClientError> {
        let result = read_status(
            &mut self.stream,
            self.limits,
            &mut self.budget,
            self.deadline,
        )
        .await;
        if result.is_err() {
            self.unusable = true;
        }
        result
    }

    /// Read a dot-terminated text block, unstuffing as it goes.
    async fn read_text_block(&mut self) -> Result<Vec<String>, ClientError> {
        let mut lines = Vec::new();
        loop {
            let result = read_line(
                &mut self.stream,
                self.limits,
                &mut self.budget,
                self.deadline,
            )
            .await;
            if result.is_err() {
                self.unusable = true;
            }
            let line = result?;
            if wire::is_terminator(&line) {
                return Ok(lines);
            }
            lines.push(wire::unstuff(line.trim_end_matches(['\r', '\n'])).to_string());
        }
    }

    /// Consume the `250 ok` that closes a text-block command.
    async fn expect_ok(&mut self) -> Result<(), ClientError> {
        let status = self.read_status().await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(refused(status))
        }
    }
}

fn refused(status: Status) -> ClientError {
    ClientError::Refused {
        code: status.code,
        text: status.text,
    }
}

/// Quote a parameter if it needs it. Words with spaces would otherwise split.
fn quote(param: &str) -> String {
    if param.is_empty() || param.contains(|c: char| c.is_whitespace() || c == '"') {
        format!("\"{}\"", param.replace('\\', r"\\").replace('"', "\\\""))
    } else {
        param.to_string()
    }
}

fn quoted_len(param: &str) -> usize {
    if param.is_empty() || param.contains(|c: char| c.is_whitespace() || c == '"') {
        param
            .len()
            .saturating_add(2)
            .saturating_add(param.bytes().filter(|&b| b == b'\\' || b == b'"').count())
    } else {
        param.len()
    }
}

async fn read_line<S>(
    stream: &mut BufReader<S>,
    limits: Limits,
    budget: &mut Budget,
    deadline: Instant,
) -> Result<String, ClientError>
where
    S: AsyncRead + Unpin,
{
    if budget.lines >= limits.max_response_lines {
        return Err(ClientError::Protocol("response line limit exceeded".into()));
    }
    let mut line = Vec::new();
    loop {
        check_deadline(deadline)?;
        let available = stream
            .fill_buf()
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if available.is_empty() {
            return Err(ClientError::Protocol("server closed mid-response".into()));
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if take > limits.max_line_bytes - line.len() {
            return Err(ClientError::Protocol(
                "response line byte limit exceeded".into(),
            ));
        }
        if take > limits.max_response_bytes - budget.bytes {
            return Err(ClientError::Protocol("response byte limit exceeded".into()));
        }
        line.extend_from_slice(&available[..take]);
        budget.bytes += take;
        stream.consume(take);
        if newline.is_some() {
            if !line.ends_with(b"\r\n") {
                return Err(ClientError::Protocol("response line lacks CRLF".into()));
            }
            budget.lines += 1;
            return String::from_utf8(line)
                .map_err(|e| ClientError::Protocol(format!("response is not UTF-8: {e}")));
        }
    }
}

async fn read_status<S>(
    stream: &mut BufReader<S>,
    limits: Limits,
    budget: &mut Budget,
    deadline: Instant,
) -> Result<Status, ClientError>
where
    S: AsyncRead + Unpin,
{
    let line = read_line(stream, limits, budget, deadline).await?;
    wire::parse_status(&line)
        .ok_or_else(|| ClientError::Protocol(format!("not a status line: {line:?}")))
}

#[cfg(test)]
#[path = "client_limits_tests.rs"]
mod limits_tests;

#[cfg(test)]
#[path = "client_deadline_tests.rs"]
mod deadline_tests;

#[cfg(test)]
mod tests;
