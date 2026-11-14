//! Scorpion requests: the subprotocol byte, its parameter, and the URL.
//!
//! A request is one line:
//!
//! ```text
//! <subprotocol><parameter?> <absolute-url>\r\n
//! ```
//!
//! The subprotocol is a single byte -- `R`, `S`, `I`, or `M` -- and what may
//! follow it before the space differs for each, which is why [`Parameter`] is
//! an enum rather than a string. The scheme in the URL is mandatory.

use core::fmt;

/// Which subprotocol a request opens. Named in the specification after the
/// methods of HTTP, though only `R` is mandatory to implement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Subprotocol {
    /// `R` -- retrieve a file's contents. The only mandatory subprotocol.
    Receive,
    /// `S` -- upload, replace, redirect, or delete a file.
    Send,
    /// `I` -- arbitrary two-way communication, usually terminal emulation.
    Interactive,
    /// `M` -- retrieve information *about* a file rather than the file.
    Meta,
}

impl Subprotocol {
    /// The byte this subprotocol is written as.
    pub fn byte(self) -> u8 {
        match self {
            Self::Receive => b'R',
            Self::Send => b'S',
            Self::Interactive => b'I',
            Self::Meta => b'M',
        }
    }

    /// Parse a subprotocol byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            b'R' => Self::Receive,
            b'S' => Self::Send,
            b'I' => Self::Interactive,
            b'M' => Self::Meta,
            _ => return None,
        })
    }
}

impl fmt::Display for Subprotocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Receive => "R",
            Self::Send => "S",
            Self::Interactive => "I",
            Self::Meta => "M",
        })
    }
}

/// A byte range, as the `R` subprotocol writes it: `start-end` where `end` is
/// the first byte *not* wanted, or `start-` for everything from `start` on.
///
/// The specification's own example is worth keeping: "3-9" means six bytes,
/// the fourth through ninth. So `end` is exclusive, unlike HTTP's `Range`,
/// and mixing the two up would silently truncate every fetch by one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    /// Zero-based offset of the first byte wanted.
    pub start: u64,
    /// Zero-based offset of the first byte *not* wanted. `None` means "to the
    /// end of the file".
    pub end: Option<u64>,
}

impl Range {
    /// A range from `start` up to but not including `end`.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end: Some(end),
        }
    }

    /// Everything from `start` to the end of the file.
    pub fn from(start: u64) -> Self {
        Self { start, end: None }
    }

    /// How many bytes this range asks for, when it has an end.
    pub fn len(self) -> Option<u64> {
        self.end.map(|end| end.saturating_sub(self.start))
    }

    /// Whether this range asks for nothing at all.
    pub fn is_empty(self) -> bool {
        self.len() == Some(0)
    }

    fn parse(text: &str) -> Option<Self> {
        let (start, end) = text.split_once('-')?;
        let start = start.parse().ok()?;
        let end = if end.is_empty() {
            None
        } else {
            Some(end.parse().ok()?)
        };
        Some(Self { start, end })
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.end {
            Some(end) => write!(f, "{}-{end}", self.start),
            None => write!(f, "{}-", self.start),
        }
    }
}

/// The parameter between the subprotocol byte and the space.
///
/// Each subprotocol reads these bytes differently, so they are kept apart
/// rather than handed around as an untyped string.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Parameter {
    /// No parameter.
    #[default]
    None,
    /// `R`: a byte range.
    Range(Range),
    /// `S`: the version of the file being replaced, for conflict detection.
    Version(String),
    /// `S`: an HMAC over everything after the `@`, including the whole request
    /// and everything the client sends afterwards, followed by `@` and the
    /// version (which may be empty).
    Hmac {
        /// The HMAC itself, as the server expects to read it.
        hmac: String,
        /// The version, empty when there is none.
        version: String,
    },
    /// `I`: requested capability codes, unparsed. Their grammar is
    /// deliberately CSI-shaped so a terminal emulator can reuse its own
    /// parser, so this crate carries them verbatim rather than imposing a
    /// structure the caller may already have.
    Capabilities(String),
    /// `M`: the MIME or ULFI type the client would prefer. The server may
    /// ignore it.
    DesiredType(String),
}

impl Parameter {
    /// How this parameter is written after the subprotocol byte.
    pub fn render(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Range(range) => range.to_string(),
            Self::Version(version) => version.clone(),
            Self::Hmac { hmac, version } => format!("{hmac}@{version}"),
            Self::Capabilities(codes) => codes.clone(),
            Self::DesiredType(kind) => kind.clone(),
        }
    }

    /// Read the parameter text according to the subprotocol that precedes it.
    ///
    /// Empty text is always [`Parameter::None`]; every subprotocol's parameter
    /// is optional.
    pub fn parse(subprotocol: Subprotocol, text: &str) -> Result<Self, RequestError> {
        if text.is_empty() {
            return Ok(Self::None);
        }
        Ok(match subprotocol {
            Subprotocol::Receive => {
                Self::Range(Range::parse(text).ok_or(RequestError::MalformedRange)?)
            }
            Subprotocol::Send => match text.split_once('@') {
                Some((hmac, version)) => Self::Hmac {
                    hmac: hmac.to_string(),
                    version: version.to_string(),
                },
                None => Self::Version(text.to_string()),
            },
            Subprotocol::Interactive => Self::Capabilities(text.to_string()),
            Subprotocol::Meta => Self::DesiredType(text.to_string()),
        })
    }
}

/// Why a request line could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// The line was empty, or held no space separating parameter from URL.
    Malformed,
    /// The first byte was not `R`, `S`, `I`, or `M`.
    UnknownSubprotocol,
    /// An `R` parameter was not a well-formed range.
    MalformedRange,
    /// The URL had no scheme. The specification makes it mandatory.
    RelativeUrl,
    /// The request was longer than the caller's limit.
    TooLong,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "request line is malformed",
            Self::UnknownSubprotocol => "first byte is not a known subprotocol",
            Self::MalformedRange => "range parameter is malformed",
            Self::RelativeUrl => "request URL has no scheme, and the scheme is mandatory",
            Self::TooLong => "request line exceeds the permitted length",
        })
    }
}

impl core::error::Error for RequestError {}

/// One parsed Scorpion request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Which subprotocol was asked for.
    pub subprotocol: Subprotocol,
    /// The parameter that followed it, if any.
    pub parameter: Parameter,
    /// The absolute URL, scheme included.
    pub url: String,
}

impl Request {
    /// A plain retrieval.
    pub fn receive(url: impl Into<String>) -> Self {
        Self {
            subprotocol: Subprotocol::Receive,
            parameter: Parameter::None,
            url: url.into(),
        }
    }

    /// A retrieval of one byte range.
    pub fn receive_range(url: impl Into<String>, range: Range) -> Self {
        Self {
            subprotocol: Subprotocol::Receive,
            parameter: Parameter::Range(range),
            url: url.into(),
        }
    }

    /// A metadata request.
    pub fn meta(url: impl Into<String>) -> Self {
        Self {
            subprotocol: Subprotocol::Meta,
            parameter: Parameter::None,
            url: url.into(),
        }
    }

    /// An upload, optionally declaring the version being replaced.
    pub fn send(url: impl Into<String>, version: Option<String>) -> Self {
        Self {
            subprotocol: Subprotocol::Send,
            parameter: version.map_or(Parameter::None, Parameter::Version),
            url: url.into(),
        }
    }

    /// An interactive session, optionally requesting capabilities.
    pub fn interactive(url: impl Into<String>, capabilities: Option<String>) -> Self {
        Self {
            subprotocol: Subprotocol::Interactive,
            parameter: capabilities.map_or(Parameter::None, Parameter::Capabilities),
            url: url.into(),
        }
    }

    /// The request as it goes on the wire, `\r\n` included.
    ///
    /// The fragment is stripped: the specification says the part from `#`
    /// onwards "is only for the client", so sending it would leak a purely
    /// local detail to the server.
    pub fn to_wire(&self) -> Vec<u8> {
        let url = strip_fragment(&self.url);
        let mut line = Vec::with_capacity(url.len() + 8);
        line.push(self.subprotocol.byte());
        line.extend_from_slice(self.parameter.render().as_bytes());
        line.push(b' ');
        line.extend_from_slice(url.as_bytes());
        line.extend_from_slice(b"\r\n");
        line
    }

    /// Parse a request line, with or without its trailing `\r\n`.
    pub fn parse(line: &str) -> Result<Self, RequestError> {
        let line = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);

        let mut bytes = line.chars();
        let first = bytes.next().ok_or(RequestError::Malformed)?;
        let subprotocol = u8::try_from(first)
            .ok()
            .and_then(Subprotocol::from_byte)
            .ok_or(RequestError::UnknownSubprotocol)?;

        let rest = &line[first.len_utf8()..];
        let (parameter, url) = rest.split_once(' ').ok_or(RequestError::Malformed)?;
        if url.is_empty() {
            return Err(RequestError::Malformed);
        }
        // "the scheme is mandatory". Checked here rather than trusted, because
        // a server that skips this will happily treat a path as a host.
        if !has_scheme(url) {
            return Err(RequestError::RelativeUrl);
        }

        Ok(Self {
            subprotocol,
            parameter: Parameter::parse(subprotocol, parameter)?,
            url: url.to_string(),
        })
    }
}

/// Whether a URL begins with a scheme, per RFC 3986's `scheme` production.
fn has_scheme(url: &str) -> bool {
    let Some(colon) = url.find(':') else {
        return false;
    };
    let scheme = &url[..colon];
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Drop the fragment, which belongs to the client alone.
fn strip_fragment(url: &str) -> &str {
    url.split_once('#').map_or(url, |(head, _)| head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_receive_round_trips() {
        let request = Request::receive("scorpion://example.com/");
        assert_eq!(request.to_wire(), b"R scorpion://example.com/\r\n");
        assert_eq!(
            Request::parse("R scorpion://example.com/\r\n").unwrap(),
            request
        );
    }

    #[test]
    fn a_range_end_is_exclusive() {
        // The spec's own example: "3-9" is six bytes, the fourth through the
        // ninth. Reading it as inclusive would truncate every ranged fetch.
        let range = Range::parse("3-9").unwrap();
        assert_eq!(range.start, 3);
        assert_eq!(range.end, Some(9));
        assert_eq!(range.len(), Some(6));
    }

    #[test]
    fn an_open_ended_range_round_trips() {
        let request = Request::receive_range("scorpion://example.com/big", Range::from(4096));
        assert_eq!(request.to_wire(), b"R4096- scorpion://example.com/big\r\n");
        let parsed = Request::parse("R4096- scorpion://example.com/big").unwrap();
        assert_eq!(parsed.parameter, Parameter::Range(Range::from(4096)));
    }

    #[test]
    fn a_send_parameter_splits_hmac_from_version() {
        let parsed = Request::parse("Sabc123@v7 scorpion://example.com/page").unwrap();
        assert_eq!(
            parsed.parameter,
            Parameter::Hmac {
                hmac: "abc123".into(),
                version: "v7".into()
            }
        );
        // The spec allows the version half to be empty.
        let empty = Request::parse("Sabc123@ scorpion://example.com/page").unwrap();
        assert_eq!(
            empty.parameter,
            Parameter::Hmac {
                hmac: "abc123".into(),
                version: String::new()
            }
        );
    }

    #[test]
    fn a_send_without_an_at_sign_is_a_bare_version() {
        let parsed = Request::parse("Sv7 scorpion://example.com/page").unwrap();
        assert_eq!(parsed.parameter, Parameter::Version("v7".into()));
    }

    #[test]
    fn the_same_bytes_mean_different_things_per_subprotocol() {
        // "3-9" is a range under R and an opaque type hint under M. This is
        // why the parameter is parsed against its subprotocol rather than on
        // its own.
        assert_eq!(
            Parameter::parse(Subprotocol::Receive, "3-9").unwrap(),
            Parameter::Range(Range::new(3, 9))
        );
        assert_eq!(
            Parameter::parse(Subprotocol::Meta, "3-9").unwrap(),
            Parameter::DesiredType("3-9".into())
        );
    }

    #[test]
    fn a_relative_url_is_refused() {
        // "the scheme is mandatory" -- a server that skipped this would read a
        // path as a host name.
        assert_eq!(
            Request::parse("R /just/a/path"),
            Err(RequestError::RelativeUrl)
        );
        assert_eq!(
            Request::parse("R example.com/path"),
            Err(RequestError::RelativeUrl)
        );
    }

    #[test]
    fn the_fragment_never_reaches_the_server() {
        // "that part is only for the client".
        let request = Request::receive("scorpion://example.com/doc#section-3");
        assert_eq!(request.to_wire(), b"R scorpion://example.com/doc\r\n");
    }

    #[test]
    fn an_unknown_subprotocol_is_named_as_such() {
        assert_eq!(
            Request::parse("G scorpion://example.com/"),
            Err(RequestError::UnknownSubprotocol)
        );
    }

    #[test]
    fn a_malformed_range_is_refused_rather_than_silently_dropped() {
        assert_eq!(
            Request::parse("Rbanana scorpion://example.com/"),
            Err(RequestError::MalformedRange)
        );
    }

    #[test]
    fn interactive_capabilities_are_carried_verbatim() {
        // CSI-shaped by design so a terminal emulator can reuse its parser.
        let parsed = Request::parse("IL1x80;24 scorpion://example.com/shell").unwrap();
        assert_eq!(parsed.parameter, Parameter::Capabilities("L1x80;24".into()));
        assert_eq!(
            parsed.to_wire(),
            b"IL1x80;24 scorpion://example.com/shell\r\n"
        );
    }
}
