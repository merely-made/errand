//! Scorpion status codes.
//!
//! A status code is two ASCII digits. The first is the **major** code and
//! decides the shape of the rest of the line: how many parameters there are,
//! and whether a body follows. The second is the **minor** code and refines
//! the reason. The specification is explicit that "clients may ignore the
//! minor code", so this module keeps the two separable rather than collapsing
//! them into one flat enum: [`Status::major`] is what a client must handle,
//! and [`Status::code`] is there when it wants the detail.
//!
//! That split is not a stylistic choice. A server is free to invent minor
//! codes this crate has never heard of, and a client that matched on a flat
//! enum would fail on codes it should have handled by class. Parsing here
//! therefore accepts **any** two digits, and only the major code is
//! interpreted.

/// The major status class, which decides how the rest of the status line
/// parses and whether a body follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Major {
    /// `0x` -- interactive mode begins. Only valid for the `I` subprotocol.
    /// The optional parameter is the negotiated capability codes.
    Interactive,
    /// `1x` -- input required. The parameter is the prompt text.
    Input,
    /// `2x` -- success; the file's bytes follow the status line.
    Success,
    /// `3x` -- redirect. The parameter is the target URL.
    Redirect,
    /// `4x` -- temporary error. Retry-after seconds, then an optional message.
    TemporaryError,
    /// `5x` -- permanent error. The parameter is the message.
    PermanentError,
    /// `6x` -- a client certificate is required. A URL-scope hint, then an
    /// explanation.
    CertificateRequired,
    /// `7x` -- ready to receive. Only valid for the `S` subprotocol.
    ReadyToReceive,
    /// `8x` -- sent data accepted. Only valid for the `S` subprotocol.
    Accepted,
}

impl Major {
    /// The digit this class is written as.
    pub fn digit(self) -> u8 {
        match self {
            Self::Interactive => 0,
            Self::Input => 1,
            Self::Success => 2,
            Self::Redirect => 3,
            Self::TemporaryError => 4,
            Self::PermanentError => 5,
            Self::CertificateRequired => 6,
            Self::ReadyToReceive => 7,
            Self::Accepted => 8,
        }
    }

    /// The class for a leading digit, or `None` for `9`, which the
    /// specification does not define.
    pub fn from_digit(digit: u8) -> Option<Self> {
        Some(match digit {
            0 => Self::Interactive,
            1 => Self::Input,
            2 => Self::Success,
            3 => Self::Redirect,
            4 => Self::TemporaryError,
            5 => Self::PermanentError,
            6 => Self::CertificateRequired,
            7 => Self::ReadyToReceive,
            8 => Self::Accepted,
            _ => return None,
        })
    }

    /// Whether the file's bytes follow the status line.
    ///
    /// Only `2x` carries a body. `8x` shares `2x`'s *parameters* but the
    /// specification is explicit that "the data of the file is omitted", which
    /// is exactly the kind of near-miss worth encoding once here rather than
    /// re-deriving at each call site.
    pub fn has_body(self) -> bool {
        matches!(self, Self::Success)
    }

    /// How many space-separated parameters precede the final free-text one.
    ///
    /// The specification says the last parameter may itself contain spaces and
    /// that "the client will know how many parameters according to the major
    /// status code" -- so splitting the status line needs exactly this number.
    fn leading_parameters(self) -> usize {
        match self {
            // size, then type, then an optional version: the version is the
            // last field and cannot contain spaces, but treating it as the
            // trailing field costs nothing and tolerates a server that adds
            // one.
            Self::Success | Self::Accepted => 2,
            // Retry-after, then an optional message.
            Self::TemporaryError => 1,
            // The URL-scope hint, then the explanation text.
            Self::CertificateRequired => 1,
            // Everything else is a single free-text parameter, or none.
            _ => 0,
        }
    }
}

/// A two-digit Scorpion status code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Status(u8);

impl Status {
    /// Beginning of two-way communication (`I` only).
    pub const INTERACTIVE: Self = Self(0);
    /// Input required.
    pub const INPUT: Self = Self(10);
    /// Success.
    pub const OK: Self = Self(20);
    /// Success, but only the requested range of the file.
    pub const PARTIAL: Self = Self(21);
    /// Success, for a metadata request rather than the file itself.
    pub const METADATA: Self = Self(22);
    /// Temporary redirect.
    pub const TEMPORARY_REDIRECT: Self = Self(30);
    /// Permanent redirect.
    pub const PERMANENT_REDIRECT: Self = Self(31);
    /// Temporary error, no more specific code.
    pub const TEMPORARY_ERROR: Self = Self(40);
    /// Down for maintenance.
    pub const MAINTENANCE: Self = Self(41);
    /// A dynamic file failed temporarily, such as a timeout.
    pub const DYNAMIC_FAILURE: Self = Self(42);
    /// The server could not complete a proxied request.
    pub const PROXY_ERROR: Self = Self(43);
    /// The client is sending requests too fast.
    pub const SLOW_DOWN: Self = Self(44);
    /// Temporarily locked file (`S` only).
    pub const LOCKED: Self = Self(45);
    /// Permanent error, no more specific code.
    pub const PERMANENT_ERROR: Self = Self(50);
    /// File not found.
    pub const NOT_FOUND: Self = Self(51);
    /// Gone, and not expected to exist again. Also a permanent lock under `S`.
    pub const GONE: Self = Self(52);
    /// A proxied request was refused.
    pub const PROXY_REFUSED: Self = Self(53);
    /// Forbidden; credentials probably will not help.
    pub const FORBIDDEN: Self = Self(54);
    /// Edit conflict (`S` only).
    pub const CONFLICT: Self = Self(55);
    /// A username and/or password are required, or the ones given were wrong.
    pub const AUTH_REQUIRED: Self = Self(56);
    /// Bad request.
    pub const BAD_REQUEST: Self = Self(59);
    /// A client certificate is required and none was given.
    pub const CERTIFICATE_REQUIRED: Self = Self(60);
    /// The certificate given is not authorized for this file.
    pub const CERTIFICATE_UNAUTHORIZED: Self = Self(61);
    /// The certificate given is not valid.
    pub const CERTIFICATE_INVALID: Self = Self(62);
    /// Ready to receive a new file.
    pub const READY_NEW: Self = Self(70);
    /// Ready to receive a replacement for an existing file.
    pub const READY_REPLACE: Self = Self(71);
    /// Ready to receive data for something other than a file.
    pub const READY_OTHER: Self = Self(72);
    /// Accepted, and a new file was created.
    pub const ACCEPTED_NEW: Self = Self(80);
    /// Accepted, and an existing file was modified.
    pub const ACCEPTED_MODIFIED: Self = Self(81);
    /// Accepted, for something other than a file.
    pub const ACCEPTED_OTHER: Self = Self(82);

    /// Build a status from two digits, refusing a leading `9`.
    ///
    /// Any *minor* digit is accepted: a server may define codes this crate
    /// does not know, and a client is expected to fall back to the major
    /// class rather than reject the response.
    pub fn new(major: u8, minor: u8) -> Option<Self> {
        if major > 8 || minor > 9 {
            return None;
        }
        Some(Self(major * 10 + minor))
    }

    /// The full two-digit code.
    pub fn code(self) -> u8 {
        self.0
    }

    /// The major class.
    pub fn major(self) -> Major {
        Major::from_digit(self.0 / 10).expect("a Status can only hold digits 0 to 8")
    }

    /// The minor digit, which a client is permitted to ignore.
    pub fn minor(self) -> u8 {
        self.0 % 10
    }

    /// Whether the file's bytes follow the status line.
    pub fn has_body(self) -> bool {
        self.major().has_body()
    }

    /// The two ASCII digits this code is written as.
    pub fn to_ascii(self) -> [u8; 2] {
        [b'0' + self.0 / 10, b'0' + self.0 % 10]
    }

    fn leading_parameters(self) -> usize {
        self.major().leading_parameters()
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02}", self.0)
    }
}

/// Split a status line's parameter text the way its major code dictates.
///
/// The final parameter may contain spaces, so this splits at most
/// `leading + 1` ways and hands the remainder back whole.
pub(crate) fn split_parameters(status: Status, rest: &str) -> Vec<&str> {
    let leading = status.leading_parameters();
    if rest.is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::with_capacity(leading + 1);
    let mut remainder = rest;
    for _ in 0..leading {
        match remainder.split_once(' ') {
            Some((head, tail)) => {
                parts.push(head);
                remainder = tail;
            }
            None => break,
        }
    }
    if !remainder.is_empty() {
        parts.push(remainder);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minor_code_this_crate_never_heard_of_still_parses_by_class() {
        // The property that matters: a server may define its own minor codes,
        // and a client must still route on the major class rather than reject
        // the response outright.
        let invented = Status::new(5, 7).expect("57 is a well-formed code");
        assert_eq!(invented.major(), Major::PermanentError);
        assert_eq!(invented.code(), 57);
        assert_eq!(invented.minor(), 7);
    }

    #[test]
    fn nine_is_not_a_status_class() {
        assert_eq!(Status::new(9, 0), None, "the spec defines 0x through 8x");
        assert_eq!(Major::from_digit(9), None);
    }

    #[test]
    fn only_success_carries_a_body() {
        // 8x shares 2x's parameters but explicitly omits the file data. This
        // is the near-miss the type system should be holding, not the reader.
        assert!(Status::OK.has_body());
        assert!(Status::PARTIAL.has_body());
        assert!(Status::METADATA.has_body());
        assert!(!Status::ACCEPTED_NEW.has_body());
        assert!(!Status::READY_NEW.has_body());
        assert!(!Status::INTERACTIVE.has_body());
    }

    #[test]
    fn the_last_parameter_keeps_its_spaces() {
        // A 2x line is `size type [version]`, and a 4x line is
        // `retry-after message` where the message is free text.
        assert_eq!(
            split_parameters(Status::OK, "1234 text/plain;charset=utf-8"),
            vec!["1234", "text/plain;charset=utf-8"]
        );
        assert_eq!(
            split_parameters(Status::TEMPORARY_ERROR, "60 come back later please"),
            vec!["60", "come back later please"]
        );
        assert_eq!(
            split_parameters(Status::NOT_FOUND, "no such file here"),
            vec!["no such file here"],
            "a 5x line is one free-text parameter, spaces and all"
        );
    }

    #[test]
    fn an_absent_retry_estimate_is_still_a_parameter() {
        // The spec allows `?` where the server cannot estimate.
        assert_eq!(
            split_parameters(Status::MAINTENANCE, "? back in a while"),
            vec!["?", "back in a while"]
        );
    }

    #[test]
    fn codes_render_as_two_digits() {
        assert_eq!(Status::INTERACTIVE.to_ascii(), *b"00");
        assert_eq!(Status::OK.to_ascii(), *b"20");
        assert_eq!(Status::ACCEPTED_OTHER.to_ascii(), *b"82");
        assert_eq!(Status::INTERACTIVE.to_string(), "00");
    }
}
