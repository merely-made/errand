//! Scorpion response headers: the status line, and what its parameters mean.
//!
//! A response is a status line, and for `2x` the file's bytes after it:
//!
//! ```text
//! <status> <parameters...>\r\n
//! [body]
//! ```
//!
//! How many parameters there are is decided by the major status code, and the
//! last one may contain spaces. [`Header::parse`] does that split; the typed
//! accessors below read the parameters each class actually defines.

use core::fmt;

use crate::status::{Status, split_parameters};

/// A declared file size, which the specification allows a server to leave
/// unknown for dynamic files by writing `?`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Size {
    /// A definite byte count.
    Known(u64),
    /// The server does not know, because the file is generated.
    Unknown,
}

impl Size {
    /// The byte count, when there is one.
    pub fn known(self) -> Option<u64> {
        match self {
            Self::Known(size) => Some(size),
            Self::Unknown => None,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        if text == "?" {
            return Some(Self::Unknown);
        }
        text.parse().ok().map(Self::Known)
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(size) => write!(f, "{size}"),
            Self::Unknown => f.write_str("?"),
        }
    }
}

/// How long to wait before retrying, from a `4x` response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryAfter {
    /// Wait this many seconds. The specification bounds it to an unsigned
    /// 31-bit number.
    Seconds(u32),
    /// The server cannot estimate.
    Unknown,
}

impl RetryAfter {
    /// The delay, when the server gave one.
    pub fn seconds(self) -> Option<u32> {
        match self {
            Self::Seconds(seconds) => Some(seconds),
            Self::Unknown => None,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        if text == "?" {
            return Some(Self::Unknown);
        }
        // "it must be an unsigned 31-bit number", so a value that overflows
        // that is out of spec rather than merely large.
        let seconds: u32 = text.parse().ok()?;
        (seconds < (1 << 31)).then_some(Self::Seconds(seconds))
    }
}

/// Which URLs a client certificate should be offered for, from a `6x`
/// response. One character, then a URL that may be empty.
///
/// The specification is emphatic that this is "only a hint and is not a
/// requirement", and that clients "MUST allow the user to override" it, so
/// nothing here decides anything on the user's behalf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateScope {
    /// How the URL is matched.
    pub match_kind: ScopeMatch,
    /// The URL the match applies to. Empty means the current URL.
    pub url: String,
}

/// The leading character of a [`CertificateScope`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeMatch {
    /// `=` -- only that exact URL, fragments aside.
    Exact,
    /// `+` -- that URL with any query string, or none.
    AnyQuery,
    /// `*` -- that URL and anything beneath it.
    Prefix,
    /// `-` -- an unspecified set that includes the URL.
    Unspecified,
}

impl ScopeMatch {
    fn from_char(c: char) -> Option<Self> {
        Some(match c {
            '=' => Self::Exact,
            '+' => Self::AnyQuery,
            '*' => Self::Prefix,
            '-' => Self::Unspecified,
            _ => return None,
        })
    }
}

impl CertificateScope {
    fn parse(text: &str) -> Option<Self> {
        let mut chars = text.chars();
        let match_kind = ScopeMatch::from_char(chars.next()?)?;
        Some(Self {
            match_kind,
            url: chars.as_str().to_string(),
        })
    }
}

/// Why a status line could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    /// The line was shorter than a status code, or held no digits.
    Malformed,
    /// The leading digit was `9`, which the specification does not define.
    UnknownStatusClass,
    /// A `2x` line did not carry the size and type it must.
    MissingParameters,
    /// The declared size was neither a number nor `?`.
    MalformedSize,
    /// The status line exceeded the caller's limit.
    TooLong,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "status line is malformed",
            Self::UnknownStatusClass => "status class 9 is not defined",
            Self::MissingParameters => "a success response must declare a size and a type",
            Self::MalformedSize => "declared size is neither a number nor '?'",
            Self::TooLong => "status line exceeds the permitted length",
        })
    }
}

impl core::error::Error for ResponseError {}

/// A parsed status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The two-digit code.
    pub status: Status,
    /// Its parameters, already split according to the major code.
    pub parameters: Vec<String>,
}

impl Header {
    /// Parse a status line, with or without its trailing `\r\n`.
    pub fn parse(line: &str) -> Result<Self, ResponseError> {
        let line = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);

        let digits = line.as_bytes();
        if digits.len() < 2 || !digits[0].is_ascii_digit() || !digits[1].is_ascii_digit() {
            return Err(ResponseError::Malformed);
        }
        let status = Status::new(digits[0] - b'0', digits[1] - b'0')
            .ok_or(ResponseError::UnknownStatusClass)?;

        // A space separates the code from the parameters, but a bare status
        // line with neither is still well formed.
        let rest = match line.get(2..) {
            None | Some("") => "",
            Some(rest) => rest.strip_prefix(' ').ok_or(ResponseError::Malformed)?,
        };

        Ok(Self {
            status,
            parameters: split_parameters(status, rest)
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
    }

    /// Render this header as it goes on the wire, `\r\n` included.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut line = Vec::new();
        line.extend_from_slice(&self.status.to_ascii());
        for parameter in &self.parameters {
            line.push(b' ');
            line.extend_from_slice(parameter.as_bytes());
        }
        line.extend_from_slice(b"\r\n");
        line
    }

    /// A `2x` response's declared size, type, and optional version.
    ///
    /// Returns `None` for any other class, so a caller cannot read a `4x`
    /// line's retry seconds as a file size by accident.
    pub fn success(&self) -> Option<Result<Success<'_>, ResponseError>> {
        use crate::status::Major;
        if !matches!(self.status.major(), Major::Success | Major::Accepted) {
            return None;
        }
        // 8x omits its parameters entirely when the file was deleted.
        if self.parameters.is_empty() && self.status.major() == Major::Accepted {
            return Some(Ok(Success {
                size: Size::Unknown,
                media_type: "",
                version: None,
            }));
        }
        if self.parameters.len() < 2 {
            return Some(Err(ResponseError::MissingParameters));
        }
        let Some(size) = Size::parse(&self.parameters[0]) else {
            return Some(Err(ResponseError::MalformedSize));
        };
        Some(Ok(Success {
            size,
            media_type: &self.parameters[1],
            version: self.parameters.get(2).map(String::as_str),
        }))
    }

    /// A `3x` response's target URL.
    pub fn redirect(&self) -> Option<&str> {
        (self.status.major() == crate::status::Major::Redirect)
            .then(|| self.parameters.first().map(String::as_str))
            .flatten()
    }

    /// A `1x` response's prompt text.
    pub fn prompt(&self) -> Option<&str> {
        (self.status.major() == crate::status::Major::Input)
            .then(|| self.parameters.first().map(String::as_str))
            .flatten()
    }

    /// A `4x` response's retry delay and message.
    pub fn temporary_error(&self) -> Option<(RetryAfter, Option<&str>)> {
        if self.status.major() != crate::status::Major::TemporaryError {
            return None;
        }
        let retry = self
            .parameters
            .first()
            .and_then(|text| RetryAfter::parse(text))
            .unwrap_or(RetryAfter::Unknown);
        Some((retry, self.parameters.get(1).map(String::as_str)))
    }

    /// A `6x` response's scope hint and explanation.
    pub fn certificate_request(&self) -> Option<(Option<CertificateScope>, Option<&str>)> {
        if self.status.major() != crate::status::Major::CertificateRequired {
            return None;
        }
        Some((
            self.parameters
                .first()
                .and_then(|t| CertificateScope::parse(t)),
            self.parameters.get(1).map(String::as_str),
        ))
    }

    /// The free-text message a `4x` or `5x` carries, if any.
    pub fn message(&self) -> Option<&str> {
        use crate::status::Major;
        match self.status.major() {
            Major::PermanentError => self.parameters.first().map(String::as_str),
            Major::TemporaryError => self.parameters.get(1).map(String::as_str),
            _ => None,
        }
    }
}

/// The parameters of a successful response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Success<'a> {
    /// The size of the **whole** file. For a `21` partial response this is
    /// still the whole file, not the length of the range returned, which is a
    /// distinction a naive reader gets wrong in exactly one direction.
    pub size: Size,
    /// The MIME or ULFI type. The specification prefers ULFI but permits MIME.
    pub media_type: &'a str,
    /// An optional opaque version, usable for conflict detection on upload.
    pub version: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_success_line_parses_size_type_and_version() {
        let header = Header::parse("20 1234 text/plain;charset=utf-8 v7\r\n").unwrap();
        assert_eq!(header.status, Status::OK);
        let success = header.success().unwrap().unwrap();
        assert_eq!(success.size, Size::Known(1234));
        assert_eq!(success.media_type, "text/plain;charset=utf-8");
        assert_eq!(success.version, Some("v7"));
    }

    #[test]
    fn a_dynamic_file_may_decline_to_state_its_size() {
        let header = Header::parse("20 ? text/scorpion").unwrap();
        let success = header.success().unwrap().unwrap();
        assert_eq!(success.size, Size::Unknown);
        assert_eq!(success.size.known(), None);
    }

    #[test]
    fn a_partial_response_reports_the_whole_file_size() {
        // The trap this pins: on a 21, the size parameter "is the entire file
        // size, and not only the requested part". A reader that treats it as
        // the range length will wait forever for bytes that never come.
        let header = Header::parse("21 100000 application/octet-stream").unwrap();
        assert_eq!(header.status, Status::PARTIAL);
        assert_eq!(header.success().unwrap().unwrap().size, Size::Known(100000));
    }

    #[test]
    fn a_deleted_file_accepts_with_no_parameters_at_all() {
        // 8x "parameters are omitted" when the file was deleted, which must
        // not read as a malformed response.
        let header = Header::parse("81").unwrap();
        assert_eq!(header.parameters, Vec::<String>::new());
        assert!(header.success().unwrap().is_ok());
    }

    #[test]
    fn typed_accessors_refuse_to_read_the_wrong_class() {
        // A 4x line's first parameter is a retry delay, not a file size. The
        // accessors return None rather than reinterpreting the bytes.
        let header = Header::parse("44 30 slow down").unwrap();
        assert!(header.success().is_none());
        assert!(header.redirect().is_none());
        let (retry, message) = header.temporary_error().unwrap();
        assert_eq!(retry, RetryAfter::Seconds(30));
        assert_eq!(message, Some("slow down"));
    }

    #[test]
    fn a_retry_estimate_beyond_31_bits_is_out_of_spec() {
        let header = Header::parse("40 4294967295 too big").unwrap();
        let (retry, _) = header.temporary_error().unwrap();
        assert_eq!(
            retry,
            RetryAfter::Unknown,
            "a value the spec forbids degrades to 'no estimate', not to a wrong one"
        );
    }

    #[test]
    fn a_certificate_scope_splits_its_match_character() {
        let header = Header::parse("60 */private/ a member certificate is needed").unwrap();
        let (scope, explanation) = header.certificate_request().unwrap();
        let scope = scope.unwrap();
        assert_eq!(scope.match_kind, ScopeMatch::Prefix);
        assert_eq!(scope.url, "/private/");
        assert_eq!(explanation, Some("a member certificate is needed"));
    }

    #[test]
    fn an_empty_scope_url_means_the_current_url() {
        let header = Header::parse("60 = this exact page only").unwrap();
        let (scope, _) = header.certificate_request().unwrap();
        let scope = scope.unwrap();
        assert_eq!(scope.match_kind, ScopeMatch::Exact);
        assert_eq!(scope.url, "", "empty means the current URL");
    }

    #[test]
    fn a_redirect_carries_its_target() {
        let header = Header::parse("31 scorpion://example.com/moved").unwrap();
        assert_eq!(header.redirect(), Some("scorpion://example.com/moved"));
    }

    #[test]
    fn an_error_message_keeps_its_spaces() {
        let header = Header::parse("51 no such file, maybe it is at Area 51").unwrap();
        assert_eq!(
            header.message(),
            Some("no such file, maybe it is at Area 51")
        );
    }

    #[test]
    fn headers_round_trip() {
        for line in [
            "20 1234 text/plain",
            "31 scorpion://example.com/moved",
            "44 30 slow down",
            "60 */private/ certificate needed",
            "00",
        ] {
            let header = Header::parse(line).unwrap();
            let rendered = header.to_wire();
            assert_eq!(
                String::from_utf8(rendered).unwrap(),
                format!("{line}\r\n"),
                "round trip of {line:?}"
            );
        }
    }

    #[test]
    fn class_nine_is_refused() {
        assert_eq!(
            Header::parse("90 whatever"),
            Err(ResponseError::UnknownStatusClass)
        );
    }
}
