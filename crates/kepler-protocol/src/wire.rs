//! Kepler's request and response grammar.
//!
//! Dependency-free and always compiled, so a consumer that only needs to read
//! or write kepler headers pulls no async runtime.
//!
//! ```text
//! request   = absolute_URI SP last_cached SP language CRLF
//!
//! response  = input / success / redirect / tempfail / permfail / auth / unchanged
//! input     = "1" DIGIT [SP prompt]      CRLF
//! success   = "2" DIGIT SP length updated expires mimetype CRLF body
//! redirect  = "3" DIGIT SP URI-reference CRLF
//! tempfail  = "4" DIGIT [SP errormsg]    CRLF
//! permfail  = "5" DIGIT [SP errormsg]    CRLF
//! auth      = "6" DIGIT [SP errormsg]    CRLF
//! unchanged = "7" DIGIT SP expires       CRLF
//! ```
//!
//! The two things kepler has that its relatives do not are both visible here:
//! the request carries a **last-cached timestamp** and an **acceptable
//! language**, and the response carries **length, last-updated and expires**.
//! That is the only cache model in the small-web family, and `7x` is the
//! answer that uses it: nothing changed, here is when to ask again.

/// Kepler's status classes, one per leading digit. Codes run 10 to 79.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `1x`: input expected; the meta is the prompt.
    Input,
    /// `2x`: success; the header carries the cache metadata and a body follows.
    Success,
    /// `3x`: redirection; the meta is a URI reference.
    Redirect,
    /// `4x`: temporary failure; retrying later is reasonable.
    TemporaryFailure,
    /// `5x`: permanent failure; it is not.
    PermanentFailure,
    /// `6x`: authentication required.
    AuthRequired,
    /// `7x`: cache control. The document is unchanged since `last_cached`, and
    /// the meta is when it expires.
    Unchanged,
}

impl Status {
    /// The class of a two-digit code, or `None` outside 10 to 79.
    pub fn from_code(code: u8) -> Option<Self> {
        match code / 10 {
            1 => Some(Self::Input),
            2 => Some(Self::Success),
            3 => Some(Self::Redirect),
            4 => Some(Self::TemporaryFailure),
            5 => Some(Self::PermanentFailure),
            6 => Some(Self::AuthRequired),
            7 => Some(Self::Unchanged),
            _ => None,
        }
    }
}

/// The cache metadata a `2x` response carries.
///
/// Each timestamp is seconds from the Unix epoch, and **-1 means unknown**,
/// which the spec uses for a non-idempotent or unbounded document. They are
/// kept as `i64` rather than `Option<u64>` so `-1` survives a round trip
/// exactly as the server wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheInfo {
    /// Body length in bytes; `-1` if unknown, in which case the body runs to
    /// end of stream.
    pub length: i64,
    /// When the document last changed; `-1` if unknown.
    pub last_updated: i64,
    /// When the document goes stale; `-1` if unknown.
    pub expires: i64,
}

impl CacheInfo {
    /// Whether the body length was declared.
    pub fn has_length(&self) -> bool {
        self.length >= 0
    }
}

/// A parsed response header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Header {
    /// `2x`: cache metadata, MIME type, and a body to follow.
    Success {
        code: u8,
        cache: CacheInfo,
        mimetype: String,
    },
    /// `7x`: unchanged since the request's `last_cached`; the value is when it
    /// expires. No body follows.
    Unchanged { code: u8, expires: i64 },
    /// Every other class: a code and an optional message. No body follows.
    Meta {
        code: u8,
        status: Status,
        meta: String,
    },
}

impl Header {
    /// The two-digit code.
    pub fn code(&self) -> u8 {
        match self {
            Self::Success { code, .. } | Self::Unchanged { code, .. } | Self::Meta { code, .. } => {
                *code
            }
        }
    }

    /// The status class.
    pub fn status(&self) -> Status {
        match self {
            Self::Success { .. } => Status::Success,
            Self::Unchanged { .. } => Status::Unchanged,
            Self::Meta { status, .. } => *status,
        }
    }
}

/// What a malformed header looked like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedHeader(pub String);

impl std::fmt::Display for MalformedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed kepler header: {}", self.0)
    }
}

impl std::error::Error for MalformedHeader {}

/// Build a request line, including its CRLF.
///
/// `last_cached` is seconds from the epoch, or `0` for "I have nothing
/// cached". `language` is an RFC 7231 accept-language value.
///
/// ```
/// assert_eq!(
///     kepler_protocol::request_line("keplers://example.net/index.md", 0, "en"),
///     "keplers://example.net/index.md 0 en\r\n"
/// );
/// ```
pub fn request_line(uri: &str, last_cached: i64, language: &str) -> String {
    format!("{uri} {last_cached} {language}\r\n")
}

/// A parsed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub uri: String,
    pub last_cached: i64,
    pub language: String,
}

/// Parse a request line, which is what a server does.
pub fn parse_request(line: &str) -> Result<Request, MalformedHeader> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut fields = line.split(' ');
    let uri = fields
        .next()
        .filter(|u| !u.is_empty())
        .ok_or_else(|| MalformedHeader(line.to_string()))?;
    if uri.len() > MAX_URI {
        return Err(MalformedHeader(format!("URI exceeds {MAX_URI} bytes")));
    }
    // Both trailing fields are optional in practice; a bare URI is still a
    // request, so default rather than refuse.
    let last_cached = fields
        .next()
        .map(|t| {
            t.parse::<i64>()
                .map_err(|_| MalformedHeader(line.to_string()))
        })
        .transpose()?
        .unwrap_or(0);
    let language = fields.next().unwrap_or("").to_string();

    Ok(Request {
        uri: uri.to_string(),
        last_cached,
        language,
    })
}

/// The spec's cap on a request URI.
pub const MAX_URI: usize = 1024;

/// Parse a response header line (without its CRLF).
///
/// ```
/// use kepler_protocol::{Header, parse_header};
///
/// // The specification's own example.
/// let header = parse_header("20 1548 1777745482 1777759482 text/markdown").unwrap();
/// match header {
///     Header::Success { code, cache, mimetype } => {
///         assert_eq!(code, 20);
///         assert_eq!(cache.length, 1548);
///         assert_eq!(cache.expires, 1777759482);
///         assert_eq!(mimetype, "text/markdown");
///     }
///     other => panic!("expected a success, got {other:?}"),
/// }
/// ```
pub fn parse_header(line: &str) -> Result<Header, MalformedHeader> {
    let line = line.trim_end_matches(['\r', '\n']);
    let bad = || MalformedHeader(line.to_string());

    let bytes = line.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(bad());
    }
    let code = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    let status = Status::from_code(code).ok_or_else(bad)?;
    let rest = line.get(2..).unwrap_or("").trim_start();

    match status {
        Status::Success => {
            // length, last_updated, expires, then the MIME type.
            let mut fields = rest.splitn(4, ' ');
            let mut number = || -> Result<i64, MalformedHeader> {
                fields
                    .next()
                    .ok_or_else(bad)?
                    .parse::<i64>()
                    .map_err(|_| bad())
            };
            let length = number()?;
            let last_updated = number()?;
            let expires = number()?;
            let mimetype = fields.next().ok_or_else(bad)?.trim().to_string();
            if mimetype.is_empty() {
                return Err(bad());
            }
            Ok(Header::Success {
                code,
                cache: CacheInfo {
                    length,
                    last_updated,
                    expires,
                },
                mimetype,
            })
        }
        Status::Unchanged => {
            let expires = rest.split(' ').next().ok_or_else(bad)?;
            Ok(Header::Unchanged {
                code,
                expires: expires.parse::<i64>().map_err(|_| bad())?,
            })
        }
        _ => Ok(Header::Meta {
            code,
            status,
            meta: rest.to_string(),
        }),
    }
}

/// Render a header back to the wire, including its CRLF.
pub fn format_header(header: &Header) -> String {
    match header {
        Header::Success {
            code,
            cache,
            mimetype,
        } => format!(
            "{code} {} {} {} {mimetype}\r\n",
            cache.length, cache.last_updated, cache.expires
        ),
        Header::Unchanged { code, expires } => format!("{code} {expires}\r\n"),
        Header::Meta { code, meta, .. } => {
            if meta.is_empty() {
                format!("{code}\r\n")
            } else {
                format!("{code} {meta}\r\n")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_specifications_own_success_example_parses() {
        let header = parse_header("20 1548 1777745482 1777759482 text/markdown").unwrap();
        assert_eq!(
            header,
            Header::Success {
                code: 20,
                cache: CacheInfo {
                    length: 1548,
                    last_updated: 1_777_745_482,
                    expires: 1_777_759_482,
                },
                mimetype: "text/markdown".into(),
            }
        );
    }

    #[test]
    fn minus_one_is_unknown_and_survives_the_round_trip() {
        let header = parse_header("20 -1 -1 -1 text/gemini").unwrap();
        let Header::Success { cache, .. } = &header else {
            panic!("expected success");
        };
        assert!(!cache.has_length(), "-1 length means read to end of stream");
        assert_eq!(format_header(&header), "20 -1 -1 -1 text/gemini\r\n");
    }

    #[test]
    fn a_mimetype_keeps_its_parameters() {
        let header = parse_header("20 5 -1 -1 text/gemini; charset=utf-8").unwrap();
        let Header::Success { mimetype, .. } = header else {
            panic!("expected success");
        };
        assert_eq!(mimetype, "text/gemini; charset=utf-8");
    }

    #[test]
    fn the_cache_hit_class_carries_only_an_expiry() {
        let header = parse_header("70 1777759482").unwrap();
        assert_eq!(
            header,
            Header::Unchanged {
                code: 70,
                expires: 1_777_759_482
            }
        );
        assert_eq!(header.status(), Status::Unchanged);
    }

    #[test]
    fn every_other_class_is_a_code_and_a_message() {
        for (line, code, status) in [
            ("10 Your name?", 10, Status::Input),
            ("31 kepler://example.net/moved", 31, Status::Redirect),
            ("44 slow down", 44, Status::TemporaryFailure),
            ("51 not found", 51, Status::PermanentFailure),
            ("61 certificate required", 61, Status::AuthRequired),
        ] {
            let header = parse_header(line).unwrap();
            assert_eq!(header.code(), code);
            assert_eq!(header.status(), status);
        }
    }

    #[test]
    fn a_message_is_optional() {
        let header = parse_header("44").unwrap();
        assert_eq!(header.code(), 44);
        assert_eq!(format_header(&header), "44\r\n");
    }

    #[test]
    fn codes_outside_ten_to_seventy_nine_are_refused() {
        assert!(parse_header("09 nope").is_err());
        assert!(parse_header("80 nope").is_err());
        assert!(parse_header("99 nope").is_err());
    }

    #[test]
    fn a_success_missing_its_metadata_is_refused() {
        assert!(parse_header("20 text/gemini").is_err());
        assert!(parse_header("20 1548 1777745482 text/gemini").is_err());
        assert!(parse_header("20 1548 1777745482 1777759482").is_err());
    }

    #[test]
    fn a_non_numeric_status_is_refused() {
        assert!(parse_header("xx nope").is_err());
        assert!(parse_header("").is_err());
    }

    #[test]
    fn the_request_line_matches_the_specifications_example() {
        assert_eq!(
            request_line("keplers://example.net/index.md", 0, "en"),
            "keplers://example.net/index.md 0 en\r\n"
        );
    }

    #[test]
    fn what_the_client_writes_the_server_reads_back() {
        let line = request_line("kepler://example.net/a", 1_777_745_482, "en-GB");
        assert_eq!(
            parse_request(&line).unwrap(),
            Request {
                uri: "kepler://example.net/a".into(),
                last_cached: 1_777_745_482,
                language: "en-GB".into(),
            }
        );
    }

    #[test]
    fn a_bare_uri_is_still_a_request() {
        let request = parse_request("kepler://example.net/a\r\n").unwrap();
        assert_eq!(request.last_cached, 0);
        assert_eq!(request.language, "");
    }

    #[test]
    fn an_over_long_request_is_refused_at_the_specifications_cap() {
        let long = format!("kepler://example.net/{}", "x".repeat(MAX_URI));
        assert!(parse_request(&long).is_err());
    }

    #[test]
    fn uri_ceiling_excludes_cache_language_and_crlf() {
        let uri = format!("kepler://x/{}", "x".repeat(MAX_URI - "kepler://x/".len()));
        let line = request_line(&uri, i64::MIN, "en-GB,en;q=0.8");
        assert!(line.len() > MAX_URI);
        assert_eq!(parse_request(&line).unwrap().uri.len(), MAX_URI);
        assert!(parse_request(&request_line(&(uri + "x"), 0, "en")).is_err());
    }

    #[test]
    fn headers_round_trip_through_both_directions() {
        for line in [
            "20 1548 1777745482 1777759482 text/markdown",
            "70 1777759482",
            "31 kepler://example.net/moved",
            "51 not found",
        ] {
            let header = parse_header(line).unwrap();
            let rendered = format_header(&header);
            assert_eq!(rendered, format!("{line}\r\n"));
            assert_eq!(parse_header(&rendered).unwrap(), header);
        }
    }
}
