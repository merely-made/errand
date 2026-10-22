//! Scroll's request and response grammar.
//!
//! Dependency-free and always compiled.
//!
//! ```text
//! request           = <URI> SP <LanguageList> CRLF
//! metadata request  = <URI> SP "+" <LanguageList> CRLF
//!
//! success  = "2" DIGIT SP <Mimetype> CRLF
//!            <Author> CRLF
//!            <PublishDate> CRLF
//!            <ModificationDate> CRLF
//!            <Data>
//! other    = <Status> SP <Description> CRLF
//! ```
//!
//! Two things distinguish scroll from its gemini base. The request carries the
//! client's **acceptable languages** (BCP47, comma-separated, most-preferred
//! first), and a success response carries **three metadata lines** before the
//! body: author, publish date, modification date, each possibly blank. Status
//! codes are gemini's, except that a success's second digit is a **Universal
//! Decimal Classification class** rather than free.

/// Scroll's well-known port (not stated in the spec text; confirmed against
/// the smolnet-portal implementation, which proxies real scroll servers).
pub const DEFAULT_PORT: u16 = 5699;

/// Status classes, one per leading digit — gemini's, by the spec's own
/// reference: "Status codes remain the same as in Gemini."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `1x`: input wanted; the description is the prompt. `11` is sensitive
    /// input (a password), which a client should mask.
    Input,
    /// `2x`: success. The second digit is the document's [`UdcClass`].
    Success,
    /// `3x`: redirect.
    Redirect,
    /// `4x`: temporary failure.
    TemporaryFailure,
    /// `5x`: permanent failure.
    PermanentFailure,
    /// `6x`: a client certificate is required.
    CertificateRequired,
}

impl Status {
    pub fn from_code(code: u8) -> Option<Self> {
        match code / 10 {
            1 => Some(Self::Input),
            2 => Some(Self::Success),
            3 => Some(Self::Redirect),
            4 => Some(Self::TemporaryFailure),
            5 => Some(Self::PermanentFailure),
            6 => Some(Self::CertificateRequired),
            _ => None,
        }
    }
}

/// The Universal Decimal Classification class a success code's second digit
/// names. Scroll is the only small-web protocol whose responses classify
/// their own subject matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdcClass {
    /// 0: general knowledge, documentation, computer science, news, data.
    Science,
    /// 1: philosophy, psychology.
    Philosophy,
    /// 2: religion, theology, scripture.
    Religion,
    /// 3: social sciences, law, politics, economics, education.
    SocialSciences,
    /// 4: the default: general menus, indexes, directories, unclassed media.
    General,
    /// 5: mathematics, natural science.
    Mathematics,
    /// 6: applied science, medicine, technology, engineering.
    AppliedScience,
    /// 7: arts, entertainment, sport, fitness.
    Arts,
    /// 8: linguistics, literature, memoirs, personal logs, reviews.
    Literature,
    /// 9: geography, history, biography.
    History,
}

impl UdcClass {
    /// The class a success code carries in its second digit.
    pub fn from_code(code: u8) -> Option<Self> {
        if !(20..30).contains(&code) {
            return None;
        }
        Some(match code % 10 {
            0 => Self::Science,
            1 => Self::Philosophy,
            2 => Self::Religion,
            3 => Self::SocialSciences,
            4 => Self::General,
            5 => Self::Mathematics,
            6 => Self::AppliedScience,
            7 => Self::Arts,
            8 => Self::Literature,
            _ => Self::History,
        })
    }
}

/// Build a request line, including its CRLF.
///
/// `languages` are BCP47 tags, most preferred first. `metadata` asks for the
/// resource's abstract instead of its body (the `+` prefix on the language
/// list).
///
/// ```
/// assert_eq!(
///     scroll_protocol::request_line("scroll://example.net/page.scroll", &["en-US", "en"], false),
///     "scroll://example.net/page.scroll en-US,en\r\n"
/// );
/// assert_eq!(
///     scroll_protocol::request_line("scroll://example.net/page.scroll", &["en"], true),
///     "scroll://example.net/page.scroll +en\r\n"
/// );
/// ```
pub fn request_line(uri: &str, languages: &[&str], metadata: bool) -> String {
    let plus = if metadata { "+" } else { "" };
    format!("{uri} {plus}{}\r\n", languages.join(","))
}

/// A parsed request, which is what a server reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub uri: String,
    pub languages: Vec<String>,
    /// Whether the `+` metadata flag was present.
    pub metadata: bool,
}

/// Parse a request line.
pub fn parse_request(line: &str) -> Option<Request> {
    let line = line.trim_end_matches(['\r', '\n']);
    // The spec forbids a leading byte order mark.
    if line.starts_with('\u{FEFF}') {
        return None;
    }
    let (uri, rest) = match line.split_once(' ') {
        Some((uri, rest)) => (uri, rest),
        None => (line, ""),
    };
    if uri.is_empty() {
        return None;
    }
    let (metadata, list) = match rest.strip_prefix('+') {
        Some(list) => (true, list),
        None => (false, rest),
    };
    Some(Request {
        uri: uri.to_string(),
        languages: list
            .split(',')
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        metadata,
    })
}

/// A success response's header: the status line plus the three metadata lines.
///
/// Dates are kept **verbatim** as the ISO 8601 strings the server sent, rather
/// than parsed into a date type: the crate takes no time dependency, and a
/// projection layer deciding how to render a date should see exactly what was
/// said. A blank line means unspecified and surfaces as `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessHeader {
    /// The full two-digit code, e.g. `20`, `24`, `27`.
    pub code: u8,
    pub mimetype: String,
    pub author: Option<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
}

impl SuccessHeader {
    /// The UDC class the second digit names.
    pub fn class(&self) -> Option<UdcClass> {
        UdcClass::from_code(self.code)
    }
}

/// A response header: either a success with its metadata, or a status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Header {
    Success(SuccessHeader),
    /// Every non-`2x` class: the code and its description. For `1x` the
    /// description is the input prompt.
    Meta {
        code: u8,
        status: Status,
        meta: String,
    },
}

/// A native response, ready for a caller-owned transport. An abstract response
/// uses the same header and puts the exact abstract bytes in `body`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub header: Header,
    pub body: Vec<u8>,
}

/// Host-selected response limits. Header limits include each line's CRLF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseLimits {
    pub max_header_line_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            max_header_line_bytes: 4096,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// A response cannot be represented faithfully within the supplied limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedReply(pub String);

impl std::fmt::Display for MalformedReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid scroll reply: {}", self.0)
    }
}

impl std::error::Error for MalformedReply {}

impl Reply {
    /// Validate before producing any wire bytes. Header fields must be single
    /// lines without control characters; dates stay verbatim, as in
    /// [`SuccessHeader`]. Content metadata semantics belong to the publisher.
    /// The encoder does not select a language, document, or abstract.
    pub fn encode(&self, limits: ResponseLimits) -> Result<Vec<u8>, MalformedReply> {
        let invalid = |message: &str| MalformedReply(message.into());
        if self.body.len() > limits.max_body_bytes {
            return Err(invalid("body exceeds host limit"));
        }
        let mut lines = Vec::with_capacity(4);
        match &self.header {
            Header::Success(header) => {
                if UdcClass::from_code(header.code).is_none()
                    || header.mimetype.is_empty()
                    || header.mimetype.trim() != header.mimetype
                    || !valid_media_type(&header.mimetype)
                {
                    return Err(invalid("invalid success code or MIME metadata"));
                }
                lines.push(format!("{} {}", header.code, header.mimetype));
                lines.push(header.author.clone().unwrap_or_default());
                lines.push(header.published.clone().unwrap_or_default());
                lines.push(header.modified.clone().unwrap_or_default());
            }
            Header::Meta { code, status, meta } => {
                if Status::from_code(*code) != Some(*status) || *status == Status::Success {
                    return Err(invalid("invalid or inconsistent status code"));
                }
                if !self.body.is_empty() {
                    return Err(invalid("a non-success response cannot carry a body"));
                }
                lines.push(format!("{code} {meta}"));
            }
        }
        for line in &lines {
            if line.chars().any(char::is_control) {
                return Err(invalid("a header field contains a control character"));
            }
            if line
                .len()
                .checked_add(2)
                .is_none_or(|length| length > limits.max_header_line_bytes)
            {
                return Err(invalid("header line exceeds host limit"));
            }
        }
        let mut out = Vec::new();
        for line in lines {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

fn valid_media_type(value: &str) -> bool {
    let essence = value.split(';').next().unwrap_or("").trim_end();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    };
    token(kind) && token(subtype)
}

/// What a malformed header looked like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedHeader(pub String);

impl std::fmt::Display for MalformedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed scroll header: {}", self.0)
    }
}

impl std::error::Error for MalformedHeader {}

/// Parse a status line (without its CRLF). For a `2x` this yields the
/// mimetype; the caller then reads the three metadata lines and finishes with
/// [`finish_success`].
pub fn parse_status_line(line: &str) -> Result<(u8, Status, String), MalformedHeader> {
    let line = line.trim_end_matches(['\r', '\n']);
    let bad = || MalformedHeader(line.to_string());
    let bytes = line.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(bad());
    }
    let code = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    let status = Status::from_code(code).ok_or_else(bad)?;
    Ok((
        code,
        status,
        line.get(2..).unwrap_or("").trim_start().to_string(),
    ))
}

/// Assemble a [`SuccessHeader`] from the status line's parts and the three
/// metadata lines that followed it. A blank line is `None`.
pub fn finish_success(
    code: u8,
    mimetype: String,
    author: &str,
    published: &str,
    modified: &str,
) -> SuccessHeader {
    let optional = |line: &str| {
        let line = line.trim_end_matches(['\r', '\n']).trim();
        (!line.is_empty()).then(|| line.to_string())
    };
    SuccessHeader {
        code,
        mimetype,
        author: optional(author),
        published: optional(published),
        modified: optional(modified),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_carries_its_languages_in_order() {
        let request = parse_request("scroll://example.net/ en-US,en,de-CH\r\n").unwrap();
        assert_eq!(request.uri, "scroll://example.net/");
        assert_eq!(request.languages, vec!["en-US", "en", "de-CH"]);
        assert!(!request.metadata);
    }

    #[test]
    fn the_plus_prefix_is_a_metadata_request() {
        let request = parse_request("scroll://example.net/doc.scroll +en\r\n").unwrap();
        assert!(request.metadata);
        assert_eq!(request.languages, vec!["en"]);
    }

    #[test]
    fn what_the_client_writes_the_server_reads_back() {
        for (languages, metadata) in [(vec!["en-US", "en"], false), (vec!["fr"], true)] {
            let refs: Vec<&str> = languages.iter().map(|s| &**s).collect();
            let line = request_line("scroll://x/", &refs, metadata);
            let parsed = parse_request(&line).unwrap();
            assert_eq!(parsed.languages, languages);
            assert_eq!(parsed.metadata, metadata);
        }
    }

    #[test]
    fn a_byte_order_mark_is_refused_as_the_spec_requires() {
        assert!(parse_request("\u{FEFF}scroll://x/ en\r\n").is_none());
    }

    #[test]
    fn a_bare_uri_is_a_request_with_no_language_preference() {
        let request = parse_request("scroll://example.net/\r\n").unwrap();
        assert!(request.languages.is_empty());
        assert!(!request.metadata);
    }

    #[test]
    fn status_codes_are_geminis() {
        assert_eq!(parse_status_line("10 Name?").unwrap().1, Status::Input);
        assert_eq!(
            parse_status_line("31 scroll://x/moved").unwrap().1,
            Status::Redirect
        );
        assert_eq!(
            parse_status_line("44 slow down").unwrap().1,
            Status::TemporaryFailure
        );
        assert_eq!(
            parse_status_line("51 gone").unwrap().1,
            Status::PermanentFailure
        );
        assert_eq!(
            parse_status_line("60 cert").unwrap().1,
            Status::CertificateRequired
        );
        assert!(parse_status_line("70 nope").is_err(), "scroll has no 7x");
        assert!(parse_status_line("xx nope").is_err());
    }

    #[test]
    fn the_second_success_digit_is_a_udc_class() {
        // The spec's own examples: 24 is the unclassed default, 27 is arts
        // and entertainment.
        assert_eq!(UdcClass::from_code(24), Some(UdcClass::General));
        assert_eq!(UdcClass::from_code(27), Some(UdcClass::Arts));
        assert_eq!(UdcClass::from_code(20), Some(UdcClass::Science));
        assert_eq!(UdcClass::from_code(29), Some(UdcClass::History));
        assert_eq!(UdcClass::from_code(31), None, "not a success code");
    }

    #[test]
    fn a_success_header_assembles_with_blanks_as_none() {
        // The vendored spec's own document is the fixture: author present,
        // both dates present.
        let header = finish_success(
            20,
            "text/scroll".into(),
            "Christian Lee Seibold",
            "2025-07-23T20:50:51Z",
            "",
        );
        assert_eq!(header.author.as_deref(), Some("Christian Lee Seibold"));
        assert_eq!(header.published.as_deref(), Some("2025-07-23T20:50:51Z"));
        assert_eq!(header.modified, None, "a blank line is unspecified");
        assert_eq!(header.class(), Some(UdcClass::Science));
    }

    fn native_reply() -> Reply {
        Reply {
            header: Header::Success(SuccessHeader {
                code: 27,
                mimetype: "text/scroll;charset=utf-8;lang=fr".into(),
                author: Some("Écrivain".into()),
                published: Some("2026-10-21T12:00:00Z".into()),
                modified: None,
            }),
            body: b"# Title\r\nSaved bytes\r\n".to_vec(),
        }
    }

    #[test]
    fn native_reply_preserves_every_line_and_exact_body() {
        let reply = native_reply();
        assert_eq!(reply.encode(ResponseLimits::default()).unwrap(),
            "27 text/scroll;charset=utf-8;lang=fr\r\nÉcrivain\r\n2026-10-21T12:00:00Z\r\n\r\n# Title\r\nSaved bytes\r\n".as_bytes());
        let abstract_reply = Reply {
            body: b"# Abstract\n".to_vec(),
            ..reply
        };
        assert!(
            abstract_reply
                .encode(ResponseLimits::default())
                .unwrap()
                .ends_with(b"\r\n\r\n# Abstract\n")
        );
    }

    #[test]
    fn reply_limits_include_crlf_and_refuse_before_encoding() {
        let reply = native_reply();
        let line_bytes = "27 text/scroll;charset=utf-8;lang=fr\r\n".len();
        let limits = ResponseLimits {
            max_header_line_bytes: line_bytes,
            max_body_bytes: reply.body.len(),
        };
        assert!(reply.encode(limits).is_ok());
        assert!(
            reply
                .encode(ResponseLimits {
                    max_header_line_bytes: line_bytes - 1,
                    ..limits
                })
                .is_err()
        );
        assert!(
            reply
                .encode(ResponseLimits {
                    max_body_bytes: reply.body.len() - 1,
                    ..limits
                })
                .is_err()
        );
    }

    #[test]
    fn reply_rejects_header_injection_and_invalid_native_metadata() {
        for field in 0..4 {
            let mut reply = native_reply();
            let Header::Success(header) = &mut reply.header else {
                unreachable!()
            };
            match field {
                0 => header.mimetype.push_str("\r\n51 injected"),
                1 => header.author = Some("writer\nother".into()),
                2 => header.published = Some("date\rnext".into()),
                _ => header.modified = Some("date\0next".into()),
            }
            assert!(reply.encode(ResponseLimits::default()).is_err());
        }
        for mime in ["", " text/scroll", "text", "text/", "text/scroll extra"] {
            let mut reply = native_reply();
            let Header::Success(header) = &mut reply.header else {
                unreachable!()
            };
            header.mimetype = mime.into();
            assert!(reply.encode(ResponseLimits::default()).is_err(), "{mime:?}");
        }
        let mut reply = native_reply();
        let Header::Success(header) = &mut reply.header else {
            unreachable!()
        };
        header.code = 30;
        assert!(reply.encode(ResponseLimits::default()).is_err());
    }

    #[test]
    fn non_success_has_one_line_and_no_body() {
        let mut reply = Reply {
            header: Header::Meta {
                code: 51,
                status: Status::PermanentFailure,
                meta: "Not found".into(),
            },
            body: vec![],
        };
        assert_eq!(
            reply.encode(ResponseLimits::default()).unwrap(),
            b"51 Not found\r\n"
        );
        reply.body.push(1);
        assert!(reply.encode(ResponseLimits::default()).is_err());
        reply.body.clear();
        reply.header = Header::Meta {
            code: 51,
            status: Status::Input,
            meta: String::new(),
        };
        assert!(reply.encode(ResponseLimits::default()).is_err());
        reply.header = Header::Meta {
            code: 20,
            status: Status::Success,
            meta: "text/scroll".into(),
        };
        assert!(reply.encode(ResponseLimits::default()).is_err());
    }
}
