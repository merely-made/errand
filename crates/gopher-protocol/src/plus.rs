//! Gopher+ : the 1993 upward-compatible enhancements to RFC 1436.
//!
//! Gopher+ adds four things to gopher, and this module models three of them
//! (the fourth, the item-line marker, belongs to [`crate::menu`] because it
//! rides in the menu):
//!
//! - a **response header**, so a reply can declare its length instead of
//!   relying on the server closing the connection ([`PlusHeader`]);
//! - **attribute blocks**, metadata about an item retrieved separately from
//!   the item itself ([`AttributeBlock`], [`View`]);
//! - **ASK forms**, the interactive questionnaire a `?` item carries
//!   ([`AskDirective`]).
//!
//! Everything here is pure parsing with no dependencies, so it is available
//! under `default-features = false`.
//!
//! Gopher+ was never an RFC. The reference is "Gopher+: Upward compatible
//! enhancements to the Internet Gopher protocol" (University of Minnesota,
//! 1993).

// ── Response header ────────────────────────────────────────────────────────

/// The first line of a Gopher+ reply.
///
/// The first character is `+` for success or `-` for failure, followed by a
/// decimal token: a byte count, `-1` for a period-terminated body, or `-2` for
/// a body that ends when the connection closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlusHeader {
    /// `+<count>`: the body is exactly this many bytes.
    Length(u64),
    /// `+-1`: read until a `.` on a line of its own.
    PeriodTerminated,
    /// `+-2`: read until the connection closes. Binary-safe, since no
    /// terminator can collide with the payload.
    UntilClose,
    /// `--1`: the request failed. The body carries the error text and is
    /// period-terminated.
    Error,
}

/// What [`parse_header`] could not make sense of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedHeader(pub String);

impl std::fmt::Display for MalformedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed gopher+ header: {}", self.0)
    }
}

impl std::error::Error for MalformedHeader {}

/// Parse a Gopher+ response header line (without its CRLF).
///
/// ```
/// use gopher_protocol::plus::{PlusHeader, parse_header};
///
/// assert_eq!(parse_header("+5340"), Ok(PlusHeader::Length(5340)));
/// assert_eq!(parse_header("+-1"), Ok(PlusHeader::PeriodTerminated));
/// assert_eq!(parse_header("+-2"), Ok(PlusHeader::UntilClose));
/// assert_eq!(parse_header("--1"), Ok(PlusHeader::Error));
/// assert!(parse_header("5340").is_err(), "a header must carry + or -");
/// ```
pub fn parse_header(line: &str) -> Result<PlusHeader, MalformedHeader> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (sign, token) = line
        .split_at_checked(1)
        .ok_or_else(|| MalformedHeader(line.to_string()))?;
    // The token may be followed by whitespace and further text; the number is
    // all that is defined.
    let token = token.split_whitespace().next().unwrap_or("");
    match (sign, token) {
        ("-", _) => Ok(PlusHeader::Error),
        ("+", "-1") => Ok(PlusHeader::PeriodTerminated),
        ("+", "-2") => Ok(PlusHeader::UntilClose),
        ("+", count) => count
            .parse::<u64>()
            .map(PlusHeader::Length)
            .map_err(|_| MalformedHeader(line.to_string())),
        _ => Err(MalformedHeader(line.to_string())),
    }
}

/// What a Gopher+ retrieval asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlusRequest {
    /// `+`: the item itself. The optional representation names one of the
    /// alternates the item's `+VIEWS` block advertises.
    Item(Option<String>),
    /// `!`: this item's attribute blocks.
    Attributes,
    /// `$`: the attribute blocks of every item in a directory.
    DirectoryAttributes,
}

impl PlusRequest {
    /// The token appended after the request's second TAB.
    pub fn token(&self) -> String {
        match self {
            Self::Item(None) => "+".to_string(),
            Self::Item(Some(view)) => format!("+{view}"),
            Self::Attributes => "!".to_string(),
            Self::DirectoryAttributes => "$".to_string(),
        }
    }

    /// Read a token back, which is what a server does with the third field.
    ///
    /// `$` may carry a filter of requested block names (`$+VIEWS+ABSTRACT`);
    /// that filter is advisory, so it is accepted and not modelled.
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim_end_matches(['\r', '\n']);
        match token.chars().next()? {
            '+' => Some(Self::Item({
                let view = &token[1..];
                (!view.is_empty()).then(|| view.to_string())
            })),
            '!' => Some(Self::Attributes),
            '$' => Some(Self::DirectoryAttributes),
            _ => None,
        }
    }
}

// ── Attribute blocks ───────────────────────────────────────────────────────

/// One Gopher+ attribute block.
///
/// A block opens with `+` in column one followed by its name and a colon;
/// every line belonging to it begins with a space. A server must return
/// `+INFO` for every item it lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeBlock {
    /// The block name without its leading `+`, e.g. `INFO`, `ADMIN`, `VIEWS`.
    pub name: String,
    /// Text on the block's own line after the colon. `+INFO` carries the
    /// item's gopher descriptor here; most other blocks leave it empty.
    pub head: Option<String>,
    /// The block's continuation lines, each with its leading space removed.
    pub lines: Vec<String>,
}

impl AttributeBlock {
    /// The block's continuation lines as `name: value` pairs, for the blocks
    /// built that way (`+ADMIN`, `+VIEWS`). Lines without a colon are skipped.
    pub fn pairs(&self) -> Vec<(&str, &str)> {
        self.lines
            .iter()
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim(), v.trim()))
            .collect()
    }
}

/// Parse a Gopher+ attribute response into its blocks, in order.
///
/// Text before the first block is ignored, and a block with no continuation
/// lines is still a block.
pub fn parse_attributes(text: &str) -> Vec<AttributeBlock> {
    let mut blocks: Vec<AttributeBlock> = Vec::new();
    for line in text.lines() {
        if line == "." {
            break;
        }
        if let Some(rest) = line.strip_prefix('+') {
            // A block name runs to the colon and cannot itself contain `+`.
            let (name, head) = match rest.split_once(':') {
                Some((name, head)) => (name, head.trim()),
                None => (rest, ""),
            };
            blocks.push(AttributeBlock {
                name: name.trim().to_string(),
                head: (!head.is_empty()).then(|| head.to_string()),
                lines: Vec::new(),
            });
        } else if let Some(content) = line.strip_prefix(' ')
            && let Some(block) = blocks.last_mut()
        {
            block.lines.push(content.to_string());
        }
    }
    blocks
}

/// One entry of a `+VIEWS` block: an alternate representation of an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    /// The representation's MIME type, e.g. `text/plain`.
    pub mime: String,
    /// The RFC 1766 language tag when the view names one, e.g. `De_DE`.
    pub language: Option<String>,
    /// The size as the server wrote it, e.g. `<10k>`. Kept verbatim because
    /// the spec's sizes are explicitly approximate.
    pub size: Option<String>,
}

/// Parse a `+VIEWS` block into its alternate representations.
///
/// ```
/// use gopher_protocol::plus::{parse_attributes, parse_views};
///
/// let blocks = parse_attributes("+VIEWS:\n Text/plain: <10k>\n Text/plain De_DE: <15k>\n");
/// let views = parse_views(&blocks[0]);
///
/// assert_eq!(views[0].mime, "Text/plain");
/// assert_eq!(views[0].language, None);
/// assert_eq!(views[1].language.as_deref(), Some("De_DE"));
/// assert_eq!(views[1].size.as_deref(), Some("<15k>"));
/// ```
pub fn parse_views(block: &AttributeBlock) -> Vec<View> {
    block
        .lines
        .iter()
        .filter_map(|line| {
            let (label, size) = match line.split_once(':') {
                Some((label, size)) => (label.trim(), size.trim()),
                None => (line.trim(), ""),
            };
            if label.is_empty() {
                return None;
            }
            // `Text/plain De_DE` is a MIME type and a language tag.
            let (mime, language) = match label.split_once(char::is_whitespace) {
                Some((mime, lang)) => (mime.trim(), Some(lang.trim().to_string())),
                None => (label, None),
            };
            Some(View {
                mime: mime.to_string(),
                language,
                size: (!size.is_empty()).then(|| size.to_string()),
            })
        })
        .collect()
}

// ── ASK forms ──────────────────────────────────────────────────────────────

/// One line of an `+ASK` block: a question to put to the user.
///
/// The client presents these in the order they appear and sends the answers
/// back in the same order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskDirective {
    /// `Ask:` a single-line answer, with an optional default.
    Ask {
        prompt: String,
        default: Option<String>,
    },
    /// `AskP:` the same, but the answer is masked as it is typed.
    AskPassword {
        prompt: String,
        default: Option<String>,
    },
    /// `AskL:` a multi-line answer.
    AskLong {
        prompt: String,
        default: Option<String>,
    },
    /// `AskF:` a local filename to store something under.
    AskFile {
        prompt: String,
        default: Option<String>,
    },
    /// `Select:` several options, any number of which may be chosen.
    Select {
        prompt: String,
        options: Vec<String>,
    },
    /// `Choose:` several options, exactly one of which may be chosen.
    Choose {
        prompt: String,
        options: Vec<String>,
    },
    /// `ChooseF:` pick an existing local file.
    ChooseFile { prompt: String },
    /// `Note:` text to show, which asks nothing.
    Note(String),
    /// A directive this crate does not model, kept verbatim so a client can
    /// show it rather than silently dropping a question.
    Unknown { directive: String, rest: String },
}

/// Parse an `+ASK` block into its directives, in order.
///
/// ```
/// use gopher_protocol::plus::{AskDirective, parse_attributes, parse_ask};
///
/// let blocks = parse_attributes("+ASK:\n Ask: How many volts?\n Choose: Deliver shock?\tYes\tNo\n");
/// let form = parse_ask(&blocks[0]);
///
/// assert!(matches!(&form[0], AskDirective::Ask { prompt, .. } if prompt == "How many volts?"));
/// match &form[1] {
///     AskDirective::Choose { options, .. } => assert_eq!(options, &["Yes", "No"]),
///     other => panic!("expected a Choose, got {other:?}"),
/// }
/// ```
pub fn parse_ask(block: &AttributeBlock) -> Vec<AskDirective> {
    block.lines.iter().map(|line| parse_ask_line(line)).collect()
}

fn parse_ask_line(line: &str) -> AskDirective {
    let (directive, rest) = match line.split_once(':') {
        Some((directive, rest)) => (directive.trim(), rest.trim_start()),
        None => (line.trim(), ""),
    };

    // A prompt and its tab-separated tail: a default for the Ask family, the
    // option list for Select and Choose.
    let mut fields = rest.split('\t');
    let prompt = fields.next().unwrap_or("").trim().to_string();
    let tail: Vec<String> = fields
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .collect();
    let default = tail.first().cloned();

    match directive {
        "Ask" => AskDirective::Ask { prompt, default },
        "AskP" => AskDirective::AskPassword { prompt, default },
        "AskL" => AskDirective::AskLong { prompt, default },
        "AskF" => AskDirective::AskFile { prompt, default },
        "Select" => AskDirective::Select {
            prompt,
            options: tail,
        },
        "Choose" => AskDirective::Choose {
            prompt,
            options: tail,
        },
        "ChooseF" => AskDirective::ChooseFile { prompt },
        "Note" => AskDirective::Note(rest.trim().to_string()),
        other => AskDirective::Unknown {
            directive: other.to_string(),
            rest: rest.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "+INFO: 0Some file or other\tmoo selector\thost2\tport2\t+\n\
                          +ADMIN:\n\
                          \x20Admin: Frodo Gophermeister <fng@bogus.edu>\n\
                          \x20Mod-Date: Wed Jul 28 17:02:01 1993 <19930728170201>\n\
                          +VIEWS:\n\
                          \x20Text/plain: <10k>\n\
                          \x20application/postscript: <100k>\n";

    #[test]
    fn header_forms() {
        assert_eq!(parse_header("+5340"), Ok(PlusHeader::Length(5340)));
        assert_eq!(parse_header("+-1"), Ok(PlusHeader::PeriodTerminated));
        assert_eq!(parse_header("+-2"), Ok(PlusHeader::UntilClose));
        assert_eq!(parse_header("--1"), Ok(PlusHeader::Error));
    }

    #[test]
    fn a_header_without_a_sign_is_malformed() {
        assert!(parse_header("5340").is_err());
        assert!(parse_header("").is_err());
        assert!(parse_header("+banana").is_err());
    }

    #[test]
    fn a_trailing_crlf_does_not_defeat_the_count() {
        assert_eq!(parse_header("+5340\r\n"), Ok(PlusHeader::Length(5340)));
    }

    #[test]
    fn blocks_split_on_the_leading_plus() {
        let blocks = parse_attributes(SAMPLE);
        assert_eq!(
            blocks.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(),
            vec!["INFO", "ADMIN", "VIEWS"]
        );
    }

    #[test]
    fn info_carries_its_descriptor_on_the_block_line() {
        let blocks = parse_attributes(SAMPLE);
        assert!(blocks[0].head.as_deref().unwrap().starts_with("0Some file"));
        assert!(blocks[0].lines.is_empty(), "INFO is a one-line block");
    }

    #[test]
    fn continuation_lines_lose_their_leading_space_and_pair_up() {
        let blocks = parse_attributes(SAMPLE);
        let admin = &blocks[1];
        assert_eq!(admin.lines.len(), 2);
        assert_eq!(
            admin.pairs()[0],
            ("Admin", "Frodo Gophermeister <fng@bogus.edu>")
        );
    }

    #[test]
    fn views_split_mime_language_and_size() {
        let blocks = parse_attributes(SAMPLE);
        let views = parse_views(&blocks[2]);
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].mime, "Text/plain");
        assert_eq!(views[0].size.as_deref(), Some("<10k>"));
        assert_eq!(views[1].mime, "application/postscript");
    }

    #[test]
    fn a_language_tag_is_split_off_the_mime_type() {
        let blocks = parse_attributes("+VIEWS:\n Text/plain De_DE: <15k>\n");
        let views = parse_views(&blocks[0]);
        assert_eq!(views[0].mime, "Text/plain");
        assert_eq!(views[0].language.as_deref(), Some("De_DE"));
    }

    #[test]
    fn ask_directives_keep_their_order_and_kind() {
        let blocks = parse_attributes(
            "+ASK:\n\
             \x20Ask: How many volts?\tdefault volts\n\
             \x20AskP: Password?\n\
             \x20Choose: Deliver shock?\tYes\tNo\n\
             \x20Note: be careful\n",
        );
        let form = parse_ask(&blocks[0]);

        assert_eq!(
            form[0],
            AskDirective::Ask {
                prompt: "How many volts?".into(),
                default: Some("default volts".into()),
            }
        );
        assert_eq!(
            form[1],
            AskDirective::AskPassword {
                prompt: "Password?".into(),
                default: None,
            }
        );
        assert_eq!(
            form[2],
            AskDirective::Choose {
                prompt: "Deliver shock?".into(),
                options: vec!["Yes".into(), "No".into()],
            }
        );
        assert_eq!(form[3], AskDirective::Note("be careful".into()));
    }

    #[test]
    fn an_unmodelled_directive_survives_rather_than_vanishing() {
        let blocks = parse_attributes("+ASK:\n Wibble: something\n");
        let form = parse_ask(&blocks[0]);
        assert_eq!(
            form[0],
            AskDirective::Unknown {
                directive: "Wibble".into(),
                rest: "something".into(),
            }
        );
    }

    #[test]
    fn a_period_terminator_ends_the_attribute_stream() {
        let blocks = parse_attributes("+INFO: 1x\n.\n+ADMIN:\n Admin: nobody\n");
        assert_eq!(blocks.len(), 1);
    }
}
