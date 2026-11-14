//! The scrolltext document format (`text/scroll`).
//!
//! Dependency-free and always compiled.
//!
//! Scrolltext is line-based like gemtext, and deliberately richer: five
//! heading levels forming sections, nested quotes and lists, ordered-list
//! markers, thematic breaks, tagged code blocks, input links, link relations,
//! inline markup, and a linetype escape. Reading it as gemtext therefore
//! loses real structure, which is exactly what this parser exists to stop.
//!
//! The parse is line-level ([`ScrollLine`]) with code-block grouping, plus a
//! separate inline pass ([`spans`]) for the toggle markup inside paragraphs,
//! list items, and quotes. The two are separate because the spec streams:
//! linetypes are decided per line, and inline toggles never cross a line.

/// One line (or grouped code block) of a scrolltext document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScrollLine {
    /// `#` through `#####`. Level 1 is the document title; level 5 is a
    /// textual title, excluded from outlines.
    Heading { level: u8, text: String },
    /// An ordinary paragraph line. Not reflowed; may be word-wrapped.
    Text(String),
    /// A blank line. Kept because blank lines are structural: they separate
    /// adjacent lists and quotes.
    Blank,
    /// `>` lines. `depth` counts the nested markers, starting at 1.
    Quote { depth: u8, text: String },
    /// A list item. `depth` counts the asterisks (1 to 4). `ordinal` is the
    /// marker of an ordered item (`"1."`, `"a."`), kept verbatim because the
    /// spec says clients render what was written and never renumber.
    ListItem {
        depth: u8,
        ordinal: Option<String>,
        text: String,
    },
    /// `=>` link. The URL may be a `#hash` reference to a heading number in
    /// this document.
    Link {
        url: String,
        label: String,
        relation: Option<Relation>,
    },
    /// `=:` input link: the label is a prompt, and the reader's input rides
    /// the query string (or a titan/spartan upload, by scheme).
    InputLink { url: String, prompt: String },
    /// `---` on its own line.
    ThematicBreak,
    /// A fenced block, grouped: its `tag` (with the `text/` prefix already
    /// omitted, per spec) and its lines, verbatim.
    CodeBlock {
        tag: Option<String>,
        lines: Vec<String>,
    },
}

/// A link's declared relationship, from the trailing `[...]` on its label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relation {
    pub polarity: Polarity,
    /// The tag, e.g. `Citation`, `Cross-reference`, `Alternate`. `None` for a
    /// bare `[+]` or `[-]`.
    pub tag: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    Positive,
    Neutral,
    Negative,
}

/// Parse a scrolltext document into lines, grouping code blocks.
pub fn parse(text: &str) -> Vec<ScrollLine> {
    let mut lines = Vec::new();
    let mut code: Option<(Option<String>, Vec<String>)> = None;

    for raw in text.lines() {
        // Inside a code block everything is verbatim until the closing fence.
        if let Some((tag, collected)) = &mut code {
            if raw.starts_with("```") {
                lines.push(ScrollLine::CodeBlock {
                    tag: tag.take(),
                    lines: std::mem::take(collected),
                });
                code = None;
            } else {
                collected.push(raw.to_string());
            }
            continue;
        }

        if let Some(rest) = raw.strip_prefix("```") {
            let tag = rest.trim();
            code = Some(((!tag.is_empty()).then(|| tag.to_string()), Vec::new()));
            continue;
        }

        lines.push(parse_line(raw));
    }

    // An unclosed fence still yields its block: the stream ended, and content
    // beats silence.
    if let Some((tag, collected)) = code {
        lines.push(ScrollLine::CodeBlock {
            tag,
            lines: collected,
        });
    }
    lines
}

fn parse_line(raw: &str) -> ScrollLine {
    if raw.trim().is_empty() {
        return ScrollLine::Blank;
    }

    // Linetype escaping: a backslash before a recognized prefix makes the
    // line a paragraph, with the backslash removed. In all other positions a
    // backslash is just a character.
    if let Some(rest) = raw.strip_prefix('\\') {
        if is_escapable(rest) {
            return ScrollLine::Text(rest.to_string());
        }
        return ScrollLine::Text(raw.to_string());
    }

    if raw == "---" {
        return ScrollLine::ThematicBreak;
    }

    if raw.starts_with('#') {
        let level = raw.chars().take_while(|c| *c == '#').count();
        if level <= 5 {
            return ScrollLine::Heading {
                level: level as u8,
                text: raw[level..].trim_start().to_string(),
            };
        }
        // Six or more is not a heading the spec defines; it is a paragraph.
        return ScrollLine::Text(raw.to_string());
    }

    if raw.starts_with('>') {
        let depth = raw.chars().take_while(|c| *c == '>').count();
        return ScrollLine::Quote {
            depth: depth.min(255) as u8,
            text: raw[depth..].trim_start().to_string(),
        };
    }

    if let Some(rest) = raw.strip_prefix("=>") {
        let (url, label) = split_link(rest);
        let (label, relation) = split_relation(&label);
        return ScrollLine::Link {
            url,
            label,
            relation,
        };
    }

    if let Some(rest) = raw.strip_prefix("=:") {
        let (url, prompt) = split_link(rest);
        return ScrollLine::InputLink { url, prompt };
    }

    // Lists: one to four asterisks followed by one required whitespace
    // character. The required whitespace is what distinguishes a list item
    // from a line beginning with bold inline markup.
    let stars = raw.chars().take_while(|c| *c == '*').count();
    if (1..=4).contains(&stars) {
        let after = &raw[stars..];
        if let Some(text) = after.strip_prefix([' ', '\t']) {
            let (ordinal, text) = split_ordinal(text);
            return ScrollLine::ListItem {
                depth: stars as u8,
                ordinal,
                text,
            };
        }
    }

    ScrollLine::Text(raw.to_string())
}

/// Whether a line body is one of the spec's escapable prefixes.
fn is_escapable(rest: &str) -> bool {
    let stars = rest.chars().take_while(|c| *c == '*').count();
    if (1..=4).contains(&stars) {
        return true;
    }
    let hashes = rest.chars().take_while(|c| *c == '#').count();
    if (1..=5).contains(&hashes) {
        return true;
    }
    rest.starts_with('>')
        || rest.starts_with("=>")
        || rest.starts_with("=:")
        || rest.starts_with("```")
        || rest == "---"
}

/// Split a link body into URL and label. Whitespace after the marker is
/// optional; the URL runs to the next whitespace.
fn split_link(rest: &str) -> (String, String) {
    let rest = rest.trim_start();
    match rest.split_once(|c: char| c.is_whitespace()) {
        Some((url, label)) => (url.to_string(), label.trim().to_string()),
        None => (rest.to_string(), String::new()),
    }
}

/// Split a trailing `[relation]` off a link label.
fn split_relation(label: &str) -> (String, Option<Relation>) {
    let trimmed = label.trim_end();
    let Some(open) = trimmed.rfind('[') else {
        return (label.to_string(), None);
    };
    let Some(inner) = trimmed[open..]
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    else {
        return (label.to_string(), None);
    };
    let (polarity, tag) = match inner.strip_prefix('+') {
        Some(tag) => (Polarity::Positive, tag),
        None => match inner.strip_prefix('-') {
            Some(tag) => (Polarity::Negative, tag),
            None => (Polarity::Neutral, inner),
        },
    };
    // An empty neutral `[]` is not a relation, just brackets.
    if tag.is_empty() && polarity == Polarity::Neutral {
        return (label.to_string(), None);
    }
    (
        trimmed[..open].trim_end().to_string(),
        Some(Relation {
            polarity,
            tag: (!tag.is_empty()).then(|| tag.to_string()),
        }),
    )
}

/// Split an ordered-list marker off an item's text: any run of decimal digits
/// followed by a dot, or exactly one ASCII letter followed by a dot.
fn split_ordinal(text: &str) -> (Option<String>, String) {
    let digits = text.chars().take_while(|c| c.is_ascii_digit()).count();
    let marker_len = if digits > 0 {
        digits
    } else if text.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        1
    } else {
        0
    };
    if marker_len > 0 && text[marker_len..].starts_with('.') {
        let (marker, rest) = text.split_at(marker_len + 1);
        return (Some(marker.to_string()), rest.trim_start().to_string());
    }
    (None, text.to_string())
}

// ── Inline markup ──────────────────────────────────────────────────────────

/// A run of text with one inline style.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub kind: SpanKind,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanKind {
    Plain,
    /// `*strong*`
    Strong,
    /// `_emphasis_`
    Emphasis,
    /// `` `code` ``
    Code,
}

/// Whitespace for inline purposes, which per spec includes the zero-width
/// space.
fn is_inline_whitespace(c: char) -> bool {
    c.is_whitespace() || c == '\u{200B}'
}

/// The spec excepts a toggle "between two symbols" from toggling. Full
/// Unicode punctuation-and-symbol categories would need a table this crate
/// does not carry, so the check covers ASCII punctuation; a non-ASCII symbol
/// neighbour is treated as an ordinary character. Recorded as a limitation.
fn is_symbolic(c: char) -> bool {
    c.is_ascii_punctuation()
}

/// Parse one line's inline markup into spans.
///
/// Toggle rules, per spec: a toggle character (`*`, `_`, `` ` ``) toggles only
/// if at least one neighbour is a non-whitespace character that is not the
/// toggle character itself, and not if both neighbours are symbols. An open
/// style closes automatically at the end of the line, because inline markup
/// never crosses lines. Inside an inline code span only the backtick is
/// recognized.
pub fn spans(line: &str) -> Vec<Span> {
    let chars: Vec<char> = line.chars().collect();
    let mut out: Vec<Span> = Vec::new();
    let mut current = String::new();
    let mut kind = SpanKind::Plain;

    let flush = |out: &mut Vec<Span>, current: &mut String, kind: SpanKind| {
        if !current.is_empty() {
            out.push(Span {
                kind,
                text: std::mem::take(current),
            });
        }
    };

    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        let toggle_kind = match c {
            '*' => Some(SpanKind::Strong),
            '_' => Some(SpanKind::Emphasis),
            '`' => Some(SpanKind::Code),
            _ => None,
        };

        let toggles = match toggle_kind {
            None => None,
            Some(candidate) => {
                // Inside code, only the backtick closes.
                if kind == SpanKind::Code && candidate != SpanKind::Code {
                    None
                } else {
                    let before = index.checked_sub(1).map(|i| chars[i]);
                    let after = chars.get(index + 1).copied();
                    let good =
                        |n: Option<char>| n.is_some_and(|n| !is_inline_whitespace(n) && n != c);
                    let both_symbols =
                        before.is_some_and(is_symbolic) && after.is_some_and(is_symbolic);
                    (!both_symbols && (good(before) || good(after))).then_some(candidate)
                }
            }
        };

        match toggles {
            Some(candidate) => {
                flush(&mut out, &mut current, kind);
                kind = if kind == candidate {
                    SpanKind::Plain
                } else {
                    candidate
                };
            }
            None => current.push(c),
        }
        index += 1;
    }
    // Auto-close at end of line: whatever is open flushes with its style.
    flush(&mut out, &mut current, kind);
    out
}

#[cfg(test)]
#[path = "scrolltext_tests.rs"]
mod tests;
