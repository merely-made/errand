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
    CodeBlock { tag: Option<String>, lines: Vec<String> },
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
        return ScrollLine::Link { url, label, relation };
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
    let Some(inner) = trimmed[open..].strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
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
                    let good = |n: Option<char>| {
                        n.is_some_and(|n| !is_inline_whitespace(n) && n != c)
                    };
                    let both_symbols = before.is_some_and(is_symbolic)
                        && after.is_some_and(is_symbolic);
                    (!both_symbols && (good(before) || good(after))).then_some(candidate)
                }
            },
        };

        match toggles {
            Some(candidate) => {
                flush(&mut out, &mut current, kind);
                kind = if kind == candidate { SpanKind::Plain } else { candidate };
            },
            None => current.push(c),
        }
        index += 1;
    }
    // Auto-close at end of line: whatever is open flushes with its style.
    flush(&mut out, &mut current, kind);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headings_carry_their_level_and_five_is_the_ceiling() {
        assert_eq!(
            parse("# Title\n##### textual\n###### not a heading\n"),
            vec![
                ScrollLine::Heading { level: 1, text: "Title".into() },
                ScrollLine::Heading { level: 5, text: "textual".into() },
                ScrollLine::Text("###### not a heading".into()),
            ]
        );
    }

    #[test]
    fn a_thematic_break_is_exactly_three_hyphens() {
        assert_eq!(parse("---\n")[0], ScrollLine::ThematicBreak);
        assert_eq!(parse("----\n")[0], ScrollLine::Text("----".into()));
    }

    #[test]
    fn quotes_nest_by_marker_count() {
        assert_eq!(
            parse("> outer\n>> inner\n"),
            vec![
                ScrollLine::Quote { depth: 1, text: "outer".into() },
                ScrollLine::Quote { depth: 2, text: "inner".into() },
            ]
        );
    }

    #[test]
    fn the_specs_own_nested_list_example_parses() {
        // Verbatim from the specification.
        let doc = "* Unordered list item 1\n** 1. Ordered sub-list item 1\n** 2. Ordered sub-list item 2\n* Unordered list item 2\n";
        assert_eq!(
            parse(doc),
            vec![
                ScrollLine::ListItem { depth: 1, ordinal: None, text: "Unordered list item 1".into() },
                ScrollLine::ListItem { depth: 2, ordinal: Some("1.".into()), text: "Ordered sub-list item 1".into() },
                ScrollLine::ListItem { depth: 2, ordinal: Some("2.".into()), text: "Ordered sub-list item 2".into() },
                ScrollLine::ListItem { depth: 1, ordinal: None, text: "Unordered list item 2".into() },
            ]
        );
    }

    #[test]
    fn a_list_needs_its_required_whitespace() {
        // Without the space this is bold inline markup, not a list: the spec
        // calls the required whitespace the disambiguator.
        assert!(matches!(parse("*bold start*\n")[0], ScrollLine::Text(_)));
        assert!(matches!(parse("* item\n")[0], ScrollLine::ListItem { .. }));
        assert!(matches!(parse("*\ttabbed item\n")[0], ScrollLine::ListItem { .. }));
        // Five stars exceeds the nesting limit.
        assert!(matches!(parse("***** too deep\n")[0], ScrollLine::Text(_)));
    }

    #[test]
    fn ordinals_are_kept_verbatim_and_never_renumbered() {
        let ScrollLine::ListItem { ordinal, text, .. } = &parse("* 7. seventh\n")[0] else {
            panic!("expected a list item");
        };
        assert_eq!(ordinal.as_deref(), Some("7."));
        assert_eq!(text, "seventh");

        let ScrollLine::ListItem { ordinal, .. } = &parse("* a. lettered\n")[0] else {
            panic!("expected a list item");
        };
        assert_eq!(ordinal.as_deref(), Some("a."));
    }

    #[test]
    fn links_split_url_label_and_relation() {
        // The spec's own relation examples.
        assert_eq!(
            parse("=> scroll://example.net/sub/cited_text_name.txt Cited Text Name [Citation]\n")[0],
            ScrollLine::Link {
                url: "scroll://example.net/sub/cited_text_name.txt".into(),
                label: "Cited Text Name".into(),
                relation: Some(Relation { polarity: Polarity::Neutral, tag: Some("Citation".into()) }),
            }
        );
        assert_eq!(
            parse("=> scroll://example.net/x.txt Name [-Citation]\n")[0],
            ScrollLine::Link {
                url: "scroll://example.net/x.txt".into(),
                label: "Name".into(),
                relation: Some(Relation { polarity: Polarity::Negative, tag: Some("Citation".into()) }),
            }
        );
        assert_eq!(
            parse("=> scroll://example.net/cited.pdf Cited Text Name [+]\n")[0],
            ScrollLine::Link {
                url: "scroll://example.net/cited.pdf".into(),
                label: "Cited Text Name".into(),
                relation: Some(Relation { polarity: Polarity::Positive, tag: None }),
            }
        );
        // No relation at all.
        assert_eq!(
            parse("=> gemini://misfin.org Misfin Protocol\n")[0],
            ScrollLine::Link {
                url: "gemini://misfin.org".into(),
                label: "Misfin Protocol".into(),
                relation: None,
            }
        );
    }

    #[test]
    fn a_hash_url_links_within_the_document() {
        assert_eq!(
            parse("=>#3.2 The second level-3 heading\n")[0],
            ScrollLine::Link {
                url: "#3.2".into(),
                label: "The second level-3 heading".into(),
                relation: None,
            }
        );
    }

    #[test]
    fn input_links_carry_their_prompt() {
        assert_eq!(
            parse("=: scroll://example.net/search Search terms\n")[0],
            ScrollLine::InputLink {
                url: "scroll://example.net/search".into(),
                prompt: "Search terms".into(),
            }
        );
    }

    #[test]
    fn code_blocks_group_with_their_tag_and_the_text_prefix_stays_off() {
        let doc = "```rust\nfn main() {}\n```\nafter\n";
        assert_eq!(
            parse(doc),
            vec![
                ScrollLine::CodeBlock {
                    tag: Some("rust".into()),
                    lines: vec!["fn main() {}".into()],
                },
                ScrollLine::Text("after".into()),
            ]
        );
    }

    #[test]
    fn linetypes_inside_a_code_block_stay_verbatim() {
        let doc = "```\n# not a heading\n=> not/a/link nope\n```\n";
        let ScrollLine::CodeBlock { lines, .. } = &parse(doc)[0] else {
            panic!("expected a code block");
        };
        assert_eq!(lines, &["# not a heading", "=> not/a/link nope"]);
    }

    #[test]
    fn an_unclosed_fence_still_yields_its_content() {
        let ScrollLine::CodeBlock { lines, .. } = &parse("```\ntrailing\n")[0] else {
            panic!("expected a code block");
        };
        assert_eq!(lines, &["trailing"]);
    }

    #[test]
    fn escaping_turns_a_linetype_into_a_paragraph() {
        assert_eq!(parse("\\# not a heading\n")[0], ScrollLine::Text("# not a heading".into()));
        assert_eq!(parse("\\=> not a link\n")[0], ScrollLine::Text("=> not a link".into()));
        assert_eq!(parse("\\---\n")[0], ScrollLine::Text("---".into()));
        // A backslash anywhere else is just a character.
        assert_eq!(parse("\\ordinary\n")[0], ScrollLine::Text("\\ordinary".into()));
    }

    #[test]
    fn blank_lines_survive_because_they_separate_lists() {
        assert_eq!(
            parse("* one\n\n* two\n"),
            vec![
                ScrollLine::ListItem { depth: 1, ordinal: None, text: "one".into() },
                ScrollLine::Blank,
                ScrollLine::ListItem { depth: 1, ordinal: None, text: "two".into() },
            ]
        );
    }

    // ── Inline markup ──────────────────────────────────────────────────

    #[test]
    fn strong_emphasis_and_code_toggle() {
        assert_eq!(
            spans("a *b* c"),
            vec![
                Span { kind: SpanKind::Plain, text: "a ".into() },
                Span { kind: SpanKind::Strong, text: "b".into() },
                Span { kind: SpanKind::Plain, text: " c".into() },
            ]
        );
        assert_eq!(spans("_e_")[0].kind, SpanKind::Emphasis);
        assert_eq!(spans("`x`")[0].kind, SpanKind::Code);
    }

    #[test]
    fn an_isolated_toggle_between_whitespace_does_not_toggle() {
        // Neither neighbour qualifies, so the star is literal.
        assert_eq!(
            spans("a * b"),
            vec![Span { kind: SpanKind::Plain, text: "a * b".into() }]
        );
    }

    #[test]
    fn a_zero_width_space_counts_as_whitespace_for_toggles() {
        let line = "a\u{200B}*\u{200B}b".to_string();
        assert_eq!(spans(&line).len(), 1, "the star must stay literal");
    }

    #[test]
    fn inline_markup_closes_at_the_end_of_the_line() {
        // An unclosed toggle styles the rest of the line and stops there.
        let out = spans("start *unclosed");
        assert_eq!(out[1].kind, SpanKind::Strong);
        assert_eq!(out[1].text, "unclosed");
    }

    #[test]
    fn other_toggles_are_inert_inside_code() {
        let out = spans("`a *not strong* b`");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SpanKind::Code);
        assert_eq!(out[0].text, "a *not strong* b");
    }

    #[test]
    fn a_toggle_between_two_symbols_is_literal() {
        // "(*)" — both neighbours are symbols, so no toggle.
        assert_eq!(
            spans("(*)"),
            vec![Span { kind: SpanKind::Plain, text: "(*)".into() }]
        );
    }
}
