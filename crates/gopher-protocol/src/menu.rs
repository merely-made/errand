//! Gopher menu parser — RFC 1436 menus into a typed item list.
//!
//! A gopher menu is tab-delimited lines: `<type><display>\t<selector>\t<host>
//! \t<port>`. The first character is the item type; a bare `.` terminates the
//! menu. This parser classifies each line into a [`GopherItem`] carrying the
//! item [`GopherKind`] (so a native viewer can show a per-type affordance) plus
//! the resolved resource URL (synthesised per RFC 4266, or extracted for a URL
//! item). Info and error lines carry no URL. A consumer decides how to present
//! each kind; the parser holds no document or render model.
//!
//! This module has no dependencies and is compiled unconditionally, so a
//! consumer that only renders menus can take the crate with
//! `default-features = false`.
//!
//! References: RFC 1436 (Gopher), RFC 4266 (gopher URI scheme).

/// The semantic class of a gopher menu line, from its item-type character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GopherKind {
    /// `i` — informational text, no resource.
    Info,
    /// `3` — server error message, no resource.
    Error,
    /// `0` — text file.
    Text,
    /// `1` — submenu / directory.
    Submenu,
    /// `7` — full-text search server.
    Search,
    /// `9` — binary.
    Binary,
    /// `g` / `I` — image.
    Image,
    /// `s` — sound.
    Sound,
    /// `8` telnet or `T` tn3270 session; [`GopherItem::raw_type`] says which.
    Telnet,
    /// `2` — CSO phone-book server, an interactive query.
    Cso,
    /// `h` — URL item (the selector carries an external URL).
    Url,
    /// Any other (still navigable) item type.
    Other(char),
}

/// The Gopher+ marker carried in an item line's fifth field.
///
/// RFC 1436 menus have four tab-separated fields and stop at the port. Gopher+
/// servers append a fifth, which RFC 1436 clients are required to ignore. Its
/// presence is how a client learns an item has attributes worth asking for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GopherPlus {
    /// `+`: the item has Gopher+ attribute blocks (`+INFO`, `+VIEWS`, …).
    Supported,
    /// `?`: the item is an interactive query carrying an `+ASK` form, which a
    /// client must fill in before retrieval.
    Form,
}

impl GopherPlus {
    /// Classify a fifth field. Anything other than `+` or `?` is `None`: the
    /// spec calls this position "extra stuff", so an unknown value is not an
    /// error, just not a marker this client acts on.
    fn from_field(field: &str) -> Option<Self> {
        match field.trim() {
            "+" => Some(Self::Supported),
            "?" => Some(Self::Form),
            _ => None,
        }
    }
}

/// One parsed gopher menu line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GopherItem {
    pub kind: GopherKind,
    /// The item-type character exactly as the menu line carried it. [`kind`]
    /// is the semantic class; this keeps what the class folds together (`g`
    /// and `I`, `8` and `T`, every type under [`GopherKind::Other`]).
    ///
    /// [`kind`]: GopherItem::kind
    pub raw_type: char,
    pub display: String,
    /// The resource URL: a synthesised `gopher://` URL (RFC 4266) for standard
    /// items, or the extracted target for a `h` URL item. `None` for [`Info`] and
    /// [`Error`] lines.
    ///
    /// [`Info`]: GopherKind::Info
    /// [`Error`]: GopherKind::Error
    pub url: Option<String>,
    /// The Gopher+ marker from the fifth field, when the server sent one.
    /// `None` for a plain RFC 1436 menu.
    pub plus: Option<GopherPlus>,
}

/// Parse a gopher menu body into items, in source order. Stops at the RFC 1436
/// `.` terminator; skips blank and malformed lines (a non-info/error item with no
/// host, or a URL item with no target).
pub fn parse(body: &str) -> Vec<GopherItem> {
    let mut items = Vec::new();
    for line in body.lines() {
        if line == "." {
            break;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(item) = parse_line(line) {
            items.push(item);
        }
    }
    items
}

fn parse_line(line: &str) -> Option<GopherItem> {
    let mut chars = line.chars();
    let type_char = chars.next()?;
    let rest = chars.as_str();

    // Five, not four: a Gopher+ server appends a marker after the port, and
    // splitting into four would leave it stuck to the port field (turning
    // `70` into `70\t+` and corrupting every synthesised URL).
    let mut parts = rest.splitn(5, '\t');
    let display = parts.next()?.to_string();
    let selector = parts.next().unwrap_or("");
    let host = parts.next().unwrap_or("");
    let port = parts.next().unwrap_or("70");
    let plus = parts.next().and_then(GopherPlus::from_field);

    match type_char {
        'i' => Some(GopherItem {
            kind: GopherKind::Info,
            raw_type: type_char,
            display,
            url: None,
            plus,
        }),
        '3' => Some(GopherItem {
            kind: GopherKind::Error,
            raw_type: type_char,
            display,
            url: None,
            plus,
        }),
        'h' => {
            // URL items: selector is typically "URL:https://…". Strip the prefix;
            // skip the line when it carries no usable target.
            let url = selector.strip_prefix("URL:").unwrap_or(selector).trim();
            if url.is_empty() {
                return None;
            }
            Some(GopherItem {
                kind: GopherKind::Url,
                raw_type: type_char,
                display,
                url: Some(url.to_string()),
                plus,
            })
        }
        _ => {
            if host.is_empty() {
                return None;
            }
            let url = synthesise_gopher_url(type_char, host, port, selector);
            Some(GopherItem {
                kind: kind_of(type_char),
                raw_type: type_char,
                display,
                url: Some(url),
                plus,
            })
        }
    }
}

fn kind_of(type_char: char) -> GopherKind {
    match type_char {
        '0' => GopherKind::Text,
        '1' => GopherKind::Submenu,
        '2' => GopherKind::Cso,
        '7' => GopherKind::Search,
        '9' => GopherKind::Binary,
        'g' | 'I' => GopherKind::Image,
        's' => GopherKind::Sound,
        '8' | 'T' => GopherKind::Telnet,
        other => GopherKind::Other(other),
    }
}

fn synthesise_gopher_url(type_char: char, host: &str, port: &str, selector: &str) -> String {
    let port_part = if port.is_empty() || port == "70" {
        String::new()
    } else {
        format!(":{port}")
    };
    // RFC 4266: gopher-path = <gophertype><selector>. The type character is the
    // first path segment, immediately followed by the selector (which may already
    // begin with `/`).
    format!("gopher://{host}{port_part}/{type_char}{selector}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(t: char, display: &str, selector: &str, host: &str, port: &str) -> String {
        format!("{t}{display}\t{selector}\t{host}\t{port}\r\n")
    }

    #[test]
    fn standard_item_synthesises_url_with_type_and_selector() {
        let items = parse(&line(
            '0',
            "Welcome text",
            "/welcome.txt",
            "example.test",
            "70",
        ));
        assert_eq!(
            items,
            vec![GopherItem {
                kind: GopherKind::Text,
                raw_type: '0',
                display: "Welcome text".into(),
                url: Some("gopher://example.test/0/welcome.txt".into()),
                plus: None,
            }]
        );
    }

    #[test]
    fn non_default_port_appears_in_url() {
        let items = parse(&line('1', "Sub", "/sub", "example.test", "7070"));
        assert_eq!(
            items[0].url.as_deref(),
            Some("gopher://example.test:7070/1/sub")
        );
        assert_eq!(items[0].kind, GopherKind::Submenu);
    }

    #[test]
    fn url_item_extracts_target() {
        let items = parse(&line(
            'h',
            "External",
            "URL:https://example.test/",
            ".",
            "70",
        ));
        assert_eq!(items[0].kind, GopherKind::Url);
        assert_eq!(items[0].url.as_deref(), Some("https://example.test/"));
    }

    #[test]
    fn info_and_error_carry_no_url() {
        let items = parse(&format!(
            "{}{}",
            line('i', "hello", "", "example.test", "70"),
            line('3', "boom", "", "example.test", "70"),
        ));
        assert_eq!(
            items[0],
            GopherItem {
                kind: GopherKind::Info,
                raw_type: 'i',
                display: "hello".into(),
                url: None,
                plus: None
            }
        );
        assert_eq!(
            items[1],
            GopherItem {
                kind: GopherKind::Error,
                raw_type: '3',
                display: "boom".into(),
                url: None,
                plus: None
            }
        );
    }

    #[test]
    fn telnet_and_tn3270_are_both_telnet_and_keep_their_type() {
        let items = parse(&format!(
            "{}{}",
            line('8', "telnet", "", "example.test", "23"),
            line('T', "tn3270", "", "example.test", "23"),
        ));
        let got: Vec<_> = items
            .iter()
            .map(|item| (item.kind.clone(), item.raw_type))
            .collect();
        assert_eq!(
            got,
            [(GopherKind::Telnet, '8'), (GopherKind::Telnet, 'T')],
            "RFC 1436: 8 is telnet, T is tn3270"
        );
    }

    #[test]
    fn cso_is_named_and_folded_types_keep_their_character() {
        let items = parse(&format!(
            "{}{}{}",
            line('2', "phone book", "", "example.test", "105"),
            line('g', "a gif", "/a.gif", "example.test", "70"),
            line('5', "dos binary", "/a.exe", "example.test", "70"),
        ));
        assert_eq!(items[0].kind, GopherKind::Cso);
        assert_eq!(items[0].url.as_deref(), Some("gopher://example.test:105/2"));
        assert_eq!(
            (items[1].kind.clone(), items[1].raw_type),
            (GopherKind::Image, 'g')
        );
        assert_eq!(
            (items[2].kind.clone(), items[2].raw_type),
            (GopherKind::Other('5'), '5')
        );
    }

    #[test]
    fn period_terminator_stops_parsing() {
        let items = parse(&format!(
            "{}{}{}",
            line('i', "before", "", "example.test", "70"),
            ".\r\n",
            line('1', "after", "/x", "example.test", "70"),
        ));
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn resource_with_missing_host_is_skipped() {
        assert!(parse("1Bad item\t/sel\t\t70\r\n").is_empty());
    }

    #[test]
    fn a_gopher_plus_marker_is_read_from_the_fifth_field() {
        let items = parse("1Archive\t/arc\texample.test\t70\t+\r\n");
        assert_eq!(items[0].plus, Some(GopherPlus::Supported));

        let items = parse("7Search\t/find\texample.test\t70\t?\r\n");
        assert_eq!(items[0].plus, Some(GopherPlus::Form));
        assert_eq!(items[0].kind, GopherKind::Search);
    }

    #[test]
    fn a_plus_field_does_not_leak_into_the_port() {
        // Splitting the line into four fields leaves the marker glued to the
        // port, which then reads as non-default and corrupts the URL.
        let items = parse("1Archive\t/arc\texample.test\t70\t+\r\n");
        assert_eq!(items[0].url.as_deref(), Some("gopher://example.test/1/arc"));

        let items = parse("1Archive\t/arc\texample.test\t7070\t+\r\n");
        assert_eq!(
            items[0].url.as_deref(),
            Some("gopher://example.test:7070/1/arc")
        );
    }

    #[test]
    fn an_unrecognised_fifth_field_is_not_a_marker() {
        let items = parse("1Thing\t/t\texample.test\t70\tsomething else\r\n");
        assert_eq!(items[0].plus, None);
        assert_eq!(items[0].url.as_deref(), Some("gopher://example.test/1/t"));
    }

    #[test]
    fn a_plain_rfc1436_menu_has_no_markers() {
        let items = parse(&line('0', "Plain", "/p", "example.test", "70"));
        assert_eq!(items[0].plus, None);
    }

    #[test]
    fn unknown_type_stays_navigable() {
        let items = parse(&line('X', "weird", "/sel", "example.test", "70"));
        assert_eq!(items[0].kind, GopherKind::Other('X'));
        assert_eq!(items[0].url.as_deref(), Some("gopher://example.test/X/sel"));
    }
}
