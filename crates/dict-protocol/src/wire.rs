//! DICT's status lines, quoting, and dot-stuffed text blocks.
//!
//! Dependency-free and always compiled.
//!
//! DICT is not shaped like the rest of the small web. Where gemini and gopher
//! answer one request and close, DICT is a **command loop**: the server greets
//! you, you issue commands, and the connection stays open until `QUIT`. It is
//! much closer to SMTP or NNTP, and the pieces below are the ones that shape
//! implies: numeric status lines, quoted parameters, and text blocks
//! terminated by a lone period.

/// DICT's well-known port.
pub const DEFAULT_PORT: u16 = 2628;

/// The spec's cap on a command line.
pub const MAX_LINE: usize = 1024;

/// A response status line: a three-digit code and the rest of the line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub code: u16,
    pub text: String,
}

impl Status {
    /// `1xx`: informational, and a text block follows.
    pub fn has_text_block(&self) -> bool {
        (100..200).contains(&self.code)
    }

    /// `2xx`: the command succeeded.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// `4xx`: temporary failure; retrying later is reasonable.
    pub fn is_temporary_failure(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// `5xx`: permanent failure; it is not.
    pub fn is_permanent_failure(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// The parameters after the code, with quoting resolved.
    pub fn params(&self) -> Vec<String> {
        split_params(&self.text)
    }
}

// The codes this crate reasons about by name. The full set is in RFC 2229 §5.
/// `110 n databases present`.
pub const DATABASES_FOLLOW: u16 = 110;
/// `111 n strategies available`.
pub const STRATEGIES_FOLLOW: u16 = 111;
/// `150 n definitions retrieved`.
pub const DEFINITIONS_FOLLOW: u16 = 150;
/// `151 word database name` — one definition's header.
pub const DEFINITION_FOLLOWS: u16 = 151;
/// `152 n matches found`.
pub const MATCHES_FOLLOW: u16 = 152;
/// `220` connection banner.
pub const BANNER: u16 = 220;
/// `250 ok`.
pub const OK: u16 = 250;
/// `550` invalid database.
pub const INVALID_DATABASE: u16 = 550;
/// `551` invalid strategy.
pub const INVALID_STRATEGY: u16 = 551;
/// `552` no match.
pub const NO_MATCH: u16 = 552;

/// Parse a status line. `None` if it does not begin with three digits.
pub fn parse_status(line: &str) -> Option<Status> {
    let line = line.trim_end_matches(['\r', '\n']);
    let digits = line.get(..3)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Status {
        code: digits.parse().ok()?,
        text: line.get(3..).unwrap_or("").trim_start().to_string(),
    })
}

/// Whether a line ends a text block: a lone period.
pub fn is_terminator(line: &str) -> bool {
    line.trim_end_matches(['\r', '\n']) == "."
}

/// Undo the server's dot-stuffing on one text line.
///
/// RFC 2229: "If a line of original text contained a period as the first
/// character of the line, that first period is doubled by the DICT server."
/// So a received `..text` is really `.text`, and a client that forgets this
/// corrupts any definition beginning with a period.
pub fn unstuff(line: &str) -> &str {
    line.strip_prefix('.')
        .filter(|_| line.starts_with(".."))
        .unwrap_or(line)
}

/// Apply dot-stuffing, which is what a server does when writing a text block.
pub fn stuff(line: &str) -> String {
    if line.starts_with('.') {
        format!(".{line}")
    } else {
        line.to_string()
    }
}

/// Split a parameter list, honouring double-quoted strings.
///
/// Database descriptions and definition headers routinely contain spaces, so
/// they arrive quoted; splitting on whitespace alone would shred them.
pub fn split_params(text: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut started = false;

    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started || !current.is_empty() {
                    params.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => current.push(c),
        }
    }
    if started || !current.is_empty() {
        params.push(current);
    }
    params
}

/// One database the server offers, from a `110` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    pub name: String,
    pub description: String,
}

/// Parse a `110` text block: each line is a database name and its description.
pub fn parse_databases(lines: &[String]) -> Vec<Database> {
    lines
        .iter()
        .filter_map(|line| {
            let params = split_params(line);
            let name = params.first()?.clone();
            if name.is_empty() {
                return None;
            }
            Some(Database {
                description: params.get(1).cloned().unwrap_or_default(),
                name,
            })
        })
        .collect()
}

/// One match from a `152` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub database: String,
    pub word: String,
}

/// Parse a `152` text block: each line is a database and a matched word.
pub fn parse_matches(lines: &[String]) -> Vec<Match> {
    lines
        .iter()
        .filter_map(|line| {
            let params = split_params(line);
            Some(Match {
                database: params.first()?.clone(),
                word: params.get(1)?.clone(),
            })
        })
        .collect()
}

/// One definition: its `151` header plus the text block that followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    pub word: String,
    pub database: String,
    /// The database's human-readable name, from the header's third parameter.
    pub database_description: String,
    /// The definition body, dot-unstuffed, one entry per line.
    pub text: Vec<String>,
}

/// Parse a `151` header's parameters: `word database name`.
pub fn parse_definition_header(status: &Status) -> Option<(String, String, String)> {
    let params = status.params();
    Some((
        params.first()?.clone(),
        params.get(1)?.clone(),
        params.get(2).cloned().unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines_split_code_from_text() {
        let status = parse_status("250 ok [d/m/c = 1/0/16; 0.000r 0.000u 0.000s]").unwrap();
        assert_eq!(status.code, 250);
        assert!(status.is_success());
        assert!(status.text.starts_with("ok"));
    }

    #[test]
    fn the_classes_are_told_apart() {
        assert!(
            parse_status("110 3 databases present")
                .unwrap()
                .has_text_block()
        );
        assert!(parse_status("220 dictd 1.12").unwrap().is_success());
        assert!(
            parse_status("420 unavailable")
                .unwrap()
                .is_temporary_failure()
        );
        assert!(parse_status("552 no match").unwrap().is_permanent_failure());
    }

    #[test]
    fn a_line_without_three_digits_is_not_a_status() {
        assert!(parse_status("hello").is_none());
        assert!(parse_status("12 too short").is_none());
        assert!(parse_status("").is_none());
    }

    #[test]
    fn a_lone_period_ends_a_text_block() {
        assert!(is_terminator("."));
        assert!(is_terminator(".\r\n"));
        assert!(!is_terminator(".."));
        assert!(!is_terminator(". "));
    }

    #[test]
    fn dot_stuffing_round_trips() {
        // The case that corrupts a definition if forgotten.
        assert_eq!(unstuff("..hidden leading dot"), ".hidden leading dot");
        assert_eq!(unstuff("ordinary text"), "ordinary text");
        // A lone period is the terminator, never content, so it is not
        // unstuffed here.
        assert_eq!(stuff(".leading"), "..leading");
        assert_eq!(stuff("ordinary"), "ordinary");
        assert_eq!(unstuff(&stuff(".leading")), ".leading");
    }

    #[test]
    fn quoted_parameters_survive_their_spaces() {
        let params = split_params(r#"foldoc "The Free On-line Dictionary of Computing""#);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "foldoc");
        assert_eq!(params[1], "The Free On-line Dictionary of Computing");
    }

    #[test]
    fn an_escaped_quote_stays_in_the_parameter() {
        let params = split_params(r#"db "a \"quoted\" name""#);
        assert_eq!(params[1], r#"a "quoted" name"#);
    }

    #[test]
    fn an_empty_quoted_parameter_is_still_a_parameter() {
        let params = split_params(r#"db "" third"#);
        assert_eq!(params, vec!["db", "", "third"]);
    }

    #[test]
    fn a_database_list_parses() {
        let lines = vec![
            r#"foldoc "The Free On-line Dictionary of Computing""#.to_string(),
            r#"wn "WordNet (r) 3.0""#.to_string(),
        ];
        assert_eq!(
            parse_databases(&lines),
            vec![
                Database {
                    name: "foldoc".into(),
                    description: "The Free On-line Dictionary of Computing".into()
                },
                Database {
                    name: "wn".into(),
                    description: "WordNet (r) 3.0".into()
                },
            ]
        );
    }

    #[test]
    fn a_match_list_parses() {
        let lines = vec![
            r#"wn "dictionary""#.to_string(),
            r#"foldoc "dict""#.to_string(),
        ];
        assert_eq!(
            parse_matches(&lines),
            vec![
                Match {
                    database: "wn".into(),
                    word: "dictionary".into()
                },
                Match {
                    database: "foldoc".into(),
                    word: "dict".into()
                },
            ]
        );
    }

    #[test]
    fn a_definition_header_yields_word_database_and_name() {
        let status = parse_status(r#"151 "dictionary" wn "WordNet (r) 3.0""#).unwrap();
        assert_eq!(status.code, DEFINITION_FOLLOWS);
        let (word, database, name) = parse_definition_header(&status).unwrap();
        assert_eq!(word, "dictionary");
        assert_eq!(database, "wn");
        assert_eq!(name, "WordNet (r) 3.0");
    }
}
