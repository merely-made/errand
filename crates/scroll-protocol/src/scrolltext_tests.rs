use super::*;

#[test]
fn headings_carry_their_level_and_five_is_the_ceiling() {
    assert_eq!(
        parse("# Title\n##### textual\n###### not a heading\n"),
        vec![
            ScrollLine::Heading {
                level: 1,
                text: "Title".into()
            },
            ScrollLine::Heading {
                level: 5,
                text: "textual".into()
            },
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
            ScrollLine::Quote {
                depth: 1,
                text: "outer".into()
            },
            ScrollLine::Quote {
                depth: 2,
                text: "inner".into()
            },
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
            ScrollLine::ListItem {
                depth: 1,
                ordinal: None,
                text: "Unordered list item 1".into()
            },
            ScrollLine::ListItem {
                depth: 2,
                ordinal: Some("1.".into()),
                text: "Ordered sub-list item 1".into()
            },
            ScrollLine::ListItem {
                depth: 2,
                ordinal: Some("2.".into()),
                text: "Ordered sub-list item 2".into()
            },
            ScrollLine::ListItem {
                depth: 1,
                ordinal: None,
                text: "Unordered list item 2".into()
            },
        ]
    );
}

#[test]
fn a_list_needs_its_required_whitespace() {
    // Without the space this is bold inline markup, not a list: the spec
    // calls the required whitespace the disambiguator.
    assert!(matches!(parse("*bold start*\n")[0], ScrollLine::Text(_)));
    assert!(matches!(parse("* item\n")[0], ScrollLine::ListItem { .. }));
    assert!(matches!(
        parse("*\ttabbed item\n")[0],
        ScrollLine::ListItem { .. }
    ));
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
            relation: Some(Relation {
                polarity: Polarity::Neutral,
                tag: Some("Citation".into())
            }),
        }
    );
    assert_eq!(
        parse("=> scroll://example.net/x.txt Name [-Citation]\n")[0],
        ScrollLine::Link {
            url: "scroll://example.net/x.txt".into(),
            label: "Name".into(),
            relation: Some(Relation {
                polarity: Polarity::Negative,
                tag: Some("Citation".into())
            }),
        }
    );
    assert_eq!(
        parse("=> scroll://example.net/cited.pdf Cited Text Name [+]\n")[0],
        ScrollLine::Link {
            url: "scroll://example.net/cited.pdf".into(),
            label: "Cited Text Name".into(),
            relation: Some(Relation {
                polarity: Polarity::Positive,
                tag: None
            }),
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
    assert_eq!(
        parse("\\# not a heading\n")[0],
        ScrollLine::Text("# not a heading".into())
    );
    assert_eq!(
        parse("\\=> not a link\n")[0],
        ScrollLine::Text("=> not a link".into())
    );
    assert_eq!(parse("\\---\n")[0], ScrollLine::Text("---".into()));
    // A backslash anywhere else is just a character.
    assert_eq!(
        parse("\\ordinary\n")[0],
        ScrollLine::Text("\\ordinary".into())
    );
}

#[test]
fn blank_lines_survive_because_they_separate_lists() {
    assert_eq!(
        parse("* one\n\n* two\n"),
        vec![
            ScrollLine::ListItem {
                depth: 1,
                ordinal: None,
                text: "one".into()
            },
            ScrollLine::Blank,
            ScrollLine::ListItem {
                depth: 1,
                ordinal: None,
                text: "two".into()
            },
        ]
    );
}

// ── Inline markup ──────────────────────────────────────────────────

#[test]
fn strong_emphasis_and_code_toggle() {
    assert_eq!(
        spans("a *b* c"),
        vec![
            Span {
                kind: SpanKind::Plain,
                text: "a ".into()
            },
            Span {
                kind: SpanKind::Strong,
                text: "b".into()
            },
            Span {
                kind: SpanKind::Plain,
                text: " c".into()
            },
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
        vec![Span {
            kind: SpanKind::Plain,
            text: "a * b".into()
        }]
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
        vec![Span {
            kind: SpanKind::Plain,
            text: "(*)".into()
        }]
    );
}
