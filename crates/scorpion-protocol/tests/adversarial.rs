//! Malformed input must fail, never panic.
//!
//! Everything this crate parses arrives from a peer, so the contract is not
//! "well-formed input parses correctly" but "no input, however crafted,
//! panics, hangs, or allocates without bound". A server that panics on a
//! malformed request line is a remote denial of service with one packet.
//!
//! Deterministic rather than random: a crash found on Tuesday and not on
//! Wednesday is not a regression test.

use scorpion_protocol::document::{self, Block, BlockType, Encoding};
use scorpion_protocol::{Header, Request};

/// Deterministic pseudo-random bytes, stable across runs and platforms.
fn noise(seed: u32, len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| {
            (seed
                .wrapping_mul(2_654_435_761)
                .wrapping_add(i.wrapping_mul(40_503))
                >> 8) as u8
        })
        .collect()
}

#[test]
fn arbitrary_bytes_never_panic_the_document_parser() {
    // The block format is pure length-prefix parsing -- a 16-bit attribute
    // length and a 24-bit body length, both attacker-controlled -- which is
    // exactly where an unchecked add or a wrong-width read shows up.
    for seed in 0..4096u32 {
        for len in [0usize, 1, 2, 3, 5, 6, 7, 9, 17, 64] {
            let _ = document::parse(&noise(seed, len));
        }
    }
}

#[test]
fn a_declared_body_larger_than_the_input_allocates_nothing() {
    // A block declaring the maximum 24-bit body, 16MB, inside seven bytes.
    // This must be refused by comparing declared against available, not by
    // allocating 16MB and discovering the shortfall.
    let bytes = [0x00u8, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x41];
    assert_eq!(
        document::parse(&bytes),
        Err(document::DocumentError::Truncated)
    );

    // Likewise a 65535-byte attribute inside four bytes.
    let bytes = [0x00u8, 0xFF, 0xFF, 0x41];
    assert_eq!(
        document::parse(&bytes),
        Err(document::DocumentError::Truncated)
    );
}

#[test]
fn a_truncated_document_iterator_terminates() {
    // The iterator must end after reporting truncation rather than yielding
    // the same error forever, which would hang any `collect`.
    for seed in 0..256u32 {
        let bytes = noise(seed, 9);
        let count = document::Blocks::new(&bytes).take(1000).count();
        assert!(count < 1000, "iterator did not terminate on seed {seed}");
    }
}

#[test]
fn every_truncation_of_a_valid_document_is_survivable() {
    let blocks = vec![
        Block {
            block_type: BlockType::Heading(1),
            encoding: Encoding::Pc,
            attribute: b"top".to_vec(),
            body: b"Title".to_vec(),
        },
        Block::link(
            b"scorpion://example.com/x".to_vec(),
            b"Next".to_vec(),
            Encoding::Pc,
        ),
    ];
    let encoded = document::encode(&blocks).unwrap();
    for length in 0..encoded.len() {
        let _ = document::parse(&encoded[..length]);
    }
}

#[test]
fn a_link_url_of_arbitrary_bytes_never_panics() {
    // `url()` truncates at a NUL and refuses non-ASCII. Both are slicing
    // operations on attacker-controlled bytes.
    for seed in 0..512u32 {
        let block = Block::link(noise(seed, 24), noise(seed ^ 0xFF, 8), Encoding::Iso2022);
        let _ = block.url();
    }
}

#[test]
fn arbitrary_text_never_panics_the_request_parser() {
    // A request line arrives from the network. Multi-byte UTF-8 in the first
    // character is the classic slicing hazard here, because the subprotocol
    // byte is read as a char and the remainder sliced after it.
    let cases = [
        "",
        " ",
        "R",
        "R ",
        "R  ",
        "\r\n",
        "\n",
        "R\r\n",
        " \r\n",
        "\u{e9} scorpion://x/",
        "\u{1F600} scorpion://x/",
        "R\u{1F600} scorpion://x/",
        "R\u{0}scorpion://x/",
        "R scorpion://\u{1F600}/",
        "S@ scorpion://x/",
        "S@@@ scorpion://x/",
        "R- scorpion://x/",
        "R-1- scorpion://x/",
        "R99999999999999999999- scorpion://x/",
        "M\u{e9} scorpion://x/",
        "I\u{7f} scorpion://x/",
        ":// scorpion://x/",
        "R :",
        "R ::::",
    ];
    for case in cases {
        let _ = Request::parse(case);
    }
    for seed in 0..1024u32 {
        let bytes = noise(seed, 24);
        if let Ok(text) = core::str::from_utf8(&bytes) {
            let _ = Request::parse(text);
        }
        // And the lossy form, which is always valid UTF-8 and often weird.
        let _ = Request::parse(&String::from_utf8_lossy(&bytes));
    }
}

#[test]
fn arbitrary_text_never_panics_the_response_parser() {
    // The status line's first two bytes are checked as ASCII digits, which is
    // what makes byte offset 2 a safe char boundary. If that check were ever
    // relaxed, `line.get(2..)` would start returning None on multi-byte input.
    let cases = [
        "",
        "2",
        "20",
        "20 ",
        "2\u{e9}",
        "\u{1F600}0 x",
        "20\u{1F600}",
        "90 nine is not a class",
        "99",
        "0",
        "  ",
        "20  ",
        "\r\n",
        "20\r\n",
        "20 ? ",
        "20 ?",
        "44 99999999999999999999 msg",
        "60",
        "60 ",
        "60 =",
        "60 \u{1F600}/path text",
        "81",
        "82 ",
    ];
    for case in cases {
        let _ = Header::parse(case);
    }
    for seed in 0..1024u32 {
        let bytes = noise(seed, 24);
        let _ = Header::parse(&String::from_utf8_lossy(&bytes));
    }
}

#[test]
fn a_status_line_with_a_multibyte_char_after_the_code_is_handled() {
    // Offset 2 is a char boundary because bytes 0 and 1 were verified ASCII
    // digits. The parse must therefore see the separator check, not silently
    // drop the parameters.
    let header = Header::parse("20\u{e9}nonsense");
    assert!(
        header.is_err(),
        "a status code not followed by a space is malformed, not parameterless"
    );
}

#[test]
fn every_request_round_trips_through_its_own_wire_form() {
    // Anything the parser accepts must survive being re-rendered and reparsed.
    // A divergence here means the two halves disagree about the grammar.
    for seed in 0..2048u32 {
        let text = String::from_utf8_lossy(&noise(seed, 32)).into_owned();
        let Ok(request) = Request::parse(&text) else {
            continue;
        };
        let wire = request.to_wire();
        let Ok(rendered) = String::from_utf8(wire) else {
            panic!("a parsed request rendered to invalid UTF-8: {request:?}");
        };
        let reparsed = Request::parse(&rendered).expect("a rendered request must reparse");
        assert_eq!(
            reparsed.subprotocol, request.subprotocol,
            "subprotocol changed across a round trip of {text:?}"
        );
        assert_eq!(
            reparsed.parameter, request.parameter,
            "parameter changed across a round trip of {text:?}"
        );
    }
}

#[test]
fn a_header_round_trips_through_its_own_wire_form() {
    for seed in 0..2048u32 {
        let text = String::from_utf8_lossy(&noise(seed, 32)).into_owned();
        let Ok(header) = Header::parse(&text) else {
            continue;
        };
        let rendered = String::from_utf8(header.to_wire()).expect("valid UTF-8");
        let reparsed = Header::parse(&rendered).expect("a rendered header must reparse");
        assert_eq!(
            reparsed.status, header.status,
            "status changed across a round trip of {text:?}"
        );
        assert_eq!(
            reparsed.parameters, header.parameters,
            "parameters changed across a round trip of {text:?}"
        );
    }
}
