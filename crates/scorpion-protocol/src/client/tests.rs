use super::*;
use crate::request::Range;
use tokio::io::duplex;

/// Serve one canned response over an in-memory pipe and return what the
/// client sent.
async fn round_trip(request: &Request, canned: &[u8]) -> (Vec<u8>, Result<Response, ClientError>) {
    let (mut client_side, mut server_side) = duplex(64 * 1024);
    let canned = canned.to_vec();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        // Read exactly the request line, then answer.
        loop {
            let read = server_side.read(&mut byte).await.unwrap();
            if read == 0 {
                break;
            }
            seen.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        server_side.write_all(&canned).await.unwrap();
        server_side.flush().await.unwrap();
        drop(server_side);
        seen
    });

    let response = exchange(&mut client_side, request, Limits::default()).await;
    (server.await.unwrap(), response)
}

#[tokio::test]
async fn a_declared_length_is_read_exactly() {
    let (sent, response) = round_trip(
        &Request::receive("scorpion://example.com/"),
        b"20 5 text/plain\r\nhello",
    )
    .await;
    assert_eq!(sent, b"R scorpion://example.com/\r\n");
    let response = response.unwrap();
    assert_eq!(response.header.status, crate::Status::OK);
    assert_eq!(response.text(), Some("hello"));
}

#[tokio::test]
async fn an_unknown_length_is_read_to_end_of_stream() {
    let (_, response) = round_trip(
        &Request::receive("scorpion://example.com/dynamic"),
        b"20 ? text/plain\r\ngenerated on the fly",
    )
    .await;
    assert_eq!(response.unwrap().text(), Some("generated on the fly"));
}

#[tokio::test]
async fn unknown_bodies_accept_exact_fit_and_refuse_the_next_byte() {
    for (payload, cap, accepted) in [
        (&b""[..], 0, true),
        (&b"a"[..], 0, false),
        (&b"abc"[..], 3, true),
        (&b"abcd"[..], 3, false),
    ] {
        let mut wire = b"20 ? text/plain\r\n".to_vec();
        wire.extend_from_slice(payload);
        let response = read_response(
            &mut wire.as_slice(),
            Limits {
                max_body: cap,
                ..Limits::default()
            },
            None,
        )
        .await;
        if accepted {
            assert_eq!(response.unwrap().body, payload);
        } else {
            assert!(
                matches!(response, Err(ClientError::BodyTooLarge { limit, .. }) if limit == cap)
            );
        }
    }
}

#[tokio::test]
async fn partial_response_refuses_policy_overflow_but_preserves_range_framing() {
    let limits = Limits {
        max_body: 3,
        ..Limits::default()
    };
    let mut oversized = &b"21 100 text/plain\r\nabcd"[..];
    assert!(matches!(
        read_response(&mut oversized, limits, Some(Range::new(0, 10))).await,
        Err(ClientError::BodyTooLarge { limit: 3, .. })
    ));

    // A following status line is not part of the requested three bytes.
    let mut framed = &b"21 100 text/plain\r\nabc70 ready\r\n"[..];
    let response = read_response(&mut framed, limits, Some(Range::new(0, 3)))
        .await
        .unwrap();
    assert_eq!(response.body, b"abc");
    assert_eq!(framed, b"70 ready\r\n");
}

#[tokio::test]
async fn a_non_success_class_reads_no_body() {
    // The property that keeps the S subprotocol working: a 7x must not
    // consume the stream looking for a body that is not there.
    let (_, response) = round_trip(
        &Request::receive("scorpion://example.com/missing"),
        b"51 no such file\r\n",
    )
    .await;
    let response = response.unwrap();
    assert_eq!(response.header.status, crate::Status::NOT_FOUND);
    assert!(response.body.is_empty());
    assert_eq!(response.header.message(), Some("no such file"));
}

#[tokio::test]
async fn a_truncated_body_is_an_error_not_a_short_read() {
    let (_, response) = round_trip(
        &Request::receive("scorpion://example.com/"),
        b"20 100 text/plain\r\nonly this much",
    )
    .await;
    assert!(
        matches!(response, Err(ClientError::Truncated { declared: 100, .. })),
        "a server that under-delivers must not look like a successful short file"
    );
}

#[tokio::test]
async fn an_oversized_declaration_is_refused_before_buffering() {
    let (mut client_side, mut server_side) = duplex(1024);
    tokio::spawn(async move {
        let mut byte = [0u8; 1];
        while server_side.read(&mut byte).await.unwrap() != 0 && byte[0] != b'\n' {}
        server_side
            .write_all(b"20 999999999 text/plain\r\n")
            .await
            .unwrap();
        // Deliberately never send the body.
        std::future::pending::<()>().await;
    });

    let limits = Limits {
        max_body: 1024,
        ..Limits::default()
    };
    let error = exchange(
        &mut client_side,
        &Request::receive("scorpion://example.com/"),
        limits,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ClientError::BodyTooLarge { limit: 1024, .. }
    ));
}

#[tokio::test]
async fn a_partial_response_is_bounded_by_the_range_not_the_declared_size() {
    // The trap, from the reading side. A 21 declares the whole file's
    // size (10) while sending only the requested range (6). A client that
    // read the declared size would block forever waiting for four bytes
    // the server was never going to send.
    let (_, response) = round_trip(
        &Request::receive_range("scorpion://example.com/file", Range::new(3, 9)),
        b"21 10 text/plain\r\n345678",
    )
    .await;
    let response = response.unwrap();
    assert_eq!(response.text(), Some("345678"), "the range, not the file");
    assert_eq!(
        response.header.success().unwrap().unwrap().size,
        crate::Size::Known(10),
        "and the header still reports the whole file's size"
    );
}

#[tokio::test]
async fn a_range_running_past_the_end_of_a_file_is_not_an_error() {
    // A server answers what exists. Fewer bytes than asked for is normal
    // here, unlike a short 20, so it must not read as truncation.
    let (_, response) = round_trip(
        &Request::receive_range("scorpion://example.com/file", Range::new(8, 100)),
        b"21 10 text/plain\r\n89",
    )
    .await;
    assert_eq!(response.unwrap().text(), Some("89"));
}

#[test]
fn the_default_port_applies_when_a_url_omits_one() {
    assert_eq!(
        authority("scorpion://example.com/page").unwrap(),
        ("example.com".to_string(), 1517)
    );
    assert_eq!(
        authority("scorpion://example.com:1234/page").unwrap(),
        ("example.com".to_string(), 1234)
    );
}
