use super::*;

pub(super) async fn gemini_exchange(
    raw: Vec<u8>,
    options: &gemini_protocol::FetchOptions,
) -> (
    Result<gemini_protocol::Response, gemini_protocol::ClientError>,
    Vec<u8>,
) {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut request = [0; 256];
        let _ = server.read(&mut request).await.unwrap();
        for fragment in raw.chunks(3) {
            if server.write_all(fragment).await.is_err() {
                break;
            }
        }
    });
    let mut seen = vec![];
    let result = gemini_protocol::exchange_streaming_with_options(
        &Url::parse("gemini://x/").unwrap(),
        &mut client,
        options,
        |_, bytes| seen.extend_from_slice(bytes),
    )
    .await;
    drop(client);
    server.await.unwrap();
    (result, seen)
}

#[tokio::test]
async fn gemini_fragmented_headers_and_callback_obey_independent_caps() {
    let options = gemini_protocol::FetchOptions {
        max_header_line_bytes: 15,
        max_body_bytes: 4,
        ..Default::default()
    };
    let (result, seen) = gemini_exchange(b"20 text/plain\r\nABCD".to_vec(), &options).await;
    assert_eq!(result.unwrap().body, b"ABCD");
    assert_eq!(seen, b"ABCD");
    let (result, seen) = gemini_exchange(b"20 text/plain\r\nABCDE".to_vec(), &options).await;
    assert!(matches!(
        result,
        Err(gemini_protocol::ClientError::Protocol(_))
    ));
    assert!(seen.len() <= 4, "oversized bytes reached callback");
    let (result, seen) = gemini_exchange(b"20 text/plainX\r\nABCD".to_vec(), &options).await;
    assert!(matches!(
        result,
        Err(gemini_protocol::ClientError::Protocol(_))
    ));
    assert!(seen.is_empty());
    let options = gemini_protocol::FetchOptions {
        max_header_line_bytes: 4096,
        ..options
    };
    let raw = format!("20 {}\r\n", "x".repeat(1020)).into_bytes();
    assert!(
        gemini_exchange(raw, &options).await.0.is_err(),
        "caller cannot lift native1024 ceiling"
    );
}

pub(super) async fn scroll_exchange(
    raw: Vec<u8>,
    options: &scroll_protocol::FetchOptions,
) -> Result<scroll_protocol::Response, scroll_protocol::ClientError> {
    let (mut client, mut server) = tokio::io::duplex(128);
    let server = tokio::spawn(async move {
        let mut request = [0; 256];
        let _ = server.read(&mut request).await.unwrap();
        let _ = server.write_all(&raw).await;
    });
    let result =
        scroll_protocol::exchange_with_options("scroll://x/", &["en"], false, &mut client, options)
            .await;
    drop(client);
    server.await.unwrap();
    result
}

#[tokio::test]
async fn scroll_long_verbatim_dates_and_native_metadata_survive_configurable_line_cap() {
    let date = format!("2026-10-22T12:00:00.{}Z", "7".repeat(5000));
    let raw = format!("27 text/scroll\r\nAuthor\r\n{date}\r\n\r\nABCD").into_bytes();
    assert!(
        scroll_exchange(raw.clone(), &Default::default())
            .await
            .is_err()
    );
    let options = scroll_protocol::FetchOptions {
        max_header_line_bytes: date.len() + 2,
        max_body_bytes: 4,
        ..Default::default()
    };
    let response = scroll_exchange(raw.clone(), &options).await.unwrap();
    let scroll_protocol::Header::Success(header) = response.header else {
        panic!("success expected")
    };
    assert_eq!(header.published.as_deref(), Some(date.as_str()));
    assert_eq!(header.author.as_deref(), Some("Author"));
    assert_eq!(header.code, 27);
    assert_eq!(response.body, b"ABCD");
    assert!(
        scroll_exchange(
            raw.clone(),
            &scroll_protocol::FetchOptions {
                max_header_line_bytes: date.len() + 1,
                ..options
            }
        )
        .await
        .is_err()
    );
    assert!(
        scroll_exchange(
            raw,
            &scroll_protocol::FetchOptions {
                max_body_bytes: 3,
                ..options
            }
        )
        .await
        .is_err()
    );
    assert!(
        scroll_exchange(b"20 text/scroll\n".to_vec(), &options)
            .await
            .is_err()
    );
}
