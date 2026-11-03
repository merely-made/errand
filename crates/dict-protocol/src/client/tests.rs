use super::*;
use tokio::io::AsyncReadExt;

/// Drive a session against a scripted server over an in-memory duplex.
async fn scripted(script: &'static [&'static str]) -> Session<tokio::io::DuplexStream> {
    let (client, mut server) = tokio::io::duplex(8192);
    tokio::spawn(async move {
        for chunk in script {
            server.write_all(chunk.as_bytes()).await.unwrap();
            // Let the client consume and issue its next command.
            let mut buf = [0u8; 512];
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(50), server.read(&mut buf))
                    .await;
        }
    });
    Session::over(client).await.unwrap()
}

#[test]
fn parameters_are_quoted_only_when_they_need_it() {
    assert_eq!(quote("wn"), "wn");
    assert_eq!(quote("free software"), "\"free software\"");
    assert_eq!(quote(""), "\"\"");
    assert_eq!(quote(r#"say "hi""#), r#""say \"hi\""#.to_string() + "\"");
}

#[tokio::test]
async fn a_non_banner_greeting_is_refused() {
    let (client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        server.write_all(b"500 go away\r\n").await.unwrap();
    });
    match Session::over(client).await {
        Err(error) => assert!(matches!(error, ClientError::Protocol(_)), "got {error:?}"),
        Ok(_) => panic!("a 500 greeting must not open a session"),
    }
}

#[tokio::test]
async fn a_definition_is_read_with_its_text_block() {
    let (client, mut server) = tokio::io::duplex(8192);
    tokio::spawn(async move {
        server.write_all(b"220 test <1@x>\r\n").await.unwrap();
        let mut buf = [0u8; 512];
        let n = server.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("DEFINE"));
        server
            .write_all(
                b"150 1 definitions retrieved\r\n\
                  151 \"dict\" wn \"WordNet\"\r\n\
                  a reference work\r\n\
                  ..a line that began with a period\r\n\
                  .\r\n\
                  250 ok\r\n",
            )
            .await
            .unwrap();
    });

    let mut session = Session::over(client).await.unwrap();
    let definitions = session.define("wn", "dict").await.unwrap();

    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions[0].word, "dict");
    assert_eq!(definitions[0].database, "wn");
    assert_eq!(definitions[0].database_description, "WordNet");
    assert_eq!(
        definitions[0].text,
        vec![
            "a reference work".to_string(),
            ".a line that began with a period".to_string(),
        ],
        "the doubled period must be undone"
    );
}

#[tokio::test]
async fn no_match_is_an_empty_answer_not_an_error() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        server.write_all(b"220 test <1@x>\r\n").await.unwrap();
        let mut buf = [0u8; 512];
        let _ = server.read(&mut buf).await.unwrap();
        server.write_all(b"552 no match\r\n").await.unwrap();
    });

    let mut session = Session::over(client).await.unwrap();
    assert!(session.define("wn", "zzzz").await.unwrap().is_empty());
}

#[tokio::test]
async fn an_invalid_database_is_refused_with_its_code() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        server.write_all(b"220 test <1@x>\r\n").await.unwrap();
        let mut buf = [0u8; 512];
        let _ = server.read(&mut buf).await.unwrap();
        server.write_all(b"550 invalid database\r\n").await.unwrap();
    });

    let mut session = Session::over(client).await.unwrap();
    let error = session.define("nope", "dict").await.unwrap_err();
    assert!(
        matches!(error, ClientError::Refused { code: 550, .. }),
        "got {error:?}"
    );
}

#[tokio::test]
async fn a_database_list_is_read_and_the_trailing_ok_consumed() {
    let (client, mut server) = tokio::io::duplex(8192);
    tokio::spawn(async move {
        server.write_all(b"220 test <1@x>\r\n").await.unwrap();
        let mut buf = [0u8; 512];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(
                b"110 2 databases present\r\n\
                  wn \"WordNet (r) 3.0\"\r\n\
                  foldoc \"Free On-line Dictionary of Computing\"\r\n\
                  .\r\n\
                  250 ok\r\n",
            )
            .await
            .unwrap();
        // A following command must see a clean stream, which only holds if
        // the 250 was consumed.
        let n = server.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("QUIT"));
        server.write_all(b"221 bye\r\n").await.unwrap();
    });

    let mut session = Session::over(client).await.unwrap();
    let databases = session.databases().await.unwrap();
    assert_eq!(databases.len(), 2);
    assert_eq!(databases[1].name, "foldoc");
    session.quit().await.unwrap();
}

#[tokio::test]
async fn an_over_long_command_never_reaches_the_wire() {
    let mut session = scripted(&["220 test <1@x>\r\n"]).await;
    let error = session
        .command(&format!("DEFINE wn {}", "x".repeat(MAX_LINE)))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Protocol(_)), "got {error:?}");
}
