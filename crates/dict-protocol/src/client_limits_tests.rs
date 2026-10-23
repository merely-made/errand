use super::*;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

struct Script {
    input: std::io::Cursor<Vec<u8>>,
    writes: Arc<Mutex<Vec<u8>>>,
    fragment: usize,
}

impl AsyncRead for Script {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let position = self.input.position() as usize;
        let remaining = &self.input.get_ref()[position..];
        let count = remaining.len().min(buffer.remaining()).min(self.fragment);
        buffer.put_slice(&remaining[..count]);
        self.input.set_position((position + count) as u64);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Script {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn session(
    response: &str,
    limits: Limits,
    fragment: usize,
) -> (Session<Script>, Arc<Mutex<Vec<u8>>>) {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let stream = Script {
        input: std::io::Cursor::new(format!("220 x\r\n{response}").into_bytes()),
        writes: writes.clone(),
        fragment,
    };
    (
        Session::over_with_limits(stream, limits).await.unwrap(),
        writes,
    )
}

const TWO_DEFINITIONS: &str = "150 999999999999999999999 definitions\r\n\
    151 a db name\r\n\
    first\r\n\
    .\r\n\
    151 b db name\r\n\
    ..second\r\n\
    .\r\n\
    250 ok\r\n";

#[test]
fn defaults_are_finite_and_keep_native_command_ceiling() {
    assert_eq!(
        Limits::default(),
        Limits {
            max_command_bytes: MAX_LINE,
            max_line_bytes: 4096,
            max_response_bytes: 64 * 1024 * 1024,
            max_response_lines: 65_536,
        }
    );
}

#[tokio::test]
async fn command_exact_limit_and_plus_one_preflight_then_recovery() {
    let limits = Limits {
        max_command_bytes: 8,
        ..Limits::default()
    };
    let (mut session, writes) = session("250 ok\r\n250 ok\r\n", limits, usize::MAX).await;
    session.command("123456").await.unwrap();
    assert!(matches!(
        session.command("1234567").await,
        Err(ClientError::Protocol(_))
    ));
    assert_eq!(&*writes.lock().unwrap(), b"123456\r\n");
    session.command("STATUS").await.unwrap();
    assert_eq!(&*writes.lock().unwrap(), b"123456\r\nSTATUS\r\n");
}

#[tokio::test]
async fn native_command_ceiling_cannot_be_raised() {
    let limits = Limits {
        max_command_bytes: usize::MAX,
        ..Limits::default()
    };
    let (mut session, writes) = session("250 ok\r\n", limits, usize::MAX).await;
    session.command(&"x".repeat(MAX_LINE - 2)).await.unwrap();
    assert!(matches!(
        session.command(&"x".repeat(MAX_LINE - 1)).await,
        Err(ClientError::Protocol(_))
    ));
    assert_eq!(writes.lock().unwrap().len(), MAX_LINE);
}

#[tokio::test]
async fn framing_injection_and_oversized_quoted_inputs_never_write_or_poison() {
    let (mut session, writes) = session("552 absent\r\n", Limits::default(), usize::MAX).await;
    assert!(session.command("STATUS\r\nQUIT").await.is_err());
    assert!(session.announce("hello\nQUIT").await.is_err());
    assert!(session.define("db", "x\r\nQUIT").await.is_err());
    assert!(
        session
            .matches("db", "exact", &"\"".repeat(MAX_LINE))
            .await
            .is_err()
    );
    assert!(session.announce(&"x".repeat(MAX_LINE)).await.is_err());
    assert!(writes.lock().unwrap().is_empty());
    assert!(session.define("db", "safe").await.unwrap().is_empty());
    assert_eq!(&*writes.lock().unwrap(), b"DEFINE db safe\r\n");
}

#[tokio::test]
async fn fragmented_line_exact_and_plus_one_include_crlf() {
    let limits = Limits {
        max_line_bytes: 8,
        ..Limits::default()
    };
    let (mut session, writes) = session("250 xx\r\n250 xxx\r\n", limits, 1).await;
    session.command("STATUS").await.unwrap();
    assert!(session.command("STATUS").await.is_err());
    let before = writes.lock().unwrap().clone();
    assert!(session.command("QUIT").await.is_err());
    assert_eq!(
        *writes.lock().unwrap(),
        before,
        "unread fragments must not be reused"
    );
    assert!(session.unusable);
}

#[tokio::test]
async fn response_bytes_are_aggregate_across_definitions_and_trailer() {
    for excess in [0, 1] {
        let limits = Limits {
            max_response_bytes: TWO_DEFINITIONS.len() - excess,
            ..Limits::default()
        };
        let (mut session, _) = session(TWO_DEFINITIONS, limits, 3).await;
        let result = session.define("db", "a").await;
        if excess == 0 {
            let definitions = result.unwrap();
            assert_eq!(definitions.len(), 2);
            assert_eq!(definitions[1].text, [".second"]);
        } else {
            assert!(
                result.is_err(),
                "the last trailer byte belongs to this response"
            );
            assert!(session.unusable);
        }
    }
}

#[tokio::test]
async fn line_limit_is_aggregate_across_definitions_and_trailer() {
    for max_response_lines in [7, 8] {
        let limits = Limits {
            max_response_lines,
            ..Limits::default()
        };
        let (mut session, _) = session(TWO_DEFINITIONS, limits, usize::MAX).await;
        let result = session.define("db", "a").await;
        assert_eq!(result.is_ok(), max_response_lines == 8);
        assert_eq!(session.unusable, max_response_lines == 7);
    }
}

#[tokio::test]
async fn empty_text_lines_and_empty_definitions_consume_line_budget() {
    for response in [
        "150 1 definitions\r\n151 a db name\r\n\r\n\r\n\r\n.\r\n250 ok\r\n",
        "150 999999 definitions\r\n151 a db name\r\n.\r\n151 b db name\r\n.\r\n250 ok\r\n",
    ] {
        let limits = Limits {
            max_response_lines: 5,
            ..Limits::default()
        };
        let (mut session, writes) = session(response, limits, 1).await;
        assert!(session.define("db", "a").await.is_err());
        let before = writes.lock().unwrap().clone();
        assert!(session.command("STATUS").await.is_err());
        assert_eq!(*writes.lock().unwrap(), before);
    }
}

#[tokio::test]
async fn complete_commands_reset_the_budget_without_discarding_buffered_data() {
    let limits = Limits {
        max_response_bytes: TWO_DEFINITIONS.len(),
        max_response_lines: 8,
        ..Limits::default()
    };
    let (mut session, writes) = session(&TWO_DEFINITIONS.repeat(2), limits, usize::MAX).await;
    assert_eq!(session.define("db", "a").await.unwrap().len(), 2);
    assert_eq!(session.define("db", "b").await.unwrap().len(), 2);
    assert_eq!(&*writes.lock().unwrap(), b"DEFINE db a\r\nDEFINE db b\r\n");
}

#[tokio::test]
async fn database_and_match_blocks_share_status_and_trailer_budget() {
    for (response, is_match) in [
        ("110 1 databases\r\ndb name\r\n.\r\n250 ok\r\n", false),
        ("152 1 matches\r\ndb word\r\n.\r\n250 ok\r\n", true),
    ] {
        let limits = Limits {
            max_response_lines: 3,
            ..Limits::default()
        };
        let (mut session, _) = session(response, limits, usize::MAX).await;
        let failed = if is_match {
            session.matches("db", "exact", "word").await.is_err()
        } else {
            session.databases().await.is_err()
        };
        assert!(failed);
        assert!(session.unusable);
    }
}

#[tokio::test]
async fn partial_eof_bare_lf_and_invalid_utf8_poison_the_session() {
    for response in [b"250 truncated".as_slice(), b"250 \xff\r\n", b"250 bare\n"] {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mut input = b"220 x\r\n".to_vec();
        input.extend_from_slice(response);
        let stream = Script {
            input: std::io::Cursor::new(input),
            writes: writes.clone(),
            fragment: 1,
        };
        let mut session = Session::over(stream).await.unwrap();
        assert!(session.command("STATUS").await.is_err());
        assert!(session.command("QUIT").await.is_err());
        assert_eq!(&*writes.lock().unwrap(), b"STATUS\r\n");
    }
}

#[tokio::test]
async fn banner_and_invalid_configuration_are_bounded() {
    let writes = Arc::new(Mutex::new(Vec::new()));
    for limits in [
        Limits {
            max_line_bytes: 6,
            ..Limits::default()
        },
        Limits {
            max_response_bytes: 6,
            ..Limits::default()
        },
        Limits {
            max_response_lines: 0,
            ..Limits::default()
        },
        Limits {
            max_command_bytes: 1,
            ..Limits::default()
        },
    ] {
        let stream = Script {
            input: std::io::Cursor::new(b"220 x\r\n".to_vec()),
            writes: writes.clone(),
            fragment: 1,
        };
        assert!(Session::over_with_limits(stream, limits).await.is_err());
    }
    assert!(writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_tcp_connect_forwards_exact_response_and_line_limits() {
    for (max_line_bytes, max_response_bytes, response, succeeds) in [
        (8, 8, "250 xx\r\n", true),
        (32, 8, "250 xxx\r\n", false),
        (8, 32, "250 xxx\r\n", false),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (peer, _) = listener.accept().await.unwrap();
            let mut peer = BufReader::new(peer);
            peer.write_all(b"220 x\r\n").await.unwrap();
            let mut request = String::new();
            peer.read_line(&mut request).await.unwrap();
            assert_eq!(request, "STATUS\r\n");
            peer.write_all(response.as_bytes()).await.unwrap();
        });
        let limits = Limits {
            max_line_bytes,
            max_response_bytes,
            max_response_lines: 1,
            ..Limits::default()
        };
        let mut session = Session::connect_with_limits("127.0.0.1", Some(address.port()), limits)
            .await
            .unwrap();
        let result = session.command("STATUS").await;
        assert_eq!(result.is_ok(), succeeds);
        assert_eq!(session.unusable, !succeeds);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn native_tcp_invalid_configuration_refuses_before_contact() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let limits = Limits {
        max_response_bytes: 0,
        ..Limits::default()
    };
    assert!(matches!(
        Session::connect_with_limits("127.0.0.1", Some(address.port()), limits).await,
        Err(ClientError::Protocol(_))
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}
