//! With no trust store installed, a TLS connection is refused before any
//! socket is opened. Its own test binary, because the store is process-wide:
//! no test here may install one.
#![cfg(feature = "tls")]

use std::net::TcpListener;

use gemini_protocol::ClientError;

/// A live loopback listener that never accepts on its own, so a connection
/// attempt would be visible as a pending accept.
fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn assert_refused_without_connecting(
    result: Result<impl std::fmt::Debug, ClientError>,
    listener: &TcpListener,
) {
    match result {
        Err(ClientError::Connect(message)) => assert!(
            message.contains("set_trust_store"),
            "the refusal names set_trust_store: {message}"
        ),
        other => panic!("expected the trust-store refusal, got {other:?}"),
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no connection was opened"
    );
}

#[tokio::test]
async fn fetch_without_a_store_is_refused_before_connecting() {
    let (listener, port) = listener();
    let result = gemini_protocol::fetch(&format!("gemini://127.0.0.1:{port}/")).await;
    assert_refused_without_connecting(result, &listener);
}

#[tokio::test]
async fn titan_and_tofu_connect_without_a_store_are_refused_too() {
    let (listener, port) = listener();
    let url = url::Url::parse(&format!("titan://127.0.0.1:{port}/upload")).unwrap();
    let result = gemini_protocol::titan::upload(&url, b"body", "text/plain", None).await;
    assert_refused_without_connecting(result, &listener);
    let result = gemini_protocol::tofu_connect("127.0.0.1", port).await;
    assert_refused_without_connecting(result, &listener);
}
