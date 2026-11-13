//! Loopback-only qualification of caller bounds across the routed protocols.
use errand::{Error, FetchOptions, Url};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

async fn tcp_reply(
    scheme: &str,
    reply: Vec<u8>,
    options: &FetchOptions,
) -> Result<errand::Response, Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 512];
        let _ = stream.read(&mut request).await.unwrap();
        let _ = stream.write_all(&reply).await;
    });
    let result = errand::fetch_with_options(&format!("{scheme}://{address}/"), options).await;
    server.await.unwrap();
    result
}

#[tokio::test]
async fn routed_tcp_body_caps_accept_exact_and_empty_refuse_one_extra() {
    for scheme in ["gopher", "finger", "nex", "spartan"] {
        for size in [0, 4, 5] {
            let options = FetchOptions {
                max_body_bytes: 4,
                ..Default::default()
            };
            let mut reply = if scheme == "spartan" {
                b"2 text/plain\r\n".to_vec()
            } else {
                vec![]
            };
            reply.extend(std::iter::repeat_n(b'x', size));
            let result = tcp_reply(scheme, reply, &options).await;
            if size <= 4 {
                assert_eq!(result.unwrap().body.len(), size, "{scheme}");
            } else {
                assert!(
                    matches!(result, Err(Error::Protocol(_))),
                    "{scheme}: {result:?}"
                );
            }
        }
        let zero = FetchOptions {
            max_body_bytes: 0,
            ..Default::default()
        };
        let reply = if scheme == "spartan" {
            b"2 text/plain\r\n".to_vec()
        } else {
            vec![]
        };
        assert!(
            tcp_reply(scheme, reply, &zero)
                .await
                .unwrap()
                .body
                .is_empty()
        );
    }
}

#[tokio::test]
async fn spartan_response_header_is_separate_from_body_budget() {
    let reply = b"2 application/octet-stream\r\nABCD".to_vec();
    let options = FetchOptions {
        max_body_bytes: 4,
        max_header_line_bytes: 28,
        ..Default::default()
    };
    assert_eq!(
        tcp_reply("spartan", reply.clone(), &options)
            .await
            .unwrap()
            .body,
        b"ABCD"
    );
    let options = FetchOptions {
        max_header_line_bytes: 27,
        ..options
    };
    assert!(matches!(
        tcp_reply("spartan", reply, &options).await,
        Err(Error::Protocol(_))
    ));
}

#[tokio::test]
async fn routed_deadlines_expire_while_peer_keeps_connection_open() {
    for scheme in [
        "gopher", "finger", "nex", "spartan", "gemini", "scroll", "titan",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("{scheme}://{}/", listener.local_addr().unwrap());
        let options = FetchOptions {
            timeout: Duration::from_millis(30),
            ..Default::default()
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _stream = stream;
            std::future::pending::<()>().await;
        });
        let result = errand::fetch_with_options(&url, &options).await;
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(
            matches!(result, Err(Error::Timeout)),
            "{scheme}: {result:?}"
        );
    }
}

#[tokio::test]
async fn routed_request_budget_refuses_before_connection() {
    for scheme in [
        "gopher", "finger", "nex", "spartan", "gemini", "scroll", "titan", "guppy",
    ] {
        let options = FetchOptions {
            max_request_bytes: 0,
            ..Default::default()
        };
        let result =
            errand::fetch_with_options(&format!("{scheme}://127.0.0.1:1/"), &options).await;
        assert!(
            matches!(result, Err(Error::Protocol(_))),
            "{scheme}: {result:?}"
        );
    }
}

async fn guppy_packets(
    packets: Vec<Vec<u8>>,
    options: &FetchOptions,
) -> Result<errand::Response, Error> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut request = [0; 2048];
        let (_, peer) = socket.recv_from(&mut request).await.unwrap();
        for packet in packets {
            socket.send_to(&packet, peer).await.unwrap();
        }
        let _ = finished.await;
        drop(socket);
    });
    let result = errand::fetch_with_options(&format!("guppy://{address}/"), options).await;
    let _ = finish.send(());
    server.await.unwrap();
    result
}

#[tokio::test]
async fn guppy_duplicates_out_of_order_eof_and_gap_filling_cannot_bypass_cap() {
    let options = FetchOptions {
        max_body_bytes: 4,
        timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let first = b"10 text/plain\r\nAB".to_vec();
    let exact = vec![
        first.clone(),
        b"12\r\nD".to_vec(),
        b"12\r\nD".to_vec(),
        b"13\r\n".to_vec(),
        b"11\r\nC".to_vec(),
    ];
    assert_eq!(guppy_packets(exact, &options).await.unwrap().body, b"ABCD");
    let overflow = vec![
        first,
        b"12\r\nD".to_vec(),
        b"13\r\n".to_vec(),
        b"11\r\nCE".to_vec(),
    ];
    assert!(matches!(
        guppy_packets(overflow, &options).await,
        Err(Error::Protocol(_))
    ));
    assert!(
        guppy_packets(vec![b"10 text/plain\r\nABCDE".to_vec()], &options)
            .await
            .is_err()
    );
    let zero = FetchOptions {
        max_body_bytes: 0,
        ..options
    };
    assert!(
        guppy_packets(
            vec![b"10 text/plain\r\n".to_vec(), b"11\r\n".to_vec()],
            &zero
        )
        .await
        .unwrap()
        .body
        .is_empty()
    );
}

#[tokio::test]
async fn guppy_special_header_budget_is_checked() {
    let options = FetchOptions {
        max_header_line_bytes: 7,
        ..Default::default()
    };
    assert_eq!(
        guppy_packets(vec![b"1 abc\r\n".to_vec()], &options)
            .await
            .unwrap()
            .meta,
        "abc"
    );
    assert!(
        guppy_packets(vec![b"1 abcd\r\n".to_vec()], &options)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn explicit_writes_count_payload_and_line_before_network() {
    let options = FetchOptions {
        max_request_bytes: 4,
        ..Default::default()
    };
    let url = Url::parse("spartan://127.0.0.1:1/").unwrap();
    assert!(matches!(
        errand::spartan_submit_with_options(&url, b"ABCD", &options).await,
        Err(Error::Protocol(_))
    ));
    let url = Url::parse("titan://127.0.0.1:1/").unwrap();
    assert!(matches!(
        errand::titan_upload_with_options(&url, b"ABCD", "text/plain", None, &options).await,
        Err(Error::Protocol(_))
    ));
}

#[tokio::test]
async fn legacy_explicit_write_wrappers_allow_caller_owned_payloads_over_read_request_default() {
    let body = vec![b'x'; 8192];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!(
        "spartan://{}/upload",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = vec![];
        loop {
            let byte = stream.read_u8().await.unwrap();
            header.push(byte);
            if header.ends_with(b"\r\n") {
                break;
            }
        }
        assert!(String::from_utf8(header).unwrap().ends_with(" 8192\r\n"));
        let mut body = vec![0; 8192];
        stream.read_exact(&mut body).await.unwrap();
        assert!(body.iter().all(|b| *b == b'x'));
        stream.write_all(b"2 text/plain\r\nreceipt").await.unwrap();
    });
    assert_eq!(
        errand::spartan_submit(&url, &body).await.unwrap().body,
        b"receipt"
    );
    server.await.unwrap();
    // A refusing loopback port distinguishes passing the legacy Titan preflight
    // from a request-size rejection without requiring any public/TLS endpoint.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let url = Url::parse(&format!("titan://{address}/upload")).unwrap();
    assert!(matches!(
        errand::titan_upload(&url, &body, "text/plain", None).await,
        Err(Error::Connect(_))
    ));
}

async fn tls_reply(
    scheme: &str,
    reply: Vec<u8>,
    options: &FetchOptions,
) -> Result<errand::Response, Error> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(cert.cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request = vec![];
        loop {
            let byte = stream.read_u8().await.unwrap();
            request.push(byte);
            if request.ends_with(b"\r\n") {
                break;
            }
        }
        let _ = stream.write_all(&reply).await;
        let _ = stream.shutdown().await;
    });
    let result = errand::fetch_with_options(&format!("{scheme}://{address}/"), options).await;
    server.await.unwrap();
    result
}

#[tokio::test]
async fn routed_tls_facade_forwards_body_and_header_policy() {
    let options = FetchOptions {
        max_body_bytes: 4,
        max_header_line_bytes: 15,
        ..Default::default()
    };
    for scheme in ["gemini", "scroll", "titan"] {
        let header = if scheme == "scroll" {
            "27 text/plain\r\nA\r\n\r\n\r\n"
        } else {
            "20 text/plain\r\n"
        };
        for size in [4, 5] {
            let raw = format!("{header}{}", "x".repeat(size)).into_bytes();
            let result = tls_reply(scheme, raw, &options).await;
            if size == 4 {
                assert_eq!(result.unwrap().body, b"xxxx", "{scheme}");
            } else {
                assert!(
                    matches!(result, Err(Error::Protocol(_))),
                    "{scheme}: {result:?}"
                );
            }
        }
        let zero = FetchOptions {
            max_body_bytes: 0,
            ..options
        };
        assert!(
            tls_reply(scheme, header.as_bytes().to_vec(), &zero)
                .await
                .unwrap()
                .body
                .is_empty()
        );
        assert!(
            tls_reply(scheme, format!("{header}x").into_bytes(), &zero)
                .await
                .is_err()
        );
        let raw = format!("{header}xxxx").into_bytes();
        let result = tls_reply(
            scheme,
            raw,
            &FetchOptions {
                max_header_line_bytes: 14,
                ..options
            },
        )
        .await;
        assert!(
            matches!(result, Err(Error::Protocol(_))),
            "{scheme}: {result:?}"
        );
    }
}

#[tokio::test]
async fn headerless_and_spartan_request_caps_are_exact_wire_bytes() {
    for (scheme, size) in [("gopher", 2), ("finger", 2), ("nex", 3), ("spartan", 15)] {
        let options = FetchOptions {
            max_request_bytes: size,
            ..Default::default()
        };
        let reply = if scheme == "spartan" {
            b"2 text/plain\r\nOK".to_vec()
        } else {
            b"OK".to_vec()
        };
        assert_eq!(
            tcp_reply(scheme, reply, &options).await.unwrap().body,
            b"OK"
        );
        let options = FetchOptions {
            max_request_bytes: size - 1,
            ..options
        };
        let error = errand::fetch_with_options(&format!("{scheme}://127.0.0.1:1/"), &options)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)), "{scheme}: {error:?}");
    }
}

#[test]
fn bounded_facade_policy_does_not_rewrite_existing_finite_native_defaults() {
    assert_eq!(FetchOptions::default().max_body_bytes, 64 * 1024 * 1024);
    assert_eq!(FetchOptions::default().timeout, Duration::from_secs(30));
    assert_eq!(
        nex_protocol::FetchOptions::default().max_body,
        16 * 1024 * 1024
    );
    assert_eq!(
        spartan_protocol::FetchOptions::default().max_body,
        16 * 1024 * 1024
    );
    assert_eq!(
        guppy_protocol::FetchOptions::default().max_body,
        16 * 1024 * 1024
    );
    assert_eq!(
        gemini_protocol::titan::UploadOptions::default().max_response_bytes,
        16 * 1024 * 1024
    );
}

#[tokio::test]
async fn native_gemini_and_scroll_request_caps_include_the_exact_line_ending() {
    let options = gemini_protocol::FetchOptions {
        max_request_bytes: "gemini://x/\r\n".len(),
        ..Default::default()
    };
    assert!(
        gemini_exchange(b"20 text/plain\r\n".to_vec(), &options)
            .await
            .0
            .is_ok()
    );
    assert!(
        gemini_exchange(
            b"20 text/plain\r\n".to_vec(),
            &gemini_protocol::FetchOptions {
                max_request_bytes: options.max_request_bytes - 1,
                ..options
            }
        )
        .await
        .0
        .is_err()
    );
    let options = scroll_protocol::FetchOptions {
        max_request_bytes: "scroll://x/ en\r\n".len(),
        ..Default::default()
    };
    assert!(
        scroll_exchange(b"20 text/plain\r\n\r\n\r\n\r\n".to_vec(), &options)
            .await
            .is_ok()
    );
    assert!(
        scroll_exchange(
            b"20 text/plain\r\n\r\n\r\n\r\n".to_vec(),
            &scroll_protocol::FetchOptions {
                max_request_bytes: options.max_request_bytes - 1,
                ..options
            }
        )
        .await
        .is_err()
    );
}

#[path = "client_limits/streaming.rs"]
mod streaming;
use streaming::{gemini_exchange, scroll_exchange};
