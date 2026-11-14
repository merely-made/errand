use super::*;
use crate::ExposeSecret;

#[tokio::test]
async fn native_tcp_peer_stalling_during_tls_handshake_is_closed_at_phase_deadline() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let server = crate::server::MisfinServer::new(
        MisfinServerConfig::new(
            identity.certificate_der,
            identity.private_key_pkcs8_der.expose_secret().to_vec(),
            Vec::new(),
        ),
        MailboxStore::in_memory().unwrap(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let budget = ReceiveBudget::new(
        Instant::now(),
        Duration::from_millis(700),
        Duration::from_secs(3),
    )
    .unwrap();
    let handler = tokio::spawn(handle_connection(
        server.acceptor,
        server.dispatcher,
        tcp,
        budget,
    ));

    assert_timeout(
        handler.await.unwrap().unwrap_err(),
        "misfin TLS handshake timed out",
    );
    let mut client = client;
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read_u8())
        .await
        .expect("timed-out server handler closes the accepted TCP peer");
    assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn expired_acceptance_deadline_stops_native_handshake_before_it_starts() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let server = crate::server::MisfinServer::new(
        MisfinServerConfig::new(
            identity.certificate_der,
            identity.private_key_pkcs8_der.expose_secret().to_vec(),
            Vec::new(),
        ),
        MailboxStore::in_memory().unwrap(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let budget = ReceiveBudget::new(
        Instant::now() - Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(1),
    )
    .unwrap();
    let handler = tokio::spawn(handle_connection(
        server.acceptor,
        server.dispatcher,
        tcp,
        budget,
    ));

    assert_timeout(
        handler.await.unwrap().unwrap_err(),
        "misfin receive timed out",
    );
    let mut client = client;
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read_u8())
        .await
        .expect("expired acceptance budget closes the TCP peer");
    assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn native_tls_client_stalling_after_handshake_is_closed_without_mail() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let store = MailboxStore::in_memory().unwrap();
    let server = crate::server::MisfinServer::new(
        MisfinServerConfig::new(
            identity.certificate_der,
            identity.private_key_pkcs8_der.expose_secret().to_vec(),
            Vec::new(),
        ),
        store.clone(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = server.acceptor.clone();
    let dispatcher = server.dispatcher.clone();
    let accepted = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let budget = ReceiveBudget::new(
            Instant::now(),
            Duration::from_millis(700),
            Duration::from_secs(3),
        )
        .unwrap();
        handle_connection(acceptor, dispatcher, tcp, budget).await
    });
    let mut client = crate::server::tests::test_tls_client(address).await;

    assert_timeout(
        accepted.await.unwrap().unwrap_err(),
        "misfin request read timed out",
    );
    let mut response = Vec::new();
    let read_result =
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("timed-out TLS handler closes its peer");
    assert_eq!(
        read_result.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof,
        "TCP close without TLS close_notify is the expected deadline outcome"
    );
    assert!(response.is_empty());
    assert!(store.list("mark@example.test").unwrap().is_empty());
}

#[tokio::test]
async fn public_listener_passes_configured_deadlines_and_gives_each_accept_a_fresh_budget() {
    let identity = deterministic_identity(
        &[1; 32],
        &MisfinIdentitySpec {
            address: MisfinAddress::parse("mark@example.test").unwrap(),
            blurb: None,
        },
    )
    .unwrap();
    let mut config = MisfinServerConfig::new(
        identity.certificate_der,
        identity.private_key_pkcs8_der.expose_secret().to_vec(),
        Vec::new(),
    );
    // The whole allowance wins; neither listener idle time nor earlier peers
    // consume the next accepted transaction's allowance.
    config.timeout = Duration::from_secs(3);
    config.receive_timeout = Duration::from_millis(700);
    let bound = crate::server::MisfinServer::new(config, MailboxStore::in_memory().unwrap())
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let listener = tokio::spawn(bound.serve(async {
        let _ = stopped.await;
    }));
    tokio::time::sleep(Duration::from_millis(800)).await;
    for _ in 0..2 {
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        let started = Instant::now();
        let closed = tokio::time::timeout(Duration::from_secs(2), peer.read_u8())
            .await
            .expect("configured whole receive budget must close the stalled peer");
        assert_eq!(closed.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "a fresh accept must receive its own budget"
        );
    }
    stop.send(()).unwrap();
    listener.await.unwrap().unwrap();
    // This observes the completed peers and accept-loop result only. It makes
    // no claim that serve() joins still-running connection tasks on shutdown.
}
