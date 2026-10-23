//! The misfin receive server (the `server` feature).
//!
//! A [`MisfinServer`] listens on a TCP port (misfin's well-known port is
//! 1958), completes a TLS handshake that **requests but does not require** a
//! client certificate, reads the single-line request, and dispatches it to a
//! [`MailboxStore`](crate::MailboxStore). Per the spec the request is
//! `misfin://<mailbox>@<host> <message>\r\n`, at most 2048 bytes, and the
//! reply is a gemini-shaped `<status> <meta>\r\n` line.
//!
//! Status codes this server returns:
//!
//! - **20** delivered — META is the recipient mailbox's certificate fingerprint
//! - **40** temporary error (storage failure)
//! - **51** mailbox doesn't exist (host served, mailbox unknown)
//! - **53** domain not serviced (no served mailbox uses that host)
//! - **59** bad request (malformed, over-long, or non-UTF-8 request line)
//! - **60** certificate required (the client presented none)
//! - **62** certificate invalid (expired; or, when
//!   [`MisfinServerConfig::require_sender_identity`] is set, a certificate
//!   that carries no misfin identity)
//! - **63** "you're a liar" (a known sender identity presented a different
//!   fingerprint; controlled by
//!   [`MisfinServerConfig::reject_changed_sender`])
//!
//! Senders are identified by certificate fingerprint (the spec: a sender's
//! identity *is* its fingerprint), and the claimed `mailbox@host` is read from
//! the certificate's USER_ID + SUBJECT_ALT_NAME so deliveries record a
//! human-readable sender address.
//!
//! The server is host-neutral: it owns no scheduling. `serve` runs until the
//! supplied shutdown future resolves, so a host just spawns it on its runtime.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use super::helpers::sha256_hex;
use super::x509_identity::{claimed_address, parse_certificate_identity};
use super::{
    IdentityCheck, MAX_REQUEST_BYTES, MailboxStore, MisfinAddress, MisfinSender, MisfinServerError,
};

const DEFAULT_RECEIVE_STEP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);

/// A gemini-shaped misfin reply: a two-digit `status` and a `meta` string,
/// encoded as `<status> <meta>\r\n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MisfinResponse {
    pub status: u8,
    pub meta: String,
}

impl MisfinResponse {
    fn new(status: u8, meta: &str) -> Self {
        Self {
            status,
            meta: meta.to_string(),
        }
    }

    /// The wire encoding: `<status> <meta>\r\n`.
    pub fn encode(&self) -> String {
        format!("{:02} {}\r\n", self.status, self.meta)
    }
}

/// A mailbox this server accepts mail for, with the fingerprint returned to a
/// sender on successful delivery (the status-20 META — the recipient's own
/// certificate fingerprint, so the sender can pin it).
#[derive(Clone, Debug)]
pub struct ServedMailbox {
    pub address: MisfinAddress,
    pub fingerprint: String,
}

/// Everything a [`MisfinServer`] needs besides its mailbox store: the
/// certificate it presents in the TLS handshake, the mailboxes it serves, and
/// its sender-validation posture.
pub struct MisfinServerConfig {
    /// The server's leaf certificate (DER) presented during the TLS handshake.
    pub tls_certificate_der: Vec<u8>,
    /// The matching private key (PKCS#8 DER).
    pub tls_private_key_pkcs8_der: Vec<u8>,
    /// The mailboxes this server delivers to. Anything else is 51/53.
    pub served: Vec<ServedMailbox>,
    /// Reply 62 to certificates that carry no misfin identity (no
    /// USER_ID/SAN). Off by default: such senders are tracked by fingerprint
    /// only.
    pub require_sender_identity: bool,
    /// Reply 63 when a known claimed sender address presents a different
    /// fingerprint (the spec's "you're a liar"). On by default; the stored
    /// fingerprint is never silently overwritten.
    pub reject_changed_sender: bool,
    /// Per-step allowance for TLS, the complete request, response write and
    /// close-notify. Default 30 seconds; incoming bytes never renew a step.
    pub timeout: Duration,
    /// Whole receiving transaction, measured from TCP acceptance through
    /// close-notify. Default 120 seconds, independent of the step allowance.
    /// Both durations must be nonzero and representable by the monotonic clock.
    pub receive_timeout: Duration,
}

impl MisfinServerConfig {
    /// A config with the default validation posture
    /// (`require_sender_identity: false`, `reject_changed_sender: true`).
    pub fn new(
        tls_certificate_der: Vec<u8>,
        tls_private_key_pkcs8_der: Vec<u8>,
        served: Vec<ServedMailbox>,
    ) -> Self {
        Self {
            tls_certificate_der,
            tls_private_key_pkcs8_der,
            served,
            require_sender_identity: false,
            reject_changed_sender: true,
            timeout: DEFAULT_RECEIVE_STEP_TIMEOUT,
            receive_timeout: DEFAULT_RECEIVE_TIMEOUT,
        }
    }
}

fn validate_receive_timeouts(timeout: Duration, receive_timeout: Duration) -> io::Result<()> {
    for (scope, duration) in [("per-step", timeout), ("whole-receive", receive_timeout)] {
        if duration.is_zero() || std::time::Instant::now().checked_add(duration).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid misfin {scope} timeout"),
            ));
        }
    }
    Ok(())
}

/// One accepted transaction; queueing before its first poll consumes time too.
struct ReceiveBudget {
    deadline: Instant,
    timeout: Duration,
}

impl ReceiveBudget {
    fn new(accepted_at: Instant, timeout: Duration, receive_timeout: Duration) -> io::Result<Self> {
        validate_receive_timeouts(timeout, receive_timeout)?;
        let deadline = accepted_at.checked_add(receive_timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid misfin whole-receive timeout",
            )
        })?;
        Ok(Self { deadline, timeout })
    }

    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "misfin receive timed out",
            ))
        } else {
            Ok(())
        }
    }

    fn dispatch(&self, operation: impl FnOnce() -> MisfinResponse) -> io::Result<MisfinResponse> {
        // Storage is synchronous. Expiry prevents starting it, but cannot
        // interrupt or roll back an operation that has already committed.
        self.check()?;
        let response = operation();
        self.check()?;
        Ok(response)
    }

    async fn step<T>(
        &self,
        name: &'static str,
        operation: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        self.check()?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        let result = tokio::time::timeout_at(deadline, operation).await;
        // Timers are cooperative: reject a ready result that crossed a deadline.
        self.check()?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("misfin {name} timed out"),
            ));
        }
        result.map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, format!("misfin {name} timed out"))
        })?
    }
}

/// The TLS-free request handler. Split out from the listener so the protocol
/// decisions are unit-testable without a socket.
struct Dispatcher {
    served: Vec<ServedMailbox>,
    store: MailboxStore,
    require_sender_identity: bool,
    reject_changed_sender: bool,
}

impl Dispatcher {
    fn dispatch(
        &self,
        request: &str,
        peer_cert: Option<&CertificateDer<'_>>,
        now: u64,
    ) -> MisfinResponse {
        let Some(cert) = peer_cert else {
            return MisfinResponse::new(60, "Certificate required.");
        };
        let Some((target, message)) = split_request(request) else {
            return MisfinResponse::new(59, "Malformed request.");
        };
        let Some(recipient) = parse_recipient(target) else {
            return MisfinResponse::new(59, "Malformed recipient address.");
        };
        if !self.serves_host(&recipient.host) {
            return MisfinResponse::new(53, "Domain not serviced.");
        }
        let Some(served) = self.find_mailbox(&recipient) else {
            return MisfinResponse::new(51, "Mailbox doesn't exist.");
        };

        let fingerprint = sha256_hex(cert.as_ref());
        let identity = parse_certificate_identity(cert.as_ref(), now).ok();
        if let Some(identity) = &identity
            && identity.expired
        {
            return MisfinResponse::new(62, "Certificate is outside its validity window.");
        }
        let claimed = identity.as_ref().and_then(claimed_address);
        if claimed.is_none() && self.require_sender_identity {
            return MisfinResponse::new(62, "Certificate is not a misfin identity.");
        }

        let sender = claimed.map(|address| MisfinSender {
            address,
            blurb: identity
                .as_ref()
                .and_then(|identity| identity.blurb.clone()),
        });

        if let Some(sender) = &sender {
            let check = self.store.check_and_record_identity(
                &sender.address.as_addr_spec(),
                &fingerprint,
                now,
            );
            match check {
                Ok(IdentityCheck::Changed { .. }) if self.reject_changed_sender => {
                    return MisfinResponse::new(
                        63,
                        "Your fingerprint changed for a known identity.",
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    log::warn!("misfin: recording sender identity failed: {error}");
                    return MisfinResponse::new(40, "Temporary server error.");
                }
            }
        }

        if let Err(error) = self.store.record_sender(&fingerprint, now) {
            log::warn!("misfin: recording sender failed: {error}");
            return MisfinResponse::new(40, "Temporary server error.");
        }
        match self
            .store
            .store(&recipient, &fingerprint, sender.as_ref(), message, now)
        {
            Ok(_) => MisfinResponse::new(20, &served.fingerprint),
            Err(error) => {
                log::warn!("misfin: storing message failed: {error}");
                MisfinResponse::new(40, "Temporary server error.")
            }
        }
    }

    fn serves_host(&self, host: &str) -> bool {
        self.served
            .iter()
            .any(|mailbox| mailbox.address.host == host)
    }

    fn find_mailbox(&self, recipient: &MisfinAddress) -> Option<&ServedMailbox> {
        self.served
            .iter()
            .find(|mailbox| &mailbox.address == recipient)
    }
}

/// Split a request line into `(target, message)` on the first space, validating
/// the misfin scheme. The message is the remainder verbatim (it may be empty or
/// contain further spaces).
fn split_request(request: &str) -> Option<(&str, &str)> {
    let (target, message) = request.trim_start().split_once(' ')?;
    if !target.starts_with("misfin://") {
        return None;
    }
    Some((target, message))
}

fn parse_recipient(target: &str) -> Option<MisfinAddress> {
    let url = url::Url::parse(target).ok()?;
    MisfinAddress::from_url(&url).ok()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// A misfin server ready to bind. Build with [`MisfinServer::new`], then
/// [`bind`](MisfinServer::bind) to start listening.
pub struct MisfinServer {
    acceptor: TlsAcceptor,
    dispatcher: Arc<Dispatcher>,
    timeout: Duration,
    receive_timeout: Duration,
}

impl MisfinServer {
    /// Build a server from its `config` and a mailbox `store`. Constructs the
    /// TLS acceptor (a client-cert-requesting, TOFU-permissive handshake); fails
    /// if timeouts are zero/unrepresentable or certificate/key are unusable.
    pub fn new(config: MisfinServerConfig, store: MailboxStore) -> Result<Self, MisfinServerError> {
        validate_receive_timeouts(config.timeout, config.receive_timeout)
            .map_err(|error| MisfinServerError::Config(error.to_string()))?;
        let cert = CertificateDer::from(config.tls_certificate_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(config.tls_private_key_pkcs8_der));
        let tls_config = rustls::ServerConfig::builder_with_provider(crate::client::tls_provider())
            .with_safe_default_protocol_versions()
            .map_err(|error| MisfinServerError::Config(error.to_string()))?
            .with_client_cert_verifier(Arc::new(AcceptAnyClient))
            .with_single_cert(vec![cert], key)
            .map_err(|error| MisfinServerError::Config(error.to_string()))?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            dispatcher: Arc::new(Dispatcher {
                served: config.served,
                store,
                require_sender_identity: config.require_sender_identity,
                reject_changed_sender: config.reject_changed_sender,
            }),
            timeout: config.timeout,
            receive_timeout: config.receive_timeout,
        })
    }

    /// Bind the listener on `addr`. Use a `:0` port and
    /// [`local_addr`](BoundMisfinServer::local_addr) to discover the chosen port.
    pub async fn bind(self, addr: SocketAddr) -> Result<BoundMisfinServer, MisfinServerError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|error| MisfinServerError::Io(error.to_string()))?;
        Ok(BoundMisfinServer {
            acceptor: self.acceptor,
            dispatcher: self.dispatcher,
            listener,
            timeout: self.timeout,
            receive_timeout: self.receive_timeout,
        })
    }
}

/// A bound misfin server, listening but not yet accepting. Call
/// [`serve`](BoundMisfinServer::serve) to run the accept loop.
pub struct BoundMisfinServer {
    acceptor: TlsAcceptor,
    dispatcher: Arc<Dispatcher>,
    listener: TcpListener,
    timeout: Duration,
    receive_timeout: Duration,
}

impl BoundMisfinServer {
    /// The address the listener bound to (resolves a `:0` request).
    pub fn local_addr(&self) -> Result<SocketAddr, MisfinServerError> {
        self.listener
            .local_addr()
            .map_err(|error| MisfinServerError::Io(error.to_string()))
    }

    /// Accept connections until `shutdown` resolves. Each connection is handled
    /// on its own task; a handshake or read failure drops that connection only.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Result<(), MisfinServerError> {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((tcp, _peer)) => {
                        let budget = ReceiveBudget::new(Instant::now(), self.timeout, self.receive_timeout)
                            .map_err(|error| MisfinServerError::Config(error.to_string()))?;
                        let acceptor = self.acceptor.clone();
                        let dispatcher = self.dispatcher.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_connection(acceptor, dispatcher, tcp, budget).await {
                                log::debug!("misfin: receiving connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => log::warn!("misfin: accept failed: {error}"),
                },
            }
        }
        Ok(())
    }
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    dispatcher: Arc<Dispatcher>,
    tcp: TcpStream,
    budget: ReceiveBudget,
) -> io::Result<()> {
    let mut tls = budget.step("TLS handshake", acceptor.accept(tcp)).await?;
    let peer_cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned();
    receive(&mut tls, &dispatcher, peer_cert.as_ref(), &budget).await
}

// The same exchange runs over TLS and controlled carriers in deadline tests.
async fn receive<S>(
    stream: &mut S,
    dispatcher: &Dispatcher,
    peer_cert: Option<&CertificateDer<'_>>,
    budget: &ReceiveBudget,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = budget.step("request read", read_request(stream)).await?;
    let response = budget.dispatch(|| match request {
        RequestRead::Line(request) => dispatcher.dispatch(&request, peer_cert, unix_now()),
        RequestRead::TooLong => MisfinResponse::new(59, "Request exceeds 2048 bytes."),
        RequestRead::NotUtf8 => MisfinResponse::new(59, "Request is not UTF-8."),
        RequestRead::Incomplete => MisfinResponse::new(59, "Request requires CRLF."),
    })?;
    budget
        .step(
            "response write",
            stream.write_all(response.encode().as_bytes()),
        )
        .await?;
    budget.step("TLS close", stream.shutdown()).await
}

/// The outcome of reading a request line: the request without its CRLF, or a
/// protocol violation the caller should answer with 59.
enum RequestRead {
    Line(String),
    TooLong,
    NotUtf8,
    Incomplete,
}

/// Read the complete request line; the caller times the entire read once.
/// A request that reaches the spec's 2048-byte ceiling without a CRLF is
/// over-long (the ceiling includes the terminator).
async fn read_request<S>(stream: &mut S) -> io::Result<RequestRead>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let count = stream.read(&mut byte).await?;
        if count == 0 {
            return Ok(RequestRead::Incomplete);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            return Ok(RequestRead::TooLong);
        }
    }
    match String::from_utf8(buf) {
        Ok(mut text) => {
            // Only the observed wire terminator is framing. Bare newlines,
            // including trailing message newlines, are valid message content.
            text.truncate(text.len() - 2);
            Ok(RequestRead::Line(text))
        }
        Err(_) => Ok(RequestRead::NotUtf8),
    }
}

/// A client-certificate verifier that requests a certificate but accepts any the
/// client presents (TOFU-permissive) and does not *require* one — a client with
/// no certificate still completes the handshake, so the server can reply 60 at
/// the application layer rather than failing the handshake. Never use for
/// CA-anchored TLS.
#[derive(Debug)]
struct AcceptAnyClient;

impl ClientCertVerifier for AcceptAnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
#[path = "server_deadline_tests.rs"]
mod server_deadline_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MisfinIdentitySpec, MisfinStatus, client, deterministic_identity};

    /// A "now" inside the minted certificates' validity window (2024-2099).
    const NOW: u64 = 1_750_000_000;

    fn spec(addr: &str) -> MisfinIdentitySpec {
        MisfinIdentitySpec {
            address: MisfinAddress::parse(addr).unwrap(),
            blurb: Some("Test".to_string()),
        }
    }

    /// Mint a certificate DER for use as a peer/client certificate in a test.
    pub(super) fn cert_der(seed: u8, addr: &str) -> Vec<u8> {
        deterministic_identity(&[seed; 32], &spec(addr))
            .unwrap()
            .certificate_der
    }

    pub(super) fn dispatcher_for(mailbox: &str) -> (Dispatcher, String) {
        let identity = deterministic_identity(&[9u8; 32], &spec(mailbox)).unwrap();
        let fingerprint = sha256_hex(&identity.certificate_der);
        let dispatcher = Dispatcher {
            served: vec![ServedMailbox {
                address: MisfinAddress::parse(mailbox).unwrap(),
                fingerprint: fingerprint.clone(),
            }],
            store: MailboxStore::in_memory().unwrap(),
            require_sender_identity: false,
            reject_changed_sender: true,
        };
        (dispatcher, fingerprint)
    }

    #[test]
    fn response_encodes_status_and_meta() {
        assert_eq!(MisfinResponse::new(20, "abc").encode(), "20 abc\r\n");
        assert_eq!(
            MisfinResponse::new(51, "Mailbox doesn't exist.").encode(),
            "51 Mailbox doesn't exist.\r\n"
        );
    }

    #[test]
    fn no_certificate_is_rejected_with_60() {
        let (dispatcher, _) = dispatcher_for("mark@example.test");
        let response = dispatcher.dispatch("misfin://mark@example.test hi", None, NOW);
        assert_eq!(response.status, 60);
    }

    #[test]
    fn malformed_request_is_rejected_with_59() {
        let (dispatcher, _) = dispatcher_for("mark@example.test");
        let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
        // No space → no message.
        assert_eq!(
            dispatcher
                .dispatch("misfin://mark@example.test", Some(&cert), NOW)
                .status,
            59
        );
        // Wrong scheme.
        assert_eq!(
            dispatcher
                .dispatch("gemini://mark@example.test hi", Some(&cert), NOW)
                .status,
            59
        );
    }

    #[test]
    fn unserved_host_is_rejected_with_53() {
        let (dispatcher, _) = dispatcher_for("mark@example.test");
        let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
        let response = dispatcher.dispatch("misfin://mark@elsewhere.test hi", Some(&cert), NOW);
        assert_eq!(response.status, 53);
    }

    #[test]
    fn unknown_mailbox_on_served_host_is_rejected_with_51() {
        let (dispatcher, _) = dispatcher_for("mark@example.test");
        let cert = CertificateDer::from(cert_der(3, "ana@other.test"));
        let response = dispatcher.dispatch("misfin://ghost@example.test hi", Some(&cert), NOW);
        assert_eq!(response.status, 51);
    }

    #[test]
    fn delivered_message_records_the_claimed_sender_identity() {
        let (dispatcher, recipient_fingerprint) = dispatcher_for("mark@example.test");
        let sender_der = cert_der(3, "ana@other.test");
        let cert = CertificateDer::from(sender_der.clone());

        let response =
            dispatcher.dispatch("misfin://mark@example.test Hello Mark", Some(&cert), NOW);
        assert_eq!(response.status, 20);
        assert_eq!(
            response.meta, recipient_fingerprint,
            "META is the recipient's fingerprint"
        );

        let inbox = dispatcher.store.list("mark@example.test").unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].body, "Hello Mark");
        assert_eq!(inbox[0].sender_fingerprint, sha256_hex(&sender_der));
        assert_eq!(inbox[0].sender_address.as_deref(), Some("ana@other.test"));
        assert_eq!(inbox[0].received_at, NOW);
    }

    #[test]
    fn a_changed_fingerprint_for_a_known_identity_is_rejected_with_63() {
        let (dispatcher, _) = dispatcher_for("mark@example.test");
        let first = CertificateDer::from(cert_der(3, "ana@other.test"));
        let second = CertificateDer::from(cert_der(4, "ana@other.test"));

        assert_eq!(
            dispatcher
                .dispatch("misfin://mark@example.test hi", Some(&first), NOW)
                .status,
            20
        );
        let response = dispatcher.dispatch(
            "misfin://mark@example.test hi again",
            Some(&second),
            NOW + 1,
        );
        assert_eq!(response.status, 63, "same claimed address, new key");

        // The original key keeps working.
        assert_eq!(
            dispatcher
                .dispatch("misfin://mark@example.test still me", Some(&first), NOW + 2)
                .status,
            20
        );
    }

    #[test]
    fn an_expired_certificate_is_rejected_with_62() {
        let (dispatcher, _) = dispatcher_for("mark@example.test");
        let expired =
            crate::identity::identity_with_validity_years(&spec("old@stale.test"), 2001, 2003)
                .unwrap();
        let cert = CertificateDer::from(expired.certificate_der);
        // `now` far beyond 2003.
        let response =
            dispatcher.dispatch("misfin://mark@example.test hi", Some(&cert), 1_800_000_000);
        assert_eq!(response.status, 62);
    }

    #[tokio::test]
    async fn round_trip_delivers_over_tls_via_the_public_client() {
        let server_identity =
            deterministic_identity(&[1u8; 32], &spec("mark@example.test")).unwrap();
        let server_fingerprint = sha256_hex(&server_identity.certificate_der);
        let store = MailboxStore::in_memory().unwrap();
        let config = MisfinServerConfig::new(
            server_identity.certificate_der.clone(),
            server_identity.private_key_pkcs8_der.clone(),
            vec![ServedMailbox {
                address: MisfinAddress::parse("mark@example.test").unwrap(),
                fingerprint: server_fingerprint.clone(),
            }],
        );
        let server = MisfinServer::new(config, store.clone()).unwrap();
        let bound = server.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = bound.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(async move {
            let _ = bound
                .serve(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let sender = deterministic_identity(&[2u8; 32], &spec("ana@other.test")).unwrap();
        let options = client::SendOptions {
            identity: Some(sender),
            connect_addr: Some(addr),
            expected_fingerprint: Some(server_fingerprint.clone()),
            ..Default::default()
        };
        let receipt = client::send(
            &MisfinAddress::parse("mark@example.test").unwrap(),
            "Hi from Ana",
            &options,
        )
        .await
        .unwrap();

        assert_eq!(receipt.status, MisfinStatus::Delivered);
        assert_eq!(receipt.meta, server_fingerprint);
        assert_eq!(receipt.server_fingerprint, server_fingerprint);
        let inbox = store.list("mark@example.test").unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].body, "Hi from Ana");
        assert_eq!(inbox[0].sender_address.as_deref(), Some("ana@other.test"));

        let _ = shutdown_tx.send(());
        let _ = serve.await;
    }

    #[tokio::test]
    async fn an_over_long_request_line_gets_59() {
        let server_identity =
            deterministic_identity(&[1u8; 32], &spec("mark@example.test")).unwrap();
        let fingerprint = sha256_hex(&server_identity.certificate_der);
        let config = MisfinServerConfig::new(
            server_identity.certificate_der.clone(),
            server_identity.private_key_pkcs8_der.clone(),
            vec![ServedMailbox {
                address: MisfinAddress::parse("mark@example.test").unwrap(),
                fingerprint,
            }],
        );
        let server = MisfinServer::new(config, MailboxStore::in_memory().unwrap()).unwrap();
        let bound = server.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(async move {
            let _ = bound
                .serve(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        // Raw client: 3000 bytes, no CRLF.
        let raw = raw_exchange(addr, &"x".repeat(3000)).await;
        assert!(raw.starts_with("59 "), "expected 59, got {raw:?}");

        let _ = shutdown_tx.send(());
        let _ = serve.await;
    }

    /// A raw TLS exchange for wire-level tests the public client refuses to
    /// produce (e.g. over-long request lines).
    async fn raw_exchange(addr: SocketAddr, line: &str) -> String {
        let mut tls = test_tls_client(addr).await;
        tls.write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
        let mut raw = Vec::new();
        tls.read_to_end(&mut raw).await.unwrap();
        String::from_utf8_lossy(&raw).to_string()
    }

    pub(super) async fn test_tls_client(
        addr: SocketAddr,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
        use rustls::pki_types::ServerName;

        #[derive(Debug)]
        struct AcceptAnyServer;
        impl ServerCertVerifier for AcceptAnyServer {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::ED25519,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                ]
            }
        }

        let config = rustls::ClientConfig::builder_with_provider(crate::client::tls_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
        connector.connect(server_name, tcp).await.unwrap()
    }
}
