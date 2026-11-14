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
//! The host supplies the runtime and shutdown signal. `serve` bounds accepted
//! connection work and joins it before returning after shutdown.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use super::helpers::sha256_hex;
use super::x509_identity::{claimed_address, parse_certificate_identity};
use super::{
    IdentityCheck, MAX_REQUEST_BYTES, MailboxStore, MisfinAddress, MisfinSender, MisfinServerError,
};

const DEFAULT_RECEIVE_STEP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MAX_CONNECTIONS: usize = 32;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

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
    /// Maximum accepted connection tasks, including TLS handshakes. Default 32.
    /// Must be nonzero. At capacity, accept pauses; pending peers are subject
    /// to OS backlog limits. No mail response is invented for overload.
    pub max_connections: usize,
    /// One graceful-drain allowance after shutdown is observed. Default 5s.
    /// Zero aborts immediately. Remaining tasks are aborted and joined after
    /// this window; cooperative cancellation cannot preempt synchronous storage.
    pub shutdown_grace: Duration,
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
            max_connections: DEFAULT_MAX_CONNECTIONS,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

fn validate_lifecycle(max_connections: usize, shutdown_grace: Duration) -> io::Result<()> {
    if max_connections == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid misfin connection limit",
        ));
    }
    if std::time::Instant::now()
        .checked_add(shutdown_grace)
        .is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid misfin shutdown grace",
        ));
    }
    Ok(())
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
    max_connections: usize,
    shutdown_grace: Duration,
}

impl MisfinServer {
    /// Build a server from its `config` and a mailbox `store`. Constructs the
    /// TLS acceptor (a client-cert-requesting, TOFU-permissive handshake); fails
    /// if timeouts are zero/unrepresentable or certificate/key are unusable.
    pub fn new(config: MisfinServerConfig, store: MailboxStore) -> Result<Self, MisfinServerError> {
        validate_lifecycle(config.max_connections, config.shutdown_grace)
            .map_err(|error| MisfinServerError::Config(error.to_string()))?;
        validate_receive_timeouts(config.timeout, config.receive_timeout)
            .map_err(|error| MisfinServerError::Config(error.to_string()))?;
        let cert = CertificateDer::from(config.tls_certificate_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(config.tls_private_key_pkcs8_der));
        let provider = crate::client::tls_provider();
        let algorithms = provider.signature_verification_algorithms;
        let tls_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| MisfinServerError::Config(error.to_string()))?
            .with_client_cert_verifier(Arc::new(AcceptAnyClient { algorithms }))
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
            max_connections: config.max_connections,
            shutdown_grace: config.shutdown_grace,
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
            max_connections: self.max_connections,
            shutdown_grace: self.shutdown_grace,
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
    max_connections: usize,
    shutdown_grace: Duration,
}

impl BoundMisfinServer {
    /// The address the listener bound to (resolves a `:0` request).
    pub fn local_addr(&self) -> Result<SocketAddr, MisfinServerError> {
        self.listener
            .local_addr()
            .map_err(|error| MisfinServerError::Io(error.to_string()))
    }

    /// Accept at most the configured number of connection tasks concurrently.
    /// Shutdown closes the listener, drains connections for one grace window,
    /// then aborts and joins any remaining tasks before returning.
    ///
    /// Signal shutdown and await this future for the joined guarantee. Dropping
    /// it requests abortion through the owned task set, but cannot await joins.
    /// Cancellation never rolls back mail already committed by a connection.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Result<(), MisfinServerError> {
        let Self {
            listener,
            acceptor,
            dispatcher,
            timeout,
            receive_timeout,
            max_connections,
            shutdown_grace,
        } = self;
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);
        let (outcome, stopped_at) = loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break (Ok(()), Instant::now()),
                joined = connections.join_next(), if !connections.is_empty() => {
                    if let Some(result) = joined {
                        report_connection_join(result);
                    }
                }
                accepted = listener.accept(), if connections.len() < max_connections => match accepted {
                    Ok((tcp, _peer)) => {
                        let budget = match ReceiveBudget::new(Instant::now(), timeout, receive_timeout) {
                            Ok(budget) => budget,
                            Err(error) => break (Err(MisfinServerError::Config(error.to_string())), Instant::now()),
                        };
                        let acceptor = acceptor.clone();
                        let dispatcher = dispatcher.clone();
                        connections.spawn(async move {
                            if let Err(error) = handle_connection(acceptor, dispatcher, tcp, budget).await {
                                log::debug!("misfin: receiving connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => log::warn!("misfin: accept failed: {error}"),
                },
            }
        };
        let grace_deadline = stopped_at.checked_add(shutdown_grace).unwrap_or(stopped_at);
        drop(listener);
        finish_connections(&mut connections, grace_deadline).await;
        outcome
    }
}

fn report_connection_join(result: Result<(), JoinError>) {
    if let Err(error) = result {
        if error.is_panic() {
            log::warn!("misfin: receiving task panicked: {error}");
        } else {
            log::debug!("misfin: receiving task cancelled: {error}");
        }
    }
}

async fn finish_connections(connections: &mut JoinSet<()>, deadline: Instant) {
    // The caller fixes this deadline when shutdown wins the select, so listener
    // teardown or scheduling before the drain's first poll cannot renew grace.
    if Instant::now() < deadline {
        let drained = tokio::time::timeout_at(deadline, async {
            while let Some(result) = connections.join_next().await {
                report_connection_join(result);
            }
        })
        .await;
        if drained.is_ok() {
            return;
        }
    }
    connections.abort_all();
    // Aborting requests cancellation. Await every terminal join so returning
    // serve() cannot leave accepted connection futures alive in the runtime.
    while let Some(result) = connections.join_next().await {
        report_connection_join(result);
    }
}

#[cfg(test)]
#[path = "server_lifecycle_tests.rs"]
mod server_lifecycle_tests;

#[cfg(test)]
#[path = "server_deadline_tests.rs"]
mod server_deadline_tests;

#[cfg(test)]
#[path = "server_signature_tests.rs"]
mod server_signature_tests;

#[cfg(test)]
mod tests;

mod transaction;

mod certificate_verifier;

use certificate_verifier::AcceptAnyClient;
use transaction::handle_connection;
#[cfg(test)]
use transaction::receive;
