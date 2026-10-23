//! The sending client (the `client` feature): one misfin transaction per call
//! (specification §1.1) — connect, TLS handshake with an optional client
//! certificate, send the request line, read the response line, close with
//! close-notify.
//!
//! Server certificates are self-signed in misfin, so the TLS layer accepts
//! any certificate and trust is decided by fingerprint: [`send`] always
//! returns the server's fingerprint, and [`SendOptions::expected_fingerprint`]
//! pins it (trust-on-first-use is then the caller storing the first-seen value
//! and passing it back on later sends).

use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::helpers::sha256_hex;
use super::status::parse_response_line;
use super::{
    MAX_REQUEST_BYTES, MISFIN_PORT, MisfinAddress, MisfinIdentityMaterial, MisfinStatus,
    normalize_fingerprint,
};

/// The TLS crypto provider, selected by the `aws-lc` / `ring` cargo features
/// (`aws-lc` wins when both are enabled).
#[cfg(any(feature = "aws-lc", feature = "ring"))]
pub(crate) fn tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "aws-lc")]
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(all(feature = "ring", not(feature = "aws-lc")))]
    return Arc::new(rustls::crypto::ring::default_provider());
}

#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
compile_error!(
    "misfin's `client`/`server` features need a TLS provider: enable the `aws-lc` or `ring` feature"
);

/// Options for a [`send`]: the sender's identity (strongly recommended — most
/// servers reply 60 without one), an alternate port, a pinned server
/// fingerprint, and independent per-step and whole-send time budgets.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// The client certificate presented in the handshake. `None` sends
    /// anonymously; spec-following servers will likely reply 60.
    pub identity: Option<MisfinIdentityMaterial>,
    /// Additional DER certificates presented after the identity's leaf — the
    /// spec §3.1 advanced setup where a mailbox certificate is signed by its
    /// mailserver's host certificate. Usually empty.
    pub extra_chain_der: Vec<Vec<u8>>,
    /// Overrides the well-known port (1958). Best practice: mailservers stay
    /// on the known port; this exists for clients reaching odd deployments.
    pub port: Option<u16>,
    /// A pinned server-certificate fingerprint (SHA-256 hex, any octet
    /// formatting). On mismatch the send aborts before the message is sent.
    pub expected_fingerprint: Option<String>,
    /// Per-step timeout (connect, handshake, write, read). `None` = 30s.
    /// Also bounds best-effort close-notify; it never renews the send budget.
    pub timeout: Option<Duration>,
    /// Whole-send timeout, after local preflight, including DNS/connect, TLS,
    /// request, response and close-notify. `None` = 120s; zero refuses before I/O.
    pub send_timeout: Option<Duration>,
    /// Connect to this socket address instead of resolving the recipient's
    /// host. The recipient host is still used for TLS SNI. For deployments
    /// where the mailserver isn't where DNS says (and for tests).
    pub connect_addr: Option<std::net::SocketAddr>,
}

/// The outcome of a successful transaction: the server's status + META and
/// the fingerprint of the certificate it presented (pin this for TOFU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    pub status: MisfinStatus,
    pub meta: String,
    pub server_fingerprint: String,
}

/// Why a [`send`] failed to complete. A whole-send timeout can retain a
/// complete response already obtained before cleanup was interrupted.
#[derive(Debug)]
pub enum SendError {
    /// The whole-send budget expired. A complete reply already obtained is
    /// retained, including its status, META and server fingerprint. With no
    /// receipt, delivery may be unknown after request transmission.
    WholeSendTimeout { receipt: Option<SendReceipt> },
    /// A configured duration cannot be represented by the monotonic clock.
    InvalidTimeout(&'static str),
    /// The request line would exceed the spec's 2048-byte ceiling. Per the
    /// best-practices document, prompt the user to split the message.
    MessageTooLong { request_bytes: usize, max: usize },
    /// The message contains a carriage return, which would terminate the
    /// request line early (bare newlines are fine).
    MessageContainsCarriageReturn,
    /// The recipient host could not be used as a TLS server name.
    InvalidHost(String),
    /// The pinned fingerprint did not match the server's certificate.
    FingerprintMismatch { expected: String, found: String },
    /// TLS configuration or handshake failure.
    Tls(String),
    /// Connect / read / write failure.
    Io(String),
    /// A step exceeded the timeout.
    Timeout(&'static str),
    /// The server's response line did not parse.
    BadResponse(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WholeSendTimeout {
                receipt: Some(receipt),
            } => write!(
                formatter,
                "misfin send timed out after server replied {}; acknowledgement retained",
                receipt.status
            ),
            Self::WholeSendTimeout { receipt: None } => write!(
                formatter,
                "misfin send timed out; delivery may be unknown; do not automatically resend"
            ),
            Self::InvalidTimeout(scope) => write!(formatter, "invalid misfin {scope} timeout"),
            Self::MessageTooLong { request_bytes, max } => write!(
                formatter,
                "misfin request would be {request_bytes} bytes (max {max}); split the message"
            ),
            Self::MessageContainsCarriageReturn => {
                write!(
                    formatter,
                    "misfin messages must not contain carriage returns"
                )
            }
            Self::InvalidHost(host) => write!(formatter, "invalid misfin host '{host}'"),
            Self::FingerprintMismatch { expected, found } => write!(
                formatter,
                "misfin server fingerprint mismatch: expected {expected}, found {found}"
            ),
            Self::Tls(message) => write!(formatter, "misfin TLS error: {message}"),
            Self::Io(message) => write!(formatter, "misfin IO error: {message}"),
            Self::Timeout(step) => write!(formatter, "misfin {step} timed out"),
            Self::BadResponse(message) => {
                write!(formatter, "misfin response did not parse: {message}")
            }
        }
    }
}

impl std::error::Error for SendError {}

/// Build the request line for `recipient` + `message`, enforcing the byte
/// ceiling and the no-carriage-return rule.
pub fn build_request(recipient: &MisfinAddress, message: &str) -> Result<String, SendError> {
    if message.contains('\r') {
        return Err(SendError::MessageContainsCarriageReturn);
    }
    // Admit borrowed lengths before constructing the complete request.
    let request_bytes = [
        9,
        recipient.mailbox.len(),
        1,
        recipient.host.len(),
        1,
        message.len(),
        2,
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add);
    if request_bytes > MAX_REQUEST_BYTES {
        return Err(SendError::MessageTooLong {
            request_bytes,
            max: MAX_REQUEST_BYTES,
        });
    }
    Ok(format!(
        "misfin://{} {message}\r\n",
        recipient.as_addr_spec()
    ))
}

/// Default allowance for each network step.
pub const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// Default allowance shared by every network stage of a send.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(120);

fn validate_timeouts(step: Duration, whole: Duration) -> Result<(), SendError> {
    for (scope, duration) in [("per-step", step), ("whole-send", whole)] {
        if std::time::Instant::now().checked_add(duration).is_none() {
            return Err(SendError::InvalidTimeout(scope));
        }
    }
    if whole.is_zero() {
        return Err(SendError::WholeSendTimeout { receipt: None });
    }
    if step.is_zero() {
        return Err(SendError::Timeout("connect"));
    }
    Ok(())
}

/// One fixed send deadline, with independent fresh deadlines for its steps.
struct SendBudget {
    deadline: Instant,
    step_timeout: Duration,
}

impl SendBudget {
    fn new(step: Duration, whole: Duration) -> Result<Self, SendError> {
        validate_timeouts(step, whole)?;
        Ok(Self {
            deadline: Instant::now()
                .checked_add(whole)
                .ok_or(SendError::InvalidTimeout("whole-send"))?,
            step_timeout: step,
        })
    }

    fn check(&self) -> Result<(), SendError> {
        if Instant::now() >= self.deadline {
            Err(SendError::WholeSendTimeout { receipt: None })
        } else {
            Ok(())
        }
    }

    async fn step<T>(
        &self,
        name: &'static str,
        operation: impl std::future::Future<Output = Result<T, SendError>>,
    ) -> Result<T, SendError> {
        self.check()?;
        let deadline = Instant::now()
            .checked_add(self.step_timeout)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        let result = tokio::time::timeout_at(deadline, operation).await;
        // A ready future can run past a timer while it is being polled.
        self.check()?;
        if Instant::now() >= deadline {
            return Err(SendError::Timeout(name));
        }
        result.map_err(|_| SendError::Timeout(name))?
    }
}

/// Deliver `message` (gemtext; bare newlines allowed) to `recipient` in one
/// misfin transaction and return the server's reply.
///
/// This does not retry, follow redirects (30/31), or resend on temporary
/// failure — per best practices those decisions belong to the user, so they
/// surface in the [`SendReceipt`] for the caller to act on.
///
/// The whole-send budget never resets between steps. Cancellation drops the
/// owned connection and performs no detached retry. After transmission, a
/// timeout or cancellation may leave delivery unknown; cancellation cannot
/// return an acknowledgement already received by the dropped future.
pub async fn send(
    recipient: &MisfinAddress,
    message: &str,
    options: &SendOptions,
) -> Result<SendReceipt, SendError> {
    let request = build_request(recipient, message)?;
    let server_name = ServerName::try_from(recipient.host.clone())
        .map_err(|_| SendError::InvalidHost(recipient.host.clone()))?;
    let timeout = options.timeout.unwrap_or(DEFAULT_STEP_TIMEOUT);
    let send_timeout = options.send_timeout.unwrap_or(DEFAULT_SEND_TIMEOUT);
    validate_timeouts(timeout, send_timeout)?;

    let builder = rustls::ClientConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| SendError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnySelfSigned));
    let config = match &options.identity {
        Some(identity) => {
            let mut chain = vec![CertificateDer::from(identity.certificate_der.clone())];
            chain.extend(
                options
                    .extra_chain_der
                    .iter()
                    .cloned()
                    .map(CertificateDer::from),
            );
            builder
                .with_client_auth_cert(
                    chain,
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        identity.private_key_pkcs8_der.clone(),
                    )),
                )
                .map_err(|error| SendError::Tls(error.to_string()))?
        }
        None => builder.with_no_client_auth(),
    };
    let connector = TlsConnector::from(Arc::new(config));
    // Request, host, duration and TLS-material validation are local preflight.
    // Every await below shares this one absolute network-transaction budget.
    let budget = SendBudget::new(timeout, send_timeout)?;

    let port = options.port.unwrap_or(MISFIN_PORT);
    let connect = async {
        match options.connect_addr {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((recipient.host.as_str(), port)).await,
        }
    };
    let tcp = budget
        .step("connect", async {
            connect
                .await
                .map_err(|error| SendError::Io(error.to_string()))
        })
        .await?;
    let mut tls = budget
        .step("TLS handshake", async {
            connector
                .connect(server_name, tcp)
                .await
                .map_err(|error| SendError::Tls(error.to_string()))
        })
        .await?;

    let server_fingerprint = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| sha256_hex(cert.as_ref()))
        .ok_or_else(|| SendError::Tls("server presented no certificate".to_string()))?;

    if let Some(expected) = &options.expected_fingerprint
        && normalize_fingerprint(expected) != server_fingerprint
    {
        // Preserve the definite trust refusal even if best-effort cleanup
        // exhausts its step or whole budget. No message has been written.
        return Err(close_after_refusal(
            &mut tls,
            &budget,
            SendError::FingerprintMismatch {
                expected: normalize_fingerprint(expected),
                found: server_fingerprint,
            },
        )
        .await);
    }

    budget
        .step("request write", async {
            tls.write_all(request.as_bytes())
                .await
                .map_err(|error| SendError::Io(error.to_string()))
        })
        .await?;
    finish_response(&mut tls, &budget, server_fingerprint).await
}

async fn close_after_refusal<S>(
    stream: &mut S,
    budget: &SendBudget,
    refusal: SendError,
) -> SendError
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let _ = budget
        .step("TLS close", async {
            stream
                .shutdown()
                .await
                .map_err(|error| SendError::Io(error.to_string()))
        })
        .await;
    refusal
}

// Shared by the native TLS send and controlled carrier tests. A peer merely
// withholding its own close-notify does not stall tokio-rustls shutdown.
async fn finish_response<S>(
    stream: &mut S,
    budget: &SendBudget,
    server_fingerprint: String,
) -> Result<SendReceipt, SendError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let line = budget
        .step("response read", read_response_line(stream))
        .await?;
    let (status, meta) = parse_response_line(&line).map_err(SendError::BadResponse)?;
    let receipt = SendReceipt {
        status,
        meta,
        server_fingerprint,
    };
    // Keep close-notify best effort, as before, but bounded by both policies.
    // If the whole budget wins, retain the exact known response in the error.
    let _ = budget
        .step("TLS close", async {
            stream
                .shutdown()
                .await
                .map_err(|error| SendError::Io(error.to_string()))
        })
        .await;
    if budget.check().is_err() {
        Err(SendError::WholeSendTimeout {
            receipt: Some(receipt),
        })
    } else {
        Ok(receipt)
    }
}

/// Read the response line: bytes up to the first CRLF, capped at the spec
/// ceiling. The caller applies one step deadline across this entire read.
async fn read_response_line<S>(stream: &mut S) -> Result<String, SendError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let count = stream
            .read(&mut byte)
            .await
            .map_err(|error| SendError::Io(error.to_string()))?;
        if count == 0 {
            return Err(SendError::BadResponse("response ended without CRLF".into()));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
        if byte[0] == b'\n' || buf.len() >= MAX_REQUEST_BYTES {
            return Err(SendError::BadResponse(
                "response has no CRLF within its byte limit".into(),
            ));
        }
    }
}

#[cfg(test)]
#[path = "client_deadline_tests.rs"]
mod client_deadline_tests;

/// Misfin peers are self-signed, so certificate-chain validation is
/// meaningless; trust is by fingerprint (TOFU / pinning), decided above the
/// TLS layer. Never use this verifier for CA-anchored TLS.
#[derive(Debug)]
struct AcceptAnySelfSigned;

impl ServerCertVerifier for AcceptAnySelfSigned {
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
mod tests {
    use super::*;

    fn addr(spec: &str) -> MisfinAddress {
        MisfinAddress::parse(spec).unwrap()
    }

    #[test]
    fn requests_carry_scheme_recipient_and_crlf() {
        let request = build_request(&addr("mark@example.test"), "Hello there").unwrap();
        assert_eq!(request, "misfin://mark@example.test Hello there\r\n");
    }

    #[test]
    fn newlines_are_allowed_but_carriage_returns_are_not() {
        assert!(build_request(&addr("a@b.test"), "line one\nline two").is_ok());
        assert!(matches!(
            build_request(&addr("a@b.test"), "bad\r\nline"),
            Err(SendError::MessageContainsCarriageReturn)
        ));
    }

    #[test]
    fn oversize_requests_are_rejected_with_the_spec_ceiling() {
        let long_message = "x".repeat(MAX_REQUEST_BYTES);
        match build_request(&addr("a@b.test"), &long_message) {
            Err(SendError::MessageTooLong { max, .. }) => assert_eq!(max, MAX_REQUEST_BYTES),
            other => panic!("expected MessageTooLong, got {other:?}"),
        }
    }
}
