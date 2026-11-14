//! An embeddable implementation of the [Misfin](https://misfin.org) mail protocol.
//!
//! Misfin is lem's gemini-style mail protocol: a message is a single TLS
//! transaction delivering UTF-8 gemtext to a mailbox addressed as
//! `misfin://user@host`, authenticated by self-signed client certificates
//! (a sender's identity *is* its certificate fingerprint). The protocol
//! specification and reference implementation live at
//! <https://github.com/JCLemme/misfin>; this crate is an independent
//! implementation of specification prototype B, not the reference.
//!
//! The crate name is held in stewardship: if the protocol's author wants
//! `misfin` on crates.io, it will be transferred on request.
//!
//! ## Features
//!
//! - **default**: addresses, gemmail parsing/composition, status codes, and
//!   identity-certificate minting and storage. Synchronous, no TLS stack.
//! - **`client`**: [`client::send`] — one async TLS transaction per message
//!   (tokio + rustls), with optional fingerprint pinning.
//! - **`server`**: [`MisfinServer`] — an async TLS receive server with a
//!   redb-backed [`MailboxStore`], sender-identity extraction from client
//!   certificates, and fingerprint-change rejection (status 63).
//! - **`cli`**: the `misfin` binary (`id` / `send` / `serve` / `inbox`).
//!
//! ## Identity keys
//!
//! Private keys are held in `secrecy` wrappers (zeroed on drop, redacted in
//! `Debug`). A persisted identity is a JSON file created owner-only (mode
//! 0600) on Unix; on Windows the file takes its directory's inherited ACL,
//! because no maintained crate sets an owner-only ACL without unsafe code of
//! our own. Where keys should ultimately live (a keychain, custody) is not
//! decided here, so the file format and location are unchanged.

use std::path::PathBuf;

/// Misfin's well-known port.
pub const MISFIN_PORT: u16 = 1958;

/// The maximum size of a request (the whole request line, CRLF included) or a
/// response line, per the specification.
pub const MAX_REQUEST_BYTES: usize = 2048;

/// A misfin address: `mailbox@host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MisfinAddress {
    pub mailbox: String,
    pub host: String,
}

/// A message sender, as carried by a gemmail sender line (`< addr blurb`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MisfinSender {
    pub address: MisfinAddress,
    pub blurb: Option<String>,
}

/// What a minted identity should say: its address and optional blurb (the
/// human-readable description stored in the certificate's COMMON_NAME).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MisfinIdentitySpec {
    pub address: MisfinAddress,
    pub blurb: Option<String>,
}

/// A parsed gemmail message: the spec's three metadata line types (sender,
/// recipients, timestamp), the derived subject (first heading), and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MisfinGemmail {
    pub sender: Option<MisfinSender>,
    pub recipients: Vec<MisfinAddress>,
    pub timestamp: Option<String>,
    pub subject: Option<String>,
    pub body: String,
}

/// The state of a persisted identity: whether it exists on disk, where, and
/// its certificate fingerprint if so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MisfinIdentityStatus {
    pub address: String,
    pub path: Option<PathBuf>,
    pub exists: bool,
    pub blurb: Option<String>,
    pub certificate_fingerprint: Option<String>,
}

/// DER material for a misfin identity: the certificate (leaf, DER) and the
/// private key (PKCS#8 DER). This is the shape a client-cert TLS sender
/// consumes.
///
/// The key is a [`SecretSlice`]: zeroed when dropped and printed as a
/// redaction by `Debug`. Read it with [`ExposeSecret::expose_secret`]; build
/// one from a `Vec<u8>` with `.into()`.
#[derive(Debug, Clone)]
pub struct MisfinIdentityMaterial {
    /// The leaf certificate, DER-encoded.
    pub certificate_der: Vec<u8>,
    /// The private key, PKCS#8 DER-encoded.
    pub private_key_pkcs8_der: SecretSlice<u8>,
}

/// The secret wrappers [`MisfinIdentityMaterial`] uses, re-exported so a
/// caller needs no direct `secrecy` dependency to build or read one.
pub use secrecy::{ExposeSecret, SecretSlice};

impl MisfinAddress {
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        let (mailbox, host) = trimmed
            .split_once('@')
            .ok_or_else(|| format!("Invalid Misfin address '{trimmed}'."))?;
        if mailbox.is_empty() || host.is_empty() {
            return Err(format!("Invalid Misfin address '{trimmed}'."));
        }
        Ok(Self {
            mailbox: mailbox.to_string(),
            host: host.to_ascii_lowercase(),
        })
    }

    pub fn from_url(url: &url::Url) -> Result<Self, String> {
        let mailbox = url.username().trim();
        if mailbox.is_empty() {
            return Err(
                "Misfin URL is missing the recipient mailbox in the username position.".to_string(),
            );
        }
        let host = url
            .host_str()
            .ok_or_else(|| "Misfin URL is missing a host.".to_string())?;
        Self::parse(&format!("{mailbox}@{host}"))
    }

    pub fn as_addr_spec(&self) -> String {
        format!("{}@{}", self.mailbox, self.host)
    }
}

pub fn url_string_for_address(address: &MisfinAddress, explicit_port: Option<u16>) -> String {
    if let Some(port) = explicit_port {
        format!("misfin://{}@{}:{port}", address.mailbox, address.host)
    } else {
        format!("misfin://{}@{}", address.mailbox, address.host)
    }
}

/// The SHA-256 hex fingerprint of a certificate's DER bytes — a misfin
/// identity (the value a server returns as the status-20 META).
pub fn certificate_fingerprint(certificate_der: &[u8]) -> String {
    helpers::sha256_hex(certificate_der)
}

/// Normalize a received fingerprint per the spec: lowercase, with octet
/// separators and other non-alphanumeric characters stripped.
pub fn normalize_fingerprint(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// A recommended identity-vault derivation salt for a misfin `address`:
/// domain-separated and per-address, so a key-derivation vault yields a stable
/// key for that address and distinct (unlinkable) keys across addresses. Feed
/// the derived 32-byte seed to [`deterministic_identity`]. The prefix is the
/// convention the Mere browser ships; any stable domain-separated salt works.
pub fn identity_salt(address: &MisfinAddress) -> Vec<u8> {
    [
        b"mere/misfin/identity/v1/".as_slice(),
        address.as_addr_spec().as_bytes(),
    ]
    .concat()
}

mod gemmail;
mod helpers;
mod identity;
mod status;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
mod mailbox;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
mod x509_identity;

pub use gemmail::{parse_gemmail, reply_recipients};
pub use identity::{
    deterministic_identity, ensure_identity_with_root, forget_identity_with_root,
    identity_material_with_root, identity_status_with_root, rotate_identity_with_root,
};
pub use status::{MisfinStatus, StatusCategory, parse_response_line};

/// Test-only: mint an identity with an explicit validity window (e.g. expired).
#[cfg(feature = "test-support")]
pub use identity::identity_with_validity_years;

#[cfg(feature = "client")]
pub use client::{SendError, SendOptions, SendReceipt, send};
#[cfg(feature = "server")]
pub use mailbox::{IdentityCheck, MailboxStore, ReceivedMessage, SenderSeen};
#[cfg(feature = "server")]
pub use server::{
    BoundMisfinServer, MisfinResponse, MisfinServer, MisfinServerConfig, ServedMailbox,
};
#[cfg(feature = "server")]
pub use x509_identity::{CertificateIdentity, claimed_address, parse_certificate_identity};

/// An error from the misfin receive server (the `server` feature): a mailbox
/// store failure, a TLS / server-config failure, or a socket failure.
#[cfg(feature = "server")]
#[derive(Debug)]
pub enum MisfinServerError {
    /// A mailbox-store failure (redb or message (de)serialization).
    Storage(String),
    /// A TLS or server-configuration failure (bad cert/key, provider).
    Config(String),
    /// A socket / IO failure (bind, accept).
    Io(String),
}

#[cfg(feature = "server")]
impl std::fmt::Display for MisfinServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(message) => write!(formatter, "misfin mailbox storage error: {message}"),
            Self::Config(message) => write!(formatter, "misfin server config error: {message}"),
            Self::Io(message) => write!(formatter, "misfin server IO error: {message}"),
        }
    }
}

#[cfg(feature = "server")]
impl std::error::Error for MisfinServerError {}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn fingerprints_normalize_per_spec() {
        assert_eq!(normalize_fingerprint("AB:CD:0f"), "abcd0f");
        assert_eq!(normalize_fingerprint("ab cd-0F"), "abcd0f");
    }

    #[test]
    fn addresses_lowercase_the_host_only() {
        let address = MisfinAddress::parse("Mark@Example.TEST").unwrap();
        assert_eq!(address.mailbox, "Mark");
        assert_eq!(address.host, "example.test");
    }
}
