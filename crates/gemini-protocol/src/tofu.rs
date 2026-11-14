//! Trust-on-first-use certificate pinning for the TLS schemes.
//!
//! Gemini capsules are conventionally self-signed, so there is no CA to
//! anchor trust. The real TOFU model pins the SHA-256 of a host's leaf
//! certificate on first contact and requires every later visit to present
//! the same one — so a *changed* certificate (a man-in-the-middle, a key
//! rotation, a moved host) is surfaced rather than silently accepted.
//!
//! Pins are keyed by capsule authority (host plus a non-default port), so two
//! TLS services on one machine do not silently share trust. The pin store is
//! a [`TofuStore`] trait so the embedder chooses
//! durability: [`InMemoryTofu`] holds pins for the process; a host with a
//! profile supplies its own durable store (a file, a database, an engram).
//! The store is installed once via [`set_trust_store`]. Until one is
//! installed, every TLS connection through this module (gemini fetches,
//! titan uploads, and [`crate::tofu_connect`] callers such as scroll) is
//! refused before a socket is opened: nothing is trusted by default.
//! Choosing trust is the embedder's job, not the fetcher's; a host that wants
//! a throwaway session installs [`InMemoryTofu`], and one that wants the old
//! accept-any behaviour installs [`PermissiveTofu`] by name.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// A store of pinned leaf-certificate fingerprints, keyed by capsule target.
///
/// `Send + Sync` so one store serves every concurrent fetch. Implementations
/// decide where pins live; the two `errand` ships are [`InMemoryTofu`] and
/// [`PermissiveTofu`]. A target is a lowercase host for the default Gemini
/// port, or `host:port` for a non-default port; IPv6 hosts retain brackets.
pub trait TofuStore: Send + Sync {
    /// The pinned SHA-256 fingerprint for `target`, or `None` if this is a
    /// first contact.
    fn fingerprint(&self, target: &str) -> Option<[u8; 32]>;
    /// Record (pin) a fingerprint for `target` after a clean first contact.
    fn pin(&self, target: &str, fingerprint: [u8; 32]);
    /// Fallible pinning hook used before the connection sends application
    /// bytes. Existing infallible stores inherit the compatible default;
    /// durable stores override it so a write failure can refuse the request.
    fn try_pin(&self, target: &str, fingerprint: [u8; 32]) -> Result<(), String> {
        self.pin(target, fingerprint);
        Ok(())
    }
}

/// A process-lifetime, in-memory [`TofuStore`]. Pins last as long as the
/// store; the right choice for a session, a test, or any host that does not
/// need pins to survive a restart.
#[derive(Debug, Default)]
pub struct InMemoryTofu {
    pins: Mutex<HashMap<String, [u8; 32]>>,
}

impl InMemoryTofu {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TofuStore for InMemoryTofu {
    fn fingerprint(&self, host: &str) -> Option<[u8; 32]> {
        self.pins.lock().unwrap().get(host).copied()
    }
    fn pin(&self, host: &str, fingerprint: [u8; 32]) {
        self.pins
            .lock()
            .unwrap()
            .insert(host.to_string(), fingerprint);
    }
}

/// The accept-any store: never reports a pin, never records one. With it
/// installed, every TLS handshake is treated as a first contact and accepted.
/// It is never installed by default; an embedder that wants accept-any says
/// so by installing it.
#[derive(Debug, Default)]
pub struct PermissiveTofu;

impl TofuStore for PermissiveTofu {
    fn fingerprint(&self, _host: &str) -> Option<[u8; 32]> {
        None
    }
    fn pin(&self, _host: &str, _fingerprint: [u8; 32]) {}
}

static TRUST_STORE: RwLock<Option<Arc<dyn TofuStore>>> = RwLock::new(None);

/// Install the process-wide [`TofuStore`] errand's TLS schemes pin against.
///
/// Call once at startup (e.g. with an [`InMemoryTofu`] or a durable store).
/// Until a store is installed, every TLS connection is refused before it is
/// opened. The most recent call wins.
pub fn set_trust_store(store: Arc<dyn TofuStore>) {
    *TRUST_STORE.write().unwrap() = Some(store);
}

/// The installed trust store, or `None` when no embedder has installed one.
pub(crate) fn trust_store() -> Option<Arc<dyn TofuStore>> {
    TRUST_STORE.read().unwrap().clone()
}

/// The refusal a TLS connection gets when no store is installed.
pub(crate) const NO_TRUST_STORE: &str = "no trust store installed: call set_trust_store \
    (gemini_protocol or errand) with a TofuStore before fetching; nothing is trusted by default";

/// The SHA-256 fingerprint of a certificate's DER bytes, via rustls's ring
/// provider (already in the dependency cone).
pub(crate) fn fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Lowercase-hex of a fingerprint, for the [`crate::ClientError::CertificateChanged`]
/// message.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable trust-store key for one TLS service.
pub(crate) fn target(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    if port == crate::DEFAULT_PORT {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct InfallibleHostStore(Mutex<HashMap<String, [u8; 32]>>);

    impl TofuStore for InfallibleHostStore {
        fn fingerprint(&self, target: &str) -> Option<[u8; 32]> {
            self.0.lock().unwrap().get(target).copied()
        }

        fn pin(&self, target: &str, fingerprint: [u8; 32]) {
            self.0
                .lock()
                .unwrap()
                .insert(target.to_string(), fingerprint);
        }
    }

    #[test]
    fn in_memory_pins_and_recalls_per_host() {
        let tofu = InMemoryTofu::new();
        assert!(tofu.fingerprint("a.example").is_none());
        tofu.pin("a.example", [1u8; 32]);
        assert_eq!(tofu.fingerprint("a.example"), Some([1u8; 32]));
        assert!(tofu.fingerprint("b.example").is_none(), "pins are per host");
    }

    #[test]
    fn permissive_never_pins() {
        let tofu = PermissiveTofu;
        tofu.pin("a.example", [1u8; 32]);
        assert!(
            tofu.fingerprint("a.example").is_none(),
            "permissive store treats every visit as first contact"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_hex_round_trips() {
        assert_eq!(fingerprint(b"cert"), fingerprint(b"cert"));
        assert_ne!(fingerprint(b"cert"), fingerprint(b"other"));
        assert_eq!(hex(&[0xde, 0xad, 0x01]), "dead01");
    }

    #[test]
    fn existing_infallible_stores_inherit_the_fallible_hook() {
        let store = InfallibleHostStore::default();
        store.try_pin("a.example", [1u8; 32]).unwrap();
        assert_eq!(store.fingerprint("a.example"), Some([1u8; 32]));
    }

    #[test]
    fn trust_targets_distinguish_ports_and_normalize_ipv6() {
        assert_eq!(target("Capsule.Example", 1965), "capsule.example");
        assert_eq!(target("Capsule.Example", 1966), "capsule.example:1966");
        assert_eq!(target("2001:db8::1", 1965), "[2001:db8::1]");
        assert_eq!(target("2001:db8::1", 1966), "[2001:db8::1]:1966");
    }
}
