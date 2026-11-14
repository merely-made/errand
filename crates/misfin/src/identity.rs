//! Misfin identity certificates (specification §3.1): self-signed x509 with
//! the mailbox in USER_ID, the blurb in COMMON_NAME, and the hostname as a
//! SUBJECT_ALT_NAME DNS entry.
//!
//! Two minting paths: [`ensure_identity_with_root`] (random key, persisted as
//! JSON under a caller-supplied directory) and [`deterministic_identity`]
//! (Ed25519 from a caller-supplied 32-byte seed; nothing to back up).

use std::fs;
use std::io::Write;
use std::path::Path;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::CertificateDer;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use super::helpers::*;
use super::{MisfinIdentityMaterial, MisfinIdentitySpec, MisfinIdentityStatus};

/// The USER_ID (uid) attribute, 0.9.2342.19200300.100.1.1 — where the spec
/// stores the mailbox name.
pub(super) const MISFIN_USER_ID_OID: [u64; 7] = [0, 9, 2342, 19200300, 100, 1, 1];

/// The on-disk identity file. Field names and order are the file format;
/// the key hex is a secret while it is in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMisfinIdentity {
    address: String,
    blurb: Option<String>,
    certificate_der_hex: String,
    #[serde(serialize_with = "serialize_exposed")]
    private_key_der_hex: SecretString,
}

/// `secrecy` serializes nothing by default; the identity file is the one
/// place this key hex is meant to be written.
fn serialize_exposed<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

#[derive(Debug, Clone)]
pub(super) struct MisfinClientIdentity {
    pub(super) certificate_chain: Vec<CertificateDer<'static>>,
    pub(super) private_key_der: SecretSlice<u8>,
}

impl From<MisfinClientIdentity> for MisfinIdentityMaterial {
    fn from(identity: MisfinClientIdentity) -> Self {
        Self {
            certificate_der: identity
                .certificate_chain
                .first()
                .map(|cert| cert.as_ref().to_vec())
                .unwrap_or_default(),
            private_key_pkcs8_der: identity.private_key_der,
        }
    }
}

/// Load the identity for `spec` from `identity_root`, minting and persisting
/// one if absent, and return its DER material (certificate + PKCS#8 key) ready
/// for a client-cert TLS handshake.
pub fn identity_material_with_root(
    spec: &MisfinIdentitySpec,
    identity_root: &Path,
) -> Result<MisfinIdentityMaterial, String> {
    load_or_create_identity(spec, identity_root).map(MisfinIdentityMaterial::from)
}

pub(super) fn load_or_create_identity(
    spec: &MisfinIdentitySpec,
    identity_root: &Path,
) -> Result<MisfinClientIdentity, String> {
    fs::create_dir_all(identity_root)
        .map_err(|error| format!("Failed to create Misfin identity directory: {error}"))?;
    let path = identity_path_for_spec(spec, identity_root);

    if path.exists() {
        let persisted = read_persisted(&path)?;
        return Ok(MisfinClientIdentity {
            certificate_chain: vec![CertificateDer::from(decode_hex(
                &persisted.certificate_der_hex,
            )?)],
            private_key_der: decode_hex(persisted.private_key_der_hex.expose_secret())?.into(),
        });
    }

    let identity = generate_identity(spec)?;
    let persisted = PersistedMisfinIdentity {
        address: spec.address.as_addr_spec(),
        blurb: spec.blurb.clone(),
        certificate_der_hex: encode_hex(identity.certificate_chain[0].as_ref()),
        private_key_der_hex: encode_hex(identity.private_key_der.expose_secret()).into(),
    };
    let content = Zeroizing::new(serde_json::to_string_pretty(&persisted).map_err(|error| {
        format!(
            "Failed to serialize Misfin identity '{}': {error}",
            path.display()
        )
    })?);
    write_owner_only(&path, content.as_bytes()).map_err(|error| {
        format!(
            "Failed to persist Misfin identity '{}': {error}",
            path.display()
        )
    })?;
    Ok(identity)
}

fn read_persisted(path: &Path) -> Result<PersistedMisfinIdentity, String> {
    let content = Zeroizing::new(fs::read_to_string(path).map_err(|error| {
        format!(
            "Failed to read Misfin identity '{}': {error}",
            path.display()
        )
    })?);
    serde_json::from_str(&content).map_err(|error| {
        format!(
            "Failed to parse Misfin identity '{}': {error}",
            path.display()
        )
    })
}

/// Create `path` (it must not exist) readable only by its owner: mode 0600
/// on Unix, set at creation so the key is never on disk with wider access.
/// Elsewhere the file takes the platform default (on Windows, the parent
/// directory's inherited ACL).
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Report the persisted identity for `spec` under `identity_root` without
/// creating one.
pub fn identity_status_with_root(
    spec: &MisfinIdentitySpec,
    identity_root: &Path,
) -> Result<MisfinIdentityStatus, String> {
    let path = identity_path_for_spec(spec, identity_root);

    if !path.exists() {
        return Ok(MisfinIdentityStatus {
            address: spec.address.as_addr_spec(),
            path: Some(path),
            exists: false,
            blurb: spec.blurb.clone(),
            certificate_fingerprint: None,
        });
    }

    let persisted = read_persisted(&path)?;
    let certificate_der = decode_hex(&persisted.certificate_der_hex)?;

    Ok(MisfinIdentityStatus {
        address: persisted.address,
        path: Some(path),
        exists: true,
        blurb: persisted.blurb,
        certificate_fingerprint: Some(sha256_hex(&certificate_der)),
    })
}

/// Ensure an identity for `spec` exists under `identity_root` (minting one if
/// needed) and report it.
pub fn ensure_identity_with_root(
    spec: &MisfinIdentitySpec,
    identity_root: &Path,
) -> Result<MisfinIdentityStatus, String> {
    let _ = load_or_create_identity(spec, identity_root)?;
    identity_status_with_root(spec, identity_root)
}

/// Replace the persisted identity for `spec` with a freshly minted one.
/// The old fingerprint is gone forever; peers that pinned it will see a
/// changed fingerprint (and spec-compliant servers may reply 63).
pub fn rotate_identity_with_root(
    spec: &MisfinIdentitySpec,
    identity_root: &Path,
) -> Result<MisfinIdentityStatus, String> {
    let _ = forget_identity_with_root(spec, identity_root)?;
    ensure_identity_with_root(spec, identity_root)
}

/// Delete the persisted identity for `spec`, returning whether one existed.
pub fn forget_identity_with_root(
    spec: &MisfinIdentitySpec,
    identity_root: &Path,
) -> Result<bool, String> {
    let path = identity_path_for_spec(spec, identity_root);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(&path).map_err(|error| {
        format!(
            "Failed to remove Misfin identity '{}': {error}",
            path.display()
        )
    })?;
    Ok(true)
}

fn spec_certificate_params(spec: &MisfinIdentitySpec) -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(vec![spec.address.host.clone()])
        .map_err(|error| format!("Misfin certificate params failed: {error}"))?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(
        DnType::CustomDnType(MISFIN_USER_ID_OID.to_vec()),
        spec.address.mailbox.clone(),
    );
    distinguished_name.push(
        DnType::CommonName,
        spec.blurb
            .clone()
            .unwrap_or_else(|| spec.address.as_addr_spec()),
    );
    params.distinguished_name = distinguished_name;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    Ok(params)
}

pub(super) fn generate_identity(spec: &MisfinIdentitySpec) -> Result<MisfinClientIdentity, String> {
    let key_pair =
        KeyPair::generate().map_err(|error| format!("Misfin key generation failed: {error}"))?;
    let params = spec_certificate_params(spec)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| format!("Misfin identity certificate generation failed: {error}"))?;

    Ok(MisfinClientIdentity {
        certificate_chain: vec![CertificateDer::from(cert.der().to_vec())],
        private_key_der: key_pair.serialize_der().into(),
    })
}

/// Deterministically mint a misfin identity from a 32-byte **Ed25519** seed.
///
/// The reproducible counterpart of [`ensure_identity_with_root`]: rather than
/// generate a random key and persist it, this derives the entire identity from
/// `seed` + `spec`. Ed25519 signs deterministically (RFC 8032) and the cert
/// uses a fixed serial + validity, so the same seed + address always reproduce
/// a byte-identical certificate and SHA-256 fingerprint — there is no
/// certificate to back up. The spec mandates no key algorithm (any valid
/// self-signed x509), so this stays interoperable.
pub fn deterministic_identity(
    seed: &[u8; 32],
    spec: &MisfinIdentitySpec,
) -> Result<MisfinIdentityMaterial, String> {
    // Import the Ed25519 key from its PKCS#8 wrapper; rcgen infers Ed25519 from
    // the embedded algorithm OID.
    let pkcs8 = ed25519_pkcs8_der(seed);
    let key_pair = KeyPair::try_from(pkcs8.as_slice())
        .map_err(|error| format!("Misfin Ed25519 key import failed: {error}"))?;

    let mut params = spec_certificate_params(spec)?;
    // Fix the serial: rcgen randomises it by default, which would churn the
    // fingerprint. The key + DN already differ per identity, so a constant is fine.
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));

    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| format!("Misfin identity certificate generation failed: {error}"))?;

    Ok(MisfinIdentityMaterial {
        certificate_der: cert.der().to_vec(),
        private_key_pkcs8_der: key_pair.serialize_der().into(),
    })
}

/// The PKCS#8 v1 (RFC 8410) DER encoding of an Ed25519 private key from its
/// 32-byte `seed`: a fixed 16-byte prefix followed by the seed.
fn ed25519_pkcs8_der(seed: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = Zeroizing::new(Vec::with_capacity(PREFIX.len() + seed.len()));
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(seed);
    der
}

/// Mint an identity whose validity window is explicit — for tests that need
/// an expired certificate.
#[cfg(any(test, feature = "test-support"))]
pub fn identity_with_validity_years(
    spec: &MisfinIdentitySpec,
    not_before_year: i32,
    not_after_year: i32,
) -> Result<MisfinIdentityMaterial, String> {
    let key_pair =
        KeyPair::generate().map_err(|error| format!("Misfin key generation failed: {error}"))?;
    let mut params = spec_certificate_params(spec)?;
    params.not_before = rcgen::date_time_ymd(not_before_year, 1, 1);
    params.not_after = rcgen::date_time_ymd(not_after_year, 12, 31);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| format!("Misfin identity certificate generation failed: {error}"))?;
    Ok(MisfinIdentityMaterial {
        certificate_der: cert.der().to_vec(),
        private_key_pkcs8_der: key_pair.serialize_der().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MisfinAddress, identity_salt};
    use tempfile::TempDir;

    fn spec(addr: &str) -> MisfinIdentitySpec {
        MisfinIdentitySpec {
            address: MisfinAddress::parse(addr).unwrap(),
            blurb: Some("Test".to_string()),
        }
    }

    #[test]
    fn identity_status_reports_persisted_identity() {
        let tempdir = TempDir::new().expect("temp dir should be created");
        let spec = spec("worker@hive.local");

        let status =
            ensure_identity_with_root(&spec, tempdir.path()).expect("identity should be created");

        assert!(status.exists);
        assert_eq!(status.address, "worker@hive.local");
        assert!(status.path.expect("identity path should exist").exists());
        assert!(status.certificate_fingerprint.is_some());
    }

    #[test]
    fn rotate_replaces_the_fingerprint_and_forget_removes_it() {
        let tempdir = TempDir::new().unwrap();
        let spec = spec("worker@hive.local");

        let first = ensure_identity_with_root(&spec, tempdir.path()).unwrap();
        let second = rotate_identity_with_root(&spec, tempdir.path()).unwrap();
        assert_ne!(
            first.certificate_fingerprint, second.certificate_fingerprint,
            "rotation mints a new key"
        );

        assert!(forget_identity_with_root(&spec, tempdir.path()).unwrap());
        assert!(!forget_identity_with_root(&spec, tempdir.path()).unwrap());
        let status = identity_status_with_root(&spec, tempdir.path()).unwrap();
        assert!(!status.exists);
    }

    #[test]
    fn same_seed_reproduces_a_byte_identical_identity() {
        let seed = [7u8; 32];
        let a = deterministic_identity(&seed, &spec("alice@example.test")).unwrap();
        let b = deterministic_identity(&seed, &spec("alice@example.test")).unwrap();
        // Ed25519 deterministic signatures + fixed serial/validity => a byte-stable
        // cert, hence a stable SHA-256 fingerprint (the misfin identity).
        assert_eq!(a.certificate_der, b.certificate_der, "cert is reproducible");
        assert_eq!(
            a.private_key_pkcs8_der.expose_secret(),
            b.private_key_pkcs8_der.expose_secret()
        );
        assert!(!a.certificate_der.is_empty());
    }

    #[test]
    fn a_different_seed_yields_a_different_identity() {
        let s = spec("alice@example.test");
        let a = deterministic_identity(&[7u8; 32], &s).unwrap();
        let c = deterministic_identity(&[8u8; 32], &s).unwrap();
        assert_ne!(a.certificate_der, c.certificate_der);
    }

    #[test]
    fn the_identity_salt_is_per_address() {
        let alice = MisfinAddress::parse("alice@example.test").unwrap();
        let bob = MisfinAddress::parse("bob@example.test").unwrap();
        assert_ne!(
            identity_salt(&alice),
            identity_salt(&bob),
            "addresses derive distinct keys"
        );
        let alice_again = MisfinAddress::parse("alice@example.test").unwrap();
        assert_eq!(
            identity_salt(&alice),
            identity_salt(&alice_again),
            "stable per address"
        );
    }

    /// The identity file as the pre-secrets code wrote it: four plain strings.
    #[derive(Serialize, Deserialize)]
    struct LegacyFile {
        address: String,
        blurb: Option<String>,
        certificate_der_hex: String,
        private_key_der_hex: String,
    }

    #[test]
    fn debug_never_prints_the_key() {
        let material = deterministic_identity(&[7u8; 32], &spec("alice@example.test")).unwrap();
        let key_hex = encode_hex(material.private_key_pkcs8_der.expose_secret());
        let tempdir = TempDir::new().unwrap();
        let client = load_or_create_identity(&spec("alice@example.test"), tempdir.path()).unwrap();
        let client_key_hex = encode_hex(client.private_key_der.expose_secret());
        let persisted = read_persisted(&identity_path_for_spec(
            &spec("alice@example.test"),
            tempdir.path(),
        ))
        .unwrap();

        for (printed, key) in [
            (format!("{material:?}"), &key_hex),
            (format!("{client:?}"), &client_key_hex),
            (format!("{persisted:?}"), &client_key_hex),
        ] {
            assert!(!printed.contains(key.as_str()), "key hex in {printed}");
            assert!(printed.contains("REDACTED"), "no redaction in {printed}");
        }
    }

    #[test]
    fn an_existing_format_identity_file_still_loads() {
        let tempdir = TempDir::new().unwrap();
        let spec = spec("alice@example.test");
        let material = deterministic_identity(&[9u8; 32], &spec).unwrap();
        let legacy = LegacyFile {
            address: spec.address.as_addr_spec(),
            blurb: spec.blurb.clone(),
            certificate_der_hex: encode_hex(&material.certificate_der),
            private_key_der_hex: encode_hex(material.private_key_pkcs8_der.expose_secret()),
        };
        let path = identity_path_for_spec(&spec, tempdir.path());
        fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

        let loaded = identity_material_with_root(&spec, tempdir.path()).unwrap();
        assert_eq!(loaded.certificate_der, material.certificate_der);
        assert_eq!(
            loaded.private_key_pkcs8_der.expose_secret(),
            material.private_key_pkcs8_der.expose_secret()
        );
    }

    #[test]
    fn a_new_identity_file_is_byte_identical_to_the_old_format() {
        let tempdir = TempDir::new().unwrap();
        let spec = spec("alice@example.test");
        ensure_identity_with_root(&spec, tempdir.path()).unwrap();
        let written = fs::read_to_string(identity_path_for_spec(&spec, tempdir.path())).unwrap();
        let legacy: LegacyFile = serde_json::from_str(&written).unwrap();
        assert_eq!(serde_json::to_string_pretty(&legacy).unwrap(), written);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tempdir = TempDir::new().unwrap();
        let spec = spec("alice@example.test");
        ensure_identity_with_root(&spec, tempdir.path()).unwrap();
        let mode = fs::metadata(identity_path_for_spec(&spec, tempdir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
