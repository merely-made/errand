// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Misfin (`misfin://`, port 1958): gemini-style mail **send**, via the
//! [`misfin`](https://crates.io/crates/misfin) crate's client (on the same
//! ring provider this crate builds rustls with).
//!
//! Misfin is gemini-flavoured peer-to-peer mail: a single TLS transaction
//! presenting a client certificate (the sender's identity *is* its
//! certificate), a `misfin://<mailbox>@<host> <message>\r\n` request line,
//! and a `<status> <meta>\r\n` reply. It is the write companion for mail, as
//! [`titan`](crate::titan_upload) is for gemini.
//!
//! errand owns only the client side and the mapping onto [`Response`]. The
//! certificate is supplied by the caller ([`ClientIdentity`]); errand never
//! generates or stores certs — that is the sender's identity layer.
//! **Receiving** misfin (serving a mailbox) is the misfin crate's `server`
//! feature, outside errand's client-transport scope.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::time::Duration;
use url::Url;

use crate::{Error, Response, Status};

/// Misfin's well-known port.
pub const MISFIN_PORT: u16 = 1958;

/// Time budgets for one explicitly authorized mail send.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendOptions {
    /// Per-step connect/TLS/write/read timeout. `None` uses the native 30 seconds.
    pub timeout: Option<Duration>,
    /// Whole-send budget, including connection cleanup. `None` uses 120 seconds.
    /// Expiry can retain an acknowledgment in [`Error::MisfinSendTimeout`].
    pub send_timeout: Option<Duration>,
}

/// A client identity for a misfin send: the certificate chain + private key,
/// in DER, supplied by the caller. The leaf comes first; further chain
/// certificates (the spec's mailbox-signed-by-host setup) follow. The key
/// must be PKCS#8 (the format Mere's vault-derived identities produce).
pub struct ClientIdentity {
    /// The client certificate chain (leaf first), DER-encoded.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// The client private key, DER-encoded (PKCS#8).
    pub private_key: PrivateKeyDer<'static>,
}

/// Send `message` to a misfin `recipient` (`misfin://mailbox@host[:port]`),
/// presenting `identity` as the client certificate. Returns the recipient
/// host's gemini-format [`Response`] (2x delivered, 3x redirect, 4x/5x
/// failure, 6x certificate). errand does not follow misfin redirects; the
/// caller decides.
pub async fn send(
    recipient: &Url,
    message: &str,
    identity: ClientIdentity,
) -> Result<Response, Error> {
    send_with_options(recipient, message, identity, &SendOptions::default()).await
}

/// Send with caller-selected step and whole-send budgets. This does not retry,
/// follow redirects, or resend after a timeout. A timeout or cancellation after
/// writing may leave delivery uncertain; an observed receipt is retained.
pub async fn send_with_options(
    recipient: &Url,
    message: &str,
    identity: ClientIdentity,
    options: &SendOptions,
) -> Result<Response, Error> {
    if recipient.scheme() != "misfin" {
        return Err(Error::UnsupportedScheme(recipient.scheme().to_string()));
    }
    let address = misfin::MisfinAddress::from_url(recipient).map_err(Error::BadUrl)?;

    let options = misfin::SendOptions {
        identity: Some(identity_material(&identity)?),
        extra_chain_der: identity
            .cert_chain
            .iter()
            .skip(1)
            .map(|cert| cert.as_ref().to_vec())
            .collect(),
        // The addr-spec omits the port; an explicit URL port is only the
        // dial target.
        port: recipient.port(),
        timeout: options.timeout,
        send_timeout: options.send_timeout,
        ..Default::default()
    };
    let receipt = misfin::send(&address, message, &options)
        .await
        .map_err(map_error)?;
    Ok(map_receipt(recipient, receipt))
}

fn identity_material(identity: &ClientIdentity) -> Result<misfin::MisfinIdentityMaterial, Error> {
    let leaf = identity
        .cert_chain
        .first()
        .ok_or_else(|| Error::Protocol("misfin identity has an empty certificate chain".into()))?;
    let PrivateKeyDer::Pkcs8(key) = &identity.private_key else {
        return Err(Error::Protocol(
            "misfin send requires a PKCS#8 private key".into(),
        ));
    };
    Ok(misfin::MisfinIdentityMaterial {
        certificate_der: leaf.as_ref().to_vec(),
        private_key_pkcs8_der: key.secret_pkcs8_der().to_vec(),
    })
}

/// Map a misfin receipt onto errand's normalized response, by the status
/// code's first digit (the same axis the gemini parser uses).
fn map_receipt(url: &Url, receipt: misfin::SendReceipt) -> Response {
    let code = receipt.status.code();
    let status = match code / 10 {
        1 => Status::Input,
        2 => Status::Success,
        3 => Status::Redirect,
        6 => Status::CertRequired,
        _ => Status::Failure,
    };
    Response {
        url: url.clone(),
        status,
        raw_status: Some(code),
        meta: receipt.meta,
        // A misfin reply is a single status line; there is no body.
        body: Vec::new(),
    }
}

fn map_error(error: misfin::SendError) -> Error {
    use misfin::SendError;
    match error {
        SendError::MessageTooLong { request_bytes, max } => Error::Protocol(format!(
            "misfin request is {request_bytes} bytes (max {max}); split the message"
        )),
        SendError::MessageContainsCarriageReturn => {
            Error::Protocol("misfin messages must not contain carriage returns".into())
        }
        SendError::InvalidHost(host) => Error::BadUrl(format!("invalid misfin host '{host}'")),
        SendError::FingerprintMismatch { expected, found } => Error::Protocol(format!(
            "misfin server fingerprint mismatch: expected {expected}, found {found}"
        )),
        SendError::Tls(message) => Error::Connect(message),
        SendError::Io(message) => Error::Io(message),
        SendError::Timeout(_) => Error::Timeout,
        SendError::WholeSendTimeout { receipt } => Error::MisfinSendTimeout { receipt },
        SendError::InvalidTimeout(scope) => {
            Error::Protocol(format!("invalid misfin {scope} timeout"))
        }
        SendError::BadResponse(message) => Error::Protocol(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misfin::{MisfinStatus, SendReceipt};

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn receipt(status: MisfinStatus, meta: &str) -> SendReceipt {
        SendReceipt {
            status,
            meta: meta.to_string(),
            server_fingerprint: "aa".repeat(32),
        }
    }

    fn valid_identity() -> ClientIdentity {
        let material = misfin::deterministic_identity(
            &[7; 32],
            &misfin::MisfinIdentitySpec {
                address: misfin::MisfinAddress::parse("sender@example.test").unwrap(),
                blurb: Some("Errand test sender".into()),
            },
        )
        .unwrap();
        ClientIdentity {
            cert_chain: vec![material.certificate_der.into()],
            private_key: PrivateKeyDer::Pkcs8(material.private_key_pkcs8_der.into()),
        }
    }

    #[test]
    fn whole_send_timeout_preserves_exact_native_acknowledgment() {
        for status in [MisfinStatus::Delivered, MisfinStatus::SendHereForever] {
            let expected = SendReceipt {
                status,
                meta: "native acknowledgment; preserve exactly".into(),
                server_fingerprint: "bc".repeat(32),
            };
            let mapped = map_error(misfin::SendError::WholeSendTimeout {
                receipt: Some(expected.clone()),
            });
            assert!(mapped.to_string().contains("after acknowledgment"));
            let Error::MisfinSendTimeout { receipt } = mapped else {
                panic!("whole-send acknowledgment was discarded");
            };
            assert_eq!(receipt, Some(expected));
        }
    }

    #[test]
    fn whole_send_timeout_without_acknowledgment_stays_distinct_from_step_timeout() {
        let mapped = map_error(misfin::SendError::WholeSendTimeout { receipt: None });
        assert!(mapped.to_string().contains("outcome unknown"));
        assert!(matches!(mapped, Error::MisfinSendTimeout { receipt: None }));
        assert!(matches!(
            map_error(misfin::SendError::Timeout("response read")),
            Error::Timeout
        ));
        assert!(matches!(
            map_error(misfin::SendError::InvalidTimeout("whole-send")),
            Error::Protocol(reason) if reason == "invalid misfin whole-send timeout"
        ));
    }

    #[test]
    fn default_send_options_defer_to_native_budgets() {
        let options = SendOptions::default();
        assert_eq!(options.timeout, None);
        assert_eq!(options.send_timeout, None);
    }

    #[tokio::test]
    async fn configured_zero_mail_budgets_refuse_before_contact() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let recipient = url(&format!("misfin://recipient@127.0.0.1:{}", address.port()));
        for whole_wins in [false, true] {
            let options = if whole_wins {
                SendOptions {
                    timeout: Some(Duration::from_secs(2)),
                    send_timeout: Some(Duration::ZERO),
                }
            } else {
                SendOptions {
                    timeout: Some(Duration::ZERO),
                    send_timeout: Some(Duration::from_secs(2)),
                }
            };
            let result = send_with_options(
                &recipient,
                "explicitly authorized message",
                valid_identity(),
                &options,
            )
            .await;
            if whole_wins {
                assert!(matches!(
                    result,
                    Err(Error::MisfinSendTimeout { receipt: None })
                ));
            } else {
                assert!(matches!(result, Err(Error::Timeout)));
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "a zero mail budget contacted the recipient"
        );
    }

    #[tokio::test]
    async fn mail_is_never_an_ordinary_fetch() {
        assert!(matches!(
            crate::fetch("misfin://recipient@127.0.0.1:1").await,
            Err(Error::UnsupportedScheme(scheme)) if scheme == "misfin"
        ));
    }

    #[test]
    fn receipts_map_by_status_category() {
        let u = url("misfin://alice@example.test");
        let delivered = map_receipt(&u, receipt(MisfinStatus::Delivered, "fp"));
        assert_eq!(delivered.status, Status::Success);
        assert_eq!(delivered.raw_status, Some(20));
        assert_eq!(delivered.meta, "fp");
        assert!(delivered.body.is_empty());

        let moved = map_receipt(
            &u,
            receipt(MisfinStatus::SendHereForever, "misfin://b@c.test"),
        );
        assert_eq!(moved.status, Status::Redirect);
        assert_eq!(moved.raw_status, Some(31));

        let full = map_receipt(&u, receipt(MisfinStatus::MailboxFull, "later"));
        assert_eq!(full.status, Status::Failure);

        let liar = map_receipt(&u, receipt(MisfinStatus::FingerprintChanged, "no"));
        assert_eq!(liar.status, Status::CertRequired);
        assert_eq!(liar.raw_status, Some(63));
    }

    #[tokio::test]
    async fn rejects_a_non_misfin_scheme() {
        let identity = ClientIdentity {
            cert_chain: vec![],
            private_key: PrivateKeyDer::Pkcs8(vec![0u8; 4].into()),
        };
        assert!(matches!(
            send(&url("gemini://example.test/"), "x", identity).await,
            Err(Error::UnsupportedScheme(_))
        ));
    }

    #[tokio::test]
    async fn rejects_a_missing_mailbox() {
        let identity = ClientIdentity {
            cert_chain: vec![],
            private_key: PrivateKeyDer::Pkcs8(vec![0u8; 4].into()),
        };
        assert!(matches!(
            send(&url("misfin://example.test"), "x", identity).await,
            Err(Error::BadUrl(_))
        ));
    }

    #[test]
    fn an_empty_chain_is_rejected_before_any_network() {
        let identity = ClientIdentity {
            cert_chain: vec![],
            private_key: PrivateKeyDer::Pkcs8(vec![0u8; 4].into()),
        };
        assert!(matches!(
            identity_material(&identity),
            Err(Error::Protocol(_))
        ));
    }
}
