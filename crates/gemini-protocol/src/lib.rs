//! # gemini-protocol
//!
//! [Gemini](https://geminiprotocol.net/) (`gemini://`, port 1965) and the
//! things its specification defines alongside it: the **gemtext** document
//! grammar, trust-on-first-use certificate pinning, and the **titan://**
//! upload companion.
//!
//! They share a crate because they share a spec. Gemtext is not a separate
//! format that happens to travel over gemini; it is the format gemini defines,
//! and titan is the write half of the same document space.
//!
//! ## Three layers, three costs
//!
//! | Layer | Feature | Pulls | What it gives you |
//! |---|---|---|---|
//! | [`gemtext`] | always on | nothing | the document grammar |
//! | [`client`] | `client` | tokio, url | the exchange over *any* stream |
//! | [`client::fetch`], [`tofu`], [`titan`] | `tls` *(default)* | rustls, ring | the ordinary internet client |
//!
//! The split is not ceremony. **Five other smolweb protocols serve
//! `text/gemini` bodies** (spartan, guppy, scroll, misfin, and titan itself),
//! so the grammar is the piece most consumers actually want, and it should
//! never drag in a TLS stack to get it:
//!
//! ```toml
//! gemini-protocol = { version = "0.1", default-features = false }
//! ```
//!
//! And the request/response is transport-independent, so gemini over an
//! already-encrypted carrier, such as a Reticulum link where the destination
//! hash *is* the peer identity and there is no certificate to pin, needs
//! `client` without `tls`.
//!
//! ## Parsing gemtext
//!
//! ```
//! use gemini_protocol::gemtext::{GemLine, parse};
//!
//! let doc = parse("# Title\n=> gemini://example.org/ A link\n* an item\n");
//!
//! assert!(matches!(&doc[0], GemLine::Heading { level: 1, .. }));
//! assert!(matches!(&doc[1], GemLine::Link { url, .. } if url == "gemini://example.org/"));
//! ```

#![forbid(unsafe_code)]

pub mod gemtext;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "tls")]
pub mod titan;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub mod tofu;

pub use gemtext::{GemLine, parse as parse_gemtext};

#[cfg(feature = "client")]
pub use client::{
    ClientError, DEFAULT_PORT, FetchOptions, Response, ResponseHead, Status, exchange,
    exchange_streaming, exchange_streaming_with_options, exchange_with_options, parse_response,
};
#[cfg(feature = "tls")]
pub use titan::{DEFAULT_MAX_RESPONSE_BYTES, UploadOptions, upload_with_options};

#[cfg(feature = "tls")]
pub use client::{
    ClientIdentity, fetch, fetch_url_streaming, fetch_url_streaming_with_identity,
    fetch_url_with_identity, tofu_connect,
};
#[cfg(feature = "tls")]
pub use tofu::{InMemoryTofu, PermissiveTofu, TofuStore, set_trust_store};

#[cfg(feature = "server")]
pub use server::{Reply, ServerConfig, acceptor, serve};
