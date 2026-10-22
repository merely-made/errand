//! # scroll-protocol
//!
//! An implementation of the Scroll protocol (`scroll://`, port 5699) and its
//! **scrolltext** document format (`text/scroll`), by Christian Lee Seibold.
//!
//! Scroll is gemini's shape with three additions, all of which this crate
//! carries:
//!
//! - the request names the client's **acceptable languages** (BCP47), and the
//!   server serves the best match;
//! - a success response carries **document metadata** — author, publish date,
//!   modification date — and its second status digit is a **Universal Decimal
//!   Classification class**, making scroll the only small-web protocol whose
//!   responses classify their own subject matter;
//! - a `+` on the language list requests a resource's **abstract** instead of
//!   its body.
//!
//! Scrolltext is richer than gemtext on purpose: five heading levels forming
//! numbered sections, nested quotes and lists with verbatim ordered markers,
//! tagged code blocks, input links, link relations (`[Citation]`, `[+]`…),
//! inline strong/emphasis/code with precise toggle rules, and a linetype
//! escape. See [`scrolltext`].
//!
//! ## Provenance, stated plainly
//!
//! The specification's own host (`scrollprotocol.us.to`) is offline. This
//! crate is written against the spec text vendored by
//! [michael-lazar/smolnet-portal](https://github.com/michael-lazar/smolnet-portal)
//! (`docs/scroll_spec.txt`, modification date 2024-08-03), cross-checked
//! against that portal's working proxy implementation, which interoperates
//! with live scroll servers. The spec titles itself *speculative*; expect
//! revisions, and read version pins accordingly.
//!
//! ## Layers
//!
//! | Layer | Feature | Pulls |
//! |---|---|---|
//! | [`wire`] + [`scrolltext`] | always on | nothing |
//! | [`client::exchange`] over any stream | `client` | tokio |
//! | [`client::fetch`] with TLS + TOFU | `tls` *(default)* | gemini-protocol |
//! | [`server::serve_connection`] over a caller-owned stream | `server` | tokio, url |
//!
//! The TLS half deliberately rides
//! [`gemini_protocol::tofu_connect`]: scroll's spec says "TOFU is used,
//! similarly to Gemini", so the two protocols share one trust seam, and a
//! host that installs a [`TofuStore`](gemini_protocol::TofuStore) has
//! installed it for both.
//!
//! ## Not implemented
//!
//! A listener or TLS/certificate owner; client certificates (the spec's misfin-certificate convention
//! included); and the inline-markup exception for toggles between two
//! **non-ASCII** symbols, which needs Unicode category tables this crate does
//! not carry — the ASCII cases are honoured and the limitation is recorded on
//! [`scrolltext::spans`].

#![forbid(unsafe_code)]

pub mod scrolltext;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub use scrolltext::{Polarity, Relation, ScrollLine, Span, SpanKind, spans};
pub use wire::{
    DEFAULT_PORT, Header, MalformedHeader, MalformedReply, Reply, Request, ResponseLimits, Status,
    SuccessHeader, UdcClass, finish_success, parse_request, parse_status_line, request_line,
};

#[cfg(feature = "client")]
pub use client::{ClientError, FetchOptions, Response, exchange, exchange_with_options};

#[cfg(feature = "tls")]
pub use client::{fetch, fetch_with_options};
