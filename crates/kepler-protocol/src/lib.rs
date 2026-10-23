//! # kepler-protocol
//!
//! An implementation of [Kepler](https://github.com/kevinboone/kepler-protocol)
//! (`kepler://` on port 2009, `keplers://` on port 10009).
//!
//! Kepler is, in its author's words, "an incremental improvement over Gemini,
//! as Gemini is an incremental improvement over Gopher". The improvement is
//! **caching**, and it is the only cache model anywhere in the small-web
//! family:
//!
//! - the request carries the epoch second of the copy you already hold, plus
//!   the languages you can read;
//! - a `2x` response declares the body's **length**, when it was **last
//!   updated**, and when it **expires**;
//! - a `7x` response says *nothing has changed*, and carries no body at all.
//!
//! Two consequences fall out of that and are worth knowing. A body's end is
//! **declared rather than implied by the connection closing**, unlike gemini
//! and gopher, so a truncated transfer is detectable. And encryption is
//! **optional**: `kepler://` is plaintext, `keplers://` is TLS, and which you
//! get is the scheme's choice rather than the protocol's.
//!
//! ## Layers
//!
//! | Layer | Feature | Pulls |
//! |---|---|---|
//! | [`wire`] grammar | always on | nothing |
//! | [`client`] | `client` *(default)* | tokio, url |
//! | `keplers://` | `tls` | rustls |
//!
//! ```
//! use kepler_protocol::{Header, parse_header};
//!
//! // The specification's own example.
//! let header = parse_header("20 1548 1777745482 1777759482 text/markdown").unwrap();
//! let Header::Success { cache, mimetype, .. } = header else { unreachable!() };
//!
//! assert_eq!(cache.length, 1548);
//! assert_eq!(mimetype, "text/markdown");
//! ```
//!
//! ## Not implemented
//!
//! A server. The client and the grammar are here; serving kepler is additive
//! and simply has not been written.

#![forbid(unsafe_code)]

pub mod wire;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "tls")]
mod tls;

pub use wire::{
    CacheInfo, Header, MAX_URI, MalformedHeader, Request, Status, format_header, parse_header,
    parse_request, request_line,
};

#[cfg(feature = "client")]
pub use client::{
    ClientError, DEFAULT_PORT, DEFAULT_TLS_PORT, Limits, Response, exchange, exchange_with_limits,
    fetch, fetch_with_limits,
};

#[cfg(all(test, feature = "client"))]
mod limits_tests;
