//! # gopher-protocol
//!
//! An implementation of [Gopher](https://datatracker.ietf.org/doc/html/rfc1436)
//! (`gopher://`, port 70) and its **Gopher+** successor: an async client, a
//! menu parser, and the Gopher+ attribute, view, and form model.
//!
//! Gopher is the elder smolweb protocol. A request is a selector and a CRLF; a
//! reply is a body with no status line and no MIME type. The item-type
//! character carried in the URL path is the only hint about what the bytes are,
//! which is why this crate reports a best-effort MIME rather than inventing a
//! status the protocol does not have.
//!
//! ## Gopher+
//!
//! [Gopher+](https://github.com/gopher-protocol/gopher-plus) (1993) is an
//! upward-compatible superset, and this crate treats it as one rather than as a
//! separate protocol: a plain RFC 1436 menu simply has no
//! [`GopherPlus`](menu::GopherPlus) markers on its items. Gopher+ adds a
//! response header carrying a real length, attribute blocks describing an item
//! without fetching it, alternate representations, and `+ASK` forms. See
//! [`plus`], and [`client::fetch_plus`] to run a Gopher+ transaction.
//!
//! ## Two halves, separately usable
//!
//! [`menu`] parses RFC 1436 menus into typed items with RFC 4266 URLs, and
//! [`plus`] parses everything Gopher+ adds. Both have no dependencies and are
//! always compiled, so a consumer that only renders gophermaps can take this
//! crate with `default-features = false` and pull no async runtime:
//!
//! ```toml
//! gopher-protocol = { version = "0.1", default-features = false }
//! ```
//!
//! [`client`] fetches over TCP and rides the default `client` feature.
//!
//! ## Parsing a menu
//!
//! ```
//! let menu = "1Software\t/software\tgopher.example\t70\r\niA note\t\t\t\r\n";
//! let items = gopher_protocol::parse_menu(menu);
//!
//! assert_eq!(items[0].url.as_deref(), Some("gopher://gopher.example/1/software"));
//! assert_eq!(items[1].kind, gopher_protocol::GopherKind::Info);
//! assert!(items[1].url.is_none(), "info lines carry no resource");
//! ```
//!
//! Fetching is [`client::fetch`], documented on that module so this example
//! stays honest under `default-features = false`.
//!
//! ## Scope
//!
//! This crate is a client and a parser. It does not serve gopher, and it holds
//! no document or render model: what a `Search` item or an `Image` item should
//! look like on screen is the consumer's decision.

#![forbid(unsafe_code)]

pub mod menu;
pub mod plus;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "tls")]
mod tls;

pub use menu::{GopherItem, GopherKind, GopherPlus, parse as parse_menu};
pub use plus::{AskDirective, AttributeBlock, PlusHeader, PlusRequest, View};

#[cfg(feature = "server")]
pub use server::{ServerConfig, serve};

#[cfg(feature = "client")]
pub use client::{
    ClientError, DEFAULT_PORT, FetchOptions, PlusReply, Response, fetch, fetch_attributes,
    fetch_attributes_with_options, fetch_directory_attributes,
    fetch_directory_attributes_with_options, fetch_plus, fetch_plus_with_options,
    fetch_with_options, mime_for_item_type,
};
