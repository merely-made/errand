//! # dict-protocol
//!
//! An implementation of [DICT](https://www.rfc-editor.org/rfc/rfc2229.html)
//! (RFC 2229, `dict://`, port 2628): look a word up in networked
//! dictionaries.
//!
//! ## It is not shaped like the rest of the small web
//!
//! Gemini and gopher answer one request and close. DICT is a **command loop**:
//! the server greets you, you issue commands, and the connection stays open
//! until `QUIT`. It is far closer to SMTP or NNTP, which is why the client
//! here is a [`Session`](client::Session) you hold rather than a function you
//! call. Hiding that behind a one-shot fetch would mean reconnecting per word,
//! which is the exact cost a command loop exists to avoid.
//!
//! Two details bite implementations that skim the RFC, and both are handled:
//!
//! - **Parameters are quoted.** Database descriptions contain spaces, so
//!   splitting a response on whitespace shreds them.
//! - **Text blocks are dot-stuffed.** A line whose first character is `.` is
//!   sent doubled, so a client that forgets to undo it corrupts any definition
//!   beginning with a period.
//!
//! Looking a word up is [`Session::define`](client::Session::define),
//! documented on that module so the example stays honest when the `client`
//! feature is off.
//!
//! ## Not implemented
//!
//! A server, and the optional `AUTH`/`SASLAUTH` and `OPTION MIME` extensions.
//! `SHOW INFO`, `SHOW SERVER`, `STATUS` and `HELP` are reachable through
//! [`Session::command`](client::Session::command), which returns the raw
//! status.

#![forbid(unsafe_code)]

pub mod wire;

#[cfg(feature = "client")]
pub mod client;

pub use wire::{
    DEFAULT_PORT, Database, Definition, MAX_LINE, Match, Status, is_terminator, parse_databases,
    parse_matches, parse_status, split_params, stuff, unstuff,
};

#[cfg(feature = "client")]
pub use client::{ClientError, Limits, Session};
