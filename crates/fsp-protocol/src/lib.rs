//! # fsp-protocol
//!
//! An implementation of [FSP](https://fsp.sourceforge.net/) (File Service
//! Protocol, `fsp://`, port 21): anonymous file transfer over UDP.
//!
//! FSP is the outlier of the small-web family. Everything else here is a TCP
//! stream; FSP is **UDP with its own reliability**, and it is deliberately
//! simple enough to run without a transport at all. The header carries both a
//! checksum and a payload size, so, in the specification's words, it "can be
//! used as very simple raw-protocol (for example for sending data over serial
//! line). This makes it very popular in embedded devices area."
//!
//! ## The detail that breaks implementations
//!
//! **The checksum is computed differently in each direction.** Server to
//! client starts from zero; client to server starts from the packet's own
//! size. Get it wrong and every packet you send is rejected while every packet
//! you receive validates, which reads like a network fault rather than a bug.
//! See [`wire::checksum`].
//!
//! ## Layers
//!
//! | Layer | Feature | Pulls |
//! |---|---|---|
//! | [`wire`] format | always on | nothing |
//! | [`client`] | `client` *(default)* | tokio |
//!
//! Fetching is [`client::Session::get_file`], documented on that module so the
//! example stays honest when the `client` feature is off.
//!
//! ## Not implemented
//!
//! The write half (`CC_UP_LOAD`, `CC_INSTALL`, `CC_DEL_FILE`, `CC_MAKE_DIR`
//! and friends), password protection, and a server. Every command code is
//! defined in [`wire::Command`] and [`client::Session::request`] will send any
//! of them, so the wire work is done even where a convenience method is not.

#![forbid(unsafe_code)]

pub mod wire;

#[cfg(feature = "client")]
pub mod client;

pub use wire::{
    Command, DEFAULT_PORT, DecodeError, DirEntry, Direction, DirectoryBlock,
    DirectoryLimitExceeded, EntryKind, HEADER_LEN, Header, MAX_PAYLOAD, Packet, checksum, decode,
    encode, parse_directory, parse_directory_bounded,
};

#[cfg(feature = "client")]
pub use client::{ClientError, Limits, Session};
