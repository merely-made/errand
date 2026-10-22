//! # finger-protocol
//!
//! Finger ([RFC 1288](https://datatracker.ietf.org/doc/html/rfc1288), port 79)
//! and its successor WebFinger
//! ([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033.html)), which honours it
//! by name.
//!
//! Both answer the same question, thirty years apart: *who is this person?*
//! Finger answers with whatever text the host felt like printing. WebFinger
//! answers with a JSON Resource Descriptor, which is why it, and not finger,
//! is what resolves `@alice@example.social` on the fediverse.
//!
//! ## Two protocols, two features
//!
//! | | Module | Feature | Pulls |
//! |---|---|---|---|
//! | Finger, RFC 1288 | [`client`] | `client` | tokio, url |
//! | Finger, serving | [`server`] | `server` *(off)* | tokio, log |
//! | WebFinger, RFC 7033 | [`webfinger`] | `webfinger` | serde, serde_json, percent-encoding |
//!
//! Both are on by default. Take `default-features = false` with just one when
//! the other is dead weight.
//!
//! ## WebFinger without an HTTP client
//!
//! WebFinger rides on HTTPS and this crate deliberately contains no HTTP
//! stack: it builds the request URL and parses the response, and the GET
//! itself belongs to the caller, who already has an HTTP client and opinions
//! about timeouts, redirects, and TLS. See [`webfinger`].
//!
//! Fingering a host is [`client::fetch`], documented on that module so the
//! example stays honest when the `client` feature is off.

#![forbid(unsafe_code)]

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "webfinger")]
pub mod webfinger;

#[cfg(feature = "client")]
pub use client::{
    ClientError, DEFAULT_PORT, FetchOptions, Response, fetch, fetch_with_options, query,
    query_with_options,
};

#[cfg(feature = "server")]
pub use server::{ServerConfig, serve};
#[cfg(feature = "webfinger")]
pub use webfinger::{Jrd, Link, MEDIA_TYPE, acct, request_url};

/// One finger request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// The user to ask about. `None` requests the host's listing.
    pub user: Option<String>,
    /// RFC 1288's `/W` switch, asking the server for its longer answer. Servers
    /// are free to ignore it.
    pub verbose: bool,
}

impl Query {
    /// A query for one user.
    pub fn user(name: impl Into<String>) -> Self {
        Self {
            user: Some(name.into()),
            verbose: false,
        }
    }

    /// The same query with RFC 1288's `/W` switch set.
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// The wire form: `{W}{S}{U}{C}` in RFC 1288's grammar.
    ///
    /// ```
    /// use finger_protocol::Query;
    ///
    /// assert_eq!(Query::user("alice").wire(), "alice\r\n");
    /// assert_eq!(Query::user("alice").verbose().wire(), "/W alice\r\n");
    /// assert_eq!(Query::default().wire(), "\r\n");
    /// ```
    pub fn wire(&self) -> String {
        let user = self.user.as_deref().unwrap_or("");
        match (self.verbose, user.is_empty()) {
            (true, true) => "/W\r\n".to_string(),
            (true, false) => format!("/W {user}\r\n"),
            (false, _) => format!("{user}\r\n"),
        }
    }
}
