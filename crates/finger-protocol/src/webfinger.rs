//! WebFinger (RFC 7033), the successor that honours finger by name.
//!
//! Where finger returned whatever text a host felt like printing, WebFinger
//! returns a **JSON Resource Descriptor**: a subject, its aliases, and a list
//! of typed links. It is what resolves `@alice@example.social` on the
//! fediverse, and it is the discovery step in OpenID Connect.
//!
//! ## What this module does and does not do
//!
//! WebFinger rides on HTTPS, and this crate does not contain an HTTP client.
//! It implements the two spec-shaped halves and leaves the GET to the caller,
//! who almost certainly has an HTTP stack already:
//!
//! - [`request_url`] builds the well-known URI, with the resource and any
//!   `rel` filters correctly encoded;
//! - [`parse`] reads the JRD that comes back.
//!
//! Perform the request with `Accept: application/jrd+json` ([`MEDIA_TYPE`]).
//!
//! ```
//! use finger_protocol::webfinger::{acct, request_url, parse};
//!
//! let url = request_url("example.social", &acct("alice", "example.social"), &["self"]);
//! assert_eq!(
//!     url,
//!     "https://example.social/.well-known/webfinger\
//!      ?resource=acct%3Aalice%40example.social&rel=self"
//! );
//!
//! // ... GET that URL, then:
//! let jrd = parse(r#"{"subject":"acct:alice@example.social",
//!     "links":[{"rel":"self","type":"application/activity+json",
//!               "href":"https://example.social/users/alice"}]}"#).unwrap();
//! assert_eq!(jrd.link("self").unwrap().href.as_deref(),
//!            Some("https://example.social/users/alice"));
//! ```

use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};

/// The media type of a JRD document, for the request's `Accept` header.
pub const MEDIA_TYPE: &str = "application/jrd+json";

/// The path every WebFinger query is served from.
pub const WELL_KNOWN_PATH: &str = "/.well-known/webfinger";

/// Everything outside RFC 3986's unreserved set is encoded, so `acct:` and its
/// `@` become `%3A` and `%40` the way RFC 7033's own examples show.
const RESOURCE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Build an `acct:` URI (RFC 7565), the usual way to name a person.
///
/// ```
/// assert_eq!(finger_protocol::webfinger::acct("bob", "example.com"),
///            "acct:bob@example.com");
/// ```
pub fn acct(user: &str, host: &str) -> String {
    format!("acct:{user}@{host}")
}

/// Build the WebFinger request URL for a resource at a host.
///
/// `rels` filters the response to the named link relations; an empty slice
/// asks for everything. A server may ignore the filter, so a caller must not
/// assume the absence of a link means the absence of the relation.
pub fn request_url(host: &str, resource: &str, rels: &[&str]) -> String {
    let mut url = format!(
        "https://{host}{WELL_KNOWN_PATH}?resource={}",
        utf8_percent_encode(resource, RESOURCE)
    );
    for rel in rels {
        url.push_str("&rel=");
        url.push_str(&utf8_percent_encode(rel, RESOURCE).to_string());
    }
    url
}

/// A JSON Resource Descriptor: WebFinger's answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jrd {
    /// The URI of the entity described, which may differ from the one asked
    /// about (a server is allowed to answer about the canonical form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Other URIs that name the same entity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Name/value pairs about the subject. Values are nullable per the spec.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Option<String>>,
    /// The typed links, which are the point of the document.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<Link>,
}

impl Jrd {
    /// The first link with the given relation.
    pub fn link(&self, rel: &str) -> Option<&Link> {
        self.links.iter().find(|link| link.rel == rel)
    }

    /// Every link with the given relation, in document order.
    pub fn links_with(&self, rel: &str) -> impl Iterator<Item = &Link> {
        self.links.iter().filter(move |link| link.rel == rel)
    }
}

/// One link relation in a [`Jrd`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// The relation type: a registered name or a URI. The only required field.
    pub rel: String,
    /// The media type of the target.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// The target URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// A URI template, used instead of `href` when the target is
    /// parameterised (OpenID Connect issuer discovery does this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Human-readable titles, keyed by language tag (or `und`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub titles: BTreeMap<String, String>,
    /// Name/value pairs about this link. Values are nullable per the spec.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Option<String>>,
}

/// Parse a JRD document.
pub fn parse(json: &str) -> Result<Jrd, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The example from RFC 7033 section 3.1, trimmed.
    const CAROL: &str = r#"{
      "subject" : "acct:carol@example.com",
      "aliases" : ["https://example.com/~carol/"],
      "properties" : { "http://example.com/ns/role" : "employee", "http://x/nil" : null },
      "links" : [
        { "rel" : "http://webfinger.example/rel/profile-page",
          "href" : "https://www.example.com/~carol/" },
        { "rel" : "self", "type" : "application/activity+json",
          "href" : "https://example.com/users/carol",
          "titles" : { "en-us" : "Carol" } }
      ]
    }"#;

    #[test]
    fn an_account_uri_is_built_per_rfc_7565() {
        assert_eq!(acct("bob", "example.com"), "acct:bob@example.com");
    }

    #[test]
    fn the_resource_is_encoded_the_way_the_rfc_shows() {
        let url = request_url("example.com", &acct("carol", "example.com"), &[]);
        assert_eq!(
            url,
            "https://example.com/.well-known/webfinger?resource=acct%3Acarol%40example.com"
        );
    }

    #[test]
    fn rel_filters_append_in_order() {
        let url = request_url("example.com", "acct:a@b", &["self", "http://x/y"]);
        assert!(
            url.ends_with("&rel=self&rel=http%3A%2F%2Fx%2Fy"),
            "got {url}"
        );
    }

    #[test]
    fn a_jrd_round_trips_its_subject_aliases_and_links() {
        let jrd = parse(CAROL).unwrap();
        assert_eq!(jrd.subject.as_deref(), Some("acct:carol@example.com"));
        assert_eq!(jrd.aliases, vec!["https://example.com/~carol/"]);
        assert_eq!(jrd.links.len(), 2);
    }

    #[test]
    fn a_link_is_found_by_relation_with_its_media_type() {
        let jrd = parse(CAROL).unwrap();
        let this = jrd.link("self").unwrap();
        assert_eq!(
            this.media_type.as_deref(),
            Some("application/activity+json")
        );
        assert_eq!(
            this.href.as_deref(),
            Some("https://example.com/users/carol")
        );
        assert_eq!(this.titles.get("en-us").map(String::as_str), Some("Carol"));
    }

    #[test]
    fn a_null_property_survives_as_a_present_key() {
        let jrd = parse(CAROL).unwrap();
        assert_eq!(jrd.properties.get("http://x/nil"), Some(&None));
        assert_eq!(
            jrd.properties.get("http://example.com/ns/role"),
            Some(&Some("employee".to_string()))
        );
    }

    #[test]
    fn a_minimal_jrd_needs_only_links() {
        let jrd = parse(r#"{"links":[{"rel":"self"}]}"#).unwrap();
        assert_eq!(jrd.subject, None);
        assert!(jrd.aliases.is_empty());
        assert_eq!(jrd.links[0].rel, "self");
    }

    #[test]
    fn a_link_without_a_rel_is_rejected() {
        assert!(parse(r#"{"links":[{"href":"https://x/"}]}"#).is_err());
    }
}
