// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The spartan protocol (`spartan://`, port 300), via the
//! [`spartan-protocol`](https://crates.io/crates/spartan-protocol) crate.
//!
//! Spartan is gemini's plaintext cousin: `<host> <path> <length>\r\n`
//! answered by a single-digit `<code> <meta>\r\n` header (2 success,
//! 3 redirect, 4 client error, 5 server error) and a body. The crate owns
//! the transaction, including the spec's URL mapping (IDN → punycode, a URL
//! query %-decodes into the upload data block); this module maps its
//! response onto errand's [`Response`].

use url::Url;

use crate::{Error, Response, Status};

/// Fetch a `spartan://` URL.
pub(crate) async fn fetch(url: &Url, options: &crate::FetchOptions) -> Result<Response, Error> {
    let response = spartan_protocol::fetch(url.as_str(), &native_options(options))
        .await
        .map_err(map_error)?;
    Ok(map_response(url, response))
}

/// Submit `body` as the data block requested by a Spartan `=:` prompt.
pub async fn submit(url: &Url, body: &[u8]) -> Result<Response, Error> {
    let defaults = crate::FetchOptions::default();
    let max_request_bytes = body
        .len()
        .checked_add(defaults.max_request_bytes)
        .ok_or_else(|| Error::Protocol("Spartan request size overflows".into()))?;
    submit_with_options(
        url,
        body,
        &crate::FetchOptions {
            max_request_bytes,
            ..defaults
        },
    )
    .await
}

/// Explicit submission with caller-owned request and response bounds.
pub async fn submit_with_options(
    url: &Url,
    body: &[u8],
    options: &crate::FetchOptions,
) -> Result<Response, Error> {
    if url.scheme() != "spartan" {
        return Err(Error::UnsupportedScheme(url.scheme().to_string()));
    }
    let response = spartan_protocol::submit(url.as_str(), body, &native_options(options))
        .await
        .map_err(map_error)?;
    Ok(map_response(url, response))
}

fn map_response(url: &Url, response: spartan_protocol::Response) -> Response {
    use spartan_protocol::Status as Spartan;
    let status = match response.status {
        Spartan::Success => Status::Success,
        Spartan::Redirect => Status::Redirect,
        Spartan::ClientError | Spartan::ServerError => Status::Failure,
    };
    Response {
        url: url.clone(),
        status,
        raw_status: Some(response.status.code()),
        meta: response.meta,
        body: response.body,
    }
}

fn map_error(error: spartan_protocol::ClientError) -> Error {
    use spartan_protocol::ClientError as Spartan;
    match error {
        Spartan::BadUrl(message) => Error::BadUrl(message),
        Spartan::Io(message) => Error::Io(message),
        Spartan::Timeout(_) => Error::Timeout,
        Spartan::Protocol(message) => Error::Protocol(message),
        Spartan::BodyTooLarge { max } => {
            Error::Protocol(format!("spartan response exceeds {max} bytes"))
        }
    }
}

fn native_options(options: &crate::FetchOptions) -> spartan_protocol::FetchOptions {
    spartan_protocol::FetchOptions {
        timeout: options.timeout,
        max_request_bytes: options.max_request_bytes,
        max_body: options.max_body_bytes,
        max_header_line_bytes: options.max_header_line_bytes,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scheme;

    fn u() -> Url {
        Url::parse("spartan://example.org/").unwrap()
    }

    #[test]
    fn success_carries_mime_and_body() {
        let r = map_response(
            &u(),
            spartan_protocol::Response {
                status: spartan_protocol::Status::Success,
                meta: "text/gemini".to_string(),
                body: b"# Hi\n".to_vec(),
            },
        );
        assert_eq!(r.status, Status::Success);
        assert_eq!(r.raw_status, Some(2));
        assert_eq!(r.mime(), Some("text/gemini"));
        assert_eq!(r.body, b"# Hi\n");
    }

    #[test]
    fn redirects_and_errors_map_with_their_digit() {
        let redirect = map_response(
            &u(),
            spartan_protocol::Response {
                status: spartan_protocol::Status::Redirect,
                meta: "/elsewhere".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(redirect.status, Status::Redirect);
        assert_eq!(redirect.raw_status, Some(3));
        assert_eq!(redirect.meta, "/elsewhere");

        let client_error = map_response(
            &u(),
            spartan_protocol::Response {
                status: spartan_protocol::Status::ClientError,
                meta: "bad request".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(client_error.status, Status::Failure);
        assert_eq!(client_error.raw_status, Some(4));

        let server_error = map_response(
            &u(),
            spartan_protocol::Response {
                status: spartan_protocol::Status::ServerError,
                meta: "boom".to_string(),
                body: Vec::new(),
            },
        );
        assert_eq!(server_error.status, Status::Failure);
        assert_eq!(server_error.raw_status, Some(5));
    }

    #[test]
    fn spartan_scheme_routes_to_port_300() {
        assert_eq!(Scheme::Spartan.default_port(), 300);
    }
}
