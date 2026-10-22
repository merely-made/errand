// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The gopher protocol (`gopher://`, port 70), via the
//! [`gopher-protocol`](https://crates.io/crates/gopher-protocol) crate.
//!
//! That crate owns the transaction and the RFC 1436 grammar, including the
//! Gopher+ successor; this module maps its reply onto errand's [`Response`].
//! Gopher has no status line, so every reply is a [`Status::Success`] whose
//! MIME the item type implies.

use url::Url;

use crate::{Error, Response, Status};

/// Fetch a `gopher://` URL.
pub(crate) async fn fetch(url: &Url, options: &crate::FetchOptions) -> Result<Response, Error> {
    let reply = gopher_protocol::fetch_with_options(url.as_str(), &native_options(options))
        .await
        .map_err(map_error)?;
    Ok(Response {
        url: url.clone(),
        status: Status::Success,
        raw_status: None,
        meta: reply.mime,
        body: reply.body,
    })
}

fn map_error(error: gopher_protocol::ClientError) -> Error {
    use gopher_protocol::ClientError as Gopher;
    match error {
        Gopher::BadUrl(message) => Error::BadUrl(message),
        Gopher::Connect(message) => Error::Connect(message),
        Gopher::Io(message) => Error::Io(message),
        Gopher::Timeout => Error::Timeout,
        Gopher::Protocol(message) => Error::Protocol(message),
        // Gopher+ transactions are not on errand's fetch path, so these two
        // cannot arise here; mapping them to Protocol keeps the match total
        // without inventing a status.
        Gopher::BadPlusHeader(message) | Gopher::PlusError(message) => Error::Protocol(message),
    }
}

pub(crate) fn native_options(
    options: &crate::FetchOptions,
) -> gopher_protocol::client::FetchOptions {
    gopher_protocol::client::FetchOptions {
        timeout: options.timeout,
        max_request_bytes: options.max_request_bytes,
        max_header_line_bytes: options.max_header_line_bytes,
        max_body_bytes: options.max_body_bytes,
    }
}
