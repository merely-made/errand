<!-- SPDX-License-Identifier: MPL-2.0 -->
# errand

Async smolweb transport in one scheme-routed call.

> **Home:** [`merely-made/errand`](https://github.com/merely-made/errand),
> alongside the protocol crates in the continuing Smolweb repository.

The spec-faithful protocol crates ([`nex-protocol`](https://crates.io/crates/nex-protocol),
[`spartan-protocol`](https://crates.io/crates/spartan-protocol),
[`guppy-protocol`](https://crates.io/crates/guppy-protocol)) live in this
subtree as workspace members, each keeping its own published identity.

`errand` fetches a URL over a small-web protocol and hands back the raw bytes, a
normalized status, and a MIME hint. One call, routed by scheme:

```rust
let page = errand::fetch("gemini://geminiprotocol.net/").await?;
if page.status == errand::Status::Success {
    println!("{} bytes of {}", page.body.len(), page.mime().unwrap_or("?"));
}
```

It does not speak HTTP, on purpose. HTTP is already well served by `reqwest`, and
a browser-extension host gets HTTP from the browser. `errand` covers the gap they
leave: the protocols of the small web, with a small dependency cone.

**Made with AI**

## Protocols

`errand::fetch` routes by URL scheme and returns a normalized `Status`, the
protocol `meta` line, and the raw body. It does not follow redirects; the caller
decides. Eight schemes are routed through `fetch`:

| Scheme      | Port | Transport          | Notes                                  |
|-------------|------|--------------------|----------------------------------------|
| `gemini://` | 1965 | TLS (TOFU)         | self-signed capsules, per-host pinning |
| `gopher://` | 70   | plaintext TCP      | no status code                         |
| `finger://` | 79   | plaintext TCP      | no status code                         |
| `spartan://`| 300  | plaintext TCP      | numeric status                         |
| `nex://`    | 1900 | plaintext TCP      | no status code                         |
| `guppy://`  | 6775 | UDP (stop-and-wait)| numeric status, ACK-per-packet         |
| `scroll://` | 5699 | TLS (TOFU) | native language and metadata API |
| `titan://`  | 1965 | TLS (TOFU)         | gemini's upload sibling; see below     |

### Write companions

Two schemes write rather than fetch, so they are direct calls, not part of
`fetch`:

- `titan_upload` — Titan (`titan://`, port 1965) is gemini's upload sibling.
  Call it with the body bytes, MIME type, and an optional token. A bare
  `titan://` URL passed to `fetch` sends a zero-byte upload and returns the
  server's gemini-format response (typically a redirect to the read location).
- `misfin_send` — Misfin (`misfin://`, port 1958) is gemini-style peer-to-peer
  mail. Delivery opens a TLS connection presenting a caller-supplied client
  certificate (`ClientIdentity`) and writes a `misfin://<mailbox>@<host>
  <message>` request line. `errand` owns only the client send side; it does not
  generate, store, or rotate certificates, and it does not serve a mailbox.

## API

- `fetch(url: &str)` / `fetch_url(url: &Url)` — fetch over the URL's scheme.
- `fetch_timeout(url, Duration)` / `fetch_url_timeout(url, Duration)` — the same
  with a per-request timeout; returns `Error::Timeout` if it does not complete.
- `titan_upload(...)` — Titan write.
- `misfin_send(...)` with `ClientIdentity` and `MISFIN_PORT` — Misfin mail send.
- `set_trust_store`, `TofuStore`, `InMemoryTofu`, `PermissiveTofu` — TOFU trust
  policy (see below).
- `Scheme` — the routable scheme enum, with `Scheme::parse(&str)` and
  `default_port()`.
- `Response { url, status, raw_status, meta, body }` with `.mime()`.
- `Status` — `Success`, `Input`, `Redirect`, `Failure`, `CertRequired`.
- `Error` — `UnsupportedScheme`, `BadUrl`, `Connect`, `Io`, `Protocol`,
  `Timeout`, `CertificateChanged { host, pinned, seen }`.
- `Url` re-exported from the `url` crate.

`Response::raw_status` preserves the protocol's own two-digit code for the
schemes that have one (gemini, spartan, guppy, titan); it is `None` for gopher,
finger, and nex, which carry no status.

## Caller limits

Errand fetch wrappers use bounded composition defaults. Existing finite native
convenience defaults (Nex/Spartan/Guppy and legacy Titan: 16 MiB) remain intact;
Errand explicitly supplies its 64 MiB response policy through the new options.
`FetchOptions` supplies
`timeout` (30 seconds for the whole DNS/connect/TLS/exchange),
`max_request_bytes` (4096), `max_header_line_bytes` (4096 per wire line including
CRLF), and `max_body_bytes` (64 MiB of response content). Gemini and Titan retain
native 1024-byte request-line and response-header ceilings even when the caller
chooses larger budgets. Scroll permits a larger configured metadata-line budget;
its four native success-header lines retain dates and author verbatim. Headerless
protocols ignore the header setting. Guppy counts each sequence once and checks
its reassembly budget before accepting/acknowledging new data.

Use `fetch_with_options`, `fetch_url_with_options`, or
`fetch_url_with_identity_and_options` (an optional Gemini identity). Streaming
callers use `fetch_gemini_url_streaming_with_options` or
`fetch_gemini_url_streaming_with_identity_and_options`; overflowing bytes never
reach the callback or returned body. Exact caps succeed; overflow is an error,
never a successful truncated document. Redirect decisions and a deadline across
multiple fetches remain with the host. Existing `*_timeout` helpers replace the
default timeout without silently imposing a second 30-second deadline.

`scroll_fetch_with_options` keeps the native language/abstract/metadata API.
`spartan_submit_with_options`, `titan_upload_with_options`, and
`titan_upload_with_identity_and_options` are explicit write operations. Their
request budget counts the full wire request including payload, independently of
the response body budget. Legacy explicit upload/submit wrappers allow the
already caller-owned payload plus their default line allowance and still bound
the response and whole operation. Passing Titan to generic fetch retains its
existing zero-byte upload behavior; callers remain responsible for requiring
explicit Submit and guarding redirects into write schemes. Misfin mail and the
standalone DICT/FSP/Kepler/Text client families have separate native policies.

```rust
let limits = errand::FetchOptions {
    max_body_bytes: 2 * 1024 * 1024,
    ..Default::default()
};
let page = errand::fetch_with_options("scroll://example.net/", &limits).await?;
```

## Trust (TOFU)

Gemini capsules are conventionally self-signed, so there is no CA to anchor
trust. `errand` pins the SHA-256 of a host's leaf certificate on first contact
and requires every later visit to present the same one. A changed certificate (a
man-in-the-middle, a key rotation, or a moved host) surfaces as
`Error::CertificateChanged` and the request is not sent; the embedder decides
whether to re-pin.

The pin store is the `TofuStore` trait, so the embedder chooses durability.
`InMemoryTofu` holds pins for the process lifetime. A host with a profile can
supply its own durable store. The store is installed once via `set_trust_store`;
until then `errand` uses `PermissiveTofu` (accept-any), so the module changes
nothing for callers that do not opt in.

## Install

```toml
[dependencies]
errand = "0.1"
```

Or as a git dependency:

```toml
[dependencies]
errand = { git = "https://github.com/mark-ik/errand" }
```

## Build and test

```sh
cargo build
cargo test
```

Tests are inline `#[cfg(test)]` modules (request construction, scheme routing,
status mapping). Loopback integration tests cover routed limits without public network access.

## Dependencies and platform

- `url` 2.5
- `tokio` 1 (features `net`, `io-util`, `time`; no full runtime)
- `rustls` 0.23 and `tokio-rustls` 0.26 on the `ring` provider, with `tls12`
- `ring` 0.17 for leaf-certificate SHA-256 (TOFU pinning)

`aws-lc-rs` is deliberately left off so the crate builds without a C toolchain.
Edition 2021, MSRV (`rust-version`) 1.74.

## Status

Version 0.1.0. Single crate, no workspace. Consumed one-way as a git dependency
by the broader Mere stack: the fetch actor routes `http(s)` to `netfetcher` and
the smolweb schemes here to `errand`, and the Misfin mail crate uses `errand` as
its client send transport. Dependency direction is one-way (consumers pull
`errand`, never the reverse).

## License

MPL-2.0. See `LICENSE`.
