# finger-protocol

Finger ([RFC 1288](https://datatracker.ietf.org/doc/html/rfc1288), port 79) and
its successor WebFinger
([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033.html)), in Rust.

Both answer the same question, thirty years apart: who is this person? Finger
answers with whatever text the host felt like printing. WebFinger answers with
a JSON Resource Descriptor, which is why it, and not finger, is what resolves
`@alice@example.social` on the fediverse.

This is not the reference implementation of either, and it does not speak for
their communities.

## Two protocols, two features

| | Feature | Pulls |
|---|---|---|
| Finger, RFC 1288 | `client` | tokio, url |
| Finger, serving | `server` *(off by default)* | tokio, log |
| WebFinger, RFC 7033 | `webfinger` | serde, serde_json, percent-encoding |

Both are on by default. Take `default-features = false` with just one when the
other is dead weight.

## WebFinger without an HTTP client

WebFinger rides on HTTPS, and this crate deliberately contains no HTTP stack.
It implements the two spec-shaped halves and leaves the GET to you, since you
already have an HTTP client and opinions about timeouts, redirects, and TLS:

```rust
use finger_protocol::webfinger::{acct, request_url, parse, MEDIA_TYPE};

let url = request_url("example.social", &acct("alice", "example.social"), &["self"]);
// GET `url` with `Accept: MEDIA_TYPE`, then:
# let body = r#"{"links":[{"rel":"self","href":"https://example.social/users/alice"}]}"#;
let jrd = parse(body).unwrap();
let profile = jrd.link("self").and_then(|l| l.href.as_deref());
```

## Fingering a host

```rust,no_run
# async fn run() -> Result<(), finger_protocol::ClientError> {
let reply = finger_protocol::fetch("finger://example.org/alice").await?;
println!("{}", reply.text());
# Ok(())
# }
```

Both `finger://host/user` and `finger://user@host` name a user; a bare
`finger://host/` asks for the listing. RFC 1288's `/W` switch is available via
`Query::verbose`.

## License

MIT.

## Client bounds

Client operations have a 30-second whole-operation deadline, including connection
setup, and a 64 MiB response-body default. Overflow returns an error rather than
a truncated success. Bounds are enforced before body append. No runtime is added to the dependency-free grammar feature.

`client::FetchOptions` supplies `timeout`, `max_request_bytes`,
`max_header_line_bytes`, and `max_body_bytes`. `fetch_with_options` and
`query_with_options` retain the native Query API. Requests default to 4096 wire
bytes including CRLF; Finger has no response header and ignores that setting.
