# gopher-protocol

An implementation of [Gopher](https://datatracker.ietf.org/doc/html/rfc1436)
(`gopher://`, port 70) and its [Gopher+](https://github.com/gopher-protocol/gopher-plus)
successor in Rust: an async client, an RFC 1436 menu parser with RFC 4266 URL
synthesis, and the Gopher+ attribute, view, and form model.

This is not the reference implementation of Gopher, and it does not speak for
the protocol's community.

## Gopher+

Gopher+ (1993) is an upward-compatible superset, so it is not a separate
protocol here: a plain RFC 1436 menu just has no Gopher+ markers on its items.
What it adds is a response header carrying a real length, attribute blocks
(`+INFO`, `+ADMIN`, `+VIEWS`) that describe an item without fetching it,
alternate representations, and `+ASK` forms for interactive queries.

Gopher-II (the [later draft](https://datatracker.ietf.org/doc/html/draft-matavka-gopher-ii-02))
is not implemented.

## Two halves, separately usable

The parsers have no dependencies and are always compiled, Gopher+ included.
A consumer that only renders gophermaps takes the crate without the client and
pulls no async runtime:

```toml
gopher-protocol = { version = "0.2", default-features = false }
```

The client rides the default `client` feature, and a **server** rides the
off-by-default `server` feature: it reads all three request fields, so one
handler answers both RFC 1436 and Gopher+ callers, and the Gopher+ length
header is written for you.

The server admits at most 32 connection tasks by default (`ServerConfig`
`max_connections`), and allows five seconds to finish admitted work after
shutdown (`shutdown_grace`). Both settings are configurable; the limit must be
nonzero and a zero grace means immediate abort. At capacity the listener pauses
accepting, leaving pending peers to the operating-system backlog. Signal
shutdown and await `serve` to close the listener, drain against one fixed grace
deadline, then abort and join remaining tasks. Dropping `serve` requests
cancellation of its owned tasks but cannot await their joins; handler side
effects already performed synchronously are not rolled back.

Gopher request parsing and response framing remain native: a Gopher+ request
still receives its counted `+<length>` header, while an ordinary request gets
the handler bytes without a status line.

## Example

```rust,no_run
# async fn run() -> Result<(), gopher_protocol::ClientError> {
let reply = gopher_protocol::fetch("gopher://gopher.floodgap.com/1/").await?;
for item in gopher_protocol::parse_menu(&String::from_utf8_lossy(&reply.body)) {
    println!("{:?} {}", item.kind, item.display);
}
# Ok(())
# }
```

## Scope

A client and a parser. It does not serve gopher, and it holds no document or
render model: how a `Search` or `Image` item should look is the consumer's
decision.

Gopher carries no status line and no MIME type, so `Response::mime` is a
best-effort inference from the item type, documented as a client convention
rather than part of the RFC.

## License

MIT.

## Client bounds

Client operations have a 30-second whole-operation deadline, including connection
setup, and a 64 MiB response-body default. Overflow returns an error rather than
a truncated success. Bounds are enforced before body append. No runtime is added to the dependency-free grammar feature.

`client::FetchOptions` supplies `timeout`, `max_request_bytes`,
`max_header_line_bytes`, and `max_body_bytes`. `fetch_with_options`,
`fetch_plus_with_options`, `fetch_attributes_with_options`, and
`fetch_directory_attributes_with_options` retain native Gopher+ headers and
attributes. Defaults are 4096 request/header-line bytes including line endings.
Counted Gopher+ replies reject lengths above the body cap and premature EOF.
For period-terminated replies the wire body, including the terminator, is bounded
before removing the terminator. Plain Gopher has no response header.
