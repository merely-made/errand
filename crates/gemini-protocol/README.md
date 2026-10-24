# gemini-protocol

[Gemini](https://geminiprotocol.net/) (`gemini://`, port 1965) in Rust, with
the things its specification defines alongside it: the **gemtext** document
grammar, trust-on-first-use certificate pinning, and the **titan://** upload
companion.

They share a crate because they share a spec. Gemtext is not a separate format
that happens to travel over gemini; it is the format gemini defines, and titan
is the write half of the same document space.

This is not the reference implementation of Gemini, and it does not speak for
the protocol's community.

## Three layers, three costs

| Layer | Feature | Pulls | What it gives you |
|---|---|---|---|
| gemtext | always on | nothing | the document grammar |
| client | `client` | tokio, url | the exchange over *any* stream |
| fetch, TOFU, titan | `tls` *(default)* | rustls, ring | the ordinary internet client |
| serving | `server` *(off)* | rustls, log | accept TLS, answer requests |

The split is not ceremony. **Five other smolweb protocols serve `text/gemini`
bodies** (spartan, guppy, scroll, misfin, and titan itself), so the grammar is
the piece most consumers actually want, and it should never drag in a TLS
stack to get it:

```toml
gemini-protocol = { version = "0.1", default-features = false }
```

And the request/response is transport-independent, so gemini over an
already-encrypted carrier, such as a [Reticulum](https://reticulum.network/)
link where the destination hash *is* the peer identity and there is no
certificate to pin, wants `client` without `tls`.

## Trust is real TOFU

The host's pinned fingerprint is checked *during* the handshake, a first
contact is pinned once it completes, and a changed certificate surfaces as
`CertificateChanged` before the request is ever sent, so nothing is disclosed
to whoever answered. Install a store with `set_trust_store`; the default is
permissive, which is a deliberate choice a host must override rather than a
silent one.

## Status classes stay apart

Temporary (`4x`) and permanent (`5x`) failure are distinct, because retrying
one is reasonable and retrying the other is not. The literal two-digit code
stays on `Response::code`, since the second digit carries detail the class
does not.

## Known gap

The client can present a caller-selected identity and retains `6x` status facts.
The built-in server acceptor does not request client certificates; selecting
server authentication policy remains a separate hosting concern.

## Server lifecycle

With the `server` feature, `server::serve` takes a listener that the caller has
already bound and a caller-built TLS acceptor. `ServerConfig` defaults to at
most 32 accepted connections and a five-second graceful shutdown window. A zero
connection limit or an unrepresentable grace duration is rejected before the
server accepts a connection or calls its handler. At capacity, accepting pauses
and waiting peers remain subject to the operating system's listener backlog.

When the shutdown future resolves, the listener closes and admitted work may
finish until the single grace deadline. Remaining connection tasks are aborted
and joined. Signal shutdown and await `serve` for that joined guarantee; dropping
the `serve` future cancels its owned tasks but cannot await their termination.
Cancellation cannot undo synchronous side effects already performed by a
handler.

## License

MIT.

## Client bounds

Client operations have a 30-second whole-operation deadline, including connection
setup, and a 64 MiB response-body default. Overflow returns an error rather than
a truncated success. Bounds are enforced before body append (and before a Gemini
streaming callback). No runtime is added to the dependency-free grammar feature.

`client::FetchOptions` supplies `timeout`, `max_request_bytes`,
`max_header_line_bytes`, and `max_body_bytes`. `exchange_with_options`,
`exchange_streaming_with_options`, `client::fetch_url_with_options`, and
`client::fetch_url_streaming_with_options` retain native response and identity
types. Native request/header ceilings remain 1024 bytes including CRLF. Titan
`upload_with_fetch_options` also accepts these bounds; its request budget includes
the payload. Legacy Titan upload helpers allow the caller-owned payload plus the
native line allowance and retain their existing 16 MiB response default, plus
the whole-operation deadline.
