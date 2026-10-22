# scroll-protocol

An implementation of the Scroll protocol (`scroll://`, port 5699) and its
**scrolltext** document format (`text/scroll`), by Christian Lee Seibold, in
Rust.

This is not the reference implementation, and it does not speak for the
protocol's author.

## What scroll adds over gemini

- The request names the client's **acceptable languages** (BCP47,
  most-preferred first), and the server serves the best match.
- A success response carries **document metadata**: author, publish date,
  modification date.
- The second digit of a success code is a **Universal Decimal Classification
  class** — scroll is the only small-web protocol whose responses classify
  their own subject matter.
- A `+` on the language list requests a resource's **abstract** instead of its
  body.

Scrolltext is richer than gemtext on purpose: five heading levels forming
numbered sections, nested quotes and lists with verbatim ordered markers,
tagged code blocks, input links (`=:`), link relations (`[Citation]`, `[+]`),
inline strong/emphasis/code with precise toggle rules, and a linetype escape.
The parser is dependency-free.

## Provenance, stated plainly

The specification's own host (`scrollprotocol.us.to`) is offline. This crate
is written against the spec text vendored by
[michael-lazar/smolnet-portal](https://github.com/michael-lazar/smolnet-portal)
(`docs/scroll_spec.txt`, modification date 2024-08-03), cross-checked against
that portal's working proxy, which interoperates with live scroll servers.
The spec titles itself *speculative*; expect revisions.

## Layers

| Layer | Feature | Pulls |
|---|---|---|
| wire grammar + scrolltext | always on | nothing |
| `exchange` over any stream | `client` | tokio |
| `fetch` with TLS + TOFU | `tls` *(default)* | gemini-protocol |
| `server::serve_connection` over a caller-owned stream | `server` | tokio, url |

The TLS half deliberately rides `gemini_protocol::tofu_connect`: scroll's spec
says "TOFU is used, similarly to Gemini", so the two protocols share one trust
seam, and a host that installs a `TofuStore` has installed it for both.

`wire::Reply::encode(ResponseLimits)` is always available, including to blocking
transport owners. It preserves native success classification, MIME/language,
author, dates and exact body or abstract bytes, and refuses header injection,
invalid response envelopes and host byte limits before producing bytes.
Header line limits include CRLF; date strings remain verbatim.

With `server`, `serve_connection` reads one bounded CRLF request and writes and
flushes one validated reply. Its host-selected deadline covers the handler and
I/O. The caller supplies the connected stream, closes it afterwards, and owns
TLS, addressing, certificates, admission and task cancellation. The crate opens
no listener and spawns no task. Dropping the exchange future stops its work.
Language preferences and the abstract flag reach the handler intact; the
handler owns content selection. A host with one declared language per page can
keep that policy without the wire layer inventing language negotiation.

## Not implemented

A listener or TLS/certificate owner; client certificates (including the spec's misfin-certificate
convention); and the inline-toggle exception between two **non-ASCII** symbols,
which needs Unicode category tables this crate does not carry — the ASCII cases
are honoured and the limitation is recorded in the docs.

## License

MIT.

## Client bounds

Client operations have a 30-second whole-operation deadline, including connection
setup, and a 64 MiB response-body default. Overflow returns an error rather than
a truncated success. Bounds are enforced before body append. No runtime is added to the dependency-free grammar feature.

`client::FetchOptions` supplies `timeout`, `max_request_bytes`,
`max_header_line_bytes`, and `max_body_bytes`. `fetch_with_options` and
`exchange_with_options` retain language preferences, abstract requests, author,
verbatim dates, and UDC status. Defaults are 4096 bytes for the request and each
of the four success-header lines, including CRLF. Callers can raise the line
budget for long native metadata. Unterminated/non-CRLF header lines are refused.
