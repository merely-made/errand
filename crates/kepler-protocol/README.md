# kepler-protocol

An implementation of [Kepler](https://github.com/kevinboone/kepler-protocol)
(`kepler://` on port 2009, `keplers://` on port 10009) in Rust.

Kepler is, in its author's words, "an incremental improvement over Gemini, as
Gemini is an incremental improvement over Gopher". The improvement is
**caching**, and it is the only cache model anywhere in the small-web family.

This is not the reference implementation, and it does not speak for the
protocol's author.

## What caching buys

- The request carries the epoch second of the copy you already hold, plus the
  languages you can read.
- A `2x` response declares the body's **length**, when it was **last updated**,
  and when it **expires**.
- A `7x` response says *nothing has changed*, and carries no body at all.

Two consequences worth knowing. A body's end is **declared rather than implied
by the connection closing**, unlike gemini and gopher, so a truncated transfer
is detectable. And encryption is **optional**: `kepler://` is plaintext,
`keplers://` is TLS, and which you get is the scheme's choice rather than the
protocol's.

## Layers

| Layer | Feature | Pulls |
|---|---|---|
| wire grammar | always on | nothing |
| client | `client` *(default)* | tokio, url |
| `keplers://` | `tls` | rustls |

```toml
kepler-protocol = { version = "0.1", default-features = false }  # grammar only
```

## Client size limits

`Limits` configures `max_request_bytes`, `max_header_line_bytes`, and
`max_body_bytes`. Use `fetch_with_limits(url, last_cached, language, &limits)`
or `exchange_with_limits(stream, request, &limits)`; the existing helpers
choose finite defaults. The same fetch options reach `keplers://` TLS.

Defaults are 4096 request bytes, 1025 response-header bytes, and 64 MiB of
body. Line budgets include CRLF. The 1025-byte header default preserves the
previous 1024-byte counter, which counted CR but omitted the final LF.
Kepler's separate 1024-byte URI ceiling remains enforced even when a caller
raises the full request allowance for cache and language fields.

Requests are checked before connecting, and constructed fields reject CR/LF
injection. Raw `exchange` requests remain caller-supplied wire bytes. Zero
request/header budgets refuse; a zero body budget permits an empty body.
Headers require CRLF. Oversized headers and bodies return `ClientError::Limit`
instead of a successful prefix. Declared body lengths are checked before
reading body bytes; short EOF is a protocol error, and the exact declared
frame is read without consuming following bytes. Unknown lengths use a
bounded overflow probe. Cache, timestamp, language, MIME and status data keep
their existing representations. These are size/framing controls; callers
still own deadlines and cancellation.

## Known gaps

**No server.** The client and the grammar are here; serving is additive and
simply has not been written.

**`keplers://` does not verify certificates.** That is stated rather than
hidden: kepler does not mandate encryption at all, so `keplers://` is best read
as "not in the clear" rather than "authenticated peer". Trust-on-first-use
pinning, as gemini has, is the obvious upgrade and is not implemented.

## License

MIT.
