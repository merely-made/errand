# scorpion-protocol

A Rust implementation of the [Scorpion protocol](https://github.com/zzo38/scorpion)
(`scorpion://`, `scorpions://`) and its document file format.

Scorpion, by zzo38, has a wider surface than most of its smolweb neighbours.
Where gemini has one verb, Scorpion has four subprotocols — receive, send,
interactive, and meta — plus range requests, uploads with conflict detection,
and a binary block document format rather than a line grammar.

This crate is independent and unaffiliated with the protocol's author. The
reference implementation is C and carries no licence file, so none of it was
consulted for code; this was written from the published specification, which
explicitly invites independent implementations.

## What costs what

The wire grammar and the document format have **no dependencies** and are
always compiled. A consumer that only parses takes the crate with
`default-features = false` and pulls in no async runtime and no TLS stack.
Everything that touches a socket is behind a feature.

| Feature | Adds |
| --- | --- |
| *(none)* | requests, responses, status codes, the document format |
| `client` | an async client over any stream, plus TCP dialling |
| `tls` | `scorpions://` transport |
| `server` | serving from a `Source` |

## Library

```rust
use scorpion_protocol::{Request, Header, Status, Range};

// Four subprotocols, each with its own parameter grammar.
let whole = Request::receive("scorpion://example.com/file");
let part = Request::receive_range("scorpion://example.com/file", Range::new(3, 9));
assert_eq!(part.to_wire(), b"R3-9 scorpion://example.com/file\r\n");

let header = Header::parse("20 1234 text/plain").unwrap();
assert_eq!(header.status, Status::OK);
```

Documents are binary blocks, so text comes back as bytes:

```rust
use scorpion_protocol::document::{self, Block, BlockType, Encoding};

let blocks = document::parse(bytes)?;
for block in &blocks {
    if let Some(url) = block.url() {
        println!("→ {url}");
    }
}
```

## Spec coverage

| Spec point | State |
| --- | --- |
| Request line: subprotocol byte, parameter, absolute URL, CRLF | client + server |
| Mandatory scheme; fragment stripped before sending | enforced |
| Status codes `0x`–`8x`, major/minor split, all detailed codes | full |
| Unknown minor codes route by major class | yes, and tested |
| `R` receive, with range requests (end-exclusive) | client + server |
| `M` meta, with optional desired type | client + server |
| `S` send: version and `HMAC@version` parameters | request grammar only; the upload phase is not driven |
| `I` interactive: capability codes | request grammar only; the session is not driven |
| Parameter parsing per major class, last parameter keeps spaces | full |
| `6x` certificate scope hints (`=`, `+`, `*`, `-`) | parsed |
| Port 1517, TLS and plaintext on one port via first-byte `0x16` | `is_tls_hello` |
| Document format: blocks, packed type+encoding byte, 16-bit attribute, 24-bit body | full |
| Link attribute: ASCII, truncated at NUL | enforced |
| Unknown block types | preserved, not dropped |
| Certificate validation policy | **deliberately not implemented** — see below |
| ULFI type system, hashed URIs, X.509 extensions, favicons | not implemented |

### On certificate validation

The specification does not say how to validate a server certificate. It says
so in as many words: *"There will be a separate document written with further
specifications about the handling of certificate validation and of certificate
chains"*, and of pinning, *"the specification for doing this is not written
yet"*.

So the `tls` feature carries the transport and leaves the policy to the caller
— `connect_with` takes any `rustls` verifier. Shipping a trust-on-first-use
store here would mean inventing a rule the protocol has not made and
presenting it as the protocol's. (Gemini is a different case: self-signed plus
TOFU *is* its written policy, which is why `gemini-protocol` in this workspace
does ship one.)

Two transport requirements the specification *does* state are implemented:
session resumption is disabled, because tickets can be used for tracking; and
`warn_on_client_cert` reports when a connection would send a client
certificate under TLS 1.2 or earlier, where it is not encrypted.

## Two traps worth naming

Both are places where a plausible reading is wrong, and both are pinned by
tests.

**A range's end is exclusive.** The specification's own example: `3-9` means
six bytes, the fourth through the ninth. Reading it as inclusive, as HTTP's
`Range` is, truncates every ranged fetch by one byte.

**A `21` declares the whole file's size, not the range's.** A client that
reads the declared size after a partial response waits forever for bytes the
server was never going to send — which is exactly the bug this crate's own
test caught during development.

## Receive limits

The native client accepts `Limits` (32 MiB body by default). Declared lengths
are checked before allocation; unknown-length bodies refuse the first byte
over the cap rather than returning a successful prefix. Partial responses obey
the caller's body cap while preserving the requested range as a frame boundary,
so a following interactive status line is left unread. Callers own the overall
operation deadline, including connection setup and interactive sessions.

## License

MIT. The specification declares no licence; this implementation is original
code written from the specification text.
