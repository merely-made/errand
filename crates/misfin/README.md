# misfin

An embeddable Rust implementation of the [Misfin](https://misfin.org) mail
protocol: identities, gemmail, a sending client, a receive server, and a small
CLI.

## Stewardship of this name

Misfin is [lem's](https://github.com/JCLemme/misfin) protocol. This crate is an
independent implementation of the specification (prototype B), **not** the
reference implementation, and it is not affiliated with the protocol's author.
The `misfin` name on crates.io is held in stewardship: **if the protocol's
author wants it, it will be transferred on request** (open an issue here or
mail the address in the commit log), and this crate will move to a qualified
name.

## What Misfin is

Mail for the small internet, heavily influenced by Gemini. A message is one
TLS transaction: the client connects (port 1958), both sides present
self-signed x509 certificates, the client sends a single CRLF-terminated
request of at most 2048 bytes —

```text
misfin://mailbox@hostname <message>
```

— and the server answers with a gemini-shaped `<status> <meta>` line. A
sender's identity *is* its certificate fingerprint; trust is
trust-on-first-use. Messages are gemtext plus three metadata line types
(sender `<`, recipients `:`, timestamp `@`).

## Library

```rust
use misfin::{MisfinAddress, SendOptions, send};

let recipient = MisfinAddress::parse("friend@example.com")?;
let receipt = send(&recipient, "What's up?", &SendOptions {
    identity: Some(my_identity),           // strongly recommended
    expected_fingerprint: pinned,           // TOFU pin, once known
    ..Default::default()
}).await?;
println!("{} {}", receipt.status, receipt.meta);
```

Identities can be minted randomly and persisted
(`ensure_identity_with_root`) or derived deterministically from a 32-byte seed
(`deterministic_identity` — nothing to back up; the same seed always
reproduces the same certificate and fingerprint).

Feature flags:

| feature | adds |
| --- | --- |
| *(none)* | addresses, gemmail parse/compose, status codes, identity minting/storage |
| `client` | `send` — async TLS delivery (tokio + rustls); pick a provider: `aws-lc` or `ring` |
| `aws-lc` / `ring` | the TLS crypto provider (`ring` builds without a C toolchain; `aws-lc` wins if both) |
| `server` | `MisfinServer` + redb `MailboxStore`, sender-identity extraction, 63 on changed fingerprints |
| `cli` | the `misfin` binary |

## CLI

```sh
cargo install misfin --features cli

misfin id mark@example.com --blurb "Mark"
misfin serve mark@example.com --listen 0.0.0.0:1958
misfin send friend@other.com "hello over misfin" --from mark@example.com
misfin inbox mark@example.com
```

## Spec coverage (prototype B, 2023-05-11)

| Spec section | State |
| --- | --- |
| §1.1 transaction shape (single request/response, CRLF, close-notify) | client + server |
| §1.2 request scheme, 2048-byte ceiling | enforced both sides (client refuses to build; server answers 59) |
| §1.3 / §2 status codes | full typed vocabulary (`MisfinStatus`), all 19 defined codes |
| §3 TLS ≥ 1.2 | rustls, TLS 1.2/1.3 |
| §3.1 identity certificates (USER_ID / COMMON_NAME / SAN, SHA-256 fingerprints) | minting and parsing |
| §3.2 TOFU validation | client: fingerprint pinning; server: per-identity pins, 63 on change |
| §4 gemmail (sender/recipients/timestamp lines, subject) | parse + compose + reply-set helper (§4.2 dedupe rules) |
| Multi-domain hosting, CA-signed mailbox certs (§3.1 advanced) | not implemented (single-domain; self-signed leaf only) |
| misfin(A) — the superseded request-response-proceed prototype (data phase, MIME types, subject line; spec repo `old/`) | not implemented; nothing live speaks it. Its large-message role is the community's misfin(C) discussion, which we watch. A/B are wire-distinguishable (B's `misfin://` prefix), so coexistence stays possible if ever needed |
| CGI (42), proxying (43), rate limiting (44), hashcash (64) | status codes surfaced; server does not implement the behaviors |

Redirects (30/31) and retryable failures (4x) are reported to the caller, not
acted on — per the best-practices document, resending is the user's decision.

## Send deadlines

`SendOptions::timeout` remains the per-step allowance, defaulting to 30 seconds
for connection/name resolution, TLS handshake, request write and the entire
response-line read. `SendOptions::send_timeout` is a separate whole-send
allowance, defaulting to 120 seconds. `None` selects these finite defaults.
One absolute send deadline spans every network stage and best-effort
close-notify after local request, host, duration and TLS-material preflight.
Progress and new steps never renew that deadline. Close-notify is also bounded
by the step allowance; a step-only cleanup failure retains the known receipt,
as with the earlier best-effort shutdown behavior.

The earlier step error stays `SendError::Timeout(step)`. Whole-budget expiry is
`WholeSendTimeout { receipt }`: `Some` retains the exact complete server status,
META and server fingerprint already received before cleanup expired. `None`
does not establish that the mail was undelivered: after a request write the
remote server may have accepted it without a reply reaching the sender.
Fingerprint mismatch remains the primary trust refusal if its bounded cleanup
expires, and the message is never written on that path.
The CLI retains the known server reply and fingerprint in its error output.

A valid response requires CRLF within the 2048-byte wire limit. EOF, bare LF
and a capped partial reply cannot become an acknowledgement. Outgoing request
length is checked before constructing the wire string. A zero whole-send
budget refuses before I/O, a zero step budget returns `Timeout("connect")`,
and unrepresentable durations return `InvalidTimeout(scope)` before a timer.

Cancellation drops the owned connection and starts no detached retry. It can
lose an acknowledgement already received by the cancelled future, so the
caller owns delivery reconciliation and any explicit resend. Deadlines are
cooperative: a custom blocking poll cannot be preempted, while late ready
completions are refused. Mailbox receiving deadlines remain server-owned.

## License

MIT, matching how the protocol's own repository licenses its reference
implementation (the protocol itself is declared public domain there, and the
spec documents are CC-BY-SA 4.0). Originally extracted from the
[Mere](https://github.com/merely-made/mere) browser workspace, which now consumes
this crate.
