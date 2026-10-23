# dict-protocol

An implementation of [DICT](https://www.rfc-editor.org/rfc/rfc2229.html)
(RFC 2229, `dict://`, port 2628) in Rust: look a word up in networked
dictionaries.

This is not the reference implementation, and it does not speak for the
protocol's community.

## It is not shaped like the rest of the small web

Gemini and gopher answer one request and close. DICT is a **command loop**: the
server greets you, you issue commands, and the connection stays open until
`QUIT`. It is far closer to SMTP or NNTP, which is why the client here is a
`Session` you hold rather than a function you call. Hiding that behind a
one-shot fetch would mean reconnecting per word, which is the exact cost a
command loop exists to avoid.

Two details bite implementations that skim the RFC, and both are handled:

- **Parameters are quoted.** Database descriptions contain spaces, so splitting
  a response on whitespace shreds them.
- **Text blocks are dot-stuffed.** A line whose first character is `.` is sent
  doubled, so forgetting to undo it corrupts any definition beginning with a
  period.

## Looking a word up

```rust,no_run
# async fn run() -> Result<(), dict_protocol::ClientError> {
let mut session = dict_protocol::Session::connect("dict.org", None).await?;

for definition in session.define("*", "smolweb").await? {
    println!("[{}] {}", definition.database, definition.text.join("\n"));
}
session.quit().await?;
# Ok(())
# }
```

`"*"` asks every database and `"!"` asks for the first that matches. A word
that is absent yields an **empty vector rather than an error**, because
`552 no match` is an answer.

## Client limits

`Session::connect_with_limits(host, port, limits)` and
`Session::over_with_limits(stream, limits)` accept a `Limits` value. Existing
constructors use finite defaults:

| Field | Default | Counted representation |
|---|---:|---|
| `max_command_bytes` | 1024 | Complete outgoing command, including CRLF; the native `MAX_LINE` ceiling always applies |
| `max_line_bytes` | 4096 | One inbound line, including CRLF |
| `max_response_bytes` | 64 MiB | All inbound bytes for a complete operation |
| `max_response_lines` | 65536 | All inbound lines for a complete operation |

Response totals include statuses, text, empty lines, dot terminators and the
final trailer, before dot unstuffing. `DEFINE` shares one budget across all
definitions. The line budget also bounds returned items and definitions;
announced server counts never determine allocation. The greeting has its own
budget, and a new command starts a fresh response budget. Byte and line budgets
are not exact heap-memory accounting: parsed strings and result containers also
occupy memory.

Commands containing CR or LF are refused before writing. Request preflight
failures leave the session usable. A receive or write failure leaves it unusable
for further commands; partial replies are never drained without a budget.
`Session::command` only reads the initial status, so use the high-level methods
for complete response handling. Hosts remain responsible for operation deadlines
and for discarding sessions after cancelling an operation.

## Layers

| Layer | Feature | Pulls |
|---|---|---|
| wire grammar | always on | nothing |
| session client | `client` *(default)* | tokio |

## Not implemented

A server, and the optional `AUTH`/`SASLAUTH` and `OPTION MIME` extensions.
`SHOW INFO`, `SHOW SERVER`, `STATUS` and `HELP` are reachable through
`Session::command`, which returns the raw status.

## License

MIT.
