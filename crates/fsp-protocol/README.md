# fsp-protocol

An implementation of [FSP](https://fsp.sourceforge.net/) (File Service
Protocol, `fsp://`, port 21) in Rust: anonymous file transfer over UDP.

This is not the reference implementation, and it does not speak for the
protocol's community.

## The outlier of the family

Everything else in this workspace is a TCP stream. FSP is **UDP with its own
reliability**, and it is deliberately simple enough to run without a transport
at all: the header carries both a checksum and a payload size, so in the
specification's words it "can be used as very simple raw-protocol (for example
for sending data over serial line). This makes it very popular in embedded
devices area."

That self-sufficiency is why FSP is awkward to carry over an already-reliable
link: you would be running two reliability layers.

## The detail that breaks implementations

**The checksum is computed differently in each direction.** Server to client
starts from zero; client to server starts from the packet's own size.

Get it wrong and every packet you send is rejected while every packet you
receive validates — which reads like a network fault rather than a bug. There
is a test asserting the two differ by exactly the packet size.

## Reliability

FSP sequences itself, and this client honours it: the client chooses the
sequence and the server echoes it, so a **stale reply is discarded and the read
continues** rather than being handed up as an answer to a question nobody
asked. The client also echoes the server's last key on every request, as the
spec requires.

## Client limits

`Session::connect_with_limits(host, port, Limits { .. })` selects caller-owned
budgets; `Session::connect` uses finite defaults. `session.limits()` returns the
selected snapshot. Request bytes include the 12-byte header and a path's NUL.

| Limit | Default |
|---|---:|
| Complete outgoing packet (`max_request_bytes`) | 1036 bytes |
| Complete incoming datagram (`max_datagram_bytes`) | 2060 bytes |
| Reply data (`max_data_bytes`) | 2048 bytes |
| Reply extra area (`max_extra_bytes`) | 2048 bytes, within the datagram cap |
| Whole file (`max_file_bytes`) | 64 MiB |
| Directory reply data (`max_directory_bytes`) | 8 MiB |
| Directory entries (`max_directory_entries`) | 65536 |

Limits are host policy, not new wire constants. In particular, `MAX_PAYLOAD`
(1024) remains the minimum supported payload and the existing short-block
completion threshold. A configured client can accept larger blocks. Exact caps
succeed, including a full final block followed by a separate empty EOF reply;
overflow returns `ClientError::LimitExceeded`, never a successful prefix.
File and directory offsets advance with checked 32-bit arithmetic. Advertised
file sizes remain metadata and do not determine allocations.

Requests are checked before packet/path copies and u16 conversion. Reply
header/data/extra budgets are checked before decoded vectors are allocated.
The UDP receive buffer has an extra sentinel byte, bounded by full UDP capacity;
truncating receives or an OS oversize error cannot masquerade as a valid packet.
Directory bytes include padding and end markers. Entry admission is checked
before copying names; `RDTYPE_SKIP` advances to another block and `RDTYPE_END`
finishes the listing, including when it follows entries in the same packet.
The dependency-free `parse_directory_bounded` also exposes entries and explicit
end-marker status; existing `decode` and `parse_directory` retain their grammar
contracts.

Retries still default to three attempts and `RESEND_AFTER` (one second) for each
reply. Within the packet budgets, stale or corrupt replies are discarded under
that same reply deadline.
These budgets do not introduce a session or whole-operation deadline.

## Layers

| Layer | Feature | Pulls |
|---|---|---|
| wire format | always on | nothing |
| client | `client` *(default)* | tokio |

## Not implemented

The write half (`CC_UP_LOAD`, `CC_INSTALL`, `CC_DEL_FILE`, `CC_MAKE_DIR` and
friends), password protection, and a server. Every command code is defined and
`Session::request` will send any of them, so the wire work is done even where a
convenience method is not.

## License

MIT.
