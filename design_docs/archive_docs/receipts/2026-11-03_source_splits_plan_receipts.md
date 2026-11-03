# Source splits: H5 Smolweb receipts

## 2026-11-03: nine remaining source exceptions

Owner: house-style H5, chat 01a19f86-cb71-7820-a6ac-aaec39d8bfd4.
Retained evidence is this compact text, under the shared 100 MB H5 cap.
Baseline source: `dd2bf4a6329e3520ecb5a7983f14e7fdc26363d1`.

| Original source | Before | After |
|---|---:|---:|
| `crates/errand/src/lib.rs` | 606 | 534 |
| `crates/errand/src/parse/feed.rs` | 671 | 476 |
| `crates/gopher-protocol/src/client.rs` | 622 | 557 |
| `crates/guppy-protocol/src/server.rs` | 645 | 413 |
| `crates/misfin/src/server.rs` | 991 | 546 |
| `crates/misfin/src/client_deadline_tests.rs` | 637 | 490 |
| `crates/misfin/src/server_deadline_tests.rs` | 702 | 507 |
| `crates/errand/tests/client_limits.rs` | 610 | 482 |
| `crates/text-protocol/src/lib.rs` | 711 | 434 |

All resulting modules are also below 600 physical lines. Nine exceptions
are removed, leaving zero in this repository. Earlier four client splits
are excluded from this count. Public module paths, framing, certificate
identity checks, protocol limits, deadline and shutdown logic are preserved.

- Baseline and post: `cargo test --workspace --all-features --locked -- --test-threads=1`,
  650 passed cases each, one unchanged ignored test.
- Initial concurrent baseline failed Guppy's immediate UDP port rebind with
  Windows AddrInUse (10048). The unchanged fixture passed serially in both
  complete baseline and post runs. This is not a source fix or weakened assertion.
- `prek run --all-files`: ceiling and all-target/all-feature Clippy pass.
- Locked Text no-default and client-only checks, Misfin server/ring check,
  and workspace all-feature public docs pass.
- Existing request/reply fixtures moved intact; native TLS tests retain the
  same helpers through their original server module. No native Unix/Mac
  or new headed/platform qualification is claimed.
