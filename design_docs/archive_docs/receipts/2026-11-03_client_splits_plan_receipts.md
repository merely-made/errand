# Protocol client splits receipts

## 2026-11-03: FSP exchange and DICT commands

Baseline: Smolweb main `0b22d00e`, clean before this pass. Owner: chat
`01a19f86-cb71-7820-a6ac-aaec39d8bfd4`. Receipt cap: 100 MB; compact text.

`cargo test -p dict-protocol -p fsp-protocol --all-features --locked` passes
before and after: 43 DICT tests, 35 FSP tests, and three doctests. The tests
exercise framing/trailers, byte/entry limits, corrupt/stale packets,
operation deadlines, key settlement and cancellation-retired sessions.
The three FSP fixture groups retain their original module paths; DICT's
existing external limits/deadline fixtures remain at their original paths.
Static review retains all 20 moved FSP test names and seven moved DICT
basic test names. Both original Session field declarations are identical.

`cargo test -p errand --test client_limits --locked`: all 14 existing
routed receiving-bound tests pass. No test inputs, retries, thresholds,
public method signatures or assertion outcomes are changed by the move.

| Source | Before lines | After lines |
|---|---:|---:|
| fsp-protocol/src/client.rs | 1488 | 440 |
| fsp-protocol/src/client/exchange.rs | moved exchange impl | 150 |
| fsp-protocol/src/client/tests.rs | moved basic fixtures | 136 |
| fsp-protocol/src/client/limit_tests.rs | moved bounds fixtures | 391 |
| fsp-protocol/src/client/operation_tests.rs | moved lifecycle fixtures | 373 |
| dict-protocol/src/client.rs | 843 | 542 |
| dict-protocol/src/client/commands.rs | moved command impl | 161 |
| dict-protocol/src/client/tests.rs | moved basic fixtures | 149 |

FSP's private request_until helper remains visible only within the original
client-module scope; its reply loop stays private to exchange. The same
Session owns socket, sequence, last key, in-flight flag and policies. DICT's
private command impl uses the original Session and its existing deadline,
framing and unusable-state helpers. Public types stay in their original
modules and root exports. Caller-configurable policy and wire codecs are
unchanged. The two obsolete ceiling exceptions are removed without adding
another exception or exclusion; eleven unrelated exceptions remain.

Builds reuse `C:/t/cargo-targets/smolweb` and its `build` directory with two
jobs. Native execution is Windows with loopback/controlled streams; no live
public server or new external interoperability acceptance is claimed.
No isolated Cargo home, target, worktree, helper tree or full logs are kept.
The remaining feature-off, public-doc and full-gate results are appended
below after qualification.

### Final qualification

- `cargo check -p dict-protocol -p fsp-protocol --no-default-features
  --target wasm32-unknown-unknown --locked`: pass. Both wire layers remain
  independently compilable without their native clients/runtime.
- `cargo doc -p dict-protocol -p fsp-protocol --all-features --no-deps
  --locked` with `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`: pass.
  Session methods resolve in the original public homes. The existing DICT
  redundant-link-target advisory is preserved.
- `prek run --all-files`: ceiling and workspace all-target/all-feature
  Clippy pass with all new modules staged. Commit runs the installed hooks
  again. No hook, lint, dependency or default-policy setting changes.
- Reviewed source moves preserve all test-module paths and Session fields;
  only private impl boundaries, necessary imports/visibility and rustfmt
  layout change. The controlled fixtures and wire bytes are unchanged.
  Both retired exception entries are absent; all eleven retained entries
  predate this pass. No replacement exceptions or exclusions are added.

The two protocol suites and their receiver total 92 passing unit/integration
tests plus three passing doctests. Execution is Windows native; wasm covers
feature isolation. Public-server and other-OS acceptance are not inferred.
The plan is complete and the source/receipt commit is pushed directly to
main. Compact receipt size remains below its 100 MB cap; the stable build
cache is retained for reuse, with no isolated generated output to clean up.
