# Client receive limits

**Status (2026-10-23):** phases 1 to 8 landed and qualified: routed clients,
native Micron limits, browser receiving, and standalone DICT/FSP/Kepler/Text
size and framing limits, native session operation deadlines, and Misfin sending
and receiving deadlines. Whole-transaction and per-step policy remain
independently configurable. Phase 9, native Misfin connection admission and
joined listener shutdown, is in progress; sibling lifecycle policies stay
separately scoped.

## Ownership and scope

Errand composes caller-selected request bytes, response header-line bytes,
body bytes and a whole-transaction deadline. Native protocol crates enforce
their own grammar and protocol ceilings before writes, allocation, append or
streaming callbacks. Redirects, explicit Submit authority, persistence and
actor lifetime remain host responsibilities. Limits refuse excess data;
success must never mean a silently truncated document. Native Scroll metadata
and the shared site snapshot V1 stay intact.

Murm owns Resource admission, encrypted transfer buffers, decompression and
segmented accumulation. A page-body budget is distinct from packed envelope
and encoded transfer budgets. Turnstone supplies those budgets and retains
its outer deadline including graceful endpoint shutdown. Mere owns the
page/subresource policy and the bodyless document fetch adapter. These are
consumer boundaries, rather than a new shared transport runtime.

The standalone slices work on smolweb main. The five native client crates own
their limits; this does not add Errand routes or product adapters. No active
consumer of these client APIs was found in Mere, Turnstone, Knot or Genet;
patch-table entries alone do not require consumer repins. Earlier consumer
worktrees have been integrated and removed. Reuse the existing stable repository
Cargo targets. Required
receipts are compact source/lock identities and focused command results under
a **100 MB total retained-byte cap across repositories**. Do not replace older
receipts. New receipt hashes must state their Git/native byte convention.

## Phases and done-conditions

1. Bound all Errand fetch routes and Gemini streaming. Done when exact-fit
   bodies succeed, cap+1 refuses before append/callback, request/header budgets
   are distinct, stalled exchanges obey the whole deadline, Guppy duplicates
   do not inflate byte accounting, and native response metadata survives.
   Preserve protocol-specific limits and independent feature graphs.
2. Bound native Micron receiving. Done when advertised/actual oversize data,
   encrypted transfer allocation, decompression, packed response decoding and
   multipart append enforce their respective budgets. Tests cover exact-fit
   packet/Resource bodies, malicious size declarations and compressed data.
   Whole-operation timeout and graceful close remain caller-owned.
3. Propagate consumer policy. Done when Mere page, streaming, subresource and
   explicit Submit receiving, plus bodyless `RemoteFetcher` and Turnstone
   Micron page/Submit, supply limits before transport buffering. Keep MIME,
   supplied-empty-body, redirect Submit refusal and existing defaults covered.
4. Publish a coherent supplier/consumer cohort and record exact qualification.
   Done when focused native tests, feature checks and production Clippy pass
   for the changed owners; source/lock receipts name every exercised boundary.
   Headed UI, radio and independent-reader qualification are separate gates.
5. Bound standalone DICT/FSP/Kepler/Text bytes and items with configurable native
   limits and finite defaults on existing helpers. DICT counts raw response
   bytes and lines across the entire command, including all DEFINE blocks,
   statuses and terminators; a partial refused reply makes the session unusable.
   FSP bounds packets, file/list aggregation and directory entries, checks
   offsets, preserves native directory markers, and retains existing retries
   and per-reply timing. Kepler/Text bound request, header and body separately;
   Kepler refuses short declared bodies and leaves following frames unread.
   Done when supplied-stream and actual TCP/UDP/TLS fixtures cover exact-fit,
   overflow, early request refusal and native framing, and each crate builds
   independently as grammar-only, native client and (where available) TLS.
   Retain compact command/source/lock receipts within the shared 100 MB cap.
6. Bound native session operations in DICT, FSP, Kepler, Text and Scorpion.
   Native `Options` keep size limits separate from `operation_timeout`, with a
   configurable 30-second convenience default. One budget spans setup and all
   nested writes/reads, retries or blocks; activity never renews it. A new
   command receives a fresh allowance, rather than charging idle session time.
   DICT/FSP retire interrupted sessions before another write. Borrowed Kepler,
   Text and Scorpion carriers remain caller-owned and must be discarded after
   interruption; Scorpion exposes absolute deadlines for multiple framed
   responses and TLS setup. Done when paused-time tests, cancellation controls,
   native TCP/UDP/TLS fixtures, pure invalid-request preflight, independent
   feature builds and strict Clippy qualify the exact source. Existing size,
   metadata and framing tests remain green. Retain new compact receipts within
   the shared 100 MB cap without replacing previous evidence.
7. Bound Misfin sends separately. Keep `SendOptions::timeout` as the 30-second
   per-step default and add independently configurable `send_timeout`, default
   120 seconds, shared across DNS/TCP/TLS/write/full response/close-notify after
   local preflight. Whole expiry remains distinct from named step timeouts.
   Preserve a complete observed receipt if cleanup exhausts the whole budget;
   preserve primary fingerprint refusal without writing the message. Bound
   cleanup without retries or redirected sends. Done when native TLS and
   controlled-carrier tests qualify cumulative budgets, cancellation, known
   receipt retention, pure preflight and complete response framing; core/client/
   server/CLI feature graphs and strict native Misfin Clippy pass. Errand uses
   the recorded existing parser lint allowances for its all-target Clippy gate.
   Errand's explicit
   send companion must forward caller-selected mail budgets and retain native
   timeout receipt facts. Receiving, ordinary fetching, actor lifetime and
   product sending UI remain outside this slice. Retain compact new receipts
   within the shared 100 MB cap without replacing previous evidence.

8. Bound native Misfin receiving transactions. `MisfinServerConfig::timeout`
   defaults to 30 seconds per TLS/full-request/write/close step, while
   `receive_timeout` defaults to 120 seconds across the entire accepted
   connection. Start the fixed deadline at TCP acceptance before spawning;
   incoming bytes never renew it or the complete request-read allowance.
   Validate nonzero, representable policy before TLS configuration or binding.
   Require complete CRLF within the native request ceiling before delivery.
   Check immediately before and after synchronous mailbox dispatch; an already
   committed delivery survives timeout, cancellation or reply failure.
   Done when controlled-carrier and actual localhost TLS fixtures qualify
   distinct step/whole expiry, cumulative timing, slow requests, blocked write/
   close, incomplete framing, pre-dispatch refusal and retained committed mail;
   core/client/server/CLI feature graphs and strict Misfin Clippy pass. Retain
   exact-source/lock and compact command receipts within the shared 100 MB cap.
   Connection admission, joined listener shutdown, other protocol servers,
   product repins and product mail UI remain separately scoped.

9. Bound native Misfin connection admission and join accepted work on shutdown.
   Add configurable `max_connections` (default 32, nonzero) and `shutdown_grace`
   (default 5s, zero requests immediate cancellation). Admission pauses accept
   before spawning at capacity; pending peers are subject to OS backlog limits.
   Track and reap completed, failed and panicked tasks. Observe shutdown before
   new admission, close the listener, drain for one fixed grace window, then
   abort remaining tasks and await every terminal join before returning.
   Existing per-transaction budgets remain independent and mailbox commits
   survive cancellation. Signal shutdown and await `serve` for the joined
   guarantee; dropping the future can request abort but cannot await cleanup.
   Done when actual TCP/TLS and controlled-task tests qualify saturation,
   capacity reuse, graceful mail completion, immediate/expired-grace cancellation,
   drop-before-return, panic handling and fixed total grace; independent feature
   graphs and strict Misfin Clippy pass on exact-source/lock receipts. Keep
   sibling server policy, Errand adapters, Djinn/Armillary, product pins and
   receiving deadline/framing semantics unchanged. Shared receipt cap 100 MB;
   explicitly set both approved Cargo target and build-directory variables.

## Findings

### 2026-10-23

- The native family survey finds detached accepted tasks in Misfin, Gemini,
  Gopher, Finger, Nex and Spartan. Their handler and I/O deadlines differ, so
  this phase qualifies Misfin first. Guppy's inline UDP loop already bounds
  peer sessions; its inline handler/shutdown responsiveness is separate work.
  Scroll and Scorpion exchange over caller-owned streams and must retain that
  ownership. Errand's `serve` adapters do not own listener lifetime.
- Djinn already composes native exchanges with host-owned policy, capacity
  controls and Armillary `ResidentTasks::close_and_join` in
  `mere/ports/djinn/src/resident_site.rs`, `moot_site.rs` and `micron_site.rs`.
  The native Misfin listener uses its existing Tokio dependency to own a local
  bounded task set; this adds no generic runtime or dependency on host actors.
  At capacity, native Misfin pauses acceptance rather than fabricating a mail
  reply. Host-specific overload and residency policy remains independently owned.
- The joined guarantee requires cooperative connection futures. Synchronous
  mailbox work cannot be preempted by abort or a grace timer; after grace,
  cancellation is requested and terminal joins are still awaited. Dropping an
  async serve future cannot perform asynchronous joining.
- Misfin receiving's former 30-second read timer restarted per byte; TLS,
  response write and close were unbounded. The receiving deadline now starts
  at acceptance and is independent of sending policy. Invalid durations are
  local configuration errors before TLS or listener I/O. Constructor users
  retain finite defaults; a workspace usage search found no external config
  struct literals requiring source repair.
- The old receive reader returned an EOF-truncated request as a dispatchable
  line. Only complete CRLF framing may reach mailbox dispatch. The synchronous
  Redb operation cannot be preempted or rolled back by an async timer; a
  deadline check after dispatch suppresses a late reply while preserving any
  delivery already committed. Cancellation has the same uncertainty boundary.
  Bare LF inside a message remains valid; strip only the final observed CRLF,
  preserving trailing message newlines that the old trimming discarded.
- Phase 8 left one detached task per accepted connection, stopping acceptance
  when its shutdown future resolved. Its deadline qualification did not cover
  connection admission or joined task shutdown; phase 9 owns those controls.
- Misfin's four existing timers bound connect, TLS, write and full response
  reads independently; both success and pin-mismatch shutdown paths were
  unbounded. A fixed send deadline clamps each step, including cleanup, without
  renewing the shared allowance. A parsed receipt and a primary pin refusal
  remain available when bounded cleanup exhausts that allowance.
- The Misfin response reader previously returned EOF/cap-truncated text to a
  permissive status parser. A saved acknowledgement now requires complete
  CRLF framing within the native byte ceiling; the general status parser and
  status/META/fingerprint representations remain unchanged.
- Real tokio-rustls shutdown flushes local close-notify and shuts down the
  underlying writer; it does not wait for peer close-notify. Controlled pending
  shutdown tests qualify cleanup expiry; native TLS fixtures qualify actual
  connection/handshake/reply and cancellation behavior separately.
- A Windows fixture's standard listener clone blocked during no-second-send
  monitoring after Tokio/IOCP registration. Use bounded asynchronous accepts
  for live fixtures. The [failed preliminary gate](../../support/receipts/mail-deadlines/preliminary-fixture-failure.json)
  is retained separately from final qualification; its 15-case focused recovery
  passes after replacing the blocking monitor.
- The [parallel fixture failure](../../support/receipts/mail-deadlines/parallel-fixture-failure.json)
  records a later read-timeout assertion with only 50 ms for earlier native
  setup. Its output omitted the actual error phase, so earlier setup expiry is
  a suspected cause. Native phase tests now provide setup headroom and error
  diagnostics; paused-time exact-budget tests retain their original policies.
- CLI and Errand are the active native send consumers. Both inherit native
  defaults; Errand's new explicit options helper makes both budgets selectable.
  Its typed whole-send timeout retains the native receipt instead of discarding
  acknowledgement facts. The CLI's error formatter also retains known reply
  and fingerprint fields. Mere's adapter remains receive-only; no product send
  UI or dependency repin is required by this supplier-native slice.
- Tokio's timeout polls the operation before its timer. Native completion and
  ready-carrier read checks must also compare the absolute deadline, so a late
  ready result cannot become success. These are cooperative async deadlines;
  they cannot preempt blocking work inside a carrier's poll.
- DICT can retain its existing unusable flag before the first command I/O,
  clearing it only after a complete response. Dropping a polled future then
  leaves the session retired without introducing a shared session runtime.
  Unpolled futures and local request refusals preserve a healthy session.
- FSP has a second state boundary beyond its retry timeout: an unanswered or
  interrupted request leaves the server key uncertain. Such sessions now
  require reconnection, including after exhausted retries. Accepted `CC_ERR`
  replies update the key and remain usable, as do post-reply aggregate refusals.
- Scorpion's borrowed framed API needs one caller-owned absolute deadline
  across TLS setup and subsequent statuses. Its verifier/resumption policy
  remains unchanged. Plain TCP fetch now refuses a secure-scheme request
  before a timer/contact, matching the existing native transport contract.
- No active product client consumer was found for the standalone native APIs;
  Scorpion likewise appears only in patch plumbing. Native supplier delivery
  does not require new Errand routes or product repins.

### 2026-10-22

- Standalone DICT response accounting must span every definition block and the
  final status, counting raw bytes before dot unstuffing and every empty line.
  Announced item counts are metadata rather than allocation sizes. Receive
  refusal leaves a partial frame, so the session cannot accept another command;
  local request refusal leaves the healthy session usable.
- FSP needs a receive sentinel or OS oversize refusal: a truncated UDP packet
  may otherwise have a valid checksum and masquerade as a complete reply.
  Datagram/data/extra limits are independent of whole-file and listing limits.
  Directory padding (`SKIP`) continues at a checked offset; `END` terminates
  even after entries in the same packet. The old session conflated padding
  with an empty result and did not retain explicit completion from the parser.
- Kepler's 1024-byte URI ceiling is distinct from the request's cache/language
  fields and CRLF. The native request parser previously counted the whole line
  against that URI ceiling. Kepler/Text's old header counters omitted the
  final LF; full-wire defaults of 1025/4097 bytes preserve the complete-header
  acceptance boundaries. Their configurable limits count both CR and LF.
- `errand/src/lib.rs` routed eight schemes without a common receive budget.
  Gemini and Scroll buffered bodies without a cap; Gopher/Finger were likewise
  unbounded. Suppressing browser progress callbacks did not bound buffering.
- Nex/Spartan already exposed timeout/body options, but checked after append;
  Spartan counted header bytes against the body budget. Guppy accounted
  duplicate chunks and tested completion before checking the cap.
- Scroll's existing `ResponseLimits` constrained outgoing server encoding,
  not browser receiving. Its per-line metadata limits must retain that name
  and meaning; Gemini's protocol ceiling cannot be raised by caller options.
- Generic read defaults allow 4096 request bytes. Legacy explicit-write helpers
  add their line allowance to the caller-owned submitted body length so this
  does not accidentally impose a new 4 KiB upload limit. The options variants
  enforce their explicitly supplied total wire-request budget.
- The facade's new 64 MiB default is composition policy. Existing native Nex,
  Spartan, Guppy and Titan conveniences retain their earlier 16 MiB caps;
  explicit facade/browser options select their own budgets. Mere's existing
  64 MiB page and 32 MiB subresource policies now reach the transport directly,
  rather than implicitly inheriting those smaller native convenience defaults.
- Standalone DICT inbound lines/results, FSP aggregate file/list operations,
  Kepler and Text bodies need native/session-specific follow-ups. They are not
  Errand fetch routes and do not inherit the new facade options. Misfin already
  bounds requests/replies and uses per-step timeouts; whole-send policy remains
  a distinct mail-effect seam. Scorpion's existing unknown-length reader used
  `take(cap)`, allowing a successful truncation; correct this in its native API.
- Retinue's page helper checked size after Resource reassembly and body copy.
  Existing advertised-size/decompression limits did not cover token allocation
  from an understated plaintext size or segment append before overflow checks.
- Mere's HTTP reader enforced caps while reading, while smolweb subresources
  checked after buffering. Bodyless `RemoteFetcher` ignored its policy for
  smolweb. Existing explicit Submit guards must remain effective at every hop.

## Progress

- 2026-10-23: started phase 9 on smolweb main. Root owns native Misfin production,
  docs and qualification; bounded Luna lanes survey sibling ownership and write
  lifecycle tests. Required receipts are actual native acceptance/shutdown,
  controlled task cleanup and exact source/lock/build/Clippy results within the
  shared 100 MB cap. Existing receiving receipts and the previously blocked
  preliminary cache are preserved. Reuse `C:/t/cargo-targets/smolweb` and its
  `build` directory, with both environment variables explicitly set.

- 2026-10-23: receiving source `2a2dbac2` completes phase 8. The final combined
  gate passes 141 unit tests, 14 integration tests and one doctest, with the
  existing live Nex ignore. The ring-only server suite passes 71 tests; six
  independent feature builds, strict all-target Misfin Clippy and changed-file
  formatting pass. Twenty new controls cover fixed acceptance epochs, distinct
  step/whole timing, slow reads, blocked reply/close, completed framing, late
  storage commits and fresh budgets through the public listener. Existing
  native TLS round trip and trust/status cases remain green. The
  [receiving supplier receipt](../../support/receipts/misfin-receive-deadlines/supplier.json)
  records exact source/tree/native hashes, commands and qualification limits.
  Sending source, Cargo.lock, product pins and previous receipts are unchanged.
  New compact evidence retains 11,820 bytes. Final gates use the stable approved
  target/build directory. A preliminary lane used the wrong build-dir variable;
  its 1,234 new generated cache files (356,351,526 bytes) remain under
  `smolweb/target/build` because automatic approval review rejected both scoped
  cleanup attempts as "blocked by policy". Neither deletion ran; existing
  source/cache/evidence was preserved. The [preliminary record](../../support/receipts/misfin-receive-deadlines/preliminary.json)
  also retains the test-only Clippy failure and its correction. Admission and
  joined shutdown remain separately queued; no new Cargo home or worktree.

- 2026-10-23: started phase 8 in native Misfin. Root owns production, docs and
  qualification; two bounded Luna lanes own focused tests and read-only review.
  Required receipts are native/carrying-stream timing results, independent
  feature/Clippy checks and exact source/lock identities. Reuse the stable
  smolweb target/build directory; retain compact summaries within the shared
  100 MB cap. Admission and joined listener shutdown stay in their own lane.

- 2026-10-23: mail source `8284fc46` completes phase 7. The final combined gate
  passes 121 unit tests, 14 integration tests and one doctest, with the existing
  live Nex test ignored. Eight independent feature builds pass; the ring-only
  native client suite also passes 34 tests. Misfin passes strict all-target
  Clippy; Errand passes with the two previously recorded parser lint allowances,
  while its strict gate still reports those six unchanged diagnostics. Changed
  Rust sources pass formatting; whole-package formatting retains unrelated
  existing Errand differences. The [mail supplier receipt](../../support/receipts/mail-deadlines/supplier.json)
  records exact source/tree, native hashes, commands and the three failed
  preliminary attempts, including a corrected new CLI status-display test
  expectation. Fifteen native, five adapter and one CLI cases qualify distinct
  step/whole expiry, cancellation, receipt retention and complete framing.
  Errand forwards selectable budgets and the CLI preserves known receipt
  fields on error. Cargo.lock, mailbox receiving and earlier evidence remain
  unchanged. New compact evidence retains 16,860 bytes; the stable smolweb
  target/build directory is reused without new isolated roots.

- 2026-10-23: started the mail deadline slice. Native Misfin owns fixed send
  budgets and delivery evidence; Errand owns explicit send option forwarding.
  Existing per-step timers and server receiving policy remain distinct.
  Native fixtures, independent review and exact-source receipts share a 100 MB
  retained-byte cap using the existing stable smolweb target/build directory.

- 2026-10-23: session source `c0ef44b1` completes phase 6. The combined gate
  passes 211 unit tests, 10 integration tests and eight doctests, with 47 new
  deadline controls. Fourteen independent feature checks and strict
  all-feature/all-target Clippy pass. Native TCP/UDP/TLS fixtures complement
  paused-time, cancellation and always-ready carrier controls. The
  [session supplier receipt](../../support/receipts/session-deadlines/supplier.json)
  records exact source/tree and native hashes, toolchain, commands and scope.
  DICT/FSP retire interrupted sessions; borrowed carrier recovery remains
  caller-owned. Scorpion supports one absolute deadline across TLS and later
  responses. Existing size/framing suites remain green. The sole lock edge
  adds the already-locked `rcgen` dev dependency to Scorpion, preserving all
  registry versions/checksums. New evidence retains 12,949 bytes including its
  byte-preserving attribute; stable targets were reused without new isolated
  roots. Misfin is unchanged and mail deadlines remain phase 7.

- 2026-10-23: started session deadlines in native DICT, FSP, Kepler/Text and
  Scorpion ownership lanes. Preserve byte-only `Limits` structs, FSP's existing
  per-reply retry timing, native transport/trust boundaries and caller actor
  lifetime. A timeout must refuse success after the absolute deadline even
  when a supplied carrier stays ready. Mail remains phase 7; no Misfin edits.

- 2026-10-22: standalone source `f04b4fa3` completes phase 5. The combined
  exact-source gate passes 106 unit tests and seven doctests, ten independent
  single-crate feature checks, and strict all-feature/all-target Clippy.
  Actual localhost TCP covers DICT/Kepler/Text, UDP covers FSP, and TLS covers
  Kepler/Text; supplied carriers cover fragmented framing and early refusal.
  The [standalone supplier receipt](../../support/receipts/standalone-client-limits/supplier.json)
  records the tested tree, native source/lock hashes, commands and limits of
  qualification. The only lock delta adds existing `rcgen` dev-dependency
  edges to Kepler/Text; registry versions and checksums remain fixed. Review
  corrected Kepler's empty raw-request/zero-budget edge and retained the old
  complete-header boundaries as 1025/4097 full-wire bytes. Existing permissive
  DICT 2xx terminal-status handling remains unchanged. No product repins or
  new isolated build roots were needed. The new receipt and its byte-preserving
  attribute retain 9,442 bytes; phase 6 remains separately queued.

- 2026-10-22: started the standalone size/framing slice in three native owner
  lanes: DICT, FSP, and Kepler/Text. Existing command/URI ceilings remain
  protocol-owned; configurable byte limits include their wire framing. DICT
  budgets span a complete command, FSP budgets span all datagrams in a file or
  listing, and stream bodies refuse excess instead of returning prefixes.
  Session/mail deadlines remain explicitly queued in phase 6.

- 2026-10-22: consumer delivery is complete. Mere source `faa6f1fb3` and
  qualification `ce7b4816f` pass 48 fetch, 75 document and three original V1
  compatibility cases, minimum feature builds and production strict Clippy.
  Turnstone source `6737085d` and qualification `0283e312` compile on the exact
  published cohort and pass 78 focused checks, including independent native
  Read/Submit encoded, packed and body budgets. The two existing external-host
  and isolated R3 prerequisite tests remain ignored. Canonical receipts:
  `mere/support/receipts/client-limits/consumer.json` and
  `turnstone/support/receipts/client-limits/consumer.json`. Their source-only
  lock substitutions preserve registry versions and unrelated suppliers.
  The earlier pure-preflight timer regression and Windows held-EOF fixture
  failure are repaired and retained separately in Mere's receipt directory.
  Temporary worktrees are integrated and removed, with stable targets reused.

- 2026-10-22: routed/native matrix passes 253 tests with one existing live Nex
  test ignored, and the final focused facade suite passes 14. Actual facade
  fixtures exercise TCP Gopher/Finger/Nex/Spartan, UDP Guppy and TLS
  Gemini/Scroll/Titan. Supplied-stream cases additionally check streaming
  callback admission and accepted long Scroll metadata. Grammar-only and
  client-without-TLS feature checks pass. Scorpion's 58-case native library
  suite and strict all-target Clippy pass separately. Review corrected native
  default widening, Gopher+ token allocation before admission, and legacy
  Titan zero-budget mutation preflight. The sole lock delta is an already
  locked `rcgen` dev-dependency edge for the local TLS fixture.
- 2026-10-22: clean native supplier source `5f32366fc0e` and qualification
  `36bad79bcc0` are published. The exact shipping source passes 19 focused
  limits cases with and without compression and strict production Clippy;
  broader preliminary native evidence is separately identified. Primary I2P
  work was preserved locally and kept out of the published supplier cohort.
- 2026-10-22: final committed Errand source `1155897e` passes the complete
  254-case matrix with one existing live-network ignore. The [supplier receipt](../../support/receipts/client-limits/supplier.json)
  records per-route TCP/UDP/TLS evidence, feature graphs and command identities.
  Strict Clippy fails only on six unchanged parser style diagnostics; the same
  all-target gate passes with the two named baseline lint allowances. This is
  qualified Clippy evidence, not a blanket strict pass. The [Scorpion receipt](../../support/receipts/client-limits/scorpion.json)
  retains its separate strict/native result. Response limits do not introduce
  aggregate browser traffic/memory budgets or cap the fetch actor's task count.

- 2026-10-22: refreshed current remotes and inspected related owner plans.
  Completed read-only research lanes before assigning bounded implementation
  owners. Browser receiving, Micron hosting and snapshot V1 are prior slices;
  their receipts are preserved. Related receiving/hosting queue:
  `mere/design_docs/mere_docs/implementation_strategy/2026-10-20_shared_site_model_plan.md`;
  native Resource work:
  `retinue/design_docs/2026-08-04_smolweb_over_reticulum_plan.md`;
  product receiving:
  `turnstone/design_docs/2026-10-06_unusual_protocols_browser_plan.md`.
