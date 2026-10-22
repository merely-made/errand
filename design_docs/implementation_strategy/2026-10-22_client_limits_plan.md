# Client receive limits

**Status (2026-10-22):** routed clients and native Micron limits implemented;
browser receiving qualification in progress. Standalone session follow-ups in
phase 5 remain open.

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

Work on the clean smolweb and Turnstone main checkouts. Retinue's existing
I2P work was merged with the upstream Signalman receiving change without
dropping either. Mere's active publication/index work requires the isolated
`Code/worktrees/mere-client-limits` checkout; integrate and remove it after
publication. Reuse the existing stable repository Cargo targets. Required
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
5. Follow with standalone native/session contracts. DICT needs bounded inbound
   lines, definition/result aggregates and an operation deadline. FSP needs
   bounded file/list aggregation and checked offsets, retaining its datagram
   retries. Kepler/Text need bounded request/header/body and whole-operation
   deadlines; Kepler must also refuse short declared bodies. Scorpion needs a
   caller deadline around its existing session/framing API. Misfin's existing
   per-step deadlines stay distinct from whole-send policy. Done when each
   owner's exact-fit/overflow/timeout tests qualify that API; routed Errand
   evidence cannot close this phase.

## Findings (2026-10-22)

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

- 2026-10-22: refreshed current remotes and inspected related owner plans.
  Completed read-only research lanes before assigning bounded implementation
  owners. Browser receiving, Micron hosting and snapshot V1 are prior slices;
  their receipts are preserved. Related receiving/hosting queue:
  `mere/design_docs/mere_docs/implementation_strategy/2026-10-20_shared_site_model_plan.md`;
  native Resource work:
  `retinue/design_docs/2026-08-04_smolweb_over_reticulum_plan.md`;
  product receiving:
  `turnstone/design_docs/2026-10-06_unusual_protocols_browser_plan.md`.
