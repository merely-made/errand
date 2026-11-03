# Protocol client splits

**Status (2026-11-03):** landed. S1-S5 complete; four client exceptions retired.
**Scope:** separate existing FSP, DICT, Gemini and Scorpion client responsibilities inside their
crates under Mere stack.1 and stack.7. Preserve native wire formats, public
session methods, limits, operation deadlines and cancellation behavior.

## Phases

- **S1. FSP exchange.** Keep connection/policy and file/directory aggregation
  in `client`; isolate request sequencing, retries and accepted-reply/key
  settlement in a private exchange implementation. Move the three existing
  fixture groups to child files with the same test module paths.
  Done when every resulting source is at most 600 lines, the existing
  reliability/limits/operation tests pass and the exception is retired.
- **S2. DICT commands.** Keep session construction, bounded framing and
  deadline/poisoning state in `client`; isolate dictionary commands as a
  private impl on the existing Session. Preserve the external limits/deadline
  fixture locations and move only the inline command fixtures.
  Done when public methods and refusal/trailer behavior are preserved,
  existing tests pass and the exception is retired without another exemption.
- **S3. Qualification.** Compare the baseline tests with the moved code;
  exercise Errand's receiving bounds, feature-off codecs and public docs;
  run the full local hook gate. Commit and push main with a compact receipt.
  Done when the source review, tests and ceiling prove the split while
  keeping manifests, lock, protocol policies and receiving behavior intact.

- **S4. Gemini connection setup.** Keep stream exchanges, response data and
  caller options in `client`; move TCP/TLS fetch and TOFU connection setup to
  a private module behind the same TLS feature. Re-export existing public
  functions and Titan's crate-private connector at their current paths.
  Done when native/Titan/receiver tests and no-TLS client checks pass,
  all resulting files fit the ceiling and the exception is removed.
- **S5. Scorpion response bodies.** Keep public exchanges, absolute-deadline
  wrappers and TCP helpers in `client`; isolate bounded header/body reads,
  including exact, unknown-length and partial-range handling.
  Done when existing framing/deadline tests pass, public paths and codecs
  remain available, the full gate passes and the exception is retired.

## Decisions

No new ruling. Mark requested another repository with useful responsibility
splits. These are internal modules in the existing protocol crates, not new
crate or transport abstractions. Existing byte/deadline policy stays under
[the client limits plan](2026-10-22_client_limits_plan.md).

## Findings

- 2026-11-03: FSP's session implements both UDP request/reply reliability
  and multi-block file/directory aggregation. Key settlement and the
  interrupted-session marker must move together with the exchange body.
- 2026-11-03: DICT's typed commands sit above existing session framing and
  whole-operation budgets. The private command impl can reuse the original
  session fields/helpers without adding a second budget or changing callers.
- Required receipts: before/after native tests, receiving-limit tests,
  feature-off codec check, docs and full local gate. Total retained cap:
  100 MB, compact text appended to
  `archive_docs/receipts/2026-11-03_client_splits_plan_receipts.md`.

## Progress

- 2026-11-03: selected FSP and DICT in the clean Smolweb checkout. The native
  baseline passes 78 unit tests and three doctests across the two crates.
- 2026-11-03: S1-S2 implemented. FSP's exchange retains the same retry,
  accepted-key and in-flight transitions; dictionary operations remain on
  the same DICT Session with its original framing/deadline helpers. All
  original test function names and Session field declarations are preserved.
  The same 78 unit tests and three doctests pass after the move; Errand's
  14 receiving-bound tests also pass. S3's remaining feature/docs/local
  gates and publication follow.
- 2026-11-03: S3 passes the codec-only wasm check, public docs with broken
  intra-doc links denied, and the full local ceiling/all-feature Clippy gate.
  All eight resulting source files are below 600 lines. Both exceptions
  are retired without replacements; eleven unrelated exceptions remain.
  Public Session APIs, wire format, caller policy and deadline/cancellation
  behavior are preserved. Qualification and publication are recorded in
  the appended receipt carried by this commit.
- 2026-11-03: Mark requested another continuation. S4-S5 select Gemini's
  native connection seam and Scorpion's bounded response reader. The Gemini
  connector is also used by Titan; its crate-private path must be preserved.
  The Scorpion range is a frame boundary and must not consume a subsequent
  status line. The pre-edit native feature baseline is running.
- 2026-11-03: S4-S5 implemented. Gemini's eight public TLS entry points
  and crate-private Titan connector retain their client paths. Scorpion's
  response reader keeps exact/unknown/range rules below unchanged absolute
  deadline wrappers. The original 143 native test/doctest cases pass before
  and after, and Errand's 14 receiving tests pass. Client-only (no TLS) and
  codec-only wasm builds pass. Public docs and full gate are next.
- 2026-11-03: S4-S5 passed public docs with broken intra-doc links denied
  and the complete local ceiling/all-feature Clippy gate. Together with
  native/Titan fixtures, Errand receiving bounds and the no-TLS/codec-only
  checks, this qualifies the two source moves. Four exceptions have now
  retired in this plan, with nine older entries remaining. All six files
  in the Gemini/Scorpion split are below 600 lines; APIs, feature boundaries,
  TOFU policy and response framing are preserved. Source and compact
  appended receipts are committed together and pushed to main.
