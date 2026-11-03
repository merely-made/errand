# Protocol client splits

**Status (2026-11-03):** landed. S1-S3 complete; two client exceptions retired.
**Scope:** separate existing FSP/DICT client responsibilities inside their
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
