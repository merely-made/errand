# Source splits: H5 Smolweb batch

**Status (2026-11-03):** landed; 9/9 paths qualified.
**Scope:** the nine remaining Smolweb ceiling exceptions, under Mere's
house-style H5 target of 50 additional files. The earlier four client
splits do not count toward this batch or H5.

## Phases

- **S1. Library and client boundaries.** Separate Errand/feed/Gopher/Guppy
  runtime code from its existing regression fixtures; preserve exported
  paths and mutable state. Extract Text's existing feature-gated inline
  client module into its ordinary source home.
- **S2. Misfin receiving and deadline fixtures.** Separate receive
  transaction/framing and TLS verifier responsibilities from listener
  lifecycle. Group large client/server deadline fixtures by receipt and
  native-TLS behavior, retaining shared setup and assertions.
- **S3. Routed receiving fixtures and qualification.** Separate existing
  controlled streaming cases from the multi-protocol integration root.
  Run the same workspace/feature tests and full local gate, then publish.

Each phase is done when its original files and resulting modules fit the
600-line ceiling, their obsolete exceptions are retired, existing public
APIs and test semantics are preserved, and appropriate gates pass. S3 also
requires all nine paths to be pushed and recorded in the aggregate H5
receipt at `mere/design_docs/archive_docs/receipts/2026-10-30_house_style_plan_receipts.md`.

## Decisions

No new ruling. Mark requested 50 additional oversize files; ordinary
responsibility and fixture-group splits implement that request. Protocol
limits, deadlines, lifecycle and cryptographic policy remain unchanged.

## Findings

- 2026-11-03: the nine remaining exceptions include separate library,
  client, server and regression-fixture responsibilities. Misfin's receive
  loop and permissive TLS certificate request must retain dispatch/identity
  checks, and shutdown still owns and joins accepted work.
- Evidence: baseline/post workspace tests, codec/feature checks where
  relevant, source review, ceiling and full local gate. Total lane cap:
  100 MB across repos; compact receipts only, appended to
  `archive_docs/receipts/2026-11-03_source_splits_plan_receipts.md`.

## Progress

- 2026-11-03: H5 Smolweb batch selected in the clean checkout. Full-feature
  workspace baseline is running before source edits.

- 2026-11-03: S1–S3 landed: all nine paths and children fit the ceiling; fixtures, feature checks, public docs and the full local gate pass. Nine exceptions retired.
