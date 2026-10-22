# Native Scroll response and connection exchange

**Status (2026-10-21):** landed; supplier and Knot encoder adoption qualified. Existing Knot publication is the forcing
consumer. This slice adds a native protocol seam; governed resident Scroll
hosting remains a later Mere/Djinn gate.

## Ownership and scope

`scroll-protocol` owns spec-shaped request/response encoding and a single
bounded transaction over a supplied stream. The caller owns TLS, certificates,
binding, acceptance, connection tasks, authorization and content selection.
Errand's generic `Source` is unchanged. Snapshot V1, Eidetic retention and Gemot
collection authority are unchanged. The wire crate retains its existing MIT
license; implement using its existing grammar and types, with Knot behavior as
a compatibility reference rather than transplanting its MPL listener.

The supplier lane owns `crates/scroll-protocol` source, focused tests, feature
configuration and its README. The coordinator owns plans/indexes, commits,
receipts and Knot adoption. Work directly on main while these file sets do not
collide. Reuse `C:/t/cargo-targets/smolweb` and
`C:/t/cargo-targets/knot-editor`; no new isolated Cargo home. Retain compact
source/test results only, under a shared 100 MB cap across this orchestration.

## Phases and done-conditions

1. Add an always-available typed reply encoder over existing `Header` and
   `SuccessHeader`, with caller-selected header/body bounds. Done when literal
   full and abstract fixtures preserve UDC, MIME/language, all three metadata
   lines, Unicode and CRLF bytes; invalid status/header combinations, header
   injection, unsupported bodies and excess lengths refuse before wire output.
2. Add an optional asynchronous single-connection exchange over caller-owned
   `AsyncRead + AsyncWrite`. Done when strict bounded request framing passes
   ordered language preferences and the abstract flag intact, malformed and
   oversized envelopes refuse, the host timeout covers the exchange, and
   cancellation leaves no spawned work. A listener and TLS are outside this API.
3. Adopt the encoder in Knot's existing blocking TLS publication path. Done
   when saved full/abstract responses are byte-identical to the donor fixtures,
   existing local TLS replacement/stop cases pass and snapshot fixtures stay
   unchanged. Pin the published supplier coherently at the consumer's active
   roots, preserving renderer and unrelated suppliers. Record narrow exact
   source/lock identities rather than implying a new resident acceptance gate.

## Findings (2026-10-21)

- `wire.rs` already owns request parsing, ordered language preferences, abstract
  requests, status parsing and native success metadata. `client.rs` already
  exchanges over a supplied stream. The crate lacks a response encoder and
  server transaction API at the existing `dce1f085` consumer pin.
- Knot's `Publication::response` currently constructs native Scroll wire bytes
  itself, while `ScrollServer` owns a local blocking TLS loop. Keeping that
  owner in place lets the shared encoder be adopted without a runtime rewrite.
- Knot currently serves one declared page language per path and ignores the
  request's preference order when selecting content. Preserve that behavior
  during extraction. Variant selection and fallback need a separate content
  rule; exposing request preferences to a handler does not supply that rule.
- Generic Errand `SourceRequest` and `Item` omit Scroll's native request and
  response metadata. A native seam avoids inventing a universal metadata bag.
  Existing TCP listeners in other protocol crates are not evidence that every
  accepted task joins on shutdown.

## Progress

- 2026-10-21: three read-only lanes mapped serving, effects/sessions and browser
  integration. Supplier code at local `50702b440` matches pinned `dce1f085`
  throughout `crates`. Selected this bounded Scroll extraction first. Broader
  owner queues and future resident gates remain canonical in
  `mere/design_docs/mere_docs/implementation_strategy/2026-10-20_shared_site_model_plan.md`.
- 2026-10-21: supplier feature gates pass: no features 32 unit tests plus one
  doctest; server-only 38 plus one; server/client and all features each 43 plus
  two. Strict all-targets no-deps Clippy passes. Feature-gated client import and
  TLS documentation now compile without TLS; a pre-existing test-only useless
  `format!` is simplified. No lock change or new isolated resource is required.
  [Supplier receipt](../../support/receipts/native-scroll-server/supplier.json).
- 2026-10-21: supplier `3d2ce3a5` and Knot receiver `02c5a2d` are published.
  The two original donor tests pass unchanged within the 22-case standalone
  publication/history suite, including actual trusted local TLS. The ordinary
  root check and strict library/bin Clippy pass. Author-byte and accepted long
  timestamp regressions preserve existing model acceptance. All non-Errand Git
  suppliers stay fixed; the older transitive Errand behind Knot's existing Mere
  cohort remains explicitly scoped. Consumer evidence:
  `knot-editor/support/receipts/native-scroll-server/consumer.json`.
  Native governed Scroll residency and browser MIME receiving remain separate.
