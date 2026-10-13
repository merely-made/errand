# smolweb Documentation Index

Rust policy (2026-10-13): working toolchain 1.99.0 and shared MSRV 1.97.1, qualified separately. Canonical policy: `mere/design_docs/2026-08-12_family_composition_thesis_brief.md`, section "Shared Rust toolchain and minimum version".

The canonical index for `smolweb/design_docs/`, per [`DOC_POLICY.md`](DOC_POLICY.md)
§6. If any other index disagrees with this file, this file wins.

Founded 2026-08-24, when the canonical policy core was distributed across the
workspace and the spec-level documents were repatriated here from mere.

## Required reading order

1. The workspace [`README.md`](../README.md) — what the thirteen crates are and
   what the workspace is for.
2. [`DOC_POLICY.md`](DOC_POLICY.md) — the shared core plus this repo's addendum,
   which states what belongs here and what belongs to genet.
3. [smolweb_home_decision](technical_architecture/2026-08-03_smolweb_home_decision.md)
   — the boundary rule itself, and the record of how the extraction ran.

## technical_architecture/

- [smolweb_home_decision](technical_architecture/2026-08-03_smolweb_home_decision.md)
  (**decided by Mark 2026-08-03**, and the governing document for this
  workspace's scope. Spec-accurate wire and grammar implementations belong
  here; enrichment, lowering and rendering stay in genet or the cambium view
  layer. Also carries **the grouping rule** — a superset successor shares its
  ancestor's crate, a format its protocol defines lives with that protocol, and
  a different protocol answering the same question gets a feature rather than a
  crate — made safe by the cost being feature-gated rather than crate-gated, so
  every grammar is dependency-free and always compiled while every transport
  rides a feature. Records the executed moves: `gopher-protocol`,
  `finger-protocol`, `gemini-protocol` and `scroll-protocol` published, errand
  down from 2786 to 1612 lines with a re-export shield that left downstream
  untouched. Also: serving was always in scope and there is to be **no
  `smolnet` sibling**; the composition layer is errand, feature-gated, with the
  content source a trait rather than a path. **Still open**: the nex
  de-duplication, and nematic's scroll engine still reading `text/scroll`
  through gemtext.)

## research/

- [protocol_carrier_independence](research/2026-08-04_protocol_carrier_independence.md)
  (analysis answering how many smolweb protocols could run over Reticulum and
  what all seventeen would cost. Companion to the home decision; the lane it
  would feed is Turnstone's Reticulum browsing plan, cited by path.)

## What is not here

Implementation-side material — the AST lowerings, capture, rendering, theming,
trust chrome, and the knot composition work — belongs to genet and mere. Per
core §5 those are cited by path rather than copied. They were repatriated to
genet on 2026-08-24, alongside the component areas for inker and verso-tile,
and now live at:

- `genet/design_docs/nematic_docs/implementation_strategy/` — the polyglot knot
  design, the knot evaluation/export plan, the polyglot block resolver plan,
  the native smolweb rendering plan, and the smolweb fidelity plan. Their
  disposition is tracked in phase C of
  `mere/design_docs/mere_docs/implementation_strategy/2026-08-24_doc_policy_consolidation_plan.md`.

## Working principles

- **Never guess a wire format.** This workspace has declined three times
  (gopher's introductory page, terse, and scroll before its spec surfaced).
  State where a spec was read; "blocked on a dead host" is a legitimate
  recorded state.
- **Record spec provenance, including when the spec calls itself speculative.**
  The durable copy of a protocol spec is as likely to live in an interoperating
  client's repository as on its author's host.
- **Feature-gate the transport, not the grammar.** A renderer parsing a
  gophermap must not pull an async runtime. Verify the dependency tree under
  `--no-default-features` per crate rather than assuming it.
- **The crate names are held in stewardship**, not owned. They belong morally
  to the protocols' communities, and `misfin` transfers to its author on
  request.

## Status

Founded 2026-08-24 with two documents. Thin by design — this workspace's
primary documentation is its crate READMEs and the specs themselves.
