# Errand

Small-web protocols and scheme-routed client/server integration, continuing the Smolweb repository.

This repository preserves the implementation history promoted from Mere on 2026-10-19. Crates retain their names, APIs, licenses and selectable features.

Canonical migration: `mere/design_docs/mere_docs/implementation_strategy/2026-10-19_family_promotion_plan.md`.

| Crate | Source |
|---|---|
| `dict-protocol` | [crates/dict-protocol](crates/dict-protocol) |
| `errand` | [crates/errand](crates/errand) |
| `finger-protocol` | [crates/finger-protocol](crates/finger-protocol) |
| `fsp-protocol` | [crates/fsp-protocol](crates/fsp-protocol) |
| `gemini-protocol` | [crates/gemini-protocol](crates/gemini-protocol) |
| `gopher-protocol` | [crates/gopher-protocol](crates/gopher-protocol) |
| `guppy-protocol` | [crates/guppy-protocol](crates/guppy-protocol) |
| `kepler-protocol` | [crates/kepler-protocol](crates/kepler-protocol) |
| `misfin` | [crates/misfin](crates/misfin) |
| `nex-protocol` | [crates/nex-protocol](crates/nex-protocol) |
| `scorpion-protocol` | [crates/scorpion-protocol](crates/scorpion-protocol) |
| `scroll-protocol` | [crates/scroll-protocol](crates/scroll-protocol) |
| `spartan-protocol` | [crates/spartan-protocol](crates/spartan-protocol) |
| `text-protocol` | [crates/text-protocol](crates/text-protocol) |

Run `cargo test --workspace` for default library coverage. Optional network, GPU, external model and host acceptance have separate gates. No registry release is implied by this source promotion.

The protocol crates retain their MIT licenses and stewardship offers to protocol authors. Errand retains MPL-2.0; see `crates/errand/LICENSE`. Protocol wire behavior and grammars remain independently consumable.
