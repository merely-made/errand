# Errand documentation

Preserve host-owned authority, existing formats and independent crate feature boundaries. Read [documentation policy](DOC_POLICY.md) before editing.

Canonical migration and current receipts: `mere/design_docs/archive_docs/2026-10-28/2026-10-19_family_promotion_plan.md` (archived 2026-10-28).

- [Native Scroll response and connection exchange](implementation_strategy/2026-10-21_native_scroll_server_plan.md): bounded native reply encoding and an optional host-owned stream exchange, with Knot as the existing consumer.
- [Client receive limits](implementation_strategy/2026-10-22_client_limits_plan.md): routed/native limits, six TCP listener lifecycles, Guppy inline shutdown and caller-owned Scroll/Scorpion exchange stop companions are qualified.

- [Protocol client splits](implementation_strategy/2026-11-03_client_splits_plan.md): qualified FSP exchange, DICT command, Gemini connection and Scorpion response splits; four exceptions retired with policy and feature boundaries preserved.

## Working principles

- **Protocol session refactors (2026-11-03):** qualify a source move with
  the existing controlled-carrier deadline/cancellation and aggregate-limit
  fixtures, plus the routed receiver. Feature-off codec checks preserve the
  independent wire layer; client-only builds separately verify that carrier
  users do not acquire native TLS dependencies. Keep one original Session
  state across private impl modules so moving commands cannot restart an operation budget.
  The [client splits plan](implementation_strategy/2026-11-03_client_splits_plan.md)
  records the concrete FSP/DICT boundaries and qualification scope.
