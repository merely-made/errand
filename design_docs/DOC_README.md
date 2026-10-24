# Errand documentation

Preserve host-owned authority, existing formats and independent crate feature boundaries. Read [documentation policy](DOC_POLICY.md) before editing.

Canonical migration and current receipts: `mere/design_docs/mere_docs/implementation_strategy/2026-10-19_family_promotion_plan.md`.

- [Native Scroll response and connection exchange](implementation_strategy/2026-10-21_native_scroll_server_plan.md): bounded native reply encoding and an optional host-owned stream exchange, with Knot as the existing consumer.
- [Client receive limits](implementation_strategy/2026-10-22_client_limits_plan.md): routed/native limits, six TCP listener lifecycles and Guppy inline shutdown are qualified; caller-owned Scroll/Scorpion exchange stop companions are in progress.
