# 06 — Complete mediated OpenSearch case scoping

**What to build:** ensure remaining active OpenSearch tool access uses the case-scoped boundary, while a repo-wide raw-client guard prevents silent bypasses and keeps agent-visible surface contracts intact.

**Blocked by:** 01 — Reconcile the current-main CI baseline.

**Status:** completed locally — integrated through `c9f0b65`, independently reviewed. The field-catalog resource fails closed without resource-read active-case propagation; this is a usability concern, not a demonstrated cross-case exposure. Live cross-case proof remains ticket 07.

- [ ] Identify and migrate remaining active access paths, allowing only documented and justified exceptions.
- [ ] Add a deliberate-revert regression that proves the guard works and agent-facing surface tests for active-case binding.
- [ ] Validate lint, targeted Pyright, focused and relevant suites; separately report legacy diagnostics.
- [ ] Apply CodeGuard Python/MCP/authentication/data-security guidance and reconcile against the gateway security model.
