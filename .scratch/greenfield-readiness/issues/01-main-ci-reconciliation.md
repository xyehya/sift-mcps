# 01 — Reconcile the current-main CI baseline

**What to build:** restore a green, truthful `main` baseline by aligning static checks and the sandbox-transition test with the committed relay architecture, without weakening capability dropping or test coverage.

**Blocked by:** None — can start immediately.

**Status:** completed — integrated as `3b3c4f6`; local full suite, full Pyright, Ruff, two-axis review, and CodeGuard review passed.

- [ ] Resolve the two current Ruff import-order failures.
- [ ] Make the Phase 6 transition test assert the relay-based security contract rather than the obsolete sudo transport, retaining a fail-on-revert assertion for the capability-dropping path.
- [ ] Run the CI-equivalent lint, targeted gateway tests, gateway type checks, and full suite; record any pre-existing failures separately.
- [ ] Perform a CodeGuard review using Python, shell, infrastructure, secrets, and MCP security guidance; confirm the gateway security model remains satisfied.
