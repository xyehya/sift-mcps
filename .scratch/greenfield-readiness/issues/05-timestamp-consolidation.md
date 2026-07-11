# 05 — Consolidate timestamp parsing performance work

**What to build:** deliver one maintainable timestamp parsing path for portal hot loops, preserving invalid-value semantics and proving the performance claim without adopting duplicate PR implementations.

**Blocked by:** 01 — Reconcile the current-main CI baseline.

**Status:** completed — integrated as `726cce0`; final combined-batch review remains.

- [ ] Use PR #48 as the centralization reference and preserve PR #47's invalid-value behavior.
- [ ] Test string, numeric, Date, invalid, and ordering cases; add a repeatable benchmark.
- [ ] Rebuild the bundle and run frontend lint and focused tests.
- [ ] Apply CodeGuard web/input-validation guidance; do not mutate GitHub PR state.
