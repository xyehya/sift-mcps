# 03 — Surface trustworthy CommitDrawer failures

**What to build:** let portal operators see sanitized, actionable CommitDrawer failures for authorization, capacity, and generic server errors instead of a misleading password-only message.

**Blocked by:** 01 — Reconcile the current-main CI baseline.

**Status:** completed — integrated as `3f670d0`; final combined-batch review remains.

- [ ] Cover 403, 429, 503, and generic failure handling end to end in the portal/API boundary.
- [ ] Preserve the portal's frozen public contracts and render only sanitized text.
- [ ] Rebuild the committed portal bundle and run frontend lint plus focused tests.
- [ ] Apply CodeGuard web/authentication/privacy guidance and report the verdict.
