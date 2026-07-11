# 08 — Fresh-VM OpenCTI golden-path acceptance

**What to build:** prove the committed shared-target installer path from a fresh VM through manifest registration, least-privilege gateway querying, core isolation, and idempotent reinstall.

**Blocked by:** 01 — Reconcile the current-main CI baseline; 02 — Harden ResponseGuard redaction coverage; human-prepared fresh VM.

**Status:** blocked

- [ ] Deploy a recorded exact source revision, clear caches, restart the four services, and execute the canonical golden-path acceptance runbook.
- [ ] Validate env-ref-only registration, agent-facing query, no case-search exposure, credential denial, core health during OpenCTI outage, and uninstall/reinstall.
- [ ] Record before/after evidence and state any unavailable proof explicitly.
