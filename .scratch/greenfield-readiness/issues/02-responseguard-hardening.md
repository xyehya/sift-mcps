# 02 — Harden ResponseGuard redaction coverage

**What to build:** make agent-visible output consistently redact the intended modern OpenAI key formats while constraining false positives and preserving existing redaction semantics.

**Blocked by:** 01 — Reconcile the current-main CI baseline.

**Status:** completed — integrated with review remediation as `c2305cd`; live agent-facing proof remains blocked on the VM window.

- [ ] Review PR #44 as a small defense-in-depth change, including the external prefix feedback.
- [ ] Add positive, negative, and boundary tests that fail if intended redaction regresses or the matcher becomes overly broad.
- [ ] Validate gateway lint, targeted Pyright, focused tests, relevant gateway suite, and CodeGuard security review.
- [ ] Produce an integration-ready branch only; do not merge, comment on, or close GitHub work without authorization.
