"""BATCH-K6 — B-MVP-17 decision: pre-context denial audit path (MVP behavior).

Decision (resolves B-MVP-17 for the MVP): denials raised BEFORE an authority
context can attach — active-case-lookup denials and tool-scope authorization
denials — are recorded on the existing local audit-mirror path with
``status="denied"`` and are NOT projected into ``app.audit_events``. The K1
``AuditEnvelopeMiddleware`` is the only DB-audit write path and covers allowed
calls and post-context (proxy / evidence-gate) denials.

Rationale: a pre-context denial occurs before a principal/case is authoritatively
resolved, so projecting it into the case-scoped ``app.audit_events`` would write
unattributable rows (null/foreign case_id, unmapped principal) and expose a DB
write path to unauthenticated/unauthorized callers. Denied attempts remain
auditable via the local mirror + Gateway logs. A hardened DB projector (with
sound principal attribution) is deferred to BATCH-V1.

This test locks that contract: the active-case denial path audits to the mirror
with status "denied" and never reaches the DB audit writer.
"""

from __future__ import annotations

import asyncio

from sift_gateway.policy_middleware import CaseContextMiddleware


class _AuditRecorder:
    def __init__(self):
        self.calls = []

    def log(self, **kwargs):
        self.calls.append(kwargs)


class _FakeGateway:
    """Gateway stub exposing only the local audit mirror — no DB audit writer."""

    def __init__(self):
        self._audit = _AuditRecorder()


def test_precontext_denial_audits_to_mirror_not_db():
    gateway = _FakeGateway()
    mw = CaseContextMiddleware(gateway)

    asyncio.run(mw._audit_denial("evidence_seal", None, "no active case for principal"))

    assert len(gateway._audit.calls) == 1
    call = gateway._audit.calls[0]
    assert call["tool"] == "evidence_seal"
    assert call["source"] == "gateway_active_case"
    assert call["extra"]["status"] == "denied"
    assert "no active case" in call["extra"]["denial_reason"]
    # MVP contract: the pre-context denial path uses the local mirror only; the
    # gateway stub has no DB audit writer and none is required for this path.
    assert not hasattr(gateway, "_db_audit")
