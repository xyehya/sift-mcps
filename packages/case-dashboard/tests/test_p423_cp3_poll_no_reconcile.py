"""P4.23 CP3 — the legacy chain-status/evidence routes are PURE reads.

Reconciliation lives in exactly one place: the target custody-status route
(``GET /portal/custody/status``). The legacy Portal reads that the global 15s
poll and the on-mount read hit —

    GET /portal/api/evidence/chain/status   (get_evidence_chain_status)
    GET /portal/api/evidence                (get_evidence)

— must NEVER trigger reconciliation: no disk scan, no ``app.evidence_inventory``
upsert, no ``app.admission_observations`` row. They forward NO reconcile intent
to the evidence adapter, and a ``?refresh=1`` query is inert (the switch was
removed). A revert that re-threads ``reconcile=True`` into the adapter — the
round-2 triple-reconcile bug — records the kwarg here and fails.
"""

from __future__ import annotations

import secrets

import case_dashboard.routes as routes_mod
import pytest
from _supabase_reauth_harness import ReauthFakeSupabaseAuth, set_operator_session
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_CASE_ID = "11111111-1111-1111-1111-111111111111"


class _FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "cp3-poll-test"}

    def get_active_case(self, principal=None):
        return self._Case()


class _RecordingEvidenceDB:
    """Records the exact kwargs the route forwards. A pure read forwards none;
    the only accepted call shape is ``(case_id)`` with no reconcile switch."""

    def __init__(self):
        self.gate_calls: list[dict] = []
        self.list_calls: list[dict] = []

    def gate_status(self, case_id, **kwargs):
        self.gate_calls.append(dict(kwargs))
        return {
            "seal_status": "unsealed",
            "gate_state": "BLOCKED_PENDING",
            "manifest_version": 0,
            "issues": [],
            "unregistered": ["evidence/img.E01"],
        }

    def list_evidence(self, case_id, **kwargs):
        self.list_calls.append(dict(kwargs))
        return [
            {
                "evidence_id": "1",
                "display_name": "img.E01",
                "display_path": "evidence/img.E01",
                "status": "detected",
                "seal_status": "unsealed",
                "current_sha256": None,
                "current_bytes": None,
            }
        ]


@pytest.fixture()
def evidence_db():
    return _RecordingEvidenceDB()


@pytest.fixture()
def client(evidence_db, tmp_path, monkeypatch):
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path / "passwords")
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        active_case_service=_FakeActiveCases(),
        evidence_service=evidence_db,
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app, raise_server_exceptions=True)
    set_operator_session(c, _SECRET)
    return c


def _no_reconcile(calls: list[dict]) -> bool:
    return all("reconcile" not in kw or kw["reconcile"] is False for kw in calls)


def test_chain_status_is_a_pure_read(client, evidence_db):
    resp = client.get("/api/evidence/chain/status")
    assert resp.status_code == 200
    assert evidence_db.gate_calls and _no_reconcile(evidence_db.gate_calls)
    assert evidence_db.list_calls and _no_reconcile(evidence_db.list_calls)


def test_chain_status_refresh_query_is_inert(client, evidence_db):
    """The removed ``?refresh`` switch must not resurrect reconciliation."""
    resp = client.get("/api/evidence/chain/status?refresh=1")
    assert resp.status_code == 200
    assert _no_reconcile(evidence_db.gate_calls)
    assert _no_reconcile(evidence_db.list_calls)
    body = resp.json()
    # Still populates the legacy Add & Seal state from the last reconciled snapshot.
    assert body["unregistered"] == ["evidence/img.E01"]


def test_get_evidence_is_a_pure_read(client, evidence_db):
    resp = client.get("/api/evidence")
    assert resp.status_code == 200
    assert evidence_db.list_calls and _no_reconcile(evidence_db.list_calls)


def test_get_evidence_refresh_query_is_inert(client, evidence_db):
    resp = client.get("/api/evidence?refresh=1")
    assert resp.status_code == 200
    assert _no_reconcile(evidence_db.list_calls)
    assert [e["path"] for e in resp.json()] == ["evidence/img.E01"]
