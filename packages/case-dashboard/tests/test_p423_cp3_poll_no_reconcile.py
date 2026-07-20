"""P4.23 CP3 round 2 — passive chain-status/evidence polling must not reconcile.

Live proof: the global Portal poll (``useDataPolling.js``) calls
``GET /portal/api/evidence/chain/status`` every 15s. That route
(``get_evidence_chain_status`` — documented "No mutation") funnels into
``_db_evidence_chain_status`` -> ``EvidenceAuthorityService.gate_status`` +
``list_evidence``, each of which reconciled on every call — so passive polling
grew ``app.admission_observations`` continuously, violating SPEC §Pre-seal
staging window ("no continuous observation… reconciliation occurs on operator
Refresh or agent dispatch") and the route's own "No mutation" contract.

Fix (CP3 r2, query-param intent): the passive read path does NOT reconcile; only
an explicit operator Refresh (``?refresh=1``) threads ``reconcile=True`` down to
the evidence service. These route-seam tests assert the reconcile INTENT the route
forwards to the injected evidence adapter — the passive poll never requests a
scan, and ``?refresh=1`` always does. A revert to unconditional reconcile fails
the passive assertions.
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
    """Records the ``reconcile`` intent the route forwards on each call."""

    def __init__(self):
        self.gate_reconcile: list[bool] = []
        self.list_reconcile: list[bool] = []

    def gate_status(self, case_id, *, reconcile=False):
        self.gate_reconcile.append(reconcile)
        return {
            "seal_status": "unsealed",
            "gate_state": "BLOCKED_PENDING",
            "manifest_version": 0,
            "issues": [],
            "unregistered": ["evidence/img.E01"],
        }

    def list_evidence(self, case_id, *, reconcile=False):
        self.list_reconcile.append(reconcile)
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


def test_chain_status_passive_read_does_not_reconcile(client, evidence_db):
    resp = client.get("/api/evidence/chain/status")
    assert resp.status_code == 200
    # The passive 15s poll path must request NO reconciliation.
    assert evidence_db.gate_reconcile == [False]
    assert evidence_db.list_reconcile == [False]


def test_chain_status_explicit_refresh_reconciles(client, evidence_db):
    resp = client.get("/api/evidence/chain/status?refresh=1")
    assert resp.status_code == 200
    body = resp.json()
    # Explicit operator Refresh reconciles AND still populates the legacy Add & Seal
    # state (the unregistered list the frontend file_specs seal contract consumes).
    assert evidence_db.gate_reconcile == [True]
    assert evidence_db.list_reconcile == [True]
    assert body["unregistered"] == ["evidence/img.E01"]


def test_get_evidence_passive_read_does_not_reconcile(client, evidence_db):
    resp = client.get("/api/evidence")
    assert resp.status_code == 200
    assert evidence_db.list_reconcile == [False]


def test_get_evidence_explicit_refresh_reconciles(client, evidence_db):
    resp = client.get("/api/evidence?refresh=1")
    assert resp.status_code == 200
    assert evidence_db.list_reconcile == [True]
    assert [e["path"] for e in resp.json()] == ["evidence/img.E01"]
