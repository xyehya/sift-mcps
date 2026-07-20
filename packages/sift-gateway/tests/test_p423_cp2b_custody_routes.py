"""P4.23 CP2B — portal/custody_routes.py acceptance tests (EC-3, EC-4).

Route-level tests drive the composed Starlette pipeline (parse -> authorize ->
domain call -> shaped response) through a real ``TestClient``, with the domain
layer (``custody.admission`` / the evidence service) replaced by fakes so no
database is required — these are the "pure-serialization/shaping" route tests;
DB-backed EC-4 coverage lives in ``custody/admission.py``'s own suite and
``test_p423_cp2b_ledger.py``'s export tests.
"""

from __future__ import annotations

from sift_gateway.custody import admission
from sift_gateway.portal.custody_routes import custody_routes_list
from starlette.applications import Starlette
from starlette.testclient import TestClient


class _ActiveCase:
    def __init__(self, case_id: str, artifact_path: str | None = None) -> None:
        self.case_id = case_id
        self.artifact_path = artifact_path


class _CaseService:
    def __init__(self, case: _ActiveCase | None) -> None:
        self._case = case

    def get_active_case(self, _principal):
        if self._case is None:
            from sift_gateway.active_case import ActiveCaseError

            raise ActiveCaseError("no_active_case", http_status=404)
        return self._case


class _EvidenceService:
    def __init__(self, inventory: list[dict]) -> None:
        self._inventory = inventory
        self.list_evidence_calls: list[str] = []

    def list_evidence(self, case_id: str):
        self.list_evidence_calls.append(case_id)
        return self._inventory


class _RaisingEvidenceService:
    def list_evidence(self, case_id: str):
        raise RuntimeError('duplicate key value violates unique constraint "x" CONTEXT: PL/pgSQL')


def _client(gateway) -> TestClient:
    app = Starlette(routes=custody_routes_list())
    app.state.gateway = gateway
    return TestClient(app, raise_server_exceptions=False)


class _Gateway:
    def __init__(self, *, case, evidence_service):
        self.control_plane_dsn = "postgresql://unused"
        self.active_case_service = _CaseService(case)
        self.evidence_service = evidence_service


def test_custody_status_buckets_ec4_correctly(monkeypatch):
    # EC-4 (route-level): a detected-only/digestless entry never lands in the
    # "sealed" bucket; only an entry the service already classified "sealed"
    # (COMMITTED version + ACTIVE manifest membership, per EvidenceAuthorityService
    # .list_evidence's EC-4-compliant join) does.
    monkeypatch.setattr(
        admission,
        "reconcile",
        lambda *a, **k: {"gate_state": "BLOCKED_PENDING", "manifest_version": 0, "issues": []},
    )
    inventory = [
        {"evidence_id": "1", "status": "sealed", "sha256": "sha256:" + "a" * 64},
        {"evidence_id": "2", "status": "detected", "sha256": None},
        {"evidence_id": "3", "status": "registered", "sha256": None},
        {"evidence_id": "4", "status": "ignored", "sha256": None},
        {"evidence_id": "5", "status": "retired", "sha256": None},
    ]
    evidence_service = _EvidenceService(inventory)
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=evidence_service))

    response = client.get("/portal/custody/status")

    assert response.status_code == 200
    body = response.json()
    assert [item["evidence_id"] for item in body["sealed"]] == ["1"]
    assert {item["evidence_id"] for item in body["pending"]} == {"2", "3"}
    assert [item["evidence_id"] for item in body["ignored"]] == ["4"]
    assert [item["evidence_id"] for item in body["retired"]] == ["5"]
    assert body["gate_state"] == "BLOCKED_PENDING"
    assert evidence_service.list_evidence_calls == ["case-1"]


def test_custody_status_without_active_case_is_shaped_not_a_stack_trace():
    client = _client(_Gateway(case=None, evidence_service=_EvidenceService([])))

    response = client.get("/portal/custody/status")

    assert response.status_code == 404
    body = response.json()
    assert set(body["error"]) == {"code", "message", "audit_id"}
    assert body["error"]["code"] == "invalid_request"
    assert body["error"]["audit_id"]  # non-empty


def test_ec3_shaped_error_never_leaks_raw_sqlstate_and_carries_a_real_audit_id(
    monkeypatch,
):
    # EC-3 fail-on-revert: an unmapped exception (here, a raw PL/pgSQL-shaped
    # message like the as-built engine leaked) is NEVER echoed verbatim; the
    # catch-all shapes it to custody_internal with a fresh, non-empty audit id.
    monkeypatch.setattr(admission, "reconcile", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_RaisingEvidenceService()))

    response = client.get("/portal/custody/status")

    assert response.status_code == 500
    body = response.json()
    error = body["error"]
    assert error["code"] == "custody_internal"
    assert error["audit_id"]
    assert error["audit_id"] != ""
    raw_diagnostics = ("SQLSTATE", "PL/pgSQL", "constraint", "CONTEXT:")
    assert not any(marker in error["message"] for marker in raw_diagnostics)


def test_custody_seal_requires_operator_identity_before_touching_seal_module():
    # No request.state.identity is set (no auth middleware in this minimal app),
    # so _operator_session() is None and the route must shape a 401 without ever
    # importing/calling into custody.seal (which would raise NotImplementedError
    # from CP2A's still-frozen stub if reached).
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_EvidenceService([])))

    response = client.post(
        "/portal/custody/seal",
        json={"phase": "begin", "idempotency_key": "k1", "password": "pw", "reason": "why"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_request"


def test_custody_seal_rejects_malformed_body_as_invalid_request():
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_EvidenceService([])))

    response = client.post("/portal/custody/seal", content=b"not json")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
