"""P4.23 CP3 — Portal custody Refresh: single reconcile trigger + pure reads.

Two established defects this file locks down:

1. **Directory bug (round 1):** ``classify_inventory_entries(case_dir)`` appends
   ``/evidence`` itself, so a caller that passes an already-suffixed evidence
   directory made the scanner open ``.../evidence/evidence`` -> ``OSError`` ->
   ``None`` -> ``BLOCKED_UNAVAILABLE``. The one operator-Refresh reconcile trigger
   is ``portal.custody_routes.custody_status`` (``GET /portal/custody/status``); it
   must hand ``admission.reconcile`` the BARE case directory, exactly as the MCP
   dispatch caller does.

2. **Triple-reconcile (final fix):** one operator Refresh must perform EXACTLY ONE
   reconciliation. Reconciliation lives in ONE place — the target custody-status
   route. ``EvidenceAuthorityService.gate_status`` / ``list_evidence`` are PURE DB
   reads (``admission.gate_state`` + PostgreSQL projection); they can never scan
   disk or append an ``app.admission_observations`` row. This makes it structurally
   impossible for the passive 15s poll (or any future read caller) to reconcile.

The fast tests below run without a database (the reconcile primitive is spied so
the REAL canonical scanner runs on the captured directory). The DSN-gated
integration test proves the end-to-end population against real PostgreSQL.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sift_core.execute.evidence_binding import classify_inventory_entries
from sift_gateway.custody import admission
from sift_gateway.portal.custody_routes import custody_routes_list
from sift_gateway.portal_services import EvidenceAuthorityService
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# Shared: a real temp case directory with a staged evidence file, and a spy that
# runs the REAL canonical scanner on whatever directory the caller hands it AND
# counts how many times reconciliation was triggered.
# ---------------------------------------------------------------------------
def _staged_case_dir(tmp_path: Path, filename: str = "img.E01") -> Path:
    """Create ``<case>/evidence/<filename>`` and return the BARE case dir."""
    case_dir = tmp_path / "case-test-2-07202033"
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / filename).write_bytes(b"\x00" * 16)
    return case_dir


def _make_reconcile_spy(captured: dict) -> object:
    """Replace ``admission.reconcile`` with a spy that COUNTS calls, captures the
    directory argument, and derives the gate from the REAL scanner run on it —
    faithfully reproducing reconcile's directory-driven ``storage_available``
    branch without a database."""

    def spy(case_id, case_dir, dsn, *, trigger="dispatch", correlation_id=None):
        captured["count"] = captured.get("count", 0) + 1
        captured["case_id"] = case_id
        captured["case_dir"] = case_dir
        captured["trigger"] = trigger
        entries = classify_inventory_entries(str(case_dir)) if case_dir else None
        captured["entries"] = entries
        if entries is None:
            result = admission._blocked(
                "BLOCKED_UNAVAILABLE",
                [admission._GATE_ISSUE["BLOCKED_UNAVAILABLE"]],
            )
        elif any(e["entry_kind"] == "regular" for e in entries):
            result = admission._gate_result("BLOCKED_PENDING", 0)
        else:
            result = admission._gate_result("OPEN", 0)
        captured["gate_state"] = result["gate_state"]
        return result

    return spy


def _assert_scanned_real_evidence_dir(captured: dict, filename: str = "img.E01") -> None:
    """The decisive directory-fix assertions."""
    passed = str(captured["case_dir"]).replace("\\", "/")
    # A revert to the double-suffix hands reconcile ``.../evidence`` and the
    # canonical scanner then opens ``.../evidence/evidence``.
    assert not passed.endswith("/evidence"), (
        f"caller pre-appended /evidence; scanner will double it: {passed}"
    )
    assert captured["entries"] is not None, "scanner saw an unavailable directory"
    assert any(e["display_name"] == filename for e in captured["entries"])
    assert any(e["display_path"] == f"evidence/{filename}" for e in captured["entries"])
    assert captured["gate_state"] == "BLOCKED_PENDING"
    assert captured["trigger"] == "refresh"


def _gate_state_stub(counter: dict, state: str = "BLOCKED_PENDING"):
    """Stub ``admission.gate_state`` (the pure computed-gate reader) — records use
    and returns a real GateResult without touching disk or the DB."""

    def stub(case_id, dsn):
        counter["gate_state"] = counter.get("gate_state", 0) + 1
        return admission._gate_result(state, 0)

    return stub


# ---------------------------------------------------------------------------
# Fakes for the post-read DB projection in the two EvidenceAuthorityService
# methods (the reconcile trigger is entirely upstream of these pure reads).
# ---------------------------------------------------------------------------
class _FakeCursor:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, *_a, **_k):
        return None

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeConn:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def cursor(self):
        return _FakeCursor(self._rows)

    def commit(self):
        return None


# ---------------------------------------------------------------------------
# Route harness (mirrors test_p423_cp2b_custody_routes.py Layer 1).
# ---------------------------------------------------------------------------
_EXAMINER_PRINCIPAL = {
    "principal_type": "operator",
    "principal_id": "22222222-2222-2222-2222-222222222222",
    "system_role": "operator",
    "status": "active",
    "case_memberships": [],
}


class _ActiveCase:
    def __init__(self, case_id: str, artifact_path: str | None) -> None:
        self.case_id = case_id
        self.artifact_path = artifact_path


class _CaseService:
    def __init__(self, case: _ActiveCase) -> None:
        self._case = case

    def get_active_case(self, _principal):
        return self._case


class _EvidenceService:
    """Fixed inventory for the route's projection; records list_evidence calls so a
    test can prove the route reads pending/sealed but never itself reconciles."""

    def __init__(self, inventory: list[dict]) -> None:
        self._inventory = inventory
        self.calls: list[str] = []

    def list_evidence(self, case_id: str):
        self.calls.append(case_id)
        return self._inventory


class _Gateway:
    def __init__(self, case: _ActiveCase, evidence_service: _EvidenceService) -> None:
        self.control_plane_dsn = "postgresql://unused"
        self.active_case_service = _CaseService(case)
        self.evidence_service = evidence_service


class _StampRoleMiddleware:
    def __init__(self, app, *, role: str = "examiner") -> None:
        self.app = app
        self._role = role

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            from starlette.requests import Request

            request = Request(scope)
            request.state.role = self._role
            request.state.principal = _EXAMINER_PRINCIPAL
        await self.app(scope, receive, send)


def _client(gateway: _Gateway) -> TestClient:
    app = Starlette(
        routes=custody_routes_list(),
        middleware=[Middleware(_StampRoleMiddleware, role="examiner")],
    )
    app.state.gateway = gateway
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# The single reconcile trigger — the target custody-status route.
# ---------------------------------------------------------------------------
def test_custody_status_route_is_the_single_reconcile_trigger(tmp_path, monkeypatch):
    """``GET /portal/custody/status`` reconciles EXACTLY ONCE, against the BARE
    case directory, and renders Pending — this is the one operator Refresh
    reconciliation trigger (SPEC pre-seal staging)."""
    case_dir = _staged_case_dir(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(captured))

    inventory = [
        {"evidence_id": "1", "display_path": "evidence/img.E01", "status": "detected"},
    ]
    evidence_service = _EvidenceService(inventory)
    gateway = _Gateway(
        case=_ActiveCase("case-1", artifact_path=str(case_dir)),
        evidence_service=evidence_service,
    )
    response = _client(gateway).get("/status")

    assert response.status_code == 200
    assert captured["count"] == 1  # exactly one reconciliation for one Refresh
    _assert_scanned_real_evidence_dir(captured)
    body = response.json()
    assert body["gate_state"] == "BLOCKED_PENDING"
    assert [item["evidence_id"] for item in body["pending"]] == ["1"]
    assert body["sealed"] == []
    assert evidence_service.calls == ["case-1"]  # route reads once, does not scan


# ---------------------------------------------------------------------------
# The legacy read methods can NEVER reconcile (structural prevention). A revert
# that reintroduces a reconcile switch/call here fails these.
# ---------------------------------------------------------------------------
def test_gate_status_is_a_pure_read_and_never_reconciles(monkeypatch):
    counter: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(counter))
    monkeypatch.setattr(admission, "gate_state", _gate_state_stub(counter))
    monkeypatch.setattr(
        EvidenceAuthorityService,
        "_connect",
        lambda self: _FakeConn([("evidence/img.E01",)]),
    )

    service = EvidenceAuthorityService("postgresql://unused")
    result = service.gate_status("case-1")

    assert counter.get("count", 0) == 0  # never scanned/persisted
    assert counter.get("gate_state", 0) == 1  # pure computed-gate read
    assert result["gate_state"] == "BLOCKED_PENDING"
    assert result["unregistered"] == ["evidence/img.E01"]


def test_list_evidence_is_a_pure_read_and_never_reconciles(monkeypatch):
    counter: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(counter))
    detected_row = (
        "id-1", "img.E01", "evidence/img.E01", None, None, "detected",
        None, None, None, None, None,
    )
    monkeypatch.setattr(
        EvidenceAuthorityService, "_connect", lambda self: _FakeConn([detected_row])
    )

    service = EvidenceAuthorityService("postgresql://unused")
    inventory = service.list_evidence("case-1")

    assert counter.get("count", 0) == 0  # never scanned/persisted
    assert [item["display_path"] for item in inventory] == ["evidence/img.E01"]
    assert inventory[0]["status"] == "detected"


def test_one_operator_refresh_reconciles_exactly_once(tmp_path, monkeypatch):
    """The composed operator Refresh: ONE target custody-status request performs
    the sole reconciliation, and the subsequent passive legacy reads add ZERO. A
    regression that reconciles inside gate_status/list_evidence (the round-2
    triple-reconcile bug) drives the count above one and fails here."""
    case_dir = _staged_case_dir(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(captured))
    # Separate dict for the gate_state stub — the reconcile spy stores a string
    # under "gate_state", so the pure-read stub must not share that counter.
    monkeypatch.setattr(admission, "gate_state", _gate_state_stub({}))
    monkeypatch.setattr(
        EvidenceAuthorityService, "_case_artifact_path", lambda self, cid: case_dir
    )
    monkeypatch.setattr(EvidenceAuthorityService, "_connect", lambda self: _FakeConn([]))

    # Step 1 — the target route: the ONE reconciliation.
    gateway = _Gateway(
        case=_ActiveCase("case-1", artifact_path=str(case_dir)),
        evidence_service=_EvidenceService([]),
    )
    assert _client(gateway).get("/status").status_code == 200
    assert captured["count"] == 1

    # Steps 2-3 — the passive legacy reads: ZERO additional reconciliations.
    service = EvidenceAuthorityService("postgresql://unused")
    service.gate_status("case-1")
    service.list_evidence("case-1")
    assert captured["count"] == 1  # still exactly one for the whole Refresh


# ---------------------------------------------------------------------------
# End-to-end proof against real PostgreSQL (DSN-gated, integration).
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_refresh_on_real_case_dir_yields_pending_not_unavailable(tmp_path):
    """Highest seam, real DB: reconciling a real temp case directory with
    ``evidence/<file>`` (as the target route does) then reading via the PURE
    service methods yields Pending/unregistered — never BLOCKED_UNAVAILABLE and
    never an empty success."""
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for the CP3 refresh integration test")

    import psycopg

    case_dir = _staged_case_dir(tmp_path)
    case_id = str(uuid.uuid4())
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "insert into app.cases(id, case_key, title, status, legacy_case_dir) "
            "values (%s, %s, 'CP3 refresh test', 'active', %s)",
            (case_id, "cp3-refresh-" + uuid.uuid4().hex[:12], str(case_dir)),
        )

    # The one reconciliation the operator Refresh performs (via the target route
    # in production; the underlying primitive here). Reads afterwards are pure.
    gate = admission.reconcile(case_id, str(case_dir), dsn, trigger="refresh")
    assert gate["gate_state"] == "BLOCKED_PENDING"

    service = EvidenceAuthorityService(dsn)

    gate_read = service.gate_status(case_id)  # pure read
    assert gate_read["gate_state"] != "BLOCKED_UNAVAILABLE"
    assert gate_read["gate_state"] == "BLOCKED_PENDING"
    assert "evidence/img.E01" in gate_read["unregistered"]

    inventory = service.list_evidence(case_id)  # pure read
    by_path = {item["display_path"]: item for item in inventory}
    assert "evidence/img.E01" in by_path
    assert by_path["evidence/img.E01"]["seal_status"] == "unsealed"
