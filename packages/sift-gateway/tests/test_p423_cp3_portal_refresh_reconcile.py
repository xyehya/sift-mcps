"""P4.23 CP3 — Portal custody Refresh reconciliation directory fix.

The demonstrated CP3 Gate CUSTODY failure: on a fresh case, clicking **Refresh
custody status** produced success toasts but the Portal stayed at *Sealed
Evidence (0 files)* / *No evidence files registered* with Add & Seal disabled,
and a direct ``GET /portal/custody/status`` returned ``BLOCKED_UNAVAILABLE`` /
"The canonical evidence directory is unavailable" — even though the two staged
files existed under the canonical evidence directory.

Root cause: ``classify_inventory_entries(case_dir)`` appends ``/evidence``
itself (the single canonical scanner), but the three Portal callers of
``custody.admission.reconcile`` —
``EvidenceAuthorityService.gate_status`` (legacy ``/api/evidence/chain/status``),
``EvidenceAuthorityService.list_evidence`` (legacy ``/api/evidence``), and
``portal.custody_routes.custody_status`` (target ``/portal/custody/status``) —
each passed an *already-suffixed* evidence directory, so the scanner opened
``.../evidence/evidence`` (nonexistent) -> ``OSError`` -> ``None`` ->
``storage_available=False`` -> ``BLOCKED_UNAVAILABLE``. The MCP dispatch caller
(``policy_middleware`` -> ``check_evidence_gate_db`` -> ``reconcile``) passes the
BARE case directory and was always correct; the fix aligns the three Portal
callers with it.

These are fail-on-revert tests through the highest Portal/Gateway seam: each
caller must hand ``reconcile`` a directory that the REAL ``classify_inventory_
entries`` resolves to the populated ``evidence/`` directory (finds the staged
file), NOT a doubled path (which returns ``None`` -> ``BLOCKED_UNAVAILABLE``). A
revert to the old ``/evidence``-suffixed argument fails every one deterministically
and without a database. The DSN-gated integration test at the bottom proves the
same end-to-end against real PostgreSQL: a real temp case directory with
``evidence/<file>`` yields Pending/unregistered after Refresh, not unavailable.
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
# runs the REAL canonical scanner on whatever directory the caller hands it.
# ---------------------------------------------------------------------------
def _staged_case_dir(tmp_path: Path, filename: str = "img.E01") -> Path:
    """Create ``<case>/evidence/<filename>`` and return the BARE case dir."""
    case_dir = tmp_path / "case-test-2-07202033"
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / filename).write_bytes(b"\x00" * 16)
    return case_dir


def _make_reconcile_spy(captured: dict) -> object:
    """Replace ``admission.reconcile`` with a spy that captures the directory
    argument and derives the gate from the REAL scanner run on it — faithfully
    reproducing reconcile's directory-driven ``storage_available`` branch without
    a database. Everything downstream sees a genuine GateResult shape."""

    def spy(case_id, case_dir, dsn, *, trigger="dispatch", correlation_id=None):
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
    """The decisive fail-on-revert assertions, shared by all three callers."""
    passed = str(captured["case_dir"]).replace("\\", "/")
    # A revert to the double-suffix hands reconcile ``.../evidence`` and the
    # canonical scanner then opens ``.../evidence/evidence``.
    assert not passed.endswith("/evidence"), (
        f"caller pre-appended /evidence; scanner will double it: {passed}"
    )
    # The REAL scanner resolved the populated evidence directory and found the
    # staged file — proving the caller handed reconcile the bare case dir.
    assert captured["entries"] is not None, "scanner saw an unavailable directory"
    assert any(e["display_name"] == filename for e in captured["entries"])
    assert any(e["display_path"] == f"evidence/{filename}" for e in captured["entries"])
    # ...and therefore the gate is not the spurious BLOCKED_UNAVAILABLE.
    assert captured["gate_state"] == "BLOCKED_PENDING"
    assert captured["trigger"] == "refresh"


# ---------------------------------------------------------------------------
# Fakes for the post-reconcile DB read in the two EvidenceAuthorityService
# methods (the directory bug is entirely upstream of these reads).
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
    """Returns a fixed inventory (the route's pending bucket is built from it —
    the directory fix under test is about what reconcile scans, not this list)."""

    def __init__(self, inventory: list[dict]) -> None:
        self._inventory = inventory

    def list_evidence(self, _case_id: str):
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
# Fail-on-revert tests — no database.
# ---------------------------------------------------------------------------
def test_gate_status_scans_bare_case_dir_and_reports_unregistered(tmp_path, monkeypatch):
    """Legacy ``/api/evidence/chain/status`` seam (drives Add & Seal via the
    ``unregistered`` list): gate_status must scan the real evidence dir, not
    ``.../evidence/evidence``."""
    case_dir = _staged_case_dir(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(captured))
    monkeypatch.setattr(
        EvidenceAuthorityService, "_case_artifact_path", lambda self, cid: case_dir
    )
    # Post-reconcile read: the detected file surfaces as an unregistered entry.
    monkeypatch.setattr(
        EvidenceAuthorityService,
        "_connect",
        lambda self: _FakeConn([("evidence/img.E01",)]),
    )

    service = EvidenceAuthorityService("postgresql://unused")
    # Explicit operator Refresh path (reconcile=True) — the only read that scans.
    result = service.gate_status("case-1", reconcile=True)

    _assert_scanned_real_evidence_dir(captured)
    assert result["gate_state"] == "BLOCKED_PENDING"
    assert result["unregistered"] == ["evidence/img.E01"]


def test_list_evidence_scans_bare_case_dir(tmp_path, monkeypatch):
    """Legacy ``/api/evidence`` seam: list_evidence must reconcile against the
    real evidence dir so the detected file is not lost to a phantom-unavailable
    scan."""
    case_dir = _staged_case_dir(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(captured))
    monkeypatch.setattr(
        EvidenceAuthorityService, "_case_artifact_path", lambda self, cid: case_dir
    )
    # One detected-only row (no version, no manifest membership) — the pending
    # shape a fresh Refresh produces.
    detected_row = (
        "id-1", "img.E01", "evidence/img.E01", None, None, "detected",
        None, None, None, None, None,
    )
    monkeypatch.setattr(
        EvidenceAuthorityService, "_connect", lambda self: _FakeConn([detected_row])
    )

    service = EvidenceAuthorityService("postgresql://unused")
    # Explicit operator Refresh path (reconcile=True) — the only read that scans.
    inventory = service.list_evidence("case-1", reconcile=True)

    _assert_scanned_real_evidence_dir(captured)
    assert len(inventory) == 1
    item = inventory[0]
    assert item["display_path"] == "evidence/img.E01"
    assert item["status"] == "detected"
    assert item["seal_status"] == "unsealed"


def test_custody_status_route_scans_bare_case_dir(tmp_path, monkeypatch):
    """Target ``/portal/custody/status`` seam: the route must reconcile against
    the real evidence dir, so Refresh returns Pending, not BLOCKED_UNAVAILABLE."""
    case_dir = _staged_case_dir(tmp_path)
    captured: dict = {}
    monkeypatch.setattr(admission, "reconcile", _make_reconcile_spy(captured))

    inventory = [
        {"evidence_id": "1", "display_path": "evidence/img.E01", "status": "detected"},
    ]
    gateway = _Gateway(
        case=_ActiveCase("case-1", artifact_path=str(case_dir)),
        evidence_service=_EvidenceService(inventory),
    )
    client = _client(gateway)

    response = client.get("/status")

    assert response.status_code == 200
    body = response.json()
    _assert_scanned_real_evidence_dir(captured)
    assert body["gate_state"] == "BLOCKED_PENDING"
    # The target route's own shape uses ``pending`` (vs the legacy ``unregistered``).
    assert [item["evidence_id"] for item in body["pending"]] == ["1"]
    assert body["sealed"] == []


# ---------------------------------------------------------------------------
# Passive-read must NOT reconcile (CP3 round 2 poll-mutation fix) — no database.
# The 15s chain-status poll and the operator Refresh call the SAME endpoints;
# only Refresh (reconcile=True) may scan/persist. A revert that reconciles on the
# default path would regrow app.admission_observations on every poll.
# ---------------------------------------------------------------------------
def _reconcile_counter(counter: dict):
    def spy(*_a, **_k):
        counter["reconcile"] = counter.get("reconcile", 0) + 1
        raise AssertionError("passive read must not reconcile")

    return spy


def _gate_state_stub(counter: dict, state: str = "BLOCKED_PENDING"):
    def stub(case_id, dsn):
        counter["gate_state"] = counter.get("gate_state", 0) + 1
        return admission._gate_result(state, 0)

    return stub


def test_gate_status_passive_read_does_not_reconcile(monkeypatch):
    counter: dict = {}
    monkeypatch.setattr(admission, "reconcile", _reconcile_counter(counter))
    monkeypatch.setattr(admission, "gate_state", _gate_state_stub(counter))
    monkeypatch.setattr(
        EvidenceAuthorityService,
        "_connect",
        lambda self: _FakeConn([("evidence/img.E01",)]),
    )

    service = EvidenceAuthorityService("postgresql://unused")
    result = service.gate_status("case-1")  # default: passive

    assert counter.get("reconcile", 0) == 0  # never scanned/persisted
    assert counter.get("gate_state", 0) == 1  # pure computed-gate read
    assert result["gate_state"] == "BLOCKED_PENDING"
    assert result["unregistered"] == ["evidence/img.E01"]


def test_list_evidence_passive_read_does_not_reconcile(monkeypatch):
    counter: dict = {}
    monkeypatch.setattr(admission, "reconcile", _reconcile_counter(counter))
    detected_row = (
        "id-1", "img.E01", "evidence/img.E01", None, None, "detected",
        None, None, None, None, None,
    )
    monkeypatch.setattr(
        EvidenceAuthorityService, "_connect", lambda self: _FakeConn([detected_row])
    )

    service = EvidenceAuthorityService("postgresql://unused")
    inventory = service.list_evidence("case-1")  # default: passive

    assert counter.get("reconcile", 0) == 0  # never scanned/persisted
    assert [item["display_path"] for item in inventory] == ["evidence/img.E01"]
    assert inventory[0]["status"] == "detected"


# ---------------------------------------------------------------------------
# End-to-end proof against real PostgreSQL (DSN-gated, integration).
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_refresh_on_real_case_dir_yields_pending_not_unavailable(tmp_path):
    """Highest seam, real DB: a real temp case directory with ``evidence/<file>``
    yields Pending/unregistered after Refresh — never BLOCKED_UNAVAILABLE and
    never an empty success — through both the legacy service methods and the
    target route's reconciliation."""
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

    service = EvidenceAuthorityService(dsn)

    gate = service.gate_status(case_id, reconcile=True)
    assert gate["gate_state"] != "BLOCKED_UNAVAILABLE"
    assert gate["gate_state"] == "BLOCKED_PENDING"
    assert "evidence/img.E01" in gate["unregistered"]

    inventory = service.list_evidence(case_id, reconcile=True)
    by_path = {item["display_path"]: item for item in inventory}
    assert "evidence/img.E01" in by_path
    assert by_path["evidence/img.E01"]["seal_status"] == "unsealed"
