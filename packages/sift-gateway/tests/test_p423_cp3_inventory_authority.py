"""P4.23 CP3 round 2 — reconciled-inventory authority for the Pending list.

Live VM proof after CP3 round 1 showed ``/portal/custody/status`` correctly
flipped BLOCKED_UNAVAILABLE -> BLOCKED_PENDING, but ``pending=[]`` /
``unregistered=[]`` / evidence ``[]`` — so the Portal still rendered *Sealed
Evidence (0)* with Add & Seal unavailable. Root cause: ``app.custody_reconcile``
upserts the on-disk snapshot into ``app.evidence_inventory`` (never
``app.evidence_objects`` — EC-1/EC-4), but ``EvidenceAuthorityService.gate_status``
selected ``unregistered`` from ``evidence_objects`` status detected/registered
(a status that no longer exists in the target model) and ``list_evidence`` read
only ``evidence_objects``. Both returned empty on a freshly reconciled case.

These integration tests drive the REAL SQL against a real migrated PostgreSQL
(DSN-gated, mirroring ``test_p423_cp2b_portal_services.py``) and prove the round-2
requirements end to end:

1. fresh inventory-only regular rows become ``gate_status.unregistered`` and
   ``list_evidence`` status detected/unsealed, and ``/portal/custody/status``
   ``pending``;
2. an ignored inventory row is not an Add & Seal ``unregistered`` target but
   surfaces as its own ``ignored`` state;
3. a sealed object is never duplicated as Pending even though the inventory still
   contains the same path (present-on-disk truth);
4. active-case isolation;
5. the current route/wire shapes and the legacy frontend contract stay usable;
   and the CP3 round-2 poll-mutation invariant — a passive (non-reconcile) read
   never appends an ``app.admission_observations`` row.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sift_gateway.portal.custody_routes import custody_routes_list
from sift_gateway.portal_services import EvidenceAuthorityService
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# DSN gate + fixtures (mirror test_p423_cp2b_portal_services.py).
# ---------------------------------------------------------------------------
def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for the CP3 inventory-authority tests")
    return dsn


def _jsonb(value):
    from psycopg.types.json import Jsonb

    return Jsonb(value)


def _staged_case_dir(tmp_path: Path, *filenames: str) -> Path:
    """Create ``<case>/evidence/<file>`` for each name; return the BARE case dir."""
    case_dir = tmp_path / ("case-" + uuid.uuid4().hex[:8])
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    for name in filenames:
        (evidence_dir / name).write_bytes(b"\x00" * 32)
    return case_dir


def _new_case(cur, *, case_dir: Path | None = None) -> str:
    case_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.cases(id, case_key, title, status, legacy_case_dir) "
        "values (%s, %s, 'CP3 inventory-authority test', 'active', %s)",
        (case_id, "cp3-inv-" + uuid.uuid4().hex[:12], str(case_dir) if case_dir else None),
    )
    return case_id


def _new_operator(cur) -> str:
    operator_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.operator_profiles(id, display_name) values (%s, 'CP3 Inv Test Operator')",
        (operator_id,),
    )
    return operator_id


def _seal_one_object(cur, *, case_id: str, actor_user_id: str, display_path: str) -> None:
    """Drive the REAL custody_seal_begin -> _protect -> _commit RPC chain so the
    sealed object/version/manifest_membership are genuinely COMMITTED — exactly
    what an operator Add & Seal produces (copied from the CP2B EC-4 fixture)."""
    idempotency_key = "seal-" + uuid.uuid4().hex[:12]
    reason = "CP3 inventory-authority fixture"
    targets = [display_path]
    request_digest = "sha256:" + "a" * 64

    cur.execute("select app.custody_reauth_binding(%s, %s, %s)", (idempotency_key, reason, targets))
    (binding,) = cur.fetchone()

    reauth_id = str(uuid.uuid4())
    cur.execute(
        """
        insert into app.audit_events
          (id, case_id, event_type, actor_type, actor_user_id, source, status, summary, details)
        values (%s, %s, 'reauth.evidence_seal', 'user', %s, 'portal_reauth', 'success',
                'CP3 fixture reauth', %s)
        """,
        (reauth_id, case_id, actor_user_id, _jsonb({"binding": binding})),
    )

    cur.execute(
        "select id from app.custody_seal_begin(%s, %s, %s, %s, %s, %s, %s, false, null)",
        (case_id, idempotency_key, request_digest, reason, reauth_id, _jsonb(targets), actor_user_id),
    )
    (operation_id,) = cur.fetchone()

    sha256 = "sha256:" + "b" * 64
    prepared_facts = {
        "items": [
            {
                "display_path": display_path,
                "sha256": sha256,
                "bytes": 4096,
                "mode": "0644",
                "immutable": True,
                "st_nlink": 1,
            }
        ]
    }
    cur.execute(
        "select phase from app.custody_seal_protect(%s, %s, %s, null)",
        (operation_id, _jsonb(prepared_facts), actor_user_id),
    )
    items = prepared_facts["items"]
    cur.execute(
        "select phase from app.custody_seal_commit(%s, %s, %s, null)",
        (operation_id, _jsonb(items), "cp3-test-examiner"),
    )
    (final_phase,) = cur.fetchone()
    assert final_phase == "COMMITTED"


def _observation_count(cur, case_id: str) -> int:
    cur.execute(
        "select count(*) from app.admission_observations where case_id = %s", (case_id,)
    )
    return int(cur.fetchone()[0])


# ---------------------------------------------------------------------------
# Compact real-service route harness for the /portal/custody/status seam.
# ---------------------------------------------------------------------------
_PRINCIPAL = {"principal_type": "operator", "system_role": "operator", "status": "active"}


class _ActiveCase:
    def __init__(self, case_id: str, artifact_path: str) -> None:
        self.case_id = case_id
        self.artifact_path = artifact_path


class _CaseService:
    def __init__(self, case: _ActiveCase) -> None:
        self._case = case

    def get_active_case(self, _principal):
        return self._case


class _Gateway:
    def __init__(self, *, dsn: str, case: _ActiveCase) -> None:
        self.control_plane_dsn = dsn
        self.active_case_service = _CaseService(case)
        self.evidence_service = EvidenceAuthorityService(dsn)


class _StampRoleMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            from starlette.requests import Request

            request = Request(scope)
            request.state.role = "examiner"
            request.state.principal = _PRINCIPAL
        await self.app(scope, receive, send)


def _route_client(dsn: str, case_id: str, case_dir: Path) -> TestClient:
    app = Starlette(
        routes=custody_routes_list(),
        middleware=[Middleware(_StampRoleMiddleware)],
    )
    app.state.gateway = _Gateway(dsn=dsn, case=_ActiveCase(case_id, str(case_dir)))
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Requirement 1 — fresh pending surfaces through every seam.
# ---------------------------------------------------------------------------
def test_fresh_inventory_surfaces_as_pending_everywhere(tmp_path):
    dsn = _dsn()
    import psycopg

    case_dir = _staged_case_dir(tmp_path, "img.E01")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur, case_dir=case_dir)

    service = EvidenceAuthorityService(dsn)

    gate = service.gate_status(case_id, reconcile=True)
    assert gate["gate_state"] == "BLOCKED_PENDING"
    assert gate["unregistered"] == ["evidence/img.E01"]

    inventory = service.list_evidence(case_id, reconcile=True)
    by_path = {i["display_path"]: i for i in inventory}
    assert set(by_path) == {"evidence/img.E01"}
    item = by_path["evidence/img.E01"]
    assert item["status"] == "detected"
    assert item["seal_status"] == "unsealed"
    assert item["current_sha256"] is None and item["current_bytes"] is None
    # Requirement 5: the exact wire keys the legacy get_evidence/_db_evidence_
    # chain_status consumers key off are all present.
    assert {
        "evidence_id", "display_name", "display_path", "description", "source",
        "status", "seal_status", "current_sha256", "current_bytes",
        "manifest_version", "registered_at", "sealed_at",
    } <= set(item)

    client = _route_client(dsn, case_id, case_dir)
    body = client.get("/status").json()
    assert body["gate_state"] == "BLOCKED_PENDING"
    assert [i["display_path"] for i in body["pending"]] == ["evidence/img.E01"]
    assert body["sealed"] == []


# ---------------------------------------------------------------------------
# Requirement 2 — ignored inventory rows are not Add & Seal targets.
# ---------------------------------------------------------------------------
def test_ignored_inventory_row_is_not_unregistered_but_surfaces_ignored(tmp_path):
    dsn = _dsn()
    import psycopg

    case_dir = _staged_case_dir(tmp_path, "keep.raw", "ignore.raw")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur, case_dir=case_dir)
        # Populate inventory (reconcile), then operator-ignore one entry. The
        # ignore disposition is preserved across later reconciliations.
        EvidenceAuthorityService(dsn).gate_status(case_id, reconcile=True)
        cur.execute(
            "update app.evidence_inventory set disposition = 'ignored' "
            "where case_id = %s and display_path = 'evidence/ignore.raw'",
            (case_id,),
        )

    service = EvidenceAuthorityService(dsn)
    gate = service.gate_status(case_id, reconcile=True)
    assert gate["unregistered"] == ["evidence/keep.raw"]  # ignored excluded

    inventory = {i["display_path"]: i for i in service.list_evidence(case_id, reconcile=True)}
    assert inventory["evidence/keep.raw"]["status"] == "detected"
    assert inventory["evidence/ignore.raw"]["status"] == "ignored"

    client = _route_client(dsn, case_id, case_dir)
    body = client.get("/status").json()
    assert [i["display_path"] for i in body["pending"]] == ["evidence/keep.raw"]
    assert [i["display_path"] for i in body["ignored"]] == ["evidence/ignore.raw"]


# ---------------------------------------------------------------------------
# Requirement 3 — a sealed object is never duplicated as Pending.
# ---------------------------------------------------------------------------
def test_sealed_object_is_not_duplicated_as_pending(tmp_path):
    dsn = _dsn()
    import psycopg

    case_dir = _staged_case_dir(tmp_path, "sealed.raw", "pending.raw")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur, case_dir=case_dir)
        actor = _new_operator(cur)
        _seal_one_object(cur, case_id=case_id, actor_user_id=actor, display_path="evidence/sealed.raw")

    service = EvidenceAuthorityService(dsn)
    # Reconcile: both files are on disk, so both land in evidence_inventory — but
    # sealed.raw must NOT also appear as Pending.
    gate = service.gate_status(case_id, reconcile=True)
    assert gate["unregistered"] == ["evidence/pending.raw"]

    inventory = service.list_evidence(case_id, reconcile=True)
    rows_by_path: dict[str, list[dict]] = {}
    for i in inventory:
        rows_by_path.setdefault(i["display_path"], []).append(i)
    # sealed.raw appears exactly once, sealed — never a second Pending row.
    assert len(rows_by_path["evidence/sealed.raw"]) == 1
    assert rows_by_path["evidence/sealed.raw"][0]["status"] == "sealed"
    assert rows_by_path["evidence/sealed.raw"][0]["seal_status"] == "sealed"
    assert len(rows_by_path["evidence/pending.raw"]) == 1
    assert rows_by_path["evidence/pending.raw"][0]["status"] == "detected"

    client = _route_client(dsn, case_id, case_dir)
    body = client.get("/status").json()
    assert [i["display_path"] for i in body["sealed"]] == ["evidence/sealed.raw"]
    assert [i["display_path"] for i in body["pending"]] == ["evidence/pending.raw"]


# ---------------------------------------------------------------------------
# Requirement 4 — active-case isolation.
# ---------------------------------------------------------------------------
def test_pending_is_active_case_scoped(tmp_path):
    dsn = _dsn()
    import psycopg

    dir_a = _staged_case_dir(tmp_path, "a.raw")
    dir_b = _staged_case_dir(tmp_path, "b.raw")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_a = _new_case(cur, case_dir=dir_a)
        case_b = _new_case(cur, case_dir=dir_b)

    service = EvidenceAuthorityService(dsn)
    service.gate_status(case_a, reconcile=True)
    service.gate_status(case_b, reconcile=True)

    gate_a = service.gate_status(case_a, reconcile=True)
    assert gate_a["unregistered"] == ["evidence/a.raw"]
    paths_a = {i["display_path"] for i in service.list_evidence(case_a, reconcile=True)}
    assert paths_a == {"evidence/a.raw"}  # never leaks case B's b.raw


# ---------------------------------------------------------------------------
# Requirement 5 (poll-mutation invariant) — passive reads never reconcile.
# ---------------------------------------------------------------------------
def test_passive_reads_do_not_grow_admission_observations(tmp_path):
    dsn = _dsn()
    import psycopg

    case_dir = _staged_case_dir(tmp_path, "img.E01")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur, case_dir=case_dir)

        service = EvidenceAuthorityService(dsn)
        # One explicit Refresh reconciles (appends exactly one observation).
        service.gate_status(case_id, reconcile=True)
        baseline = _observation_count(cur, case_id)
        assert baseline >= 1

        # Passive reads (the 15s poll path) must NOT append observations or scan.
        for _ in range(3):
            g = service.gate_status(case_id)  # default: passive
            assert g["gate_state"] == "BLOCKED_PENDING"
            assert g["unregistered"] == ["evidence/img.E01"]  # last snapshot, still surfaced
            service.list_evidence(case_id)  # default: passive
        assert _observation_count(cur, case_id) == baseline

        # A further explicit Refresh does append exactly one more (proving the
        # counter above is live, not a dead assertion).
        service.gate_status(case_id, reconcile=True)
        assert _observation_count(cur, case_id) == baseline + 1
