"""P4.23 CP3 — reconciled-inventory authority + current-manifest-only rendering.

Two authority defects this file locks down against a real migrated PostgreSQL
(DSN-gated, mirroring ``test_p423_cp2b_portal_services.py``):

1. **Pending authority:** ``app.custody_reconcile`` writes the on-disk snapshot to
   ``app.evidence_inventory`` (never ``app.evidence_objects`` — EC-1/EC-4).
   ``gate_status.unregistered`` / ``list_evidence`` must project Pending / Ignored
   from that inventory (mirroring ``app.custody_gate_state``), while Sealed /
   Retired come from ``evidence_objects``.

2. **Current-manifest-only rendering (reviewer failure 2):** ``list_evidence``
   must render each Evidence Object at most ONCE, and Sealed only when its current
   Evidence Version is an ACTIVE member of the case's LATEST Manifest Version. A
   join to every historical ACTIVE membership fanned a carried-forward object into
   multiple rows; the multi-manifest test below (Seal v1, Seal v2 carry-forward,
   Retire v3) proves one row per object and correct Retired rendering.

Reconciliation is triggered exactly as production does — the target custody-status
route calls ``admission.reconcile`` once — and the reads afterwards are PURE.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sift_gateway.custody import admission
from sift_gateway.portal.custody_routes import custody_routes_list
from sift_gateway.portal_services import EvidenceAuthorityService
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# DSN gate + fixtures.
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


def _refresh(dsn: str, case_id: str, case_dir: Path) -> admission.GateResult:
    """The one operator-Refresh reconciliation, via the production primitive the
    target custody-status route calls (bare case dir)."""
    return admission.reconcile(case_id, str(case_dir), dsn, trigger="refresh")


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


def _seal_one_object(cur, *, case_id: str, actor_user_id: str, display_path: str) -> str:
    """Drive the REAL custody_seal_begin -> _protect -> _commit RPC chain (one new
    Manifest Version per call) and return the sealed Evidence Object id."""
    idempotency_key = "seal-" + uuid.uuid4().hex[:12]
    reason = "CP3 inventory-authority fixture"
    targets = [display_path]
    request_digest = "sha256:" + "a" * 64

    cur.execute(
        "select app.custody_reauth_binding(%s, %s, %s)",
        (idempotency_key, reason, _jsonb(targets)),
    )
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

    prepared_facts = {
        "items": [
            {
                "display_path": display_path,
                "sha256": "sha256:" + "b" * 64,
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
    cur.execute(
        "select phase from app.custody_seal_commit(%s, %s, %s, null)",
        (operation_id, _jsonb(prepared_facts["items"]), "cp3-test-examiner"),
    )
    (final_phase,) = cur.fetchone()
    assert final_phase == "COMMITTED"

    cur.execute(
        "select id::text from app.evidence_objects where case_id = %s and display_path = %s",
        (case_id, display_path),
    )
    return str(cur.fetchone()[0])


def _retire_object(cur, *, case_id: str, actor_user_id: str, object_id: str) -> None:
    """Drive the REAL custody_retire RPC (new Manifest Version excluding the object)."""
    idempotency_key = "retire-" + uuid.uuid4().hex[:12]
    reason = "CP3 fan-out retire"
    cur.execute(
        "select app.custody_reauth_binding(%s, %s, %s)",
        (idempotency_key, reason, _jsonb([str(object_id)])),
    )
    (binding,) = cur.fetchone()
    reauth_id = str(uuid.uuid4())
    cur.execute(
        """
        insert into app.audit_events
          (id, case_id, event_type, actor_type, actor_user_id, source, status, summary, details)
        values (%s, %s, 'reauth.evidence_retire', 'user', %s, 'portal_reauth', 'success',
                'CP3 retire reauth', %s)
        """,
        (reauth_id, case_id, actor_user_id, _jsonb({"binding": binding})),
    )
    cur.execute(
        "select id from app.custody_retire(%s, %s, %s, %s, %s, %s)",
        (case_id, object_id, reason, reauth_id, idempotency_key, actor_user_id),
    )
    cur.fetchone()


def _observation_count(cur, case_id: str) -> int:
    cur.execute(
        "select count(*) from app.admission_observations where case_id = %s", (case_id,)
    )
    return int(cur.fetchone()[0])


def _by_path(inventory: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for item in inventory:
        out.setdefault(item["display_path"], []).append(item)
    return out


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
    _refresh(dsn, case_id, case_dir)

    service = EvidenceAuthorityService(dsn)

    gate = service.gate_status(case_id)  # pure read
    assert gate["gate_state"] == "BLOCKED_PENDING"
    assert gate["unregistered"] == ["evidence/img.E01"]

    inventory = service.list_evidence(case_id)  # pure read
    by_path = _by_path(inventory)
    assert set(by_path) == {"evidence/img.E01"}
    item = by_path["evidence/img.E01"][0]
    assert item["status"] == "detected"
    assert item["seal_status"] == "unsealed"
    assert item["current_sha256"] is None and item["current_bytes"] is None
    # Requirement 5: the exact wire keys the legacy consumers key off are present.
    assert {
        "evidence_id", "display_name", "display_path", "description", "source",
        "status", "seal_status", "current_sha256", "current_bytes",
        "manifest_version", "registered_at", "sealed_at",
    } <= set(item)

    # Target route (reconciles once itself, then reads).
    body = _route_client(dsn, case_id, case_dir).get("/status").json()
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
        _refresh(dsn, case_id, case_dir)  # populate inventory
        # Operator-ignore one entry (disposition preserved across reconciliations).
        cur.execute(
            "update app.evidence_inventory set disposition = 'ignored' "
            "where case_id = %s and display_path = 'evidence/ignore.raw'",
            (case_id,),
        )

    service = EvidenceAuthorityService(dsn)
    gate = service.gate_status(case_id)  # pure read
    assert gate["unregistered"] == ["evidence/keep.raw"]  # ignored excluded

    inventory = {i["display_path"]: i for i in service.list_evidence(case_id)}
    assert inventory["evidence/keep.raw"]["status"] == "detected"
    assert inventory["evidence/ignore.raw"]["status"] == "ignored"

    body = _route_client(dsn, case_id, case_dir).get("/status").json()
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
    _refresh(dsn, case_id, case_dir)  # both files on disk -> both in inventory

    service = EvidenceAuthorityService(dsn)
    gate = service.gate_status(case_id)  # pure read
    assert gate["unregistered"] == ["evidence/pending.raw"]  # sealed path not Pending

    by_path = _by_path(service.list_evidence(case_id))
    assert len(by_path["evidence/sealed.raw"]) == 1
    assert by_path["evidence/sealed.raw"][0]["status"] == "sealed"
    assert by_path["evidence/sealed.raw"][0]["seal_status"] == "sealed"
    assert len(by_path["evidence/pending.raw"]) == 1
    assert by_path["evidence/pending.raw"][0]["status"] == "detected"

    body = _route_client(dsn, case_id, case_dir).get("/status").json()
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
    _refresh(dsn, case_a, dir_a)
    _refresh(dsn, case_b, dir_b)

    service = EvidenceAuthorityService(dsn)
    assert service.gate_status(case_a)["unregistered"] == ["evidence/a.raw"]
    paths_a = {i["display_path"] for i in service.list_evidence(case_a)}
    assert paths_a == {"evidence/a.raw"}  # never leaks case B's b.raw


# ---------------------------------------------------------------------------
# Requirement (reviewer failure 2) — multi-manifest: one row per object, correct
# Retired rendering, no historical fan-out.
# ---------------------------------------------------------------------------
def test_multi_manifest_no_duplicate_sealed_rows_and_retired_renders_once(tmp_path):
    dsn = _dsn()
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)  # object branch needs no disk files
        actor = _new_operator(cur)
        obj_a = _seal_one_object(cur, case_id=case_id, actor_user_id=actor, display_path="evidence/a.raw")
        # Sealing b advances to Manifest v2, carrying a forward as an ACTIVE member
        # of v2 too — so object a now has ACTIVE membership in BOTH v1 and v2.
        _seal_one_object(cur, case_id=case_id, actor_user_id=actor, display_path="evidence/b.raw")
        cur.execute(
            "select count(*) from app.manifest_membership mm "
            "join app.evidence_objects o on o.id = mm.evidence_object_id "
            "where o.case_id = %s and o.display_path = 'evidence/a.raw' "
            "and mm.entry_status = 'ACTIVE'",
            (case_id,),
        )
        row = cur.fetchone()
        assert row is not None
        active_memberships_a = int(row[0])
    # Premise: the historical fan-out condition genuinely exists.
    assert active_memberships_a >= 2

    service = EvidenceAuthorityService(dsn)
    by_path = _by_path(service.list_evidence(case_id))
    # Despite two ACTIVE memberships, object a renders EXACTLY ONCE, sealed at the
    # LATEST manifest — the current-manifest-only fix.
    assert len(by_path["evidence/a.raw"]) == 1
    assert by_path["evidence/a.raw"][0]["status"] == "sealed"
    assert len(by_path["evidence/b.raw"]) == 1
    assert by_path["evidence/b.raw"][0]["status"] == "sealed"
    latest_mv = by_path["evidence/a.raw"][0]["manifest_version"]
    assert latest_mv == by_path["evidence/b.raw"][0]["manifest_version"]

    # Retire a -> new Manifest Version excluding a; a renders Retired ONCE, b stays
    # sealed ONCE. Historical ACTIVE memberships remain in PostgreSQL but never
    # resurrect a as sealed or duplicate it.
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        _retire_object(cur, case_id=case_id, actor_user_id=actor, object_id=obj_a)

    by_path2 = _by_path(service.list_evidence(case_id))
    assert len(by_path2["evidence/a.raw"]) == 1
    assert by_path2["evidence/a.raw"][0]["status"] == "retired"
    assert len(by_path2["evidence/b.raw"]) == 1
    assert by_path2["evidence/b.raw"][0]["status"] == "sealed"


# ---------------------------------------------------------------------------
# Poll-mutation invariant — passive reads never reconcile (append observations).
# ---------------------------------------------------------------------------
def test_passive_reads_do_not_grow_admission_observations(tmp_path):
    dsn = _dsn()
    import psycopg

    case_dir = _staged_case_dir(tmp_path, "img.E01")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur, case_dir=case_dir)

        # One explicit Refresh reconciles (appends exactly one observation).
        _refresh(dsn, case_id, case_dir)
        baseline = _observation_count(cur, case_id)
        assert baseline >= 1

        service = EvidenceAuthorityService(dsn)
        # Passive reads (the 15s poll path) must NOT append observations or scan.
        for _ in range(3):
            g = service.gate_status(case_id)  # pure read
            assert g["gate_state"] == "BLOCKED_PENDING"
            assert g["unregistered"] == ["evidence/img.E01"]  # last snapshot, still surfaced
            service.list_evidence(case_id)  # pure read
        assert _observation_count(cur, case_id) == baseline

        # A further explicit Refresh appends exactly one more (proving the counter
        # above is live, not a dead assertion).
        _refresh(dsn, case_id, case_dir)
        assert _observation_count(cur, case_id) == baseline + 1


# ---------------------------------------------------------------------------
# PF-009 R2 — reload/resume: begin -> fresh service projects the recorded key +
# freshly listed targets -> resume completes by the recorded operation (COMMITTED).
# ---------------------------------------------------------------------------
def test_reload_resume_projects_key_and_completes_by_recorded_operation(tmp_path):
    dsn = _dsn()
    import psycopg

    case_dir = _staged_case_dir(tmp_path, "a.raw", "b.raw")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur, case_dir=case_dir)
        actor = _new_operator(cur)
    _refresh(dsn, case_id, case_dir)  # inventory + one admission_observation (snapshot)

    # BEGIN a seal (REQUESTED) via the canonical RPC path, leaving it incomplete.
    idempotency_key = "resume-" + uuid.uuid4().hex[:12]
    reason = "resume fixture"
    targets = ["evidence/a.raw", "evidence/b.raw"]
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "select app.custody_reauth_binding(%s, %s, %s)",
            (idempotency_key, reason, _jsonb(targets)),
        )
        binding_row = cur.fetchone()
        assert binding_row is not None
        (binding,) = binding_row
        reauth_id = str(uuid.uuid4())
        cur.execute(
            "insert into app.audit_events (id, case_id, event_type, actor_type, "
            "actor_user_id, source, status, summary, details) values "
            "(%s, %s, 'reauth.evidence_seal', 'user', %s, 'portal_reauth', 'success', "
            "'resume fixture', %s)",
            (reauth_id, case_id, actor, _jsonb({"binding": binding})),
        )
        cur.execute(
            "select r.id::text, r.idempotency_key "
            "from app.custody_seal_begin(%s, %s, %s, %s, %s, %s, %s, false, null) r",
            (case_id, idempotency_key, "sha256:" + "a" * 64, reason, reauth_id,
             _jsonb(targets), actor),
        )
        begin_row = cur.fetchone()
        assert begin_row is not None
        op_id, recorded_key = begin_row

    # RELOAD: a FRESH service projects ONLY the path-free resume handle.
    gate = EvidenceAuthorityService(dsn).gate_status(case_id)
    assert gate["incomplete_operation"] == {
        "operation_id": str(op_id),
        "idempotency_key": recorded_key,
        "staging_window_open": False,
    }
    assert recorded_key == idempotency_key  # the projected key IS the begin key
    # Freshly listed targets + a real snapshot are available to rebuild the request.
    assert set(gate["unregistered"]) == {"evidence/a.raw", "evidence/b.raw"}
    assert isinstance(gate["snapshot_observation_id"], int)

    # RESUME completes by the recorded operation (protect -> commit) -> COMMITTED.
    items = [
        {"display_path": p, "sha256": "sha256:" + "b" * 64, "bytes": 4096,
         "mode": "0644", "immutable": True, "st_nlink": 1}
        for p in targets
    ]
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "select phase from app.custody_seal_protect(%s, %s, %s, null)",
            (op_id, _jsonb({"items": items}), actor),
        )
        cur.execute(
            "select phase from app.custody_seal_commit(%s, %s, %s, null)",
            (op_id, _jsonb(items), "resume-examiner"),
        )
        commit_row = cur.fetchone()
        assert commit_row is not None
        (final_phase,) = commit_row
    assert final_phase == "COMMITTED"

    # Post-commit: no resume handle remains (fail-closed complete).
    assert EvidenceAuthorityService(dsn).gate_status(case_id)["incomplete_operation"] is None
