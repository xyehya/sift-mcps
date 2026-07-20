"""P4.23 CP2B — portal_services.EvidenceAuthorityService EC-4 core acceptance test.

Repair round 1, MUST-FIX 3: ``list_evidence()``'s SQL join (the EC-4 rewrite's
core — gating "sealed" on a COMMITTED Evidence Version with ACTIVE manifest
membership) had zero direct coverage; the route test injects a fake
``_EvidenceService`` that bypasses the real SQL, and the frontend fixture has
only one always-sealed item. This drives the REAL join against a real migrated
PostgreSQL, gated on ``SIFT_CONTROL_PLANE_DSN`` (DSN-skip), mirroring
``test_p423_cp2b_ledger.py``.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for the EC-4 core integration test")
    return dsn


def _new_case(cur) -> str:
    case_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.cases(id,case_key,title,status) values (%s,%s,'CP2B EC-4 test','active')",
        (case_id, "cp2b-ec4-" + uuid.uuid4().hex[:12]),
    )
    return case_id


def _new_operator(cur) -> str:
    operator_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.operator_profiles(id, display_name) values (%s, 'CP2B EC-4 Test Operator')",
        (operator_id,),
    )
    return operator_id


def _seal_one_object(cur, *, case_id: str, actor_user_id: str, display_path: str) -> None:
    """Drive the REAL custody_seal_begin -> _protect -> _commit RPC chain so the
    resulting evidence_objects/evidence_versions/manifest_membership rows are
    genuinely COMMITTED — not a shortcut insert — proving list_evidence()'s
    join against the actual authoritative shape a live Seal produces."""
    idempotency_key = "seal-" + uuid.uuid4().hex[:12]
    reason = "CP2B EC-4 integration fixture"
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
                'CP2B EC-4 fixture reauth', %s)
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
        (operation_id, _jsonb(items), "cp2b-test-examiner"),
    )
    (final_phase,) = cur.fetchone()
    assert final_phase == "COMMITTED"


def _jsonb(value):
    from psycopg.types.json import Jsonb

    return Jsonb(value)


@pytest.mark.integration
def test_list_evidence_classifies_detected_only_as_pending_and_sealed_as_sealed():
    dsn = _dsn()
    import psycopg
    from sift_gateway.portal_services import EvidenceAuthorityService

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)
        actor_user_id = _new_operator(cur)

        # A genuinely sealed object: real custody_seal_begin -> _protect ->
        # _commit chain, exactly what an operator Add & Seal produces.
        _seal_one_object(cur, case_id=case_id, actor_user_id=actor_user_id, display_path="evidence/sealed.raw")

        # A detected-only object alongside it — no version, no manifest
        # membership. This is the EC-1/EC-4 phantom-object shape: a real row
        # in evidence_objects with nothing behind it.
        cur.execute(
            """
            insert into app.evidence_objects (case_id, display_name, display_path, status, seal_status)
            values (%s, 'detected-only.raw', 'evidence/detected-only.raw', 'detected', 'unsealed')
            """,
            (case_id,),
        )

    service = EvidenceAuthorityService(dsn)
    items = {item["display_path"]: item for item in service.list_evidence(case_id)}

    assert items["evidence/sealed.raw"]["status"] == "sealed"
    assert items["evidence/sealed.raw"]["seal_status"] == "sealed"
    assert items["evidence/sealed.raw"]["current_sha256"] == "sha256:" + "b" * 64
    assert items["evidence/sealed.raw"]["manifest_version"] == 1

    # EC-4 fail-on-revert: the detected-only object is NEVER "sealed" — it
    # keeps its raw status, and carries no digest despite existing in the
    # SAME query result set as the genuinely sealed object above.
    assert items["evidence/detected-only.raw"]["status"] == "detected"
    assert items["evidence/detected-only.raw"]["seal_status"] == "unsealed"
    assert items["evidence/detected-only.raw"]["current_sha256"] is None
    assert items["evidence/detected-only.raw"]["current_bytes"] is None
    assert items["evidence/detected-only.raw"]["manifest_version"] is None
