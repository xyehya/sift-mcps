"""P4.23 CP2B — custody/ledger.py acceptance tests (SPEC §Testing, OPERATING-MODEL §9).

Pure-serialization/shaping tests run without a DB (verify_ledger/anchor_manifest_head
fail-closed and validation paths that never open a connection). DB-touching tests
require a real migrated PostgreSQL via ``SIFT_CONTROL_PLANE_DSN`` and are marked
``integration`` — gated exactly like ``tests/test_cp1_composed_admission.py``, they
skip locally and run in CI's Postgres job / the CP3 VM gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid

import pytest
from sift_gateway.custody import ledger


# ---------------------------------------------------------------------------
# Pure tests — no DB, no case_id/dsn resolved.
# ---------------------------------------------------------------------------
def test_verify_ledger_fails_closed_without_case_or_dsn():
    assert ledger.verify_ledger(case_id="", dsn="postgresql://x").consistent is False
    assert ledger.verify_ledger(case_id="case-1", dsn=None).consistent is False


def test_anchor_manifest_head_returns_none_when_no_anchorer_supplied():
    # Disabled-by-default (SPEC §Solana): no anchorer configured -> instant None,
    # never touches the DB or requires a case/dsn.
    assert (
        ledger.anchor_manifest_head(case_id="case-1", dsn="postgresql://x", anchorer=None)
        is None
    )


class _FakeAnchorer:
    def anchor_head(self, *, case_id, head_digest):  # pragma: no cover - unreachable
        raise AssertionError("anchorer must not be invoked for a rejected request")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"password": "pw"},
        {"reason": "why"},
        {"idempotency_key": "key-1"},
        {"password": "pw", "reason": "why"},
    ],
)
def test_anchor_manifest_head_rejects_partial_manual_reauth(kwargs):
    # EC discriminator fix: a call carrying SOME but not all reauth fields is
    # never silently treated as either Manual or Auto (the CP1-flagged gap).
    with pytest.raises(ValueError, match="partial reauth"):
        ledger.anchor_manifest_head(
            case_id="case-1", dsn="postgresql://x", anchorer=_FakeAnchorer(), **kwargs
        )


def test_anchor_manifest_head_rejects_report_digest_without_manual_reauth():
    with pytest.raises(ValueError, match="report_digest"):
        ledger.anchor_manifest_head(
            case_id="case-1",
            dsn="postgresql://x",
            anchorer=_FakeAnchorer(),
            report_digest="sha256:" + "a" * 64,
        )


def test_build_solana_anchorer_is_none_when_unconfigured():
    assert ledger._build_solana_anchorer(keypair_path=None) is None
    assert ledger._build_solana_anchorer(keypair_path="") is None


def test_build_solana_anchorer_constructs_when_configured():
    anchorer = ledger._build_solana_anchorer(keypair_path="/tmp/fake-keypair.json")
    assert anchorer is not None
    assert isinstance(anchorer, ledger._SolanaAnchorer)


def test_canonical_bytes_is_sorted_and_deterministic():
    a = ledger._canonical_bytes({"b": 1, "a": 2})
    b = ledger._canonical_bytes({"a": 2, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1}'


# ---------------------------------------------------------------------------
# Integration tests — real migrated PostgreSQL required.
# ---------------------------------------------------------------------------
def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for CP2B ledger integration tests")
    return dsn


def _new_case(cur) -> str:
    case_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.cases(id,case_key,title,status) values (%s,%s,'CP2B ledger test','active')",
        (case_id, "cp2b-" + uuid.uuid4().hex[:12]),
    )
    return case_id


def _new_operator(cur) -> str:
    operator_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.operator_profiles(id, display_name) values (%s, 'CP2B Test Operator')",
        (operator_id,),
    )
    return operator_id


def _append_event(cur, *, case_id: str, seq: int, prev_hash: str, event_hash: str) -> None:
    cur.execute(
        """
        insert into app.evidence_custody_events
          (case_id, seq, event_type, prev_hash, event_hash)
        values (%s, %s, 'EVIDENCE_DETECTED', %s, %s)
        """,
        (case_id, seq, prev_hash, event_hash),
    )


def _chain_hash(material: str) -> str:
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


class _Session:
    def __init__(self, actor_user_id: str) -> None:
        self.actor_user_id = actor_user_id
        self.session_id = "test-session"


@pytest.mark.integration
def test_verify_ledger_recomputes_a_clean_chain():
    dsn = _dsn()
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)
        h1 = _chain_hash("event-1")
        h2 = _chain_hash("event-2")
        h3 = _chain_hash("event-3")
        _append_event(cur, case_id=case_id, seq=1, prev_hash="", event_hash=h1)
        _append_event(cur, case_id=case_id, seq=2, prev_hash=h1, event_hash=h2)
        _append_event(cur, case_id=case_id, seq=3, prev_hash=h2, event_hash=h3)

    result = ledger.verify_ledger(case_id=case_id, dsn=dsn)
    assert result.consistent is True
    assert result.head_seq == 3
    assert result.head_hash == h3
    assert result.broken_at_seq is None


@pytest.mark.integration
def test_verify_ledger_rejects_a_tampered_chain():
    # Fail-on-revert (SPEC §Testing): a tampered event fails verification.
    dsn = _dsn()
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)
        h1 = _chain_hash("event-1")
        h2 = _chain_hash("event-2")
        _append_event(cur, case_id=case_id, seq=1, prev_hash="", event_hash=h1)
        # Tampered: seq 2's prev_hash does not chain to seq 1's event_hash.
        _append_event(
            cur, case_id=case_id, seq=2, prev_hash="sha256:" + "0" * 64, event_hash=h2
        )

    result = ledger.verify_ledger(case_id=case_id, dsn=dsn)
    assert result.consistent is False
    assert result.broken_at_seq == 2


@pytest.mark.integration
def test_generate_export_digest_is_reproducible_and_recorded():
    dsn = _dsn()
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)
        operator_id = _new_operator(cur)
        h1 = _chain_hash("export-event-1")
        _append_event(cur, case_id=case_id, seq=1, prev_hash="", event_hash=h1)

    session = _Session(operator_id)
    first = ledger.generate_export(session=session, case_id=case_id, dsn=dsn)
    second = ledger.generate_export(session=session, case_id=case_id, dsn=dsn)

    assert first.schema_version == "custody_export_v1"
    assert first.export_digest.startswith("sha256:")
    assert first.export_digest == second.export_digest
    # Sorted-keys, byte-stable canonical JSON round-trips.
    reencoded = json.dumps(
        first.document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert first.export_digest == "sha256:" + hashlib.sha256(reencoded).hexdigest()

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "select export_digest, source_ledger_head from app.custody_exports "
            "where case_id = %s order by created_at desc limit 1",
            (case_id,),
        )
        row = cur.fetchone()
    assert row is not None
    assert row[0] == first.export_digest
    assert row[1] == h1


@pytest.mark.integration
def test_anchor_manifest_head_disabled_records_nothing():
    dsn = _dsn()
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)

    # No anchorer configured -> disabled; never writes a solana_receipts row.
    receipt = ledger.anchor_manifest_head(case_id=case_id, dsn=dsn, anchorer=None)
    assert receipt is None

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) from app.solana_receipts where case_id = %s", (case_id,)
        )
        (count,) = cur.fetchone()
    assert count == 0


@pytest.mark.integration
def test_anchor_manifest_head_failed_receipt_records_without_rollback():
    # A failing anchorer records a 'failed' receipt and never raises or blocks
    # (SPEC §Solana: anchor failure never rolls back custody or blocks the gate).
    dsn = _dsn()
    import psycopg

    class _FailingAnchorer:
        def anchor_head(self, *, case_id, head_digest):
            raise RuntimeError("simulated Solana submission failure")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        case_id = _new_case(cur)

    receipt = ledger.anchor_manifest_head(
        case_id=case_id, dsn=dsn, anchorer=_FailingAnchorer()
    )
    assert receipt is not None
    assert receipt.status == "failed"
    assert receipt.error_category == "anchor_submission_failed"

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "select status, error_category from app.solana_receipts "
            "where case_id = %s order by created_at desc limit 1",
            (case_id,),
        )
        row = cur.fetchone()
    assert row == ("failed", "anchor_submission_failed")
