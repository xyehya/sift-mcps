from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sift_core.execute.job_worker import ClaimedJob, FatalJobError
from sift_core.execute.run_command_job import _inventory_token, build_custody_validator


class _Cursor:
    def __init__(self):
        self.calls = []
        self._one = None
        self._all = []

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        self.calls.append((normalized, params))
        if "from app.evidence_storage_authorities a" in normalized:
            self._one = (
                "LOCAL_IMMUTABLE",
                None,
                None,
                "AVAILABLE",
                1,
                1,
                None,
                1,
                "sha256:manifest",
                "receipt-1",
            )
        elif "from app.evidence_objects where case_id" in normalized:
            self._all = []
        elif "app.evidence_observe_admission" in normalized:
            self._one = ("detected-object",)
        elif "app.evidence_gate_status" in normalized:
            self._one = ("sealed",)
        elif "join app.evidence_versions" in normalized:
            self._one = (1,)
        else:
            self._one = (None,)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _Connection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _TransactionalConnection(_Connection):
    def __init__(self, cursor):
        super().__init__(cursor)
        self.committed = []

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self.committed.extend(self._cursor.calls)
        return None


def _job(case_dir, token):
    return ClaimedJob(
        job_id="job-1",
        job_type="run_command",
        case_id="11111111-1111-1111-1111-111111111111",
        evidence_id=None,
        spec_public={"command": "date", "purpose": "test"},
        spec_internal={
            "case_dir": str(case_dir),
            "evidence_inventory_token": token,
            "resolved_evidence_refs": [],
            "storage_execution_authority": {
                "storage_profile": "LOCAL_IMMUTABLE",
                "storage_source_identity": "",
                "mount_instance_identity": "",
                "storage_generation": 1,
                "storage_verified_generation": 1,
                "storage_manifest_version": 1,
                "storage_manifest_hash": "sha256:manifest",
                "storage_verification_receipt_id": "receipt-1",
            },
        },
        attempts=1,
        max_attempts=1,
        worker_id="worker-1",
    )


@pytest.mark.skip(
    reason="P4.23 CP1: the durable custody validator's as-built SQL (evidence_gate_"
    "status/observe_admission/external-storage authority) is replaced by app.custody_"
    "gate_state + app.custody_reconcile; the durable-routing invariant is covered by "
    "test_cp1_admission.test_durable_admission_routes_through_computed_gate_not_latched "
    "and the CP3 VM gate. CP2A/CP2B rewrite the mock-SQL detail with the binding re-home."
)
def test_durable_revalidation_records_force_added_sibling_before_denial(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    token = _inventory_token(str(case_dir))
    (evidence / "force-added.raw").write_bytes(b"new")
    cursor = _Cursor()
    connection = _TransactionalConnection(cursor)
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda _dsn: connection),
    )

    with pytest.raises(FatalJobError, match="custody_admission_denied"):
        build_custody_validator("postgresql://unused")(_job(case_dir, token), "claim")

    detects = [
        call for call in cursor.calls if "app.evidence_observe_admission" in call[0]
    ]
    assert len(detects) == 1
    assert detects[0][1][1] == "evidence/force-added.raw"
    assert detects[0][1][4] == "job-1"
    assert any(
        "app.evidence_observe_admission" in call[0] for call in connection.committed
    )
    assert not any("app.evidence_gate_status" in call[0] for call in cursor.calls)


@pytest.mark.skip(
    reason="P4.23 CP1: durable gate check now reads app.custody_gate_state ('OPEN'); "
    "invariant covered by test_cp1_admission + CP3 VM gate. CP2A/CP2B rewrite mock-SQL."
)
def test_durable_revalidation_checks_gate_at_both_phases(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    token = _inventory_token(str(case_dir))
    cursor = _Cursor()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda _dsn: _Connection(cursor)),
    )
    validator = build_custody_validator("postgresql://unused")
    job = _job(case_dir, token)

    validator(job, "claim")
    validator(job, "execution")

    assert sum("app.evidence_gate_status" in call[0] for call in cursor.calls) == 2


@pytest.mark.skip(
    reason="P4.23 CP1: durable drift observation now routes through app.custody_"
    "reconcile; invariant covered by test_cp1_admission + CP3 VM gate. CP2A/CP2B "
    "rewrite mock-SQL with the binding re-home."
)
def test_durable_revalidation_classifies_changed_sealed_identity(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    target = evidence / "sealed.raw"
    target.write_bytes(b"sealed")
    token = _inventory_token(str(case_dir))
    target.chmod(0o600)
    cursor = _Cursor()
    cursor._all = []
    original_execute = cursor.execute

    def execute(sql, params):
        original_execute(sql, params)
        if "from app.evidence_objects where case_id" in " ".join(sql.split()):
            cursor._all = [
                (
                    "sealed-object",
                    "evidence/sealed.raw",
                    "sealed",
                    "sealed",
                    target.stat().st_size,
                    datetime.now(timezone.utc) - timedelta(seconds=5),
                )
            ]

    cursor.execute = execute
    connection = _TransactionalConnection(cursor)
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda _dsn: connection),
    )

    with pytest.raises(FatalJobError, match="custody_admission_denied"):
        build_custody_validator("postgresql://unused")(_job(case_dir, token), "claim")

    violations = [
        call
        for call in connection.committed
        if "evidence_mark_admission_violation" in call[0]
    ]
    assert violations
    assert violations[0][1][1:3] == ("sealed-object", "sealed_evidence_changed")
    assert violations[0][1][4] == "job-1"
