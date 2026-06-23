"""Unit 2 / Gap B live-prove fix: digit-bearing ingest-id prefixes must be
accepted as finding provenance citations.

The opensearch ingest scheme embeds the worker PID in the audit-id prefix:
``opensearchingest<PID>-sift-service-YYYYMMDD-NNN`` — e.g.
``opensearchingest1018805-sift-service-20260623-040``. The provenance gate's
``_AUDIT_ID_PATTERN`` used a letters-only ``[a-z]+`` prefix, so such ids failed
the format check in ``_classify_provenance`` and short-circuited to the "none"
bucket BEFORE the ``_db_audit_id_known`` authority lookup ever ran — a finding
citing a real (DB-recorded) ingest id was rejected "no evidence trail". This was
reproduced live on the VM (Gap B B-D2 wrote the rows correctly, but they could
never be cited end-to-end).

Fix: prefix segment ``[a-z]+`` -> ``[a-z][a-z0-9]*`` (must still START with a
letter — the anti-injection guarantee — but may carry digits thereafter).

These tests cover the regression the existing B-D2 tests missed: the END-TO-END
citation path (pattern acceptance + reaching the DB-known branch instead of
short-circuiting), plus the anti-injection cases that must STAY rejected.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sift_core.case_manager as cm
from sift_core.case_manager import CaseManager

INGEST_ID = "opensearchingest1018805-sift-service-20260623-040"
CASE_UUID = "44444444-4444-4444-4444-444444444444"


# ---------------------------------------------------------------------------
# (1) pure-pattern acceptance / rejection
# ---------------------------------------------------------------------------


def test_pattern_accepts_digit_bearing_ingest_prefix():
    """The live id (PID digits in the prefix) now matches; sibling scheme ids
    that already worked still match."""
    P = cm._AUDIT_ID_PATTERN
    assert P.match(INGEST_ID)
    # Regression guard for the exact live id observed on the VM.
    assert P.match("opensearchingest1018805-sift-service-20260623-040")
    # Pre-existing scheme ids must keep matching.
    assert P.match("siftgateway-examiner-20260601-001")
    assert P.match("opensearch-examiner-20260623-007")
    assert P.match("shell-claud-new-portal-20260622-001")


@pytest.mark.parametrize(
    "bad",
    [
        "../etc-passwd-20260101-001",            # path traversal
        "123-sift-service-20260101-001",          # pure-digit prefix (must start w/ letter)
        "open.search-sift-service-20260101-001",  # dot injection in prefix
        "opensearchingest1018805-sift-service-20260623-040-junk",  # trailing junk
        "-leadinghyphen-20260101-001",            # leading hyphen
        "opensearchingest1018805-sift-service-2026062-040",        # short date
    ],
)
def test_pattern_still_rejects_injection_and_malformed(bad):
    """The digit-bearing relaxation must NOT open injection vectors: the prefix
    must still start with a letter, no dots/slashes, exact date/seq shape."""
    assert not cm._AUDIT_ID_PATTERN.match(bad)


# ---------------------------------------------------------------------------
# (2) END-TO-END citation path: a DB-known ingest id reaches the DB branch and
#     is classified MCP (the regression that would have caught the live defect)
# ---------------------------------------------------------------------------


def _register_minimal_evidence(case_dir: Path) -> None:
    records = case_dir / "records"
    records.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence").mkdir(exist_ok=True)
    (case_dir / "evidence" / "sample.log").write_text("log line\n")
    manifest = {
        "files": [
            {"path": "evidence/sample.log", "sha256": "0" * 64, "status": "SEALED"}
        ]
    }
    (records / "evidence-manifest.json").write_text(json.dumps(manifest))


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    """CaseManager in DB-active mode; real Postgres never dialled."""
    from sift_core.active_case_context import AuthorityContext, use_active_case_context

    case_dir = tmp_path / "case-ingest-cite"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-ingest-cite\nstatus: active\n")
    _register_minimal_evidence(case_dir)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://test")

    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-ingest-cite",
        artifact_path=str(case_dir),
        db_active=True,
    )
    mgr = CaseManager()
    with use_active_case_context(ctx):
        yield mgr, case_dir


def test_classify_provenance_ingest_id_in_db_is_mcp(db_manager, monkeypatch):
    """A DB-known ingest id REACHES the _db_audit_id_known branch (rather than
    short-circuiting to 'none' at the pattern gate) and is classified MCP."""
    mgr, case_dir = db_manager
    monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", lambda *a, **k: True)
    result = mgr._classify_provenance([INGEST_ID], case_dir)
    assert INGEST_ID in result["mcp"], result
    assert result["summary"] == "MCP", result


def test_ingest_id_candidates_forwarded_to_db_lookup(db_manager, monkeypatch):
    """The ingest id is forwarded to the DB authority lookup — proving it passed
    the format gate (the pre-fix bug never reached this call)."""
    mgr, case_dir = db_manager
    received: list[list[str]] = []

    def capture(dsn, case_id, candidates):
        received.append(list(candidates))
        return True

    monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", capture)
    mgr._classify_provenance([INGEST_ID], case_dir)
    assert received, "DB lookup was never called — id short-circuited at the pattern gate"
    all_candidates = [c for batch in received for c in batch]
    assert INGEST_ID in all_candidates


def test_classify_provenance_ingest_id_not_in_db_is_none(db_manager, monkeypatch):
    """Fail-closed: an ingest id the DB does NOT know stays 'none' (no false
    acceptance just because the format now matches)."""
    mgr, case_dir = db_manager
    monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", lambda *a, **k: False)
    result = mgr._classify_provenance([INGEST_ID], case_dir)
    assert INGEST_ID in result["none"], result


def test_classify_provenance_injection_prefix_still_none(db_manager, monkeypatch):
    """Even if the DB would say True, a malformed/injection id is rejected at the
    pattern gate before the DB is consulted."""
    mgr, case_dir = db_manager
    monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", lambda *a, **k: True)
    bad = "../etc-passwd-20260101-001"
    result = mgr._classify_provenance([bad], case_dir)
    assert bad in result["none"], result
