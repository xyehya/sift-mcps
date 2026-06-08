"""BATCH-K1: DB-active authority context + legacy-fallback fail-closed.

Proves the K1 security invariant in sift-core: in DB-active mode the active case
is decided only by the AuthorityContext loaded from Postgres. Tampering with the
legacy ``~/.sift/active_case`` pointer cannot steer authoritative work, and a
missing context fails closed instead of silently reading env/pointer files. Legacy
(non-DB-active) resolution is preserved.
"""

from __future__ import annotations

import pytest
import yaml

from sift_core import case_manager as case_manager_mod
from sift_core.active_case_context import (
    AuthorityContext,
    ActiveCaseContext,
    db_authority_active,
    use_active_case_context,
)
from sift_core.case_manager import CaseManager


def _make_case(root, name):
    case = root / name
    case.mkdir()
    (case / "CASE.yaml").write_text(
        yaml.dump({"case_id": name, "name": name, "status": "open", "examiner": "t"})
    )
    return case


# --------------------------------------------------------------------------
# db_authority_active() signal
# --------------------------------------------------------------------------


def test_db_authority_inactive_by_default(monkeypatch):
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    assert db_authority_active() is False


def test_db_authority_active_via_env(monkeypatch):
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    assert db_authority_active() is True


def test_db_authority_active_via_context(monkeypatch):
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    ctx = AuthorityContext(case_id="c", case_key="c", db_active=True)
    with use_active_case_context(ctx):
        assert db_authority_active() is True
    assert db_authority_active() is False


def test_authority_context_alias_is_active_case_context():
    assert ActiveCaseContext is AuthorityContext


def test_record_audit_event_collects_ids():
    ctx = AuthorityContext(case_id="c", case_key="c")
    ctx.record_audit_event("evt-1")
    ctx.record_audit_event(None)  # ignored
    ctx.record_audit_event("evt-2")
    assert ctx.audit_event_ids == ["evt-1", "evt-2"]
    assert ctx.primary_audit_event_id == "evt-1"


# --------------------------------------------------------------------------
# CaseManager._require_active_case() — DB-active vs legacy
# --------------------------------------------------------------------------


def test_db_active_context_wins_over_pointer_tampering(monkeypatch, tmp_path):
    db_case = _make_case(tmp_path, "db-case")
    tampered = _make_case(tmp_path, "tampered")
    pointer = tmp_path / "active_case"
    pointer.write_text(str(tampered.resolve()))
    monkeypatch.setattr(case_manager_mod, "_ACTIVE_CASE_FILE", pointer)

    ctx = AuthorityContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        artifact_path=str(db_case),
        db_active=True,
    )
    cm = CaseManager()
    with use_active_case_context(ctx):
        assert cm._require_active_case() == db_case


def test_db_active_without_context_fails_closed(monkeypatch, tmp_path):
    # A valid (tampered) pointer file exists, but DB-active mode must NOT read it.
    legacy_case = _make_case(tmp_path, "legacy")
    pointer = tmp_path / "active_case"
    pointer.write_text(str(legacy_case.resolve()))
    monkeypatch.setattr(case_manager_mod, "_ACTIVE_CASE_FILE", pointer)
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)

    cm = CaseManager()
    with use_active_case_context(None):
        with pytest.raises(ValueError):
            cm._require_active_case()


def test_legacy_mode_still_reads_pointer(monkeypatch, tmp_path):
    legacy_case = _make_case(tmp_path, "legacy")
    pointer = tmp_path / "active_case"
    pointer.write_text(str(legacy_case.resolve()))
    monkeypatch.setattr(case_manager_mod, "_ACTIVE_CASE_FILE", pointer)
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)

    cm = CaseManager()
    with use_active_case_context(None):
        assert cm._require_active_case() == legacy_case
