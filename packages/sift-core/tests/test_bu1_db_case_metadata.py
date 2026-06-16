"""BU1: DB-authoritative case-metadata reader + DB-mode reader fail-closed.

These cover the foundational ``resolve_case_metadata`` reader and the cross-file
behaviour that a DB error in DB-active mode fails closed instead of falling back
to the tamperable CASE.yaml mirror.
"""

import pytest

from sift_core import investigation_store
from sift_core.active_case_context import (
    AuthorityContext,
    use_active_case_context,
)
from sift_core.investigation_store import (
    InvestigationStoreError,
    _case_meta_from_row,
    resolve_case_metadata,
)


def _row(status="active", metadata=None):
    # (id, case_key, title, description, status, legacy_case_dir, metadata)
    return (
        "11111111-1111-1111-1111-111111111111",
        "inc-2026-01",
        "Acme Intrusion",
        "Initial access via phishing",
        status,
        "/cases/inc-2026-01",
        metadata or {},
    )


class TestCaseMetaFromRow:
    def test_columns_override_jsonb_and_status_maps_to_yaml(self):
        meta = _case_meta_from_row(
            _row(
                status="active",
                metadata={
                    "examiner": "alice",
                    "incident_type": "ransomware",
                    "name": "STALE",  # JSONB must not win over the title column
                },
            )
        )
        assert meta["case_id"] == "inc-2026-01"
        assert meta["name"] == "Acme Intrusion"
        assert meta["description"] == "Initial access via phishing"
        assert meta["status"] == "open"  # active -> open
        assert meta["examiner"] == "alice"
        assert meta["incident_type"] == "ransomware"

    @pytest.mark.parametrize(
        "db_status,expected",
        [
            ("active", "open"),
            ("closed", "closed"),
            ("paused", "paused"),
            ("archived", "archived"),
            ("draft", "draft"),
            ("weird", "weird"),  # unknown statuses pass through unchanged
        ],
    )
    def test_status_mapping(self, db_status, expected):
        assert _case_meta_from_row(_row(status=db_status))["status"] == expected


class TestResolveCaseMetadata:
    def test_file_mode_returns_none(self, monkeypatch):
        monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
        assert resolve_case_metadata() is None

    def test_db_active_without_dsn_returns_none(self, monkeypatch):
        # No control-plane DSN configured: refusing this misconfiguration is BU3.
        monkeypatch.setattr(investigation_store, "control_plane_dsn", lambda: None)
        ctx = AuthorityContext(case_id="uuid", case_key="k", db_active=True)
        with use_active_case_context(ctx):
            assert resolve_case_metadata() is None

    def test_db_active_without_case_in_context_fails_closed(self, monkeypatch):
        monkeypatch.setattr(
            investigation_store, "control_plane_dsn", lambda: "postgresql://x"
        )
        monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
        # db_authority_active via env, but no AuthorityContext bound.
        with pytest.raises(InvestigationStoreError):
            resolve_case_metadata()

    def test_missing_case_row_fails_closed(self, monkeypatch):
        monkeypatch.setattr(
            investigation_store, "control_plane_dsn", lambda: "postgresql://x"
        )

        class _Store:
            def __init__(self, dsn):
                pass

            def get_case_metadata(self, case_id):
                return None

        monkeypatch.setattr(investigation_store, "PostgresCaseStore", _Store)
        ctx = AuthorityContext(case_id="uuid", case_key="k", db_active=True)
        with use_active_case_context(ctx):
            with pytest.raises(InvestigationStoreError):
                resolve_case_metadata()

    def test_db_failure_propagates_fails_closed(self, monkeypatch):
        monkeypatch.setattr(
            investigation_store, "control_plane_dsn", lambda: "postgresql://x"
        )

        class _Store:
            def __init__(self, dsn):
                pass

            def get_case_metadata(self, case_id):
                raise InvestigationStoreError("connection refused")

        monkeypatch.setattr(investigation_store, "PostgresCaseStore", _Store)
        ctx = AuthorityContext(case_id="uuid", case_key="k", db_active=True)
        with use_active_case_context(ctx):
            with pytest.raises(InvestigationStoreError):
                resolve_case_metadata()

    def test_db_active_returns_db_metadata(self, monkeypatch):
        monkeypatch.setattr(
            investigation_store, "control_plane_dsn", lambda: "postgresql://x"
        )

        class _Store:
            def __init__(self, dsn):
                pass

            def get_case_metadata(self, case_id):
                return {"case_id": "inc-1", "name": "DB", "status": "open"}

        monkeypatch.setattr(investigation_store, "PostgresCaseStore", _Store)
        ctx = AuthorityContext(
            case_id="uuid", case_key="inc-1", db_active=True
        )
        with use_active_case_context(ctx):
            meta = resolve_case_metadata()
        assert meta == {"case_id": "inc-1", "name": "DB", "status": "open"}


class TestGetExaminerDbMode:
    def test_db_mode_examiner_from_db_not_case_yaml(self, tmp_path, monkeypatch):
        import yaml

        from sift_core import case_io

        # env examiners must be unset so the case-metadata path is exercised.
        monkeypatch.delenv("SIFT_EXAMINER", raising=False)
        monkeypatch.delenv("SIFT_ANALYST", raising=False)
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"examiner": "tampered"}, f)

        monkeypatch.setattr(case_io, "db_authority_active", lambda: True, raising=False)
        # get_examiner imports these at call time from their modules.
        import sift_core.active_case_context as acc

        monkeypatch.setattr(acc, "db_authority_active", lambda: True)
        monkeypatch.setattr(
            investigation_store,
            "resolve_case_metadata",
            lambda: {"examiner": "dbexam"},
        )
        assert case_io.get_examiner(case_dir) == "dbexam"


class TestRequireActiveCaseDbClosedGate:
    """BU1: CaseManager._require_active_case enforces the DB closed-case gate and
    fails closed on DB error — neither may be swallowed by the broad except.
    """

    def _manager(self, tmp_path):
        from sift_core.case_manager import CaseManager

        return CaseManager()

    def _ctx(self, case_dir):
        from sift_core.active_case_context import AuthorityContext

        return AuthorityContext(
            case_id="55555555-5555-5555-5555-555555555555",
            case_key="INC-CLOSED",
            artifact_path=str(case_dir),
            db_active=True,
        )

    def test_db_closed_case_refused_even_if_case_yaml_says_open(
        self, tmp_path, monkeypatch
    ):
        import yaml

        from sift_core.active_case_context import use_active_case_context

        case_dir = tmp_path / "INC-CLOSED"
        case_dir.mkdir()
        # Tampered/stale mirror: file says open, DB authority says closed.
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-CLOSED", "status": "open"}, f)

        monkeypatch.setattr(
            investigation_store,
            "resolve_case_metadata",
            lambda: {"case_id": "INC-CLOSED", "status": "closed"},
        )
        manager = self._manager(tmp_path)
        with use_active_case_context(self._ctx(case_dir)):
            with pytest.raises(ValueError, match="closed"):
                manager._require_active_case()

    def test_db_error_fails_closed_not_file_fallback(self, tmp_path, monkeypatch):
        import yaml

        from sift_core.active_case_context import use_active_case_context

        case_dir = tmp_path / "INC-CLOSED"
        case_dir.mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-CLOSED", "status": "open"}, f)

        def _boom():
            raise InvestigationStoreError("connection refused")

        monkeypatch.setattr(investigation_store, "resolve_case_metadata", _boom)
        manager = self._manager(tmp_path)
        with use_active_case_context(self._ctx(case_dir)):
            with pytest.raises(InvestigationStoreError):
                manager._require_active_case()
