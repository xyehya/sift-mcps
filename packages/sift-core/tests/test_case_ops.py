"""Tests for sift_core.case_ops case lifecycle functions."""

from pathlib import Path

import pytest
import yaml

from sift_core.case_ops import (
    case_activate_data,
    case_init_data,
    case_list_data,
    case_status_data,
)


@pytest.fixture
def cases_dir(tmp_path):
    """Temporary cases directory."""
    d = tmp_path / "cases"
    d.mkdir()
    return d


@pytest.fixture
def active_home(tmp_path, monkeypatch):
    """Redirect Path.home() to tmp_path so active_case pointer goes there."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    sift_dir = tmp_path / ".sift"
    sift_dir.mkdir(exist_ok=True)
    return tmp_path


class TestCaseListData:
    def test_list_shows_cases(self, cases_dir):
        case1 = cases_dir / "INC-2026-001"
        case1.mkdir()
        with open(case1 / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-2026-001", "name": "Phishing", "status": "open"}, f)
        case2 = cases_dir / "INC-2026-002"
        case2.mkdir()
        with open(case2 / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-2026-002", "name": "Ransomware", "status": "closed"}, f)

        result = case_list_data(cases_dir)
        assert len(result["cases"]) == 2
        ids = [c["id"] for c in result["cases"]]
        assert "INC-2026-001" in ids
        assert "INC-2026-002" in ids

    def test_list_shows_names_and_status(self, cases_dir):
        case1 = cases_dir / "INC-2026-001"
        case1.mkdir()
        with open(case1 / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-2026-001", "name": "Phishing", "status": "open"}, f)

        result = case_list_data(cases_dir)
        c = result["cases"][0]
        assert c["name"] == "Phishing"
        assert c["status"] == "open"

    def test_list_marks_active_case(self, cases_dir, active_home):
        case1 = cases_dir / "INC-2026-001"
        case1.mkdir()
        with open(case1 / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-2026-001", "name": "Active Case", "status": "open"}, f)

        (active_home / ".sift" / "active_case").write_text(str(case1))

        result = case_list_data(cases_dir)
        assert result["cases"][0]["active"] is True

    def test_list_no_cases(self, cases_dir):
        result = case_list_data(cases_dir)
        assert result["cases"] == []

    def test_list_nonexistent_dir(self, tmp_path):
        result = case_list_data(tmp_path / "nonexistent")
        assert result["cases"] == []

    def test_list_skips_dirs_without_case_yaml(self, cases_dir):
        (cases_dir / "not-a-case").mkdir()
        case1 = cases_dir / "INC-2026-001"
        case1.mkdir()
        with open(case1 / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-2026-001", "name": "Real Case", "status": "open"}, f)

        result = case_list_data(cases_dir)
        assert len(result["cases"]) == 1
        assert result["cases"][0]["id"] == "INC-2026-001"

    def test_list_from_env(self, cases_dir, monkeypatch):
        monkeypatch.setenv("SIFT_CASES_DIR", str(cases_dir))
        case1 = cases_dir / "INC-TEST"
        case1.mkdir()
        with open(case1 / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-TEST", "name": "Env Test", "status": "open"}, f)

        result = case_list_data()
        ids = [c["id"] for c in result["cases"]]
        assert "INC-TEST" in ids


class TestCaseInitData:
    def test_creates_case_directory(self, cases_dir, active_home):
        result = case_init_data(
            name="Test Case",
            examiner="tester",
            cases_dir=cases_dir,
            case_id="INC-TEST-001",
        )
        assert result["case_id"] == "INC-TEST-001"
        assert (cases_dir / "INC-TEST-001").is_dir()

    def test_creates_subdirectories(self, cases_dir, active_home):
        case_init_data(
            name="Test Case",
            examiner="tester",
            cases_dir=cases_dir,
            case_id="INC-TEST-001",
        )
        case_dir = cases_dir / "INC-TEST-001"
        for subdir in ("evidence", "extractions", "reports", "audit", "agent"):
            assert (case_dir / subdir).is_dir()

    def test_creates_case_yaml(self, cases_dir, active_home):
        case_init_data(
            name="Phishing Investigation",
            examiner="alice",
            cases_dir=cases_dir,
            case_id="INC-TEST-001",
        )
        meta_file = cases_dir / "INC-TEST-001" / "CASE.yaml"
        assert meta_file.exists()
        meta = yaml.safe_load(meta_file.read_text())
        assert meta["name"] == "Phishing Investigation"
        assert meta["examiner"] == "alice"
        assert meta["status"] == "open"

    def test_sets_active_case_pointer(self, cases_dir, active_home):
        case_init_data(
            name="Test Case",
            examiner="tester",
            cases_dir=cases_dir,
            case_id="INC-TEST-001",
        )
        active_file = active_home / ".sift" / "active_case"
        assert active_file.exists()
        content = active_file.read_text().strip()
        assert "INC-TEST-001" in content

    def test_rejects_existing_case(self, cases_dir, active_home):
        case_init_data(
            name="First",
            examiner="tester",
            cases_dir=cases_dir,
            case_id="INC-TEST-001",
        )
        with pytest.raises(ValueError, match="already exists"):
            case_init_data(
                name="Duplicate",
                examiner="tester",
                cases_dir=cases_dir,
                case_id="INC-TEST-001",
            )

    def test_rejects_empty_examiner(self, cases_dir, active_home):
        with pytest.raises(ValueError, match="examiner"):
            case_init_data(
                name="Test",
                examiner="",
                cases_dir=cases_dir,
                case_id="INC-TEST-001",
            )

    def test_rejects_invalid_case_id(self, cases_dir, active_home):
        with pytest.raises(ValueError):
            case_init_data(
                name="Test",
                examiner="tester",
                cases_dir=cases_dir,
                case_id="../../evil",
            )

    def test_autogenerates_case_id(self, cases_dir, active_home):
        result = case_init_data(
            name="Auto ID Case",
            examiner="tester",
            cases_dir=cases_dir,
        )
        assert result["case_id"].startswith("INC-")
        assert (cases_dir / result["case_id"]).is_dir()


class TestCaseActivateData:
    def test_activate_sets_active_pointer(self, cases_dir, active_home):
        # Create a case first
        case_dir = cases_dir / "INC-TEST-001"
        case_dir.mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-TEST-001", "name": "Test", "status": "open"}, f)

        result = case_activate_data("INC-TEST-001", cases_dir=cases_dir)
        assert result["case_id"] == "INC-TEST-001"

        active_file = active_home / ".sift" / "active_case"
        assert active_file.exists()
        content = active_file.read_text().strip()
        assert "INC-TEST-001" in content

    def test_activate_nonexistent_case_raises(self, cases_dir):
        with pytest.raises((ValueError, FileNotFoundError)):
            case_activate_data("NONEXISTENT", cases_dir=cases_dir)


class TestCaseStatusData:
    def test_status_returns_case_meta(self, cases_dir):
        case_dir = cases_dir / "INC-TEST-001"
        case_dir.mkdir()
        for subdir in ("evidence", "extractions", "reports", "audit"):
            (case_dir / subdir).mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump(
                {
                    "case_id": "INC-TEST-001",
                    "name": "Status Test",
                    "status": "open",
                    "examiner": "tester",
                    "created": "2026-01-01T00:00:00Z",
                },
                f,
            )
        for fname in ("findings.json", "timeline.json", "evidence.json"):
            (case_dir / fname).write_text("[]")

        result = case_status_data(case_dir)
        assert result["case_id"] == "INC-TEST-001"
        assert result["name"] == "Status Test"
        assert result["status"] == "open"

    def test_status_surfaces_case_brief(self, cases_dir):
        """D-008: case_status exposes the curated intake brief to the agent."""
        case_dir = cases_dir / "INC-TEST-BRIEF"
        case_dir.mkdir()
        for subdir in ("evidence", "extractions", "reports", "audit"):
            (case_dir / subdir).mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump(
                {
                    "case_id": "INC-TEST-BRIEF",
                    "name": "Brief Test",
                    "status": "open",
                    "examiner": "tester",
                    "description": "Home break-in targeting SRL laptop.",
                    "incident_type": "unauthorized_access",
                    "severity": "high",
                    "occurred_at": "2020-11-13",
                    "affected_accounts": ["frocba@stark-research-labs.com"],
                    "impact_summary": "",  # empty → must be omitted
                },
                f,
            )
        for fname in ("findings.json", "timeline.json", "evidence.json"):
            (case_dir / fname).write_text("[]")

        brief = case_status_data(case_dir)["case_brief"]
        assert brief["description"].startswith("Home break-in")
        assert brief["incident_type"] == "unauthorized_access"
        assert brief["severity"] == "high"
        assert brief["affected_accounts"] == ["frocba@stark-research-labs.com"]
        assert "impact_summary" not in brief  # empty values dropped
        assert "examiner" not in brief  # lifecycle fields stay out of the brief

    def test_status_brief_empty_when_no_intake(self, cases_dir):
        """No intake metadata → empty brief (not missing key)."""
        case_dir = cases_dir / "INC-NO-BRIEF"
        case_dir.mkdir()
        for subdir in ("evidence", "extractions", "reports", "audit"):
            (case_dir / subdir).mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump(
                {"case_id": "INC-NO-BRIEF", "name": "n", "status": "open", "examiner": "t"},
                f,
            )
        for fname in ("findings.json", "timeline.json", "evidence.json"):
            (case_dir / fname).write_text("[]")
        assert case_status_data(case_dir)["case_brief"] == {}


# ---------------------------------------------------------------------------
# R0-4: case_list_data — reads SIFT_CASES_ROOT first
# ---------------------------------------------------------------------------


class TestCaseListEnvVarPriority:
    def test_reads_sift_cases_root(self, tmp_path, monkeypatch):
        """SIFT_CASES_ROOT set → case_list_data reads from that root."""
        cases_root = tmp_path / "cases"
        case_dir = cases_root / "rocba-20260525-1200"
        case_dir.mkdir(parents=True)
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "rocba-20260525-1200", "name": "ROCBA Test", "status": "open"}, f)
        monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
        monkeypatch.delenv("SIFT_CASES_DIR", raising=False)
        result = case_list_data()
        ids = [c["id"] for c in result["cases"]]
        assert "rocba-20260525-1200" in ids

    def test_cases_root_beats_cases_dir(self, tmp_path, monkeypatch):
        """SIFT_CASES_ROOT takes priority over SIFT_CASES_DIR."""
        root_cases = tmp_path / "root" / "cases"
        legacy_cases = tmp_path / "legacy" / "cases"
        case_in_root = root_cases / "rootcase-001"
        case_in_root.mkdir(parents=True)
        with open(case_in_root / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "rootcase-001", "status": "open"}, f)
        legacy_cases.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASES_ROOT", str(root_cases))
        monkeypatch.setenv("SIFT_CASES_DIR", str(legacy_cases))
        result = case_list_data()
        assert result["cases_root"] == str(root_cases)
        assert any(c["id"] == "rootcase-001" for c in result["cases"])

    def test_falls_back_to_sift_cases_dir(self, tmp_path, monkeypatch):
        """No SIFT_CASES_ROOT → falls back to SIFT_CASES_DIR."""
        cases_dir = tmp_path / "mydir" / "cases"
        case_dir = cases_dir / "fallback-case-001"
        case_dir.mkdir(parents=True)
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "fallback-case-001", "status": "open"}, f)
        monkeypatch.delenv("SIFT_CASES_ROOT", raising=False)
        monkeypatch.setenv("SIFT_CASES_DIR", str(cases_dir))
        result = case_list_data()
        ids = [c["id"] for c in result["cases"]]
        assert "fallback-case-001" in ids

    def test_marks_active_case_from_env(self, tmp_path, monkeypatch):
        """SIFT_CASE_DIR → active case identified without reading legacy file."""
        cases_root = tmp_path / "cases"
        case_dir = cases_root / "active-case-20260525-1200"
        case_dir.mkdir(parents=True)
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "active-case-20260525-1200", "status": "open"}, f)
        monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        result = case_list_data()
        active = [c for c in result["cases"] if c["active"]]
        assert len(active) == 1
        assert active[0]["id"] == "active-case-20260525-1200"


# ---------------------------------------------------------------------------
# R0-5: case_status_data — includes explicit path fields
# ---------------------------------------------------------------------------


class TestCaseStatusPaths:
    def test_includes_evidence_dir(self, tmp_path):
        """case_status_data returns evidence_dir field."""
        case_dir = tmp_path / "INC-TEST-STATUS"
        case_dir.mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({
                "case_id": "INC-TEST-STATUS",
                "name": "Status Paths Test",
                "status": "open",
                "examiner": "tester",
            }, f)
        for fname in ("findings.json", "timeline.json", "evidence.json"):
            (case_dir / fname).write_text("[]")
        result = case_status_data(case_dir)
        assert result["evidence_dir"] == str(case_dir / "evidence")
        assert result["extractions_dir"] == str(case_dir / "extractions")
        assert result["reports_dir"] == str(case_dir / "reports")
        assert result["audit_dir"] == str(case_dir / "audit")
        assert result["agent_dir"] == str(case_dir / "agent")

    def test_path_fields_are_strings(self, tmp_path):
        """All dir fields are plain strings, not Path objects."""
        case_dir = tmp_path / "INC-TEST-PATHS"
        case_dir.mkdir()
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump({"case_id": "INC-TEST-PATHS", "status": "open", "examiner": "t"}, f)
        for fname in ("findings.json", "timeline.json", "evidence.json"):
            (case_dir / fname).write_text("[]")
        result = case_status_data(case_dir)
        for field in (
            "evidence_dir",
            "extractions_dir",
            "reports_dir",
            "audit_dir",
            "agent_dir",
        ):
            assert isinstance(result[field], str), f"{field} should be a str"


class TestCaseStatusDbCounters:
    """BU1: in DB-active mode case_status_data is DB-authoritative and fails closed.

    Metadata and counters come from Postgres authority; CASE.yaml is never read,
    so a tampered/stale mirror cannot change orientation, and a DB error fails
    closed rather than falling back to the file mirror.
    """

    @staticmethod
    def _make_case(tmp_path, *, tamper=False):
        case_dir = tmp_path / "INC-DB-COUNTERS"
        case_dir.mkdir()
        # CASE.yaml is intentionally stale/forged: DB mode must ignore it.
        yaml_meta = (
            {"case_id": "TAMPERED", "name": "TAMPERED", "status": "closed",
             "examiner": "evil", "incident_type": "phishing"}
            if tamper
            else {"case_id": "INC-DB-COUNTERS", "name": "File Name",
                  "status": "open", "examiner": "t"}
        )
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump(yaml_meta, f)
        # Stale file mirror: one draft finding only.
        (case_dir / "findings.json").write_text(
            '[{"id": "F-old-001", "status": "DRAFT"}]'
        )
        (case_dir / "timeline.json").write_text("[]")
        (case_dir / "todos.json").write_text("[]")
        return case_dir

    # DB-authoritative metadata (CASE.yaml-shaped) the reader resolves from app.cases.
    _DB_META = {
        "case_id": "INC-DB-COUNTERS",
        "name": "DB Name",
        "status": "open",
        "examiner": "dbexam",
        "incident_type": "ransomware",
    }

    class _Store:
        def list_findings(self, case_id):
            return [
                {"id": "F-a-001", "status": "DRAFT"},
                {"id": "F-a-002", "status": "DRAFT"},
                {"id": "F-a-003", "status": "APPROVED"},
            ]

        def list_timeline(self, case_id):
            return [{"id": "T-a-001", "status": "APPROVED"}]

        def list_todos(self, case_id):
            return [{"todo_id": "TD-1", "status": "open"}]

    def _ctx(self, case_dir):
        from sift_core.active_case_context import AuthorityContext

        return AuthorityContext(
            case_id="33333333-3333-3333-3333-333333333333",
            case_key="INC-DB-COUNTERS",
            artifact_path=str(case_dir),
            db_active=True,
        )

    def _patch_db(self, monkeypatch, meta=None):
        from sift_core import investigation_store

        monkeypatch.setattr(
            investigation_store,
            "resolve_case_metadata",
            lambda: (self._DB_META if meta is None else meta),
        )
        monkeypatch.setattr(
            investigation_store, "resolve_investigation_store", lambda: self._Store()
        )

    def test_db_active_metadata_and_counters_from_db(self, tmp_path, monkeypatch):
        from sift_core.active_case_context import use_active_case_context

        case_dir = self._make_case(tmp_path)
        self._patch_db(monkeypatch)
        with use_active_case_context(self._ctx(case_dir)):
            result = case_status_data(case_dir)

        assert result["counters_authority"] == "db"
        # Metadata from DB authority, not CASE.yaml.
        assert result["name"] == "DB Name"
        assert result["examiner"] == "dbexam"
        assert result["case_brief"].get("incident_type") == "ransomware"
        # Counters from the DB store, not the stale file mirror.
        assert result["finding_count"] == 3
        assert result["finding_draft"] == 2
        assert result["finding_approved"] == 1
        assert result["timeline_count"] == 1
        assert result["timeline_approved"] == 1
        assert result["todo_open"] == 1
        assert result["todo_total"] == 1

    def test_tampered_case_yaml_ignored_in_db_mode(self, tmp_path, monkeypatch):
        """A forged CASE.yaml must not change DB-mode orientation output."""
        from sift_core.active_case_context import use_active_case_context

        case_dir = self._make_case(tmp_path, tamper=True)
        self._patch_db(monkeypatch)
        with use_active_case_context(self._ctx(case_dir)):
            result = case_status_data(case_dir)

        assert result["name"] == "DB Name"
        assert result["status"] == "open"
        assert result["examiner"] == "dbexam"
        assert result["case_id"] == "INC-DB-COUNTERS"

    def test_db_outage_fails_closed(self, tmp_path, monkeypatch):
        """A DB failure must fail closed, not fall back to CASE.yaml values."""
        from sift_core import investigation_store
        from sift_core.active_case_context import use_active_case_context

        case_dir = self._make_case(tmp_path)

        def _boom():
            raise investigation_store.InvestigationStoreError("connection refused")

        monkeypatch.setattr(
            investigation_store, "resolve_case_metadata", _boom
        )
        with use_active_case_context(self._ctx(case_dir)):
            with pytest.raises(investigation_store.InvestigationStoreError):
                case_status_data(case_dir)

    def test_file_mode_counters_unchanged(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
        case_dir = self._make_case(tmp_path)
        result = case_status_data(case_dir)
        assert result["counters_authority"] == "file"
        assert result["name"] == "File Name"
        assert result["finding_count"] == 1
        assert result["finding_draft"] == 1

    def test_db_context_mismatch_fails_closed(self, tmp_path, monkeypatch):
        """A DB context bound to a different case dir must fail closed, not leak."""
        from sift_core import investigation_store
        from sift_core.active_case_context import (
            AuthorityContext,
            use_active_case_context,
        )

        case_dir = self._make_case(tmp_path)
        other_dir = tmp_path / "OTHER-CASE"
        other_dir.mkdir()
        self._patch_db(monkeypatch)
        ctx = AuthorityContext(
            case_id="44444444-4444-4444-4444-444444444444",
            case_key="OTHER-CASE",
            artifact_path=str(other_dir),
            db_active=True,
        )
        with use_active_case_context(ctx):
            with pytest.raises(investigation_store.InvestigationStoreError):
                case_status_data(case_dir)
