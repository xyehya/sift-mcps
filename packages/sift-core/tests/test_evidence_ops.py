"""Tests for sift_core.evidence_ops data functions."""

import pytest

from sift_core.evidence_ops import (
    list_evidence_data,
    register_evidence_data,
    verify_evidence_data,
)


@pytest.fixture
def case_dir(tmp_path):
    """Case directory with evidence subdirectory."""
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence.json").write_text('{"files": []}')
    return tmp_path


class TestRegisterEvidenceData:
    def test_register_returns_entry(self, case_dir):
        ev_file = case_dir / "evidence" / "malware.bin"
        ev_file.write_bytes(b"malware content")
        entry = register_evidence_data(case_dir, str(ev_file), "analyst1", "Test malware")
        assert "sha256" in entry
        assert entry["description"] == "Test malware"
        assert entry["registered_by"] == "analyst1"

    def test_register_updates_evidence_json(self, case_dir):
        import json

        ev_file = case_dir / "evidence" / "malware.bin"
        ev_file.write_bytes(b"malware content")
        register_evidence_data(case_dir, str(ev_file), "analyst1", "Test malware")
        reg = json.loads((case_dir / "evidence.json").read_text())
        assert len(reg["files"]) == 1
        assert reg["files"][0]["sha256"]
        assert reg["files"][0]["description"] == "Test malware"

    def test_register_nonexistent_file_raises(self, case_dir):
        with pytest.raises(FileNotFoundError):
            register_evidence_data(case_dir, str(case_dir / "evidence" / "ghost.bin"), "analyst1")

    def test_register_directory_raises(self, case_dir):
        with pytest.raises(ValueError, match="directory"):
            register_evidence_data(case_dir, str(case_dir / "evidence"), "analyst1")

    def test_register_outside_case_raises(self, tmp_path):
        """Files outside the case directory are rejected."""
        actual_case_dir = tmp_path / "case"
        actual_case_dir.mkdir()
        (actual_case_dir / "evidence").mkdir()
        (actual_case_dir / "evidence.json").write_text('{"files": []}')
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"data")
        with pytest.raises(ValueError, match="case directory"):
            register_evidence_data(actual_case_dir, str(outside), "analyst1")

    def test_register_same_file_twice_returns_already_registered(self, case_dir):
        ev_file = case_dir / "evidence" / "same.bin"
        ev_file.write_bytes(b"same content")
        register_evidence_data(case_dir, str(ev_file), "analyst1")
        result = register_evidence_data(case_dir, str(ev_file), "analyst1")
        assert "already registered" in result.get("note", "")

    def test_register_same_path_different_hash_updates(self, case_dir):
        ev_file = case_dir / "evidence" / "updated.bin"
        ev_file.write_bytes(b"original")
        register_evidence_data(case_dir, str(ev_file), "analyst1")
        ev_file.write_bytes(b"modified content")
        result = register_evidence_data(case_dir, str(ev_file), "analyst1")
        assert "updated" in result.get("note", "")


class TestListEvidenceData:
    def test_list_shows_registered_files(self, case_dir):
        ev_file = case_dir / "evidence" / "sample.bin"
        ev_file.write_bytes(b"test data")
        register_evidence_data(case_dir, str(ev_file), "analyst1", "Test file")
        result = list_evidence_data(case_dir)
        assert result["registry_exists"] is True
        assert len(result["evidence"]) == 1
        assert "sample.bin" in result["evidence"][0]["path"]
        assert result["evidence"][0]["description"] == "Test file"

    def test_list_empty_registry(self, case_dir):
        result = list_evidence_data(case_dir)
        assert result["registry_exists"] is True
        assert result["evidence"] == []

    def test_list_no_registry(self, case_dir):
        (case_dir / "evidence.json").unlink()
        result = list_evidence_data(case_dir)
        assert result["registry_exists"] is False
        assert result["evidence"] == []

    def test_list_multiple_files(self, case_dir):
        for name in ("alpha.bin", "beta.bin", "gamma.bin"):
            ev = case_dir / "evidence" / name
            ev.write_bytes(b"data")
            register_evidence_data(case_dir, str(ev), "analyst1")
        result = list_evidence_data(case_dir)
        assert len(result["evidence"]) == 3


class TestVerifyEvidenceData:
    def test_verify_ok(self, case_dir):
        ev_file = case_dir / "evidence" / "intact.bin"
        ev_file.write_bytes(b"original data")
        register_evidence_data(case_dir, str(ev_file), "analyst1")
        result = verify_evidence_data(case_dir)
        assert result["verified"] == 1
        assert result["modified"] == 0
        assert result["missing"] == 0
        assert result["results"][0]["status"] == "OK"

    def test_verify_modified(self, case_dir):
        ev_file = case_dir / "evidence" / "tampered.bin"
        ev_file.write_bytes(b"original data")
        register_evidence_data(case_dir, str(ev_file), "analyst1")
        ev_file.write_bytes(b"tampered data")
        result = verify_evidence_data(case_dir)
        assert result["modified"] == 1
        assert result["results"][0]["status"] == "MODIFIED"

    def test_verify_missing(self, case_dir):
        ev_file = case_dir / "evidence" / "deleted.bin"
        ev_file.write_bytes(b"data")
        register_evidence_data(case_dir, str(ev_file), "analyst1")
        ev_file.unlink()
        result = verify_evidence_data(case_dir)
        assert result["missing"] == 1
        assert result["results"][0]["status"] == "MISSING"

    def test_verify_empty_registry(self, case_dir):
        result = verify_evidence_data(case_dir)
        assert result["verified"] == 0
        assert result["results"] == []

    def test_verify_no_registry(self, case_dir):
        (case_dir / "evidence.json").unlink()
        result = verify_evidence_data(case_dir)
        assert result["verified"] == 0
        assert result["results"] == []

    def test_verify_mixed_results(self, case_dir):
        ok_file = case_dir / "evidence" / "ok.bin"
        ok_file.write_bytes(b"intact")
        register_evidence_data(case_dir, str(ok_file), "analyst1")

        bad_file = case_dir / "evidence" / "bad.bin"
        bad_file.write_bytes(b"original")
        register_evidence_data(case_dir, str(bad_file), "analyst1")
        bad_file.write_bytes(b"tampered")

        result = verify_evidence_data(case_dir)
        assert result["verified"] == 1
        assert result["modified"] == 1
