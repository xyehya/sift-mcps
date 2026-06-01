"""Core case-metadata set/get validation (Phase 2, F-E portal-owned)."""

from __future__ import annotations

import pytest
import yaml

from sift_core.case_metadata import (
    PROTECTED_FIELDS,
    get_case_metadata,
    set_case_metadata,
)


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "meta-test", "name": "MetaCase", "examiner": "alice"})
    )
    return tmp_path


def _reload(case_dir):
    return yaml.safe_load((case_dir / "CASE.yaml").read_text())


class TestSetMetadata:
    def test_set_enum_field(self, case_dir):
        result = set_case_metadata(case_dir, "incident_type", "ransomware")
        assert result == {"status": "set", "field": "incident_type", "value": "ransomware"}
        assert _reload(case_dir)["incident_type"] == "ransomware"

    def test_set_text_field(self, case_dir):
        result = set_case_metadata(case_dir, "client", "ACME Corp")
        assert result["status"] == "set"
        assert _reload(case_dir)["client"] == "ACME Corp"

    def test_tlp_uppercased(self, case_dir):
        result = set_case_metadata(case_dir, "tlp", "amber")
        assert result["value"] == "AMBER"
        assert _reload(case_dir)["tlp"] == "AMBER"

    def test_list_field(self, case_dir):
        result = set_case_metadata(case_dir, "tags", ["apt", "lateral-movement"])
        assert result["status"] == "set"
        assert _reload(case_dir)["tags"] == ["apt", "lateral-movement"]

    def test_iso8601_date_field(self, case_dir):
        result = set_case_metadata(case_dir, "detected_at", "2026-06-01T12:00:00")
        assert result["status"] == "set"

    def test_existing_metadata_preserved(self, case_dir):
        set_case_metadata(case_dir, "severity", "high")
        meta = _reload(case_dir)
        assert meta["case_id"] == "meta-test"
        assert meta["severity"] == "high"


class TestSetMetadataRejections:
    @pytest.mark.parametrize("field", sorted(PROTECTED_FIELDS))
    def test_protected_field_rejected(self, case_dir, field):
        result = set_case_metadata(case_dir, field, "x")
        assert "error" in result
        assert "protected" in result["error"].lower()

    def test_unknown_field_rejected(self, case_dir):
        result = set_case_metadata(case_dir, "not_a_field", "x")
        assert "error" in result
        assert "Unknown metadata field" in result["error"]

    def test_invalid_enum_rejected(self, case_dir):
        result = set_case_metadata(case_dir, "severity", "apocalyptic")
        assert "error" in result
        assert "Invalid value" in result["error"]

    def test_bad_date_rejected(self, case_dir):
        result = set_case_metadata(case_dir, "detected_at", "not-a-date")
        assert "error" in result
        assert "ISO 8601" in result["error"]

    def test_list_field_requires_list(self, case_dir):
        result = set_case_metadata(case_dir, "tags", "not-a-list")
        assert "error" in result
        assert "JSON array" in result["error"]

    def test_null_byte_rejected(self, case_dir):
        with pytest.raises(ValueError):
            set_case_metadata(case_dir, "client", "bad\x00value")


class TestGetMetadata:
    def test_get_all(self, case_dir):
        meta = get_case_metadata(case_dir)
        assert meta["case_id"] == "meta-test"

    def test_get_single_field(self, case_dir):
        set_case_metadata(case_dir, "severity", "low")
        assert get_case_metadata(case_dir, "severity") == {"field": "severity", "value": "low"}

    def test_get_unset_field_is_none(self, case_dir):
        assert get_case_metadata(case_dir, "client") == {"field": "client", "value": None}
