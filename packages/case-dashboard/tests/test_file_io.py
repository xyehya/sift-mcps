"""Characterization tests for case_dashboard.file_io helpers.

These tests capture the current behaviour of _load_json, _load_yaml, and
_load_jsonl before their extraction from routes.py.  They exercise every
branch that the original code in routes.py covered and serve as the
regression net for the D4 refactor.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from case_dashboard.file_io import _load_json, _load_yaml, _load_jsonl

# Verify that the names are still importable from the original routes module
# (backcompat re-export via module-level import in routes.py).
from case_dashboard import routes as _routes_mod  # noqa: F401

assert hasattr(_routes_mod, "_load_json")
assert hasattr(_routes_mod, "_load_yaml")
assert hasattr(_routes_mod, "_load_jsonl")


# ---------------------------------------------------------------------------
# _load_json
# ---------------------------------------------------------------------------


class TestLoadJson:
    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        result = _load_json(tmp_path / "no-such-file.json")
        assert result is None

    def test_parses_json_list(self, tmp_path: Path) -> None:
        f = tmp_path / "data.json"
        f.write_text(json.dumps([{"id": 1}, {"id": 2}]), encoding="utf-8")
        result = _load_json(f)
        assert result == [{"id": 1}, {"id": 2}]

    def test_parses_json_dict(self, tmp_path: Path) -> None:
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"key": "value"}), encoding="utf-8")
        result = _load_json(f)
        assert result == {"key": "value"}

    def test_returns_none_for_corrupt_json(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not-json{{{", encoding="utf-8")
        result = _load_json(f)
        assert result is None

    def test_returns_none_for_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.json"
        f.write_text("", encoding="utf-8")
        result = _load_json(f)
        assert result is None

    def test_returns_none_on_permission_error(self, tmp_path: Path) -> None:
        f = tmp_path / "noperm.json"
        f.write_text(json.dumps({"x": 1}), encoding="utf-8")
        f.chmod(0o000)
        try:
            result = _load_json(f)
            assert result is None
        finally:
            f.chmod(0o644)  # restore so tmp_path cleanup works


# ---------------------------------------------------------------------------
# _load_yaml
# ---------------------------------------------------------------------------


class TestLoadYaml:
    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        result = _load_yaml(tmp_path / "no-such-file.yaml")
        assert result is None

    def test_parses_simple_mapping(self, tmp_path: Path) -> None:
        f = tmp_path / "data.yaml"
        f.write_text("name: test\nvalue: 42\n", encoding="utf-8")
        result = _load_yaml(f)
        assert result == {"name": "test", "value": 42}

    def test_returns_empty_dict_for_empty_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        result = _load_yaml(f)
        # yaml.safe_load("") is None; _load_yaml returns {} (falsy guard)
        assert result == {}

    def test_raises_value_error_for_corrupt_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        # Tabs are illegal in YAML indentation and trigger a scanner error
        f.write_text("key:\n\t- bad\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Corrupt YAML"):
            _load_yaml(f)

    def test_raises_value_error_on_os_error(self, tmp_path: Path) -> None:
        f = tmp_path / "noperm.yaml"
        f.write_text("key: val\n", encoding="utf-8")
        f.chmod(0o000)
        try:
            with pytest.raises(ValueError, match="Cannot read YAML"):
                _load_yaml(f)
        finally:
            f.chmod(0o644)


# ---------------------------------------------------------------------------
# _load_jsonl
# ---------------------------------------------------------------------------


class TestLoadJsonl:
    def test_returns_empty_list_for_missing_file(self, tmp_path: Path) -> None:
        result = _load_jsonl(tmp_path / "no-such-file.jsonl")
        assert result == []

    def test_parses_all_valid_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "data.jsonl"
        f.write_text(
            json.dumps({"a": 1}) + "\n" + json.dumps({"b": 2}) + "\n",
            encoding="utf-8",
        )
        result = _load_jsonl(f)
        assert result == [{"a": 1}, {"b": 2}]

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "data.jsonl"
        f.write_text(
            json.dumps({"a": 1}) + "\n\n" + json.dumps({"b": 2}) + "\n",
            encoding="utf-8",
        )
        result = _load_jsonl(f)
        assert result == [{"a": 1}, {"b": 2}]

    def test_skips_corrupt_lines_continues(self, tmp_path: Path) -> None:
        f = tmp_path / "data.jsonl"
        f.write_text(
            json.dumps({"a": 1}) + "\nBAD_LINE\n" + json.dumps({"c": 3}) + "\n",
            encoding="utf-8",
        )
        result = _load_jsonl(f)
        assert result == [{"a": 1}, {"c": 3}]

    def test_returns_empty_list_for_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.jsonl"
        f.write_text("", encoding="utf-8")
        result = _load_jsonl(f)
        assert result == []

    def test_returns_empty_list_on_permission_error(self, tmp_path: Path) -> None:
        f = tmp_path / "noperm.jsonl"
        f.write_text(json.dumps({"x": 1}) + "\n", encoding="utf-8")
        f.chmod(0o000)
        try:
            result = _load_jsonl(f)
            assert result == []
        finally:
            f.chmod(0o644)

    def test_all_corrupt_lines_returns_empty_list(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.jsonl"
        f.write_text("not-json\nalso-bad\n", encoding="utf-8")
        result = _load_jsonl(f)
        assert result == []
