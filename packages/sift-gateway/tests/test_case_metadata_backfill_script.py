from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml


def _load_script_module():
    script = Path(__file__).resolve().parents[3] / "scripts" / "backfill_case_metadata.py"
    spec = importlib.util.spec_from_file_location("backfill_case_metadata", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Cursor:
    def __init__(self, conn):
        self.conn = conn
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.statements.append((sql, params))
        normalized = " ".join(sql.lower().split())
        if normalized.startswith("select id::text"):
            self._rows = self.conn.rows
        elif normalized.startswith("update app.cases"):
            self.conn.updated.append(params)

    def fetchall(self):
        return self._rows


class _Connection:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []
        self.updated = []
        self.committed = False

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.committed = True


def test_backfill_case_metadata_script_updates_missing_and_reports_divergence(
    tmp_path, monkeypatch
):
    module = _load_script_module()
    monkeypatch.setattr(module, "_jsonb", lambda value: value)
    case_dir = tmp_path / "case-one"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        yaml.safe_dump(
            {
                "case_id": "case-one",
                "name": "Case One",
                "description": "Yaml description",
                "status": "open",
                "examiner": "analyst",
                "severity": "high",
            }
        ),
        encoding="utf-8",
    )
    conn = _Connection(
        [
            (
                "11111111-1111-1111-1111-111111111111",
                "case-one",
                "Case One",
                None,
                "active",
                str(case_dir),
                None,
                {"severity": "low"},
            )
        ]
    )

    summary = module.backfill_case_metadata(conn)

    assert summary["scanned"] == 1
    assert summary["updated"] == 1
    assert summary["divergences"] == [
        {
            "case_key": "case-one",
            "field": "severity",
            "db": "low",
            "case_yaml": "high",
        }
    ]
    assert conn.committed is True
    update_params = conn.updated[0]
    assert update_params[2] == "Yaml description"
    assert update_params[4]["status"] == "open"
    assert update_params[4]["examiner"] == "analyst"
    assert update_params[4]["severity"] == "low"
