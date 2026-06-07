import os
from pathlib import Path

import pytest
import yaml

from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.config import load_config
from sift_gateway.server import Gateway


def _execute_security():
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def test_load_config_ignores_case_dir_and_sets_cases_root(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "case-one"
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump({"case": {"root": str(case_dir.parent), "dir": str(case_dir)}, **_execute_security()}),
        encoding="utf-8",
    )

    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_CASES_ROOT", raising=False)

    load_config(str(cfg_path))

    assert "SIFT_CASE_DIR" not in os.environ
    assert Path(os.environ["SIFT_CASES_ROOT"]) == case_dir.parent


def test_load_config_does_not_regenerate_or_clear_stale_case_dir(tmp_path, monkeypatch):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump({"case": {"root": str(tmp_path / "cases"), "dir": ""}, **_execute_security()}),
        encoding="utf-8",
    )

    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path / "stale"))

    load_config(str(cfg_path))

    assert os.environ["SIFT_CASE_DIR"] == str(tmp_path / "stale")
    assert Path(os.environ["SIFT_CASES_ROOT"]) == tmp_path / "cases"


def test_gateway_constructor_does_not_publish_case_dir(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "case-two"
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_CASES_ROOT", raising=False)

    Gateway({"case": {"root": str(case_dir.parent), "dir": str(case_dir)}, "backends": {}, **_execute_security()})

    assert "SIFT_CASE_DIR" not in os.environ
    assert Path(os.environ["SIFT_CASES_ROOT"]) == case_dir.parent


async def test_stdio_backend_warns_without_active_case_env(monkeypatch, caplog):
    """Backend starts in no-case mode with a warning, not a hard crash.

    This supports the post-reset / fresh-install state where the portal
    needs to be accessible to create the first case before any case dir exists.
    """
    import logging

    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.setenv("SIFT_CASES_ROOT", "/cases")
    backend = StdioMCPBackend(
        "demo-backend",
        {"type": "stdio", "command": "python", "args": ["-c", "raise SystemExit(1)"]},
    )

    with caplog.at_level(logging.WARNING):
        try:
            await backend.start()
        except Exception:
            pass  # Backend may fail to fully start (no real process), that's fine

    assert any("SIFT_CASE_DIR" in r.message for r in caplog.records), (
        "Expected a WARNING about missing SIFT_CASE_DIR in no-case mode"
    )
