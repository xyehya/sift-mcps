import os
from pathlib import Path

import pytest
import yaml

from sift_gateway.backends.stdio_backend import StdioMCPBackend
from sift_gateway.config import load_config
from sift_gateway.server import Gateway


def test_load_config_sets_case_dir_and_cases_root(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "case-one"
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump({"case": {"root": str(case_dir.parent), "dir": str(case_dir)}}),
        encoding="utf-8",
    )

    monkeypatch.delenv("AGENTIR_CASE_DIR", raising=False)
    monkeypatch.delenv("AGENTIR_CASES_ROOT", raising=False)

    load_config(str(cfg_path))

    assert Path(os.environ["AGENTIR_CASE_DIR"]) == case_dir
    assert Path(os.environ["AGENTIR_CASES_ROOT"]) == case_dir.parent


def test_load_config_clears_stale_case_dir_when_no_active_case(tmp_path, monkeypatch):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump({"case": {"root": str(tmp_path / "cases"), "dir": ""}}),
        encoding="utf-8",
    )

    monkeypatch.setenv("AGENTIR_CASE_DIR", str(tmp_path / "stale"))

    load_config(str(cfg_path))

    assert "AGENTIR_CASE_DIR" not in os.environ
    assert Path(os.environ["AGENTIR_CASES_ROOT"]) == tmp_path / "cases"


def test_gateway_constructor_applies_case_env(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "case-two"
    monkeypatch.delenv("AGENTIR_CASE_DIR", raising=False)
    monkeypatch.delenv("AGENTIR_CASES_ROOT", raising=False)

    Gateway({"case": {"root": str(case_dir.parent), "dir": str(case_dir)}, "backends": {}})

    assert Path(os.environ["AGENTIR_CASE_DIR"]) == case_dir
    assert Path(os.environ["AGENTIR_CASES_ROOT"]) == case_dir.parent


async def test_stdio_backend_refuses_launch_without_active_case_env(monkeypatch):
    monkeypatch.delenv("AGENTIR_CASE_DIR", raising=False)
    monkeypatch.setenv("AGENTIR_CASES_ROOT", "/cases")
    backend = StdioMCPBackend(
        "case-mcp",
        {"type": "stdio", "command": "python", "args": ["-m", "case_mcp.server"]},
    )

    with pytest.raises(RuntimeError, match="AGENTIR_CASE_DIR"):
        await backend.start()
