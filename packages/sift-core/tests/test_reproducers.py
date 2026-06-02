from __future__ import annotations
import os
import shutil
import pytest
from pathlib import Path
from sift_core.execute import worker
from sift_core.execute.tools import generic
from sift_core.execute.security import (
    split_command_by_operators,
    parse_subcommand_argv_and_redirects,
)
from sift_core.execute.catalog import clear_catalog_cache
from sift_core.execute.security_policy import SECURITY_POLICY_ENV, policy_to_env_json

@pytest.fixture(autouse=True)
def _run_as_current_user(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "__current__")

def _set_policy(monkeypatch, policy: dict) -> None:
    monkeypatch.setenv(SECURITY_POLICY_ENV, policy_to_env_json(policy))
    clear_catalog_cache()

def test_quoting_bug(monkeypatch):
    # This should split by the '|' operator
    parts = split_command_by_operators("printf 'alpha\\nbeta\\n' | grep beta")
    assert parts == [("printf 'alpha\\nbeta\\n'", "|"), ("grep beta", "")]

def test_sequential_outputs(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-REPRO-1\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    
    _set_policy(monkeypatch, {
        "mode": "denylist",
        "denied_binaries": [],
        "allowed_binaries": [],
        "dangerous_flags": [],
        "tool_allowed_flags": {},
        "tool_blocked_flags": {},
        "output_flags": [],
    })
    
    # When running two commands sequentially, we should see outputs of both
    res = generic.run_command("echo a ; echo b", purpose="test sequential output")
    assert "a" in res["stdout"]
    assert "b" in res["stdout"]

def test_redirect_cwd(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-REPRO-2\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    
    # Create the agent/outputs directory inside the case
    outputs_dir = case_dir / "agent" / "outputs"
    outputs_dir.mkdir(parents=True, exist_ok=True)
    
    _set_policy(monkeypatch, {
        "mode": "denylist",
        "denied_binaries": [],
        "allowed_binaries": [],
        "dangerous_flags": [],
        "tool_allowed_flags": {},
        "tool_blocked_flags": {},
        "output_flags": [],
    })
    
    # Running a redirect to a relative path should resolve to the case directory,
    # NOT the gateway cwd, and succeed.
    res = generic.run_command("echo hi > agent/outputs/repro.txt", purpose="test redirect cwd")
    assert res["exit_code"] == 0
    assert (outputs_dir / "repro.txt").read_text() == "hi\n"
