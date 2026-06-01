from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from sift_core.execute import worker
from sift_core.execute.catalog import clear_catalog_cache
from sift_core.execute.exceptions import DeniedBinaryError, ExecutionTimeoutError
from sift_core.execute.executor import execute
from sift_core.execute.security_policy import SECURITY_POLICY_ENV, policy_to_env_json
from sift_core.execute.tools import generic


def _set_policy(monkeypatch, policy: dict) -> None:
    monkeypatch.setenv(SECURITY_POLICY_ENV, policy_to_env_json(policy))
    clear_catalog_cache()


def test_run_command_executes_allowed_command_through_isolated_worker(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-001\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    _set_policy(monkeypatch, {"denied_binaries": ["env"]})

    result = generic.run_command(["date"], purpose="test isolated worker")

    assert result["exit_code"] == 0
    assert result["executor"] == "isolated_worker"
    assert result["command"][0].endswith("/date")


def test_denied_command_rejected_before_executor_is_invoked(monkeypatch):
    _set_policy(monkeypatch, {"denied_binaries": ["echo"]})
    called = False

    def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor should not run for denied commands")

    monkeypatch.setattr(generic, "execute", _fail_if_called)

    with pytest.raises(DeniedBinaryError, match="blocked by security policy"):
        generic.run_command(["env"], purpose="test denied preflight")

    assert called is False


def test_allowlist_blocked_command_rejected_before_executor_is_invoked(monkeypatch):
    _set_policy(
        monkeypatch,
        {
            "mode": "allowlist",
            "allowed_binaries": ["date"],
            "denied_binaries": ["env"],
        },
    )
    called = False

    def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor should not run for allowlist blocks")

    monkeypatch.setattr(generic, "execute", _fail_if_called)

    with pytest.raises(DeniedBinaryError, match="not allowed"):
        generic.run_command(["cat", "--version"], purpose="test allowlist preflight")

    assert called is False


def test_worker_invokes_requested_process_with_shell_false(monkeypatch):
    calls = []

    class FakeProcess:
        pid = 12345
        returncode = 0
        stdout = io.BytesIO(b"ok\n")
        stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    def fake_popen(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return FakeProcess()

    monkeypatch.setattr(worker.subprocess, "Popen", fake_popen)

    result = worker._execute_payload(
        {
            "cmd": ["/bin/echo", "ok"],
            "timeout": 5,
            "cwd": None,
            "max_output_bytes": 1024,
            "memory_limit_bytes": 0,
        }
    )

    assert result["stdout"] == "ok\n"
    assert calls[0][0] == ["/bin/echo", "ok"]
    assert calls[0][1]["shell"] is False


def test_timeout_enforced_by_isolated_executor():
    with pytest.raises(ExecutionTimeoutError, match="timed out"):
        execute(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=1,
            cwd=None,
        )


def test_large_output_autowrites_under_case_run_commands(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-002\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_RESPONSE_BUDGET", "1000")

    result = execute(
        [sys.executable, "-c", "print('A' * 2000)"],
        timeout=10,
        cwd=str(case_dir),
    )

    output_file = Path(result["output_file"])
    assert output_file.is_file()
    assert output_file.read_text().startswith("A" * 100)
    assert output_file.parent.parent == case_dir / "agent" / "run_commands"
    assert output_file.parent.name == "output1"
    assert result["stdout_total_bytes"] > 1000
