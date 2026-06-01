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


def test_run_command_uses_systemd_run_when_available(monkeypatch):
    import shutil
    import subprocess
    import json

    called_cmd = []
    called_env = {}

    def fake_which(cmd):
        if cmd in ("systemd-run", "systemctl"):
            return f"/usr/bin/{cmd}"
        return None

    class FakeCompletedProcess:
        returncode = 0
        stdout = json.dumps({"exit_code": 0, "stdout": "systemd-run-ok", "stderr": "", "stdout_total_bytes": 14})
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        called_cmd.append(cmd)
        called_env.update(kwargs.get("env", {}))
        return FakeCompletedProcess()

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)

    # Trigger via direct executor run helper
    from sift_core.execute.executor import _run_isolated_worker
    res = _run_isolated_worker(["/usr/bin/date"], timeout=5, cwd=None, max_output_bytes=1024, memory_limit_bytes=0)

    assert res["stdout"] == "systemd-run-ok"
    assert called_cmd[0][0] == "/usr/bin/systemd-run"
    assert called_cmd[0][1] == "--user"
    assert called_cmd[0][2] == "--scope"
    assert any(arg.startswith("--unit=sift-execute-") for arg in called_cmd[0])
    assert "DBUS_SESSION_BUS_ADDRESS" in called_env
    assert "XDG_RUNTIME_DIR" in called_env


def test_run_command_sets_systemd_run_memory_limits(monkeypatch):
    import shutil
    import subprocess
    import json

    called_cmd = []

    def fake_which(cmd):
        return f"/usr/bin/{cmd}"

    class FakeCompletedProcess:
        returncode = 0
        stdout = json.dumps({"exit_code": 0, "stdout": "limit-ok", "stderr": ""})
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        called_cmd.append(cmd)
        return FakeCompletedProcess()

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)

    from sift_core.execute.executor import _run_isolated_worker
    _run_isolated_worker(["/usr/bin/date"], timeout=5, cwd=None, max_output_bytes=1024, memory_limit_bytes=50_000_000)

    assert called_cmd[0][0] == "/usr/bin/systemd-run"
    assert "--property=MemoryMax=50000000" in called_cmd[0]
    assert "--property=MemoryHigh=40000000" in called_cmd[0]


def test_run_command_falls_back_when_systemd_run_fails(monkeypatch):
    import shutil
    import subprocess
    import json

    called_cmds = []

    def fake_which(cmd):
        return f"/usr/bin/{cmd}"

    class FakeFailProcess:
        returncode = 1
        stdout = ""
        stderr = "Failed to connect to bus"

    class FakeSuccessProcess:
        returncode = 0
        stdout = json.dumps({"exit_code": 0, "stdout": "fallback-ok", "stderr": ""})
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        called_cmds.append(cmd)
        if cmd[0] == "/usr/bin/systemd-run":
            return FakeFailProcess()
        # Direct run or systemctl reset-failed
        return FakeSuccessProcess()

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)

    from sift_core.execute.executor import _run_isolated_worker
    res = _run_isolated_worker(["/usr/bin/date"], timeout=5, cwd=None, max_output_bytes=1024, memory_limit_bytes=0)

    assert res["stdout"] == "fallback-ok"
    assert len(called_cmds) >= 3  # systemd-run, systemctl reset-failed, then direct run
    assert called_cmds[0][0] == "/usr/bin/systemd-run"
    assert called_cmds[1][0] == "/usr/bin/systemctl"
    assert called_cmds[1][1:] == ["--user", "reset-failed", called_cmds[0][3].split("=")[1]]
    assert called_cmds[2][1] == "-m"
    assert called_cmds[2][2] == "sift_core.execute.worker"


def test_sudo_validation_rules(tmp_path, monkeypatch):
    import shutil
    from sift_core.execute.exceptions import DeniedBinaryError

    # Set up case
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-003\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    # 1. Blocking sudo reboot (denied binary check)
    with pytest.raises(DeniedBinaryError, match="Agent-supplied sudo is blocked"):
        generic.run_command(["sudo", "reboot"], purpose="test sudo block")

    with pytest.raises(DeniedBinaryError, match="Agent-supplied sudo is blocked"):
        generic.run_command(["sudo", "-i"], purpose="test sudo interactive")

    with pytest.raises(DeniedBinaryError, match="Agent-supplied sudo is blocked"):
        generic.run_command(["sudo"], purpose="test empty sudo")


def test_privileged_path_direct_success(tmp_path, monkeypatch):
    import shutil
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-004\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    # Mock finding mount binary
    def fake_which(cmd):
        if cmd == "mount":
            return "/usr/bin/mount"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    _set_policy(monkeypatch, {
        "mode": "denylist",
        "denied_binaries": [],
        "allowed_binaries": [],
        "dangerous_flags": [],
        "tool_allowed_flags": {},
        "tool_blocked_flags": {},
        "output_flags": [],
    })

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {"exit_code": 0, "stdout": "mounted ok\n", "stderr": "", "stdout_total_bytes": 11}
    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command(["mount", "/dev/sdb1", str(case_dir / "tmp")], purpose="test mount success")

    assert res["exit_code"] == 0
    assert res["privilege_escalation"]["mechanism"] == "direct_unprivileged"
    assert res["privilege_escalation"]["status"] == "success"
    assert len(calls) == 1
    assert calls[0] == ["/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")]


def test_privileged_path_sudo_fallback(tmp_path, monkeypatch):
    import shutil
    import os
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-005\n", encoding="utf-8")
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

    # Mock mount and sudo binaries
    def fake_which(cmd):
        if cmd == "mount":
            return "/usr/bin/mount"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)
    
    # Mock /usr/bin/sudo exists
    monkeypatch.setattr(os.path, "exists", lambda path: path == "/usr/bin/sudo" or os.path.exists(path))

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        if cmd_list[0] == "/usr/bin/mount":
            # Direct run fails with permission denied
            return {"exit_code": 1, "stdout": "", "stderr": "mount: only root can do that\n", "stdout_total_bytes": 0}
        else:
            # Sudo run succeeds
            return {"exit_code": 0, "stdout": "sudo mounted ok\n", "stderr": "", "stdout_total_bytes": 16}
    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command(["mount", "/dev/sdb1", str(case_dir / "tmp")], purpose="test mount fallback")

    assert res["exit_code"] == 0
    assert res["privilege_escalation"]["mechanism"] == "sudo_fallback"
    assert res["privilege_escalation"]["status"] == "success"
    assert len(calls) == 2
    assert calls[0] == ["/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")]
    assert calls[1] == ["/usr/bin/sudo", "-n", "--", "/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")]
    assert len(res["privilege_events"]) == 2
    assert res["privilege_events"][0]["status"] == "fallback_attempt"
    assert res["privilege_events"][1]["status"] == "success"


def test_privileged_path_non_permission_failure(tmp_path, monkeypatch):
    import shutil
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-006\n", encoding="utf-8")
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

    def fake_which(cmd):
        if cmd == "mount":
            return "/usr/bin/mount"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        # Direct run fails with syntax error (not a permission class error)
        return {"exit_code": 1, "stdout": "", "stderr": "mount: bad usage\n", "stdout_total_bytes": 0}
    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command(["mount", "/dev/sdb1", str(case_dir / "tmp")], purpose="test syntax error")

    # Exit code is 1, and no sudo was called (only 1 execute call)
    assert res["exit_code"] == 1
    assert len(calls) == 1
    assert calls[0] == ["/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")]
    # No escalation metadata because it failed and didn't fall back
    assert "privilege_escalation" not in res


def test_privileged_validators_fail_before_execution(tmp_path, monkeypatch):
    import shutil
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-007\n", encoding="utf-8")
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

    def fake_which(cmd):
        if cmd in ("dd", "mount", "losetup"):
            return f"/usr/bin/{cmd}"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    # 1. dd with invalid output target (outside case)
    with pytest.raises(ValueError, match="of= target must be under case"):
        generic.run_command(["dd", "if=/dev/sdb", "of=/etc/passwd"], purpose="test dd validator")

    # 2. mount with invalid target (outside case)
    with pytest.raises(ValueError, match="mount target directory must be inside the case"):
        generic.run_command(["mount", "/dev/sda", "/"], purpose="test mount validator")

    # 3. losetup without -r flag for setup
    with pytest.raises(ValueError, match="losetup loop device setup requires the read-only flag"):
        generic.run_command(["losetup", "/dev/loop0", str(case_dir / "evidence.raw")], purpose="test losetup validator")

    # 4. Wildcard/glob arguments in command
    with pytest.raises(ValueError, match="Wildcard/glob characters"):
        generic.run_command(["dd", "if=/dev/sdb*", "of=" + str(case_dir / "tmp/out")], purpose="test wildcard validator")


def test_allowlist_mode_sudo_target(tmp_path, monkeypatch):
    import shutil
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-008\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    # Enable allowlist mode
    _set_policy(monkeypatch, {
        "mode": "allowlist",
        "allowed_binaries": ["mount"],
        "denied_binaries": ["reboot"],
        "dangerous_flags": [],
        "tool_allowed_flags": {},
        "tool_blocked_flags": {},
        "output_flags": [],
    })

    def fake_which(cmd):
        if cmd in ("mount", "reboot"):
            return f"/usr/bin/{cmd}"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    # Allowed target should pass validation
    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {"exit_code": 0, "stdout": "", "stderr": ""}
    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command(["mount", "/dev/sdb1", str(case_dir / "tmp")], purpose="test allowed target")
    assert res["exit_code"] == 0

    # Denied binary (by deny floor or denylist reboot) should be rejected
    from sift_core.execute.exceptions import DeniedBinaryError
    with pytest.raises(DeniedBinaryError, match="blocked by security policy"):
        generic.run_command(["reboot"], purpose="test denied target")

