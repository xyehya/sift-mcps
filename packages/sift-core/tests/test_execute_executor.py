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
from sift_core.execute.tools.discovery import get_tool_help


@pytest.fixture(autouse=True)
def _run_as_current_user(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "__current__")


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
    assert result["executor"] == "direct_worker"
    assert Path(result["command"][0]["argv"][0]).name == "date"



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

        def poll(self):
            return self.returncode

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
    assert result["stdout_total_bytes"] > 1000



def test_run_command_uses_direct_worker_without_systemd(monkeypatch):
    import json
    import subprocess

    called_cmd = []

    class FakeCompletedProcess:
        returncode = 0
        stdout = json.dumps({"exit_code": 0, "stdout": "worker-ok", "stderr": "", "stdout_total_bytes": 9})
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        called_cmd.append(cmd)
        payload = json.loads(kwargs["input"])
        assert payload["cmd"] == ["/usr/bin/date"]
        assert payload["runtime_user"] == ""
        return FakeCompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Trigger via direct executor run helper
    from sift_core.execute.executor import _run_isolated_worker
    res = _run_isolated_worker(["/usr/bin/date"], timeout=5, cwd=None, max_output_bytes=1024, memory_limit_bytes=0)

    assert res["stdout"] == "worker-ok"
    assert called_cmd[0][:3] == [sys.executable, "-m", "sift_core.execute.worker"]


def test_run_command_passes_memory_limit_to_worker(monkeypatch):
    import json
    import subprocess

    payloads = []

    class FakeCompletedProcess:
        returncode = 0
        stdout = json.dumps({"exit_code": 0, "stdout": "limit-ok", "stderr": ""})
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        payloads.append(json.loads(kwargs["input"]))
        return FakeCompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)

    from sift_core.execute.executor import _run_isolated_worker
    _run_isolated_worker(["/usr/bin/date"], timeout=5, cwd=None, max_output_bytes=1024, memory_limit_bytes=50_000_000)

    assert payloads[0]["memory_limit_bytes"] == 50_000_000


def test_native_runtime_user_requires_existing_local_account(monkeypatch):
    import pwd

    from sift_core.execute.exceptions import ExecutionError

    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "agent_runtime")
    monkeypatch.setattr(pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))

    with pytest.raises(ExecutionError, match="local account does not exist"):
        execute(["/usr/bin/date"], timeout=5, cwd=None)


def test_native_runtime_user_prefixes_stage_with_sudo(monkeypatch):
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

        def poll(self):
            return self.returncode

    def fake_popen(cmd, **kwargs):
        calls.append(cmd)
        return FakeProcess()

    monkeypatch.setattr(worker.subprocess, "Popen", fake_popen)

    result = worker._execute_payload(
        {
            "cmd": ["/usr/bin/id"],
            "runtime_user": "agent_runtime",
            "sudo_path": "/usr/bin/sudo",
            "timeout": 5,
            "cwd": None,
            "max_output_bytes": 1024,
            "memory_limit_bytes": 0,
        }
    )

    assert result["stdout"] == "ok\n"
    assert calls[0][:5] == ["/usr/bin/sudo", "-n", "-u", "agent_runtime", "--"]
    assert calls[0][5:] == ["/usr/bin/id"]


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
    assert calls[0] == [{"argv": ["/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")], "redirects": []}]



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
    monkeypatch.setattr(os.path, "exists", lambda path, orig=os.path.exists: path == "/usr/bin/sudo" or orig(path))

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        first_argv = cmd_list[0]["argv"]
        if first_argv[0] != "/usr/bin/sudo":
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
    assert calls[0] == [{"argv": ["/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")], "redirects": []}]
    assert calls[1] == [{"argv": ["/usr/bin/sudo", "-n", "--", "/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")], "redirects": [], "runtime_user": ""}]
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
    assert calls[0] == [{"argv": ["/usr/bin/mount", "/dev/sdb1", str(case_dir / "tmp")], "redirects": []}]
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


def test_validate_shell_command_safety_checks(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-009\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    # Mock finding commands
    import shutil
    def fake_which(cmd):
        if cmd in ("ls", "grep", "echo", "git", "kubectl", "dd", "rm"):
            return f"/usr/bin/{cmd}"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    _set_policy(monkeypatch, {
        "mode": "denylist",
        "denied_binaries": ["env"],
        "allowed_binaries": [],
        "dangerous_flags": [],
        "tool_allowed_flags": {},
        "tool_blocked_flags": {},
        "output_flags": [">", ">>"],
    })

    # 1. Pipeline check (should pass)
    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {"exit_code": 0, "stdout": "pipeline ok\n", "stderr": ""}
    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command("ls -la | grep txt", purpose="test pipeline")
    assert res["exit_code"] == 0
    assert calls[0] == [
        {"argv": ["/usr/bin/ls", "-la"], "redirects": []},
        {"argv": ["/usr/bin/grep", "txt"], "redirects": []}
    ]

    # 2. Control characters rejection
    with pytest.raises(ValueError, match="Command contains non-printable control characters"):
        generic.run_command("ls -la \x00 | grep txt", purpose="control char inject")

    # 3. IFS injection rejection
    with pytest.raises(ValueError, match="Modifying the IFS variable is blocked"):
        generic.run_command("IFS=:; ls", purpose="ifs inject")

    # 4. Proc/Environ access rejection
    with pytest.raises(ValueError, match="Direct access to process environment info"):
        generic.run_command("cat /proc/self/environ", purpose="proc inject")

    # 5. Process substitution rejection
    with pytest.raises(ValueError, match="Process substitution"):
        generic.run_command("echo hello > >(tee file.txt)", purpose="proc sub inject")

    # 6. Destructive commands rejection
    with pytest.raises(ValueError, match="Command matches a blocked destructive pattern"):
        generic.run_command("DROP TABLE users;", purpose="destructive db")
    with pytest.raises(ValueError, match="Command matches a blocked destructive pattern"):
        generic.run_command("DELETE FROM events", purpose="destructive db delete")

    # 7. Denied binary anywhere in pipeline
    from sift_core.execute.exceptions import DeniedBinaryError
    with pytest.raises(DeniedBinaryError, match="blocked by security policy"):
        generic.run_command("ls | env", purpose="denied in pipe")

    # 8. Output redirections check
    # Output to valid location (should pass)
    res2 = generic.run_command("echo 'hi' > " + str(case_dir / "agent/outputs/test.txt"), purpose="valid output redirection")
    assert res2["exit_code"] == 0

    # Output to invalid location (should fail)
    with pytest.raises(ValueError, match="Output path.*must be inside the case"):
        generic.run_command("echo 'hi' > /etc/passwd", purpose="invalid output redirection")


def test_newline_cr_ampersand_splitting(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-010\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    def fake_which(cmd):
        if cmd in ("echo", "ls", "grep"):
            return f"/usr/bin/{cmd}"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    from sift_core.execute.security import split_command_by_operators
    res = split_command_by_operators("echo a\necho b\recho c & echo d")
    assert len(res) == 4
    assert res[0] == ("echo a", ";")
    assert res[1] == ("echo b", ";")
    assert res[2] == ("echo c", "&")
    assert res[3] == ("echo d", "")


def test_nested_interpreter_rejection(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-011\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    def fake_which(cmd):
        return f"/usr/bin/{cmd}"
    monkeypatch.setattr(shutil, "which", fake_which)

    from sift_core.execute.exceptions import DeniedBinaryError

    for interp in ("sh", "python", "python3", "bash", "xargs", "timeout"):
        with pytest.raises(DeniedBinaryError, match=f"Binary '{interp}' is blocked"):
            generic.run_command(f"{interp} -c 'echo'", purpose="test nested interpreter rejection")


def test_basename_evasion_prevention(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-012\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    def fake_which(cmd):
        if cmd == "evil_bin":
            return str(case_dir / "agent" / "evil_bin")
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    evil_bin = case_dir / "agent" / "evil_bin"
    evil_bin.parent.mkdir(parents=True, exist_ok=True)
    evil_bin.touch()
    evil_bin.chmod(0o755)

    with pytest.raises(ValueError, match="resolves to.*which is inside the case directory"):
        generic.run_command("evil_bin", purpose="test basename evasion")


def test_evidence_write_delete_mutation_blocked(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    evidence_dir = case_dir / "evidence"
    tmp_dir = case_dir / "tmp"
    evidence_dir.mkdir(parents=True)
    tmp_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-018\n", encoding="utf-8")
    (evidence_dir / "sealed.bin").write_text("sealed", encoding="utf-8")
    (tmp_dir / "work.bin").write_text("work", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil

    def fake_which(cmd):
        if cmd in ("cp", "rm", "mv"):
            return f"/usr/bin/{cmd}"
        return None

    monkeypatch.setattr(shutil, "which", fake_which)

    calls = []

    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {"exit_code": 0, "stdout": "", "stderr": "", "stdout_total_bytes": 0}

    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command(
        "cp evidence/sealed.bin tmp/copy.bin",
        purpose="allow evidence read to writable output",
    )
    assert res["exit_code"] == 0
    assert calls[0] == [
        {"argv": ["/usr/bin/cp", "evidence/sealed.bin", "tmp/copy.bin"], "redirects": []}
    ]

    with pytest.raises(ValueError, match="Output denied: path .*protected case"):
        generic.run_command(
            "cp /usr/bin/python3 evidence/qa-decoy-REMOVEME",
            purpose="block evidence write",
        )

    with pytest.raises(ValueError, match="Blocked: rm in protected directory") as rm_exc:
        generic.run_command("rm evidence/sealed.bin", purpose="block evidence delete")
    assert "Exit Claude Code" not in str(rm_exc.value)
    assert "run the rm command directly" not in str(rm_exc.value)
    assert "Ask the operator" in str(rm_exc.value)

    with pytest.raises(ValueError, match="Move denied: path .*protected case"):
        generic.run_command("mv evidence/sealed.bin tmp/sealed.bin", purpose="block evidence move")


def test_run_command_help_has_no_self_redacting_absolute_path_example():
    help_data = get_tool_help("run_command")
    text = repr(help_data)
    assert ">/dev/null" not in text
    assert "[REDACTED:absolute_path]" not in text


def test_run_command_tool_description_disambiguates_sync_receipt_id():
    from sift_core.agent_tools import CORE_TOOL_SPECS

    spec = next(item for item in CORE_TOOL_SPECS if item.name == "run_command")
    assert "synchronous" in spec.description
    assert "rc-* receipt id is not a durable job id" in spec.description
    assert "use run_command_job" in spec.description
    assert "job_status" in spec.description


def test_native_runtime_fails_when_sudo_missing(monkeypatch):
    import pwd

    from sift_core.execute import executor as executor_module

    from sift_core.execute.exceptions import ExecutionError

    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "agent_runtime")
    monkeypatch.setattr(pwd, "getpwnam", lambda name: object())
    monkeypatch.setattr(executor_module.shutil, "which", lambda cmd: "/missing/sudo")

    with pytest.raises(ExecutionError, match="requires sudo"):
        execute(["date"])


def test_stages_auditing(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-013\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    def fake_which(cmd):
        if cmd in ("ls", "grep"):
            return f"/usr/bin/{cmd}"
        return None
    monkeypatch.setattr(shutil, "which", fake_which)

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {
            "exit_code": 0,
            "stdout": "res\n",
            "stderr": "",
            "stages": [
                {"binary": "ls", "argv": ["ls"], "exit_code": 0},
                {"binary": "grep", "argv": ["grep"], "exit_code": 0}
            ]
        }
    monkeypatch.setattr(generic, "execute", fake_execute)

    res = generic.run_command("ls | grep pattern", purpose="test stages audit")
    assert "stages" in res
    assert len(res["stages"]) == 2
    assert res["stages"][0]["binary"] == "ls"
    assert res["stages"][1]["binary"] == "grep"


def test_path_shadow_executes_resolved_binary(tmp_path, monkeypatch):
    """A binary referenced by a path whose basename shadows an allowed tool
    must execute the PATH-resolved real tool, never the literal path. This
    closes the "validate one binary, execute another" RCE: an attacker who
    drops a copy of python3 at <case>/tmp/ls and runs './ls -c ...' would
    otherwise pass basename validation but execute their file."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-014\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/ls" if cmd == "ls" else None)

    # Stage an attacker-controlled file named after an allowed tool.
    shadow = case_dir / "tmp" / "ls"
    shadow.parent.mkdir(parents=True, exist_ok=True)
    shadow.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    shadow.chmod(0o755)

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {"exit_code": 0, "stdout": "", "stderr": ""}
    monkeypatch.setattr(generic, "execute", fake_execute)

    generic.run_command(str(shadow) + " -la", purpose="test path shadow")

    # The executed argv[0] must be the resolved real binary, not the shadow.
    executed_argv = calls[0][0]["argv"]
    assert executed_argv[0] == "/usr/bin/ls"
    assert str(shadow) not in executed_argv


def test_stderr_merge_2to1_supported(tmp_path, monkeypatch):
    """'2>&1' must survive splitting/parsing and become a redirect directive
    rather than being treated as a statement separator ('&') or a file open."""
    from sift_core.execute.security import (
        split_command_by_operators,
        parse_subcommand_argv_and_redirects,
    )

    # '&' inside 2>&1 must not split the command.
    parts = split_command_by_operators("tool 2>&1 | grep err")
    assert parts == [("tool 2>&1", "|"), ("grep err", "")]

    argv, redirects = parse_subcommand_argv_and_redirects("tool 2>&1")
    assert argv == ["tool"]
    assert ("2>&1", "") in redirects


def test_quoted_redirect_literals_are_arguments_not_operators():
    """A quoted operator must remain a literal argument, not be interpreted as
    a redirect (the quote info is lost after shlex, so detection happens via an
    unforgeable sentinel during the char walk)."""
    from sift_core.execute.security import parse_subcommand_argv_and_redirects as p

    # Quoted forms -> literal arguments, no redirects.
    assert p('grep ">" log.txt') == (["grep", ">", "log.txt"], [])
    assert p('grep "2>&1" log.txt') == (["grep", "2>&1", "log.txt"], [])
    assert p("grep '<' log.txt") == (["grep", "<", "log.txt"], [])

    # Unquoted forms -> real redirects.
    assert p("cmd > out.txt") == (["cmd"], [(">", "out.txt")])
    assert p("cmd >> out.txt") == (["cmd"], [(">>", "out.txt")])
    assert p("cmd < in.txt") == (["cmd"], [("<", "in.txt")])


def test_heredoc_rejected(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-015\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: f"/usr/bin/{cmd}")

    with pytest.raises(ValueError, match="Heredocs"):
        generic.run_command("cat << EOF", purpose="test heredoc reject")


def test_exotic_fd_redirect_rejected(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-016\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: f"/usr/bin/{cmd}")

    # File-descriptor duplication forms have no forensic use and are rejected.
    for cmd in ("tool >&2", "tool 1>&2", "tool 3>out"):
        with pytest.raises(ValueError, match="Unsupported redirection"):
            generic.run_command(cmd, purpose="test exotic fd reject")

    # Valid op but target outside the case is rejected by output-path validation.
    with pytest.raises(ValueError, match="must be inside the case"):
        generic.run_command("tool 2>/etc/x", purpose="test stderr file outside case")


def test_stderr_file_redirects_supported(tmp_path, monkeypatch):
    """'2>'/'2>>'/'&>' and /dev/null sinks parse cleanly and validate."""
    from sift_core.execute.security import parse_subcommand_argv_and_redirects as p

    assert p("tool 2> err.log") == (["tool"], [("2>", "err.log")])
    assert p("tool 2>> err.log") == (["tool"], [("2>>", "err.log")])
    assert p("tool &> all.log") == (["tool"], [("&>", "all.log")])
    assert p("tool 2>/dev/null") == (["tool"], [("2>", "/dev/null")])

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: EXEC-017\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: f"/usr/bin/{cmd}")

    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        return {"exit_code": 0, "stdout": "", "stderr": ""}
    monkeypatch.setattr(generic, "execute", fake_execute)

    # /dev/null and an in-case stderr file are both accepted.
    generic.run_command("grep x 2>/dev/null", purpose="discard stderr")
    generic.run_command(
        "grep x 2>" + str(case_dir / "tmp" / "e.log"), purpose="stderr to case file"
    )
    assert calls[0][0]["redirects"] == [("2>", "/dev/null")]


def test_worker_stderr_to_file(tmp_path):
    """The worker routes stderr to a separate file for the '2>' op, keeping it
    out of the captured stdout/stderr streams."""
    err_file = tmp_path / "err.log"
    stages = [{
        "argv": [sys.executable, "-c", "import sys; sys.stderr.write('BOOM'); print('OK')"],
        "redirects": [("2>", str(err_file))],
    }]
    result = worker._execute_payload({
        "stages": stages,
        "timeout": 10,
        "max_output_bytes": 100000,
        "memory_limit_bytes": 0,
    })
    assert result["exit_code"] == 0
    assert "OK" in result["stdout"]
    assert result["stderr"] == ""
    assert err_file.read_text() == "BOOM"


def test_worker_merges_stderr_into_stdout(tmp_path):
    """End-to-end (no systemd): the worker routes stderr into stdout when the
    2>&1 directive is present on a stage."""
    stages = [{
        "argv": [sys.executable, "-c", "import sys; sys.stderr.write('E'); print('O')"],
        "redirects": [("2>&1", "")],
    }]
    result = worker._execute_payload({
        "stages": stages,
        "timeout": 10,
        "max_output_bytes": 100000,
        "memory_limit_bytes": 0,
    })
    assert result["exit_code"] == 0
    assert "O" in result["stdout"] and "E" in result["stdout"]
    assert result["stderr"] == ""


# ── AUT2-B5: pipeline upstream failures must be diagnosable ────────────────


def test_worker_surfaces_per_stage_stderr_and_exit_codes(tmp_path):
    result = worker._execute_payload({
        "stages": [
            {"argv": ["ls", str(tmp_path / "does-not-exist-xyz")], "redirects": []},
            {"argv": ["head", "-1"], "redirects": []},
        ],
        "timeout": 10,
        "max_output_bytes": 65536,
    })
    # Final stage (head) succeeds — exit_code alone would mask the failure.
    assert result["exit_code"] == 0
    stages = result["stages"]
    assert stages[0]["exit_code"] != 0
    assert "does-not-exist-xyz" in stages[0].get("stderr_tail", "")
    assert stages[1]["exit_code"] == 0
    assert "stderr_tail" not in stages[1]


# ── AUT2-B4: writable tool cache inside the case write-jail ────────────────


def test_worker_cache_dir_sets_xdg_cache_home(tmp_path):
    cache = tmp_path / "tmp" / "cache"
    result = worker._execute_payload({
        "cmd": ["env"],
        "timeout": 10,
        "max_output_bytes": 65536,
        "cache_dir": str(cache),
    })
    assert result["exit_code"] == 0
    assert f"XDG_CACHE_HOME={cache}" in result["stdout"]
    assert cache.is_dir()


def test_sudo_wrapper_reapplies_cache_env_via_env_binary():
    argv = worker._argv_for_runtime_user(
        ["vol", "-f", "mem.raw"], "agent_runtime", "/usr/bin/sudo",
        env_overrides={"XDG_CACHE_HOME": "/case/tmp/cache"},
    )
    assert argv[:5] == ["/usr/bin/sudo", "-n", "-u", "agent_runtime", "--"]
    assert "/usr/bin/env" in argv
    assert "XDG_CACHE_HOME=/case/tmp/cache" in argv
    assert argv[-3:] == ["vol", "-f", "mem.raw"]


# ── B4 follow-up: writable HOME/XDG jail + vol --symbol-dirs ────────────────


def test_worker_cache_dir_provisions_writable_home_and_xdg(tmp_path):
    cache = tmp_path / "tmp" / "cache"
    result = worker._execute_payload({
        "cmd": ["env"],
        "timeout": 10,
        "max_output_bytes": 65536,
        "cache_dir": str(cache),
    })
    assert result["exit_code"] == 0
    out = result["stdout"]
    jail = tmp_path / "tmp"
    home = jail / "home"
    assert f"HOME={home}" in out
    assert f"XDG_CONFIG_HOME={home / '.config'}" in out
    assert f"XDG_DATA_HOME={home / '.local' / 'share'}" in out
    assert f"XDG_STATE_HOME={home / '.local' / 'state'}" in out
    assert f"XDG_CACHE_HOME={cache}" in out
    # The vol symbol store is provisioned inside the same write-jail.
    assert (jail / "vol-symbols").is_dir()


def test_inject_vol_symbol_dir_prepends_for_vol():
    out = worker._inject_vol_symbol_dir(
        ["vol", "-f", "mem.raw", "windows.info"], "/case/tmp/vol-symbols"
    )
    assert out == [
        "vol", "--symbol-dirs", "/case/tmp/vol-symbols", "-f", "mem.raw", "windows.info",
    ]
    # Resolved absolute binary path is still recognised by basename.
    out2 = worker._inject_vol_symbol_dir(["/opt/volatility3/bin/vol", "-f", "m"], "/s")
    assert out2[:3] == ["/opt/volatility3/bin/vol", "--symbol-dirs", "/s"]


def test_inject_vol_symbol_dir_skips_non_vol_and_existing_flag():
    # Non-vol command untouched.
    assert worker._inject_vol_symbol_dir(["grep", "x", "evidence/y"], "/s") == [
        "grep", "x", "evidence/y",
    ]
    # An invocation that already specifies a symbol dir is not doubled up.
    already = ["vol", "--symbol-dirs", "/operator/dir", "-f", "m", "windows.info"]
    assert worker._inject_vol_symbol_dir(already, "/s") == already
    assert worker._inject_vol_symbol_dir([], "/s") == []


# ── AUT2-B7: binary stdout switches to saved-file-first ────────────────────


def test_binary_stdout_saved_first_and_suppressed_inline(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    (case_dir / "agent").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: B7-001\n", encoding="utf-8")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    result = execute(["dd", "if=/dev/zero", "bs=64", "count=1"], timeout=10)

    assert result["exit_code"] == 0
    assert result.get("binary_output") is True
    assert result.get("output_file"), result
    assert result["stdout"] == ""
    assert "Binary output detected" in result.get("stdout_note", "")
    saved = Path(result["output_file"])
    assert saved.exists()
    assert saved.stat().st_size == 64
