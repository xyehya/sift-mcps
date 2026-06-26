"""SEC-11 + SEC-16 — run_command isolation surfacing + seccomp kill safety.

SEC-11: the systemd cgroup scope must never silently downgrade to the direct
worker (no IPAddressDeny=any / cgroup caps); the old "auto" mode is removed and a
missing systemd-run fails closed. The worker/executor also surface the ACTUAL
applied isolation posture so it can ride the agent-facing run_command response.

SEC-16: the per-tool seccomp filter is flipped to KILL on the sync lane. socket()
must stay LOG-only (curl/wget/AF_UNIX survive) while a genuinely dangerous
denylisted syscall (ptrace/unshare/...) is killed.
"""

from __future__ import annotations

import json
import pwd
import subprocess
from types import SimpleNamespace

import pytest
from sift_core.execute import dfir_exec_launcher as launcher
from sift_core.execute import executor as ex
from sift_core.execute.exceptions import ExecutionError

_BPF_JEQ = launcher.BPF_JMP | launcher.BPF_JEQ | launcher.BPF_K
_BPF_RET = launcher.BPF_RET | launcher.BPF_K


# --- SEC-11: systemd scope fail-closed (no silent downgrade) ------------------


def test_systemd_scope_mode_removes_auto(monkeypatch):
    # The legacy silent-downgrade "auto" value now resolves to required.
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "auto")
    assert ex._systemd_scope_mode() == "required"
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "1")
    assert ex._systemd_scope_mode() == "required"
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "0")
    assert ex._systemd_scope_mode() == "off"


def test_systemd_scope_required_missing_systemd_run_fails_closed(monkeypatch):
    """=required + no systemd-run ⇒ ExecutionError, never a direct-worker downgrade."""
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "1")
    monkeypatch.setattr(ex.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(ex.Path, "exists", lambda self: False)

    with pytest.raises(ExecutionError, match="systemd-run"):
        ex._systemd_scope_command(
            ["python", "-m", "sift_core.execute.worker"],
            timeout=5,
            memory_limit_bytes=0,
            runtime_user="agent_runtime",
        )


def test_systemd_scope_auto_missing_systemd_run_fails_closed(monkeypatch):
    """The old 'auto' silent fallback is gone: auto + no systemd-run fails closed."""
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "auto")
    monkeypatch.setattr(ex.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(ex.Path, "exists", lambda self: False)

    with pytest.raises(ExecutionError, match="systemd-run"):
        ex._systemd_scope_command(
            ["python", "-m", "sift_core.execute.worker"],
            timeout=5,
            memory_limit_bytes=0,
            runtime_user="agent_runtime",
        )


def test_systemd_scope_command_reports_scope_applied(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "1")
    monkeypatch.setattr(
        ex.shutil,
        "which",
        lambda cmd: "/usr/bin/systemd-run" if cmd == "systemd-run" else None,
    )
    monkeypatch.setattr(pwd, "getpwnam", lambda name: SimpleNamespace(pw_gid=995))

    cmd, runtime_user_applied, scope_applied = ex._systemd_scope_command(
        ["python", "-m", "sift_core.execute.worker"],
        timeout=5,
        memory_limit_bytes=0,
        runtime_user="agent_runtime",
    )
    assert scope_applied is True
    assert runtime_user_applied is True
    assert "IPAddressDeny=any" in cmd


def test_systemd_scope_off_reports_not_applied(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "0")
    worker_cmd = ["python", "-m", "sift_core.execute.worker"]
    cmd, runtime_user_applied, scope_applied = ex._systemd_scope_command(
        worker_cmd,
        timeout=5,
        memory_limit_bytes=0,
        runtime_user="agent_runtime",
    )
    assert scope_applied is False
    assert runtime_user_applied is False
    assert cmd == worker_cmd


# --- SEC-11: isolation posture surfaced through executor/worker ---------------


def test_run_isolated_worker_merges_systemd_into_isolation(monkeypatch):
    """The executor merges its systemd-scope facts onto the worker isolation block."""
    monkeypatch.setenv("SIFT_EXECUTE_SYSTEMD_SCOPE", "1")
    monkeypatch.setattr(
        ex.shutil,
        "which",
        lambda cmd: "/usr/bin/systemd-run" if cmd == "systemd-run" else None,
    )
    monkeypatch.setattr(pwd, "getpwnam", lambda name: SimpleNamespace(pw_gid=995))

    worker_iso = {
        "launcher_applied": True,
        "runtime_user_applied": True,
        "seccomp_mode": "kill",
        "landlock": "required",
    }

    class FakeCompletedProcess:
        returncode = 0
        stdout = json.dumps(
            {"exit_code": 0, "stdout": "ok", "stderr": "", "isolation": worker_iso}
        )
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompletedProcess())

    res = ex._run_isolated_worker(
        ["/usr/bin/date"],
        timeout=5,
        cwd="/cases/c",
        max_output_bytes=1024,
        memory_limit_bytes=0,
        runtime_user="agent_runtime",
        sudo_path="/usr/bin/sudo",
    )
    iso = res["isolation"]
    assert iso["systemd_scope_applied"] is True
    assert iso["systemd_scope_mode"] == "required"
    # Worker-reported per-tool facts are preserved.
    assert iso["launcher_applied"] is True
    assert iso["seccomp_mode"] == "kill"
    assert iso["landlock"] == "required"


def test_worker_emits_isolation_block_same_user_dev(monkeypatch):
    """In same-user dev (no launcher), the worker reports an honest 'off' posture."""
    from sift_core.execute import worker

    class FakeProcess:
        pid = 4242
        returncode = 0
        stdout = None
        stderr = None

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def poll(self):
            return self.returncode

    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **k: FakeProcess())
    result = worker._execute_payload(
        {
            "cmd": ["/bin/echo", "ok"],
            "timeout": 5,
            "cwd": None,
            "max_output_bytes": 1024,
            "memory_limit_bytes": 0,
        }
    )
    iso = result["isolation"]
    assert iso["launcher_applied"] is False
    assert iso["runtime_user_applied"] is False
    # No launcher ⇒ no seccomp/landlock actually installed; do not imply one.
    assert iso["seccomp_mode"] == "off"
    assert iso["landlock"] == "off"


# --- SEC-16: seccomp KILL safety for socket() --------------------------------


def _ret_for_syscall(filters, syscall_nr):
    """Return the BPF RET action k for the JEQ-matched syscall_nr, or None."""
    for idx, f in enumerate(filters[:-1]):
        if f.code == _BPF_JEQ and f.k == syscall_nr:
            ret = filters[idx + 1]
            assert ret.code == _BPF_RET, "JEQ must be immediately followed by RET"
            return ret.k
    return None


def test_socket_always_logged_even_under_kill():
    """socket(41) must return LOG even when the global action is KILL (SEC-16)."""
    filters = launcher._build_seccomp_filters(launcher.SECCOMP_RET_KILL_PROCESS)
    assert _ret_for_syscall(filters, 41) == launcher.SECCOMP_RET_LOG


def test_socket_not_in_kill_denylist():
    assert 41 in launcher._X86_64_ALWAYS_LOG_SYSCALLS
    assert 41 not in launcher._X86_64_DENY_SYSCALLS


@pytest.mark.parametrize(
    "syscall_nr",
    [
        101,  # ptrace
        272,  # unshare
        321,  # bpf
        246,  # kexec_load
        175,  # init_module
        308,  # setns
    ],
)
def test_dangerous_syscalls_killed_under_kill_mode(syscall_nr):
    filters = launcher._build_seccomp_filters(launcher.SECCOMP_RET_KILL_PROCESS)
    assert _ret_for_syscall(filters, syscall_nr) == launcher.SECCOMP_RET_KILL_PROCESS


@pytest.mark.parametrize("syscall_nr", [101, 272, 321])
def test_denylist_syscalls_logged_under_log_mode(syscall_nr):
    filters = launcher._build_seccomp_filters(launcher.SECCOMP_RET_LOG)
    assert _ret_for_syscall(filters, syscall_nr) == launcher.SECCOMP_RET_LOG
    # socket still LOG in log mode too.
    assert _ret_for_syscall(filters, 41) == launcher.SECCOMP_RET_LOG


def test_seccomp_filter_terminates_with_allow():
    filters = launcher._build_seccomp_filters(launcher.SECCOMP_RET_KILL_PROCESS)
    assert filters[-1].code == _BPF_RET
    assert filters[-1].k == launcher.SECCOMP_RET_ALLOW
