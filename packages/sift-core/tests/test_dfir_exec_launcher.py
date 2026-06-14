from __future__ import annotations

import pytest
from sift_core.execute import dfir_exec_launcher as launcher


def test_launcher_policy_round_trip():
    policy = {
        "case_dir": "/cases/c",
        "runtime_user": "agent_runtime",
        "runtime_uid": 995,
        "require_landlock": True,
    }

    assert launcher.decode_policy(launcher.encode_policy(policy)) == policy


def test_launcher_rejects_root_uid(monkeypatch):
    monkeypatch.setattr(launcher.os, "getuid", lambda: 0)

    with pytest.raises(launcher.LauncherError, match="uid 0"):
        launcher._assert_runtime_identity({"service_uid": 1000, "runtime_uid": 995})


def test_launcher_rejects_service_uid(monkeypatch):
    monkeypatch.setattr(launcher.os, "getuid", lambda: 1000)

    with pytest.raises(launcher.LauncherError, match="service uid"):
        launcher._assert_runtime_identity({"service_uid": 1000, "runtime_uid": 995})


def test_launcher_rejects_wrong_runtime_uid(monkeypatch):
    monkeypatch.setattr(launcher.os, "getuid", lambda: 1001)

    with pytest.raises(launcher.LauncherError, match="expected runtime uid"):
        launcher._assert_runtime_identity({"service_uid": 1000, "runtime_uid": 995})


def test_landlock_fail_closed_when_required(monkeypatch):
    monkeypatch.setattr(launcher, "_landlock_abi", lambda: 0)

    with pytest.raises(launcher.LauncherError, match="Landlock unavailable"):
        launcher._install_landlock({"require_landlock": True})

    assert launcher._install_landlock({"require_landlock": False}) == 0


def test_seccomp_defaults_to_log_mode():
    assert launcher._seccomp_action({}) == launcher.SECCOMP_RET_LOG
    assert launcher._seccomp_action({"seccomp_mode": "log"}) == launcher.SECCOMP_RET_LOG
    assert launcher._seccomp_action({"seccomp_mode": "kill"}) == launcher.SECCOMP_RET_KILL_PROCESS


def test_prepare_exec_sequence_and_scrubbed_env(monkeypatch):
    calls = []
    captured = {}

    class ExecCalled(Exception):
        pass

    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "secret")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(launcher, "_close_inherited_fds", lambda: calls.append("close"))
    monkeypatch.setattr(launcher, "_set_limits", lambda policy: calls.append("limits"))
    monkeypatch.setattr(
        launcher,
        "_assert_runtime_identity",
        lambda policy: calls.append("identity"),
    )
    monkeypatch.setattr(launcher, "_set_no_new_privs", lambda: calls.append("nnp"))
    monkeypatch.setattr(launcher, "_install_landlock", lambda policy: calls.append("landlock"))
    monkeypatch.setattr(launcher, "_install_seccomp", lambda policy: calls.append("seccomp"))

    def fake_execvpe(file, argv, env):
        captured["file"] = file
        captured["argv"] = argv
        captured["env"] = env
        raise ExecCalled

    monkeypatch.setattr(launcher.os, "execvpe", fake_execvpe)

    with pytest.raises(ExecCalled):
        launcher._prepare_and_exec({"cwd": "", "case_dir": ""}, ["/bin/echo", "ok"])

    assert calls == ["close", "limits", "identity", "nnp", "landlock", "seccomp"]
    assert captured["file"] == "/bin/echo"
    assert captured["argv"] == ["/bin/echo", "ok"]
    assert captured["env"]["PATH"] == "/usr/bin:/bin"
    assert "SUPABASE_SERVICE_ROLE_KEY" not in captured["env"]
