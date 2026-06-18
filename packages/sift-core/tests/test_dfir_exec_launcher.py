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


def test_forensic_tool_rx_roots_cover_approved_venv_tools():
    """XYE-81: the approved operator-installed forensic-tool roots are present.

    These are the /opt roots whose wrapper shebangs resolve to a venv
    interpreter (or a symlinked script) that the kernel must read+execute. Each
    was confirmed against a live wrapper shebang. Pin them so a drop is caught.
    """
    approved = {
        "/opt/pyhindsight",
        "/opt/analyzemft",
        "/opt/usnparser",
        "/opt/indxparse",
        "/opt/sqlite-carver",
        "/opt/page-brute",
        "/opt/packerid",
        "/opt/mvt",
        "/opt/mac-apt",
        "/opt/python-evtx",
        "/opt/pdf-tools",
    }
    roots = set(launcher.FORENSIC_TOOL_RX_ROOTS)
    assert approved <= roots, f"missing approved rx roots: {sorted(approved - roots)}"


def test_forensic_tool_rx_roots_exclude_non_approved_opt_roots():
    """No /opt wildcard: only the specifically-approved tool roots are listed.

    /opt holds many other directories (e.g. /opt/microsoft, /opt/containerd,
    /opt/machinae) that the agent has no approved tool for. None of them — nor
    an /opt glob — may appear on the rx allow-list.
    """
    roots = set(launcher.FORENSIC_TOOL_RX_ROOTS)
    for forbidden in ("/opt", "/opt/*", "/opt/microsoft", "/opt/containerd", "/opt/machinae"):
        assert forbidden not in roots, f"unexpected rx root: {forbidden}"


def test_forensic_tool_rx_roots_applied_as_read_execute(monkeypatch):
    """Each approved root is granted FS_RX (read+execute), like /opt/volatility3.

    Drive _install_landlock with stubbed syscalls so it runs without the
    kernel, and capture the (path, access) tuples handed to _add_path_rule.
    Assert every existing approved root receives exactly FS_RX (masked by the
    handled access set) and never any write/make/remove bit.
    """
    monkeypatch.setattr(launcher, "_landlock_abi", lambda: 1)
    monkeypatch.setattr(launcher, "_syscall", lambda *a, **k: 0)
    monkeypatch.setattr(launcher.os, "close", lambda fd: None)

    # Only pretend the forensic-tool roots (plus a couple of base roots) exist,
    # so the assertion is not skewed by whatever happens to be on the test host.
    present = set(launcher.FORENSIC_TOOL_RX_ROOTS) | {"/usr", "/bin"}
    monkeypatch.setattr(launcher.Path, "exists", lambda self: str(self) in present)

    captured: dict[str, int] = {}

    def fake_add_rule(ruleset_fd, path, access):
        captured[path] = access

    monkeypatch.setattr(launcher, "_add_path_rule", fake_add_rule)

    launcher._install_landlock({"require_landlock": False})

    handled = launcher._fs_handled_access(1)
    expected_rx = launcher.FS_RX & handled
    write_bits = launcher.FS_WRITE & handled
    for root in launcher.FORENSIC_TOOL_RX_ROOTS:
        assert root in captured, f"{root} was not granted any Landlock rule"
        granted = captured[root]
        assert granted == expected_rx, f"{root} did not get exactly FS_RX"
        assert granted & write_bits == 0, f"{root} unexpectedly got write access"


def test_install_landlock_does_not_grant_unapproved_opt_root(monkeypatch):
    """A non-approved /opt root never receives a Landlock rule.

    Even if such a directory exists on the host, _install_landlock must not
    grant it any access — the rx floor is the explicit code-defined list only.
    """
    monkeypatch.setattr(launcher, "_landlock_abi", lambda: 1)
    monkeypatch.setattr(launcher, "_syscall", lambda *a, **k: 0)
    monkeypatch.setattr(launcher.os, "close", lambda fd: None)
    # Claim everything exists so the filter cannot be the reason it's absent.
    monkeypatch.setattr(launcher.Path, "exists", lambda self: True)

    captured: dict[str, int] = {}
    monkeypatch.setattr(
        launcher,
        "_add_path_rule",
        lambda ruleset_fd, path, access: captured.__setitem__(path, access),
    )

    launcher._install_landlock({"require_landlock": False})

    assert "/opt/microsoft" not in captured
    assert "/opt" not in captured


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
