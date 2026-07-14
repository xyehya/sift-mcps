"""Fail-on-revert: run_command scope broker must transition into dfir-exec."""

from __future__ import annotations

import re

from _installer_support import REPO_ROOT

APPARMOR = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"
DFIR_EXEC_APPARMOR = REPO_ROOT / "configs" / "apparmor" / "dfir-exec.template"


def _broker_body() -> str:
    source = APPARMOR.read_text(encoding="utf-8")
    match = re.search(
        r"profile sift-run-command-scope flags=\(attach_disconnected\) \{(.*?)\}",
        source,
        flags=re.DOTALL,
    )
    assert match is not None, "sift-run-command-scope profile missing"
    return match.group(1)


def test_broker_transitions_worker_python_to_dfir_exec() -> None:
    body = _broker_body()
    assert "/opt/sift-mcps/.venv/bin/python            px -> dfir-exec," in body
    assert "/opt/sift-mcps/.venv/bin/python3*          px -> dfir-exec," in body
    assert "/usr/bin/python3*                          px -> dfir-exec," in body
    assert "/opt/sift-mcps/.venv/bin/python            rix," not in body
    assert "/opt/sift-mcps/.venv/bin/python3*          rix," not in body
    # Catch-all rix on venv/bin conflicts with px (apparmor_parser reject).
    assert "/opt/sift-mcps/.venv/bin/**                rix," not in body


def test_broker_remains_case_and_secret_blind() -> None:
    body = _broker_body()
    assert not re.search(r"(?m)^\s*/cases", body)
    assert not re.search(r"(?m)^\s*/var/lib/sift", body)
    for secret in (
        "supabase.env",
        "control-plane.env",
        "audit-writer.env",
        "DATABASE_URL",
        "OPENCTI_TOKEN",
    ):
        assert secret not in body


def test_gateway_still_px_into_scope_broker() -> None:
    source = APPARMOR.read_text(encoding="utf-8")
    assert (
        "/usr/local/sbin/sift-run-command-systemd-scope px -> sift-run-command-scope,"
        in source
    )


def test_dfir_exec_allows_only_the_fixed_dotnet_runtime_for_zimmerman_wrappers() -> None:
    source = DFIR_EXEC_APPARMOR.read_text(encoding="utf-8")
    assert "/usr/lib/dotnet/dotnet                   rix," in source
    assert "/usr/lib/dotnet/**                        rix," not in source


def test_dfir_exec_keeps_proc_narrow_while_allowing_dotnet_runtime_metadata() -> None:
    source = DFIR_EXEC_APPARMOR.read_text(encoding="utf-8")

    for rule in (
        "/proc/meminfo                            r,",
        "/proc/stat                               r,",
        "/proc/[0-9]*/mountinfo                   r,",
        "/proc/[0-9]*/fdinfo/[0-9]*               r,",
        "/proc/[0-9]*/fd/                         r,",
        "/proc/[0-9]*/fd/[0-9]*                   r,",
        "/sys/devices/system/**                   r,",
    ):
        assert rule in source
    assert "\n  /proc/**" not in source
    assert "\n  /proc/self/**" not in source
    assert "\n  /proc/[0-9]*/**" not in source
    assert "\n  /proc/[0-9]*/fdinfo/**" not in source
    assert "\n  /proc/[0-9]*/fd/**" not in source


def test_dfir_exec_external_final_open_grants_do_not_weaken_confinement() -> None:
    rules = {" ".join(line.split()) for line in DFIR_EXEC_APPARMOR.read_text(
        encoding="utf-8"
    ).splitlines()}

    assert {
        rule
        for rule in rules
        if rule.startswith("/proc/[0-9]*/fd")
    } == {
        "/proc/[0-9]*/fdinfo/[0-9]* r,",
        "/proc/[0-9]*/fd/ r,",
        "/proc/[0-9]*/fd/[0-9]* r,",
    }
    assert {
        "deny @@SIFT_CASES_ROOT@@/*/evidence/** wklmx,",
        "deny mount,",
        "deny remount,",
        "deny umount,",
        "deny ptrace,",
        "deny network inet,",
        "deny network inet6,",
    } <= rules


def test_dfir_exec_allows_the_public_file_magic_database_read_only() -> None:
    source = DFIR_EXEC_APPARMOR.read_text(encoding="utf-8")
    assert "/etc/magic                               r," in source
    assert "/etc/magic                               rw" not in source
