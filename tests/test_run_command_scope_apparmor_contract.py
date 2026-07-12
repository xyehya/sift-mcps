"""Fail-on-revert: run_command scope broker must transition into dfir-exec."""

from __future__ import annotations

import re

from _installer_support import REPO_ROOT

APPARMOR = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"


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
