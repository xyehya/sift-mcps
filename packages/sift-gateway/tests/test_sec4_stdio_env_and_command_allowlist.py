"""SEC-4 — minimal stdio backend env + stdio command allowlist.

Fail-on-revert guards for two distinct controls:

  * DSS-CAN-020 (env): a spawned stdio backend's child environment must NOT
    inherit the gateway's secrets (``*_DSN``, Supabase service keys, other
    backends' bearer tokens). It receives only a minimal OS/case-context base
    plus the explicitly-approved ``env_refs`` overlay. Reverting to
    ``dict(os.environ)`` fails ``test_spawned_stdio_env_excludes_secrets``.
  * DSS-CAN-003 (command allowlist): a registered stdio ``command`` must be an
    installed/allowlisted add-on launcher, not an arbitrary interpreter/binary.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest
import sift_gateway.backends.stdio_backend as sb
from sift_gateway.backends.stdio_backend import _build_minimal_backend_env
from sift_gateway.mcp_backends_registry import (
    BackendRegistryError,
    assert_stdio_command_allowlisted,
)
from sift_gateway.rest import register_backend_logic

_SECRET_VARS = [
    "SIFT_CONTROL_PLANE_DSN",
    "SIFT_AUDIT_WRITER_DSN",
    "SIFT_DB_DSN",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_ANON_KEY",
    "SIFT_BACKEND_WINTOOLS_MCP_TOKEN",
    "SIFT_TOKEN_PEPPER",
    "SIFT_HMAC_KEY",
    "SIFT_PORTAL_SESSION_SECRET",
]


# --- minimal env (DSS-CAN-020) ---------------------------------------------


def test_build_minimal_env_drops_secrets_keeps_case_context():
    base = {
        "PATH": "/usr/bin",
        "HOME": "/home/sift",
        "LC_ALL": "C.UTF-8",
        "SIFT_CASE_DIR": "/cases/c1",
        "SIFT_CASES_ROOT": "/cases",
        **{k: "SENSITIVE" for k in _SECRET_VARS},
    }
    env = _build_minimal_backend_env(base, {})
    for secret in _SECRET_VARS:
        assert secret not in env, f"{secret} leaked into stdio child env"
    assert env["PATH"] == "/usr/bin"
    assert env["SIFT_CASE_DIR"] == "/cases/c1"
    assert env["SIFT_CASES_ROOT"] == "/cases"
    assert env["LC_ALL"] == "C.UTF-8"


def test_build_minimal_env_overlay_is_the_only_secret_channel():
    """An approved env_ref (e.g. RAG's knowledge-corpus DSN) still reaches the
    child — but only because it is explicitly overlaid, not inherited."""
    base = {"PATH": "/usr/bin", "SIFT_CONTROL_PLANE_DSN": "inherited"}
    # No overlay -> inherited DSN is dropped.
    assert "SIFT_CONTROL_PLANE_DSN" not in _build_minimal_backend_env(base, {})
    # Explicit overlay (resolved env_ref) -> present, by design.
    env = _build_minimal_backend_env(base, {"SIFT_CONTROL_PLANE_DSN": "approved"})
    assert env["SIFT_CONTROL_PLANE_DSN"] == "approved"


async def test_spawned_stdio_env_excludes_secrets(monkeypatch):
    """End-to-end: the env handed to StdioServerParameters carries no secrets."""
    for k in _SECRET_VARS:
        monkeypatch.setenv(k, "SENSITIVE")
    monkeypatch.setenv("SIFT_CASE_DIR", "/cases/c1")
    monkeypatch.setenv("PATH", "/usr/bin")

    captured: dict = {}

    def fake_stdio_client(server_params):
        captured["env"] = dict(server_params.env or {})
        raise RuntimeError("stop before spawn")

    monkeypatch.setattr(sb, "stdio_client", fake_stdio_client)

    backend = sb.StdioMCPBackend(
        "windows-triage",
        {"type": "stdio", "command": "/x/bin/wt", "env": {"OPENSEARCH_CONFIG": "/etc/os.yml"}},
    )
    with pytest.raises(RuntimeError):
        await backend.start()

    env = captured["env"]
    for secret in _SECRET_VARS:
        assert secret not in env, f"{secret} reached the spawned stdio backend env"
    assert env["SIFT_CASE_DIR"] == "/cases/c1"
    assert env["OPENSEARCH_CONFIG"] == "/etc/os.yml"  # approved env_ref overlay


# --- command allowlist (DSS-CAN-003) ---------------------------------------


def test_allowlist_accepts_venv_console_script():
    venv_bin = os.path.dirname(os.path.abspath(sys.executable))
    assert_stdio_command_allowlisted(os.path.join(venv_bin, "forensic-rag-mcp"))


@pytest.mark.parametrize(
    "command",
    ["sh", "bash", "python", "uv", "/bin/sh", "/usr/bin/nc", "/usr/bin/python3", "/tmp/evil", "  ", ""],
)
def test_allowlist_rejects_off_catalog_commands(command):
    with pytest.raises(BackendRegistryError):
        assert_stdio_command_allowlisted(command)


def test_allowlist_honors_explicit_env(monkeypatch):
    monkeypatch.setenv("SIFT_ADDON_COMMAND_ALLOWLIST", "/opt/custom/bin/mybackend")
    assert_stdio_command_allowlisted("/opt/custom/bin/mybackend")
    with pytest.raises(BackendRegistryError):
        assert_stdio_command_allowlisted("/opt/custom/bin/other")


def test_allowlist_honors_explicit_dir(monkeypatch, tmp_path):
    bindir = tmp_path / "addons"
    bindir.mkdir()
    launcher = bindir / "my-mcp"
    launcher.write_text("#!/bin/sh\n")
    monkeypatch.setenv("SIFT_ADDON_COMMAND_ALLOWLIST_DIRS", str(bindir))
    assert_stdio_command_allowlisted(str(launcher))


async def test_register_logic_rejects_off_allowlist_stdio_command():
    """The agent-reachable registration surface rejects an off-catalog command."""
    gateway = SimpleNamespace(mcp_backend_registry=None)
    body = {"name": "evil-backend", "config": {"type": "stdio", "command": "/bin/sh"}}
    response, status = await register_backend_logic(gateway, body, actor=None)
    assert status == 422
    assert response.get("registered") is False
    reasons = " ".join(r.get("reason", "") for r in response.get("reasons", []))
    assert "allowlist" in reasons.lower() or "absolute path" in reasons.lower()
