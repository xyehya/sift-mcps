"""BATCH-B1 — Gateway policy parity + agent response redaction.

Drivers: docs/migration/task-batches.md BATCH-B1; Session-Notes F-MVP-2 / F-MVP-3.

Acceptance covered here:
  - Agent tokens cannot use REST to bypass MCP policy (REST tool exec is
    operator-only; agents use the MCP surface). [F-MVP-3]
  - case_info / evidence_info / finding views / run-command-style responses
    expose no absolute case/evidence/mount paths over the agent MCP path; the
    agent keeps IDs, names, RELATIVE display paths, size, hash, seal status. [F-MVP-2]
  - Evidence-gate denial is fail-closed (no active case => blocked) and audited.
  - Response guard (secret redaction) and per-principal rate limit still apply
    on the agent MCP path.
"""

from __future__ import annotations

import json
import secrets
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

from sift_core.evidence_chain import ChainStatus
from sift_gateway.auth import AuthMiddleware
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.response_guard import (
    _redact_paths_in_text,
    guard_tool_result,
    redact_paths_structured,
)
from sift_gateway.rest import rest_routes
from sift_gateway.server import Gateway


# ---------------------------------------------------------------------------
# F-MVP-3: REST tool execution is operator-only
# ---------------------------------------------------------------------------

_EXAMINER_KEY = "sift_gw_" + secrets.token_hex(24)
_AGENT_KEY = "sift_svc_" + secrets.token_hex(24)
_SERVICE_KEY = "sift_svc_" + secrets.token_hex(24)

_API_KEYS = {
    _EXAMINER_KEY: {"examiner": "alice", "role": "examiner"},
    _AGENT_KEY: {"examiner": "hermes", "role": "agent", "agent_id": "hermes"},
    _SERVICE_KEY: {"examiner": "svc", "role": "service"},
}


def _rest_app():
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    gateway._tool_map = {"addon_echo": "addon"}

    async def call_tool(name, arguments, examiner=None, identity=None):
        return [TextContent(type="text", text=f"ran {name} for {examiner}")]

    gateway.call_tool = call_tool
    app = Starlette(
        routes=rest_routes(),
        middleware=[Middleware(AuthMiddleware, api_keys=_API_KEYS)],
    )
    app.state.gateway = gateway
    return app


@pytest.fixture()
def rest_client():
    return TestClient(_rest_app(), raise_server_exceptions=True)


def test_agent_token_blocked_from_rest_tool_execution(rest_client):
    resp = rest_client.post(
        "/api/v1/tools/addon_echo",
        json={"arguments": {}},
        headers={"Authorization": f"Bearer {_AGENT_KEY}"},
    )
    assert resp.status_code == 403
    assert "operator-only" in resp.json()["error"]


def test_service_token_blocked_from_rest_tool_execution(rest_client):
    resp = rest_client.post(
        "/api/v1/tools/addon_echo",
        json={"arguments": {}},
        headers={"Authorization": f"Bearer {_SERVICE_KEY}"},
    )
    assert resp.status_code == 403


def test_operator_token_allowed_on_rest_tool_execution(rest_client):
    resp = rest_client.post(
        "/api/v1/tools/addon_echo",
        json={"arguments": {}},
        headers={"Authorization": f"Bearer {_EXAMINER_KEY}"},
    )
    assert resp.status_code == 200
    assert resp.json()["tool"] == "addon_echo"


def test_agent_rest_block_does_not_invoke_tool(rest_client):
    """The 403 must fire before tool dispatch (no policy-less execution)."""
    resp = rest_client.post(
        "/api/v1/tools/addon_echo",
        json={"arguments": {"command": "ls"}},
        headers={"Authorization": f"Bearer {_AGENT_KEY}"},
    )
    assert resp.status_code == 403
    # The operator-only error body never contains tool output.
    assert "ran addon_echo" not in json.dumps(resp.json())


# ---------------------------------------------------------------------------
# F-MVP-2: absolute-path redaction unit behaviour
# ---------------------------------------------------------------------------


def test_path_redaction_collapses_in_case_path_to_relative():
    case = "/cases/case-acme-01020304"
    text = f"wrote {case}/evidence/disk.E01 and {case}/agent/out.txt"
    out, count = _redact_paths_in_text(text, case)
    assert "evidence/disk.E01" in out
    assert "agent/out.txt" in out
    assert case not in out
    assert count == 2


def test_path_redaction_redacts_sensitive_keeps_benign_paths():
    # AUT2 item-0: only SENSITIVE prefixes (cases root, evidence mounts,
    # /mnt, /media, /var/lib/sift, /dev, SIFT_STATE_DIR) are redacted. Benign
    # system paths (tool configs, tracebacks under /usr, /etc, /opt, /tmp)
    # pass through so the agent can diagnose tool failures autonomously.
    case = "/cases/case-acme-01020304"
    text = (
        "mount at /mnt/evidence/image.dd and config /etc/sift/gateway.yaml "
        "other case /cases/case-other-9/evidence/x.E01 state /var/lib/sift/db "
        "traceback /usr/lib/python3/dist-packages/volatility3/cli.py"
    )
    out, _ = _redact_paths_in_text(text, case)
    assert "/mnt/evidence/image.dd" not in out
    assert "/cases/case-other-9" not in out
    assert "/var/lib/sift/db" not in out
    assert "/etc/sift/gateway.yaml" in out
    assert "/usr/lib/python3/dist-packages/volatility3/cli.py" in out
    assert out.count("[REDACTED:absolute_path]") == 3


def test_path_redaction_keeps_relative_and_ids():
    case = "/cases/case-acme-01020304"
    text = "evidence/disk.E01 sha256=abc123 evidence_id=EV-7 size=4096"
    out, count = _redact_paths_in_text(text, case)
    assert out == text
    assert count == 0


def test_redact_paths_structured_mixed():
    case = "/cases/case-acme-01020304"
    value = {
        "evidence_id": "EV-7",
        "display_name": "Suspect Disk",
        "display_path": "evidence/disk.E01",
        "case_dir": f"{case}/evidence",  # in-case absolute -> relative
        "mount_path": "/mnt/raw/image.dd",  # foreign abs -> redacted
        "size_bytes": 4096,
        "sha256": "deadbeef",
        "seal_status": "OK",
    }
    out, findings = redact_paths_structured(value, case_dir_resolved=case)
    assert out["case_dir"] == "evidence"
    assert out["mount_path"] == "[REDACTED:absolute_path]"
    assert out["evidence_id"] == "EV-7"
    assert out["display_path"] == "evidence/disk.E01"
    assert out["sha256"] == "deadbeef"
    assert out["seal_status"] == "OK"
    # Only the foreign path produces an audit finding.
    assert any(f["path"] == "$.mount_path" for f in findings)
    assert not any(f["path"] == "$.case_dir" for f in findings)


# ---------------------------------------------------------------------------
# F-MVP-2: guard_tool_result end-to-end (the agent MCP choke point)
# ---------------------------------------------------------------------------


def test_guard_tool_result_redacts_absolute_paths(tmp_path):
    case = str(tmp_path)
    result = ToolResult(
        content=[TextContent(type="text", text=f"output_file={case}/agent/run.txt")],
        structured_content={
            "case_info": {
                "case_id": "C-1",
                "case_dir": f"{case}/evidence",
                "mount": "/mnt/raw/img.dd",
                "evidence_files": [
                    {"display_path": "evidence/a.E01", "sha256": "ff", "seal_status": "OK"}
                ],
            }
        },
    )
    guarded, findings, _ = guard_tool_result(
        result,
        override_active=False,
        case_dir=case,
        tool_name="case_info",
        cap_bytes=1_000_000,
    )
    serialized = json.dumps(
        {
            "content": [c.model_dump(mode="json") for c in guarded.content],
            "structured": guarded.structured_content,
        },
        default=str,
    )
    # No absolute case/mount path survives to the agent.
    assert case not in serialized
    assert "/mnt/raw/img.dd" not in serialized
    # Relative display path + IDs + hash + seal preserved.
    assert "evidence/a.E01" in serialized
    assert '"case_id": "C-1"' in serialized
    assert '"sha256": "ff"' in serialized
    # Foreign-path redaction is recorded for audit.
    assert any(f["pattern_name"] == "Absolute Path" for f in findings)


def test_guard_tool_result_path_redaction_ignores_secret_override(tmp_path):
    """Even with a secret override active, host paths are never re-exposed."""
    case = str(tmp_path)
    result = ToolResult(
        content=[TextContent(type="text", text="probe")],
        structured_content={"mount": "/mnt/raw/img.dd"},
    )
    guarded, _, _ = guard_tool_result(
        result,
        override_active=True,
        case_dir=case,
        tool_name="evidence_info",
        cap_bytes=1_000_000,
    )
    assert "/mnt/raw/img.dd" not in json.dumps(guarded.structured_content)


# ---------------------------------------------------------------------------
# Full MCP middleware stack: redaction + gate + audit + rate limit
# ---------------------------------------------------------------------------


def _gate(status):
    return {
        "blocked": status != ChainStatus.OK,
        "status": status,
        "issues": [] if status == ChainStatus.OK else [f"issue:{status}"],
        "manifest_version": 1,
    }


def _fake_gateway():
    gateway = MagicMock()
    gateway._audit = MagicMock()
    gateway._audit.log = MagicMock(return_value="aid-1")
    gateway._tool_map = {}
    gateway.active_case_service = None
    return gateway


async def test_mcp_path_redacts_absolute_case_path(monkeypatch, tmp_path):
    case = str(tmp_path)
    monkeypatch.setenv("SIFT_CASE_DIR", case)
    gateway = _fake_gateway()
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gateway))

    @mcp.tool(name="evidence_info")
    def evidence_info():
        return ToolResult(
            structured_content={
                "evidence_files": [{"display_path": "evidence/a.E01", "seal_status": "OK"}],
                "case_dir": f"{case}/evidence",
                "host_mount": "/mnt/raw/image.dd",
            }
        )

    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value=_gate(ChainStatus.OK),
    ), patch(
        "sift_gateway.policy_middleware.current_mcp_identity",
        return_value=None,
    ):
        result = await mcp.call_tool("evidence_info", {})

    serialized = json.dumps(
        {
            "content": [c.model_dump(mode="json") for c in result.content],
            "structured": result.structured_content,
        },
        default=str,
    )
    assert case not in serialized
    assert "/mnt/raw/image.dd" not in serialized
    assert "evidence/a.E01" in serialized


async def test_mcp_evidence_gate_fail_closed_and_audited(monkeypatch, tmp_path):
    """No active case (empty case dir) => fail-closed block, tool never runs, audited."""
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    gateway = _fake_gateway()
    ran = False
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gateway))

    @mcp.tool(name="run_command")
    async def run_command():
        nonlocal ran
        ran = True
        return "ran"

    # Real check_evidence_gate with no case dir must block (fail-closed).
    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity",
        return_value=None,
    ):
        result = await mcp.call_tool("run_command", {})

    assert ran is False
    assert "evidence_chain_unsealed" in result.content[0].text
    sources = [c.kwargs["source"] for c in gateway._audit.log.call_args_list]
    assert "gateway_evidence_gate" in sources


async def test_mcp_path_still_redacts_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path))
    secret = "AKIAIOSFODNN7EXAMPLE"
    gateway = _fake_gateway()
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gateway))

    @mcp.tool(name="case_info")
    def case_info():
        return ToolResult(structured_content={"token": secret})

    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value=_gate(ChainStatus.OK),
    ), patch(
        "sift_gateway.policy_middleware.current_mcp_identity",
        return_value=None,
    ):
        result = await mcp.call_tool("case_info", {})

    assert secret not in json.dumps(result.structured_content, default=str)
