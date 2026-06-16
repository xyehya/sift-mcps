"""BU3 (XYE-21): no control-plane DSN ⇒ the gateway refuses to serve DFIR tools.

Two enforcement points are proven here:

1. Serve entrypoint (``sift_gateway.__main__.main``) refuses to start when no
   control-plane DSN is configured — the misconfiguration is operator-visible
   (process exits non-zero) instead of silently degrading to file authority.
2. In-process backstop (``ControlPlaneRequiredMiddleware``) refuses every tool
   call when the gateway has no control-plane DSN, so an embedded/test-built app
   that bypasses ``__main__`` can never reach the file-authority readers via a
   DFIR tool call. With a DSN configured the backstop is transparent.

The evidence gate is also asserted to be DB-authority only (no file branch).
"""

from __future__ import annotations

import json

import pytest

from sift_gateway.active_case import ActiveCase
from sift_core.evidence_chain import ChainStatus
from sift_gateway.policy_middleware import (
    ControlPlaneRequiredMiddleware,
    EvidenceGateMiddleware,
    _use_gateway_active_case,
)


_DSN = "postgresql://service@localhost/sift"
_CASE = "11111111-1111-1111-1111-111111111111"


class _Audit:
    def __init__(self):
        self.calls = []

    def log(self, **kwargs):
        self.calls.append(kwargs)


class _Gateway:
    def __init__(self, dsn):
        self.control_plane_dsn = dsn
        self._audit = _Audit()


class _Message:
    def __init__(self, name="run_command"):
        self.name = name
        self.arguments = {}


class _Context:
    def __init__(self, name="run_command"):
        self.message = _Message(name)


# ---------------------------------------------------------------------------
# 1. Serve-entry refusal
# ---------------------------------------------------------------------------


def test_main_refuses_to_start_without_dsn(monkeypatch, capsys):
    import sift_gateway.__main__ as entry

    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    # setup_logging() reconfigures global logging; keep it from leaking into
    # other tests' caplog by neutralising it here.
    monkeypatch.setattr(entry, "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr(entry, "load_config", lambda _path: {"gateway": {}})
    monkeypatch.setattr(entry.sys, "argv", ["sift-gateway", "--config", "x.yaml"])

    def _no_uvicorn(*a, **k):  # pragma: no cover - must never be reached
        raise AssertionError("uvicorn.run must not be called without a DSN")

    monkeypatch.setattr(entry.uvicorn, "run", _no_uvicorn)

    with pytest.raises(SystemExit) as exc:
        entry.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "control-plane DSN" in err


def test_main_proceeds_with_dsn(monkeypatch):
    import sift_gateway.__main__ as entry

    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", _DSN)
    monkeypatch.setattr(entry, "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr(entry, "load_config", lambda _path: {"gateway": {}})
    monkeypatch.setattr(entry.sys, "argv", ["sift-gateway", "--config", "x.yaml"])

    built = {}

    class _FakeGateway:
        def __init__(self, config):
            built["config"] = config

        def create_app(self):
            built["app"] = object()
            return built["app"]

    ran = {}
    monkeypatch.setattr(entry, "Gateway", _FakeGateway)
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **k: ran.setdefault("app", app))

    entry.main()
    assert ran["app"] is built["app"]


# ---------------------------------------------------------------------------
# 2. In-process dispatch backstop
# ---------------------------------------------------------------------------


async def test_backstop_blocks_dfir_tool_without_dsn():
    gateway = _Gateway(dsn=None)
    middleware = ControlPlaneRequiredMiddleware(gateway)

    async def call_next(_context):  # pragma: no cover - must not be reached
        raise AssertionError("tool dispatch must be refused without a DSN")

    result = await middleware.on_call_tool(_Context("run_command"), call_next)
    payload = result.structured_content
    assert payload["blocked"] is True
    assert payload["reason"] == "control_plane_unavailable"
    assert payload["tool"] == "run_command"
    # Refusal is audited.
    assert gateway._audit.calls
    assert gateway._audit.calls[0]["source"] == "gateway_control_plane_required"


async def test_backstop_transparent_with_dsn():
    gateway = _Gateway(dsn=_DSN)
    middleware = ControlPlaneRequiredMiddleware(gateway)

    async def call_next(_context):
        return "allowed"

    result = await middleware.on_call_tool(_Context("run_command"), call_next)
    assert result == "allowed"
    assert gateway._audit.calls == []


# ---------------------------------------------------------------------------
# 3. Evidence gate is DB-authority only (no file branch)
# ---------------------------------------------------------------------------


async def test_evidence_gate_uses_db_authority_only(monkeypatch, tmp_path):
    calls = {}

    def fake_db_gate(case_id, dsn):
        calls["db"] = (case_id, dsn)
        return {"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 1}

    monkeypatch.setattr(
        "sift_gateway.policy_middleware.check_evidence_gate_db", fake_db_gate
    )
    # Any file-chain read raising must not affect the gate decision.
    monkeypatch.setattr(
        "sift_core.evidence_chain.chain_status",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("file chain must not be read")),
    )

    gateway = _Gateway(dsn=_DSN)
    middleware = EvidenceGateMiddleware(gateway)
    case = ActiveCase(
        case_id=_CASE,
        case_key="db-case",
        title="DB Case",
        description=None,
        status="active",
        artifact_path=str(tmp_path),
        metadata={},
    )

    async def call_next(_context):
        return "allowed"

    with _use_gateway_active_case(case):
        result = await middleware.on_call_tool(_Context("run_command"), call_next)
    assert result == "allowed"
    assert calls["db"] == (_CASE, _DSN)


def test_file_evidence_gate_function_removed():
    """The file-backed gate must be gone (provably unreachable by removal)."""
    import sift_gateway.evidence_gate as eg

    assert not hasattr(eg, "check_evidence_gate")
    assert not hasattr(eg, "_refresh")
