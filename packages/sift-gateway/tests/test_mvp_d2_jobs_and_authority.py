"""BATCH-D2: Gateway job adapter + add-on authority enforcement tests."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest
from fastmcp import FastMCP

from sift_core.evidence_chain import ChainStatus
from sift_gateway.identity import CaseMembership, Identity
from sift_gateway.jobs import EnqueuedJob, JobService, JobServiceError
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.server import Gateway


# ---------------------------------------------------------------------------
# Fake psycopg connection plumbing for JobService
# ---------------------------------------------------------------------------


class _FakeCursor:
    def __init__(self, conn: "_FakeConn") -> None:
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._conn.executed.append((" ".join(sql.split()), params))
        self._conn._last_sql = " ".join(sql.split())

    def fetchone(self):
        sql = self._conn._last_sql
        return self._conn.responder(sql)


class _FakeConn:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.executed: list[tuple[str, object]] = []
        self.committed = False
        self._last_sql = ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.committed = True


def _job_service_with(responder):
    svc = JobService("postgresql://stub", audit=None)
    conn = _FakeConn(responder)
    svc._connect = lambda: conn  # type: ignore[assignment]
    return svc, conn


def _operator(case_id="case-1", system_role=None):
    return Identity(
        principal="alice",
        principal_type="user",
        token_id="t1",
        agent_id=None,
        created_by=None,
        role="examiner",
        source_ip=None,
        auth_surface="mcp",
        principal_id="op-1",
        system_role=system_role,
        case_memberships=(CaseMembership(case_id=case_id, role="owner"),),
    )


def _agent(case_id="case-1"):
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id="agent-1",
        agent_id="agent-1",
        created_by=None,
        role="agent",
        source_ip=None,
        auth_surface="mcp",
        case_id=case_id,
        principal_id="agent-1",
        case_memberships=(),
    )


# ---------------------------------------------------------------------------
# Deliverable 1: job adapter
# ---------------------------------------------------------------------------


def test_enqueue_returns_only_job_id_and_uses_d1_rpc():
    def responder(sql):
        if "insert into app.audit_events" in sql:
            return ("audit-evt-1",)
        if "app.enqueue_job" in sql:
            return ("job-uuid-1",)
        return None

    svc, conn = _job_service_with(responder)
    result = svc.enqueue_job(
        job_type="ingest",
        case_id="case-1",
        evidence_id="ev-1",
        spec_public={"label": "parse"},
        spec_internal={"local_path": "/cases/x/evidence/disk.E01"},
        actor=_operator(),
    )

    assert isinstance(result, EnqueuedJob)
    # Caller-visible payload is the opaque job_id ONLY.
    assert result.public_dict() == {"job_id": "job-uuid-1"}

    sqls = [sql for sql, _ in conn.executed]
    # Uses the D1 enqueue RPC.
    assert any("app.enqueue_job" in sql for sql in sqls)
    # Audit event written first, then linked as p_enqueue_audit_event_id.
    enqueue_call = next(p for sql, p in conn.executed if "app.enqueue_job" in sql)
    assert enqueue_call[-1] == "audit-evt-1"
    assert conn.committed is True

    # The internal spec / local path is sent to the RPC but never echoed back.
    serialized = json.dumps(result.public_dict())
    assert "spec_internal" not in serialized
    assert "/cases/" not in serialized


def test_enqueue_rejects_unknown_job_type():
    svc, _ = _job_service_with(lambda sql: None)
    with pytest.raises(JobServiceError) as exc:
        svc.enqueue_job(job_type="not_a_type", case_id="case-1", actor=_operator())
    assert exc.value.reason == "invalid_job_type"


def test_job_status_is_sanitized_and_uses_public_view():
    row = (
        "job-uuid-1",            # job_id
        "ingest",               # job_type
        "running",              # status
        "case-1",               # case_id
        "ev-1",                 # evidence_id
        100,                     # priority
        1,                       # attempts
        3,                       # max_attempts
        {"label": "parse"},     # spec_public
        None,                    # result_public
        None,                    # error_summary
        None,                    # provenance_id
        "2026-06-08T00:00:00+00:00",  # created_at
        None,                    # started_at
        None,                    # finished_at
        "2026-06-08T00:01:00+00:00",  # updated_at
        2,                       # step_count
        1,                       # steps_succeeded
    )

    def responder(sql):
        if "app.job_status_public" in sql:
            return row
        return None

    svc, conn = _job_service_with(responder)
    status = svc.job_status_public("job-uuid-1", principal=_operator())

    sqls = [sql for sql, _ in conn.executed]
    assert any("from app.job_status_public" in sql for sql in sqls)

    assert status["job_id"] == "job-uuid-1"
    assert status["status"] == "running"
    assert status["spec_public"] == {"label": "parse"}
    assert status["step_count"] == 2

    serialized = json.dumps(status, default=str)
    # No worker/lease/internal/path leakage.
    for forbidden in ("spec_internal", "worker_id", "lease_expires_at", "/cases/"):
        assert forbidden not in serialized


def test_job_status_denies_non_member():
    row = ("j1", "ingest", "queued", "other-case") + (None,) * 14

    def responder(sql):
        if "app.job_status_public" in sql:
            return row
        return None

    svc, _ = _job_service_with(responder)
    with pytest.raises(JobServiceError) as exc:
        svc.job_status_public("j1", principal=_operator(case_id="case-1"))
    assert exc.value.reason == "job_case_membership_required"


def test_job_status_allows_agent_default_case_binding():
    row = ("j1", "run_command", "succeeded", "case-1") + (None,) * 14

    def responder(sql):
        if "app.job_status_public" in sql:
            return row
        return None

    svc, _ = _job_service_with(responder)

    status = svc.job_status_public("j1", principal=_agent(case_id="case-1"))

    assert status["job_id"] == "j1"
    assert status["status"] == "succeeded"


def test_job_status_not_found():
    svc, _ = _job_service_with(lambda sql: None)
    with pytest.raises(JobServiceError) as exc:
        svc.job_status_public("missing", principal=_operator())
    assert exc.value.reason == "job_not_found"


def test_expire_stale_jobs_calls_d1_rpc_and_returns_count():
    def responder(sql):
        if "app.expire_stale_jobs" in sql:
            return (3,)
        return None

    svc, conn = _job_service_with(responder)
    assert svc.expire_stale_jobs() == 3
    assert any("app.expire_stale_jobs" in sql for sql, _ in conn.executed)
    assert conn.committed is True


def test_gateway_reaper_hook_invokes_expire_stale_jobs():
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})

    calls = {"n": 0}

    class _StubJobService:
        def expire_stale_jobs(self):
            calls["n"] += 1
            raise asyncio.CancelledError()

    gateway.job_service = _StubJobService()
    gateway.config["gateway"] = {"jobs": {"reaper_interval_seconds": 5}}

    async def _no_sleep(_secs):
        return None

    async def _run():
        with patch("sift_gateway.server.asyncio.sleep", _no_sleep):
            await gateway._job_reaper()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_run())
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# Deliverable 2: add-on authority enforcement
# ---------------------------------------------------------------------------


def _execute_security():
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def _addon_manifest(*, required_scopes, prohibited=None, non_authoritative=True):
    tool = {
        "name": "cti_search",
        "description": "search threat intel",
        "read_only": True,
        "readOnlyHint": True,
        "evidence_class": "read_only",
        "category": "threat-intel",
        "recommended_phase": "CORRELATE",
        "required_scopes": list(required_scopes),
    }
    health = {
        "name": "cti_health",
        "description": "health",
        "read_only": True,
        "readOnlyHint": True,
        "evidence_class": "read_only",
        "category": "threat-intel",
        "recommended_phase": "CORRELATE",
        "health": True,
    }
    manifest = {
        "spec_version": "1.0",
        "name": "opencti-mcp",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "cti",
        "capabilities": {"provides": ["threat-intel"], "requires": [], "enriches_responses": False},
        "tools": [tool, health],
        "health": "cti_health",
    }
    if prohibited is not None or non_authoritative:
        manifest["authority_contract"] = {
            "non_authoritative": non_authoritative,
            "plane": "reference",
            "query_only": True,
            "prohibited_operations": list(prohibited or []),
        }
    return manifest


class _FakeBackend:
    started = False

    def __init__(self, manifest):
        self.manifest = manifest
        self.config = {"type": "stdio", "command": "true"}
        self.enabled = True


def _gateway_with_addon(manifest):
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends[manifest["name"]] = _FakeBackend(manifest)
    asyncio.run(gateway._build_tool_map())
    return gateway


async def _async_gateway_with_addon(manifest):
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends[manifest["name"]] = _FakeBackend(manifest)
    await gateway._build_tool_map()
    return gateway


def _identity_with_scopes(*scopes):
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id="t1",
        agent_id="hermes",
        created_by="alice",
        role="agent",
        source_ip=None,
        auth_surface="mcp",
        tool_scopes=frozenset(scopes),
    )


def _server_with_addon_tool(gateway, tool_name="cti_search"):
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gateway, auth_enabled=True))

    @mcp.tool(name=tool_name)
    async def _addon_tool():
        return "dispatched"

    return mcp


def test_addon_authority_profile_indexes_scopes_and_contract():
    gateway = _gateway_with_addon(
        _addon_manifest(required_scopes=["cti:read"], prohibited=["seal_evidence"])
    )
    profile = gateway.addon_authority_for_tool("cti_search")
    assert profile["required_scopes"] == ["cti:read"]
    assert profile["non_authoritative"] is True
    assert "seal_evidence" in profile["prohibited_operations"]
    # Core tools carry no add-on authority contract.
    assert gateway.addon_authority_for_tool("run_command") is None


async def test_missing_required_scope_denied_before_dispatch():
    gateway = await _async_gateway_with_addon(_addon_manifest(required_scopes=["cti:read"]))
    mcp = _server_with_addon_tool(gateway)
    identity = _identity_with_scopes("namespace:cti")  # grants tool, lacks cti:read

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 1},
    ):
        result = await mcp.call_tool("cti_search", {})

    assert result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["error"] == "addon_scope_missing"
    assert payload["missing_scopes"] == ["cti:read"]
    # Denied before dispatch: the backend tool body never ran.
    assert "dispatched" not in json.dumps(
        [i.model_dump(mode="json") for i in result.content], default=str
    )


async def test_required_scope_present_allows_dispatch():
    gateway = await _async_gateway_with_addon(_addon_manifest(required_scopes=["cti:read"]))
    mcp = _server_with_addon_tool(gateway)
    identity = _identity_with_scopes("namespace:cti", "cti:read")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 1},
    ):
        result = await mcp.call_tool("cti_search", {})

    assert not result.is_error
    assert "dispatched" in result.content[0].text


async def test_mcp_star_scope_satisfies_required_scope():
    gateway = await _async_gateway_with_addon(_addon_manifest(required_scopes=["cti:read"]))
    mcp = _server_with_addon_tool(gateway)
    identity = _identity_with_scopes("mcp:*")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 1},
    ):
        result = await mcp.call_tool("cti_search", {})

    assert not result.is_error
    assert "dispatched" in result.content[0].text


async def test_prohibited_operation_argument_denied_before_dispatch():
    gateway = await _async_gateway_with_addon(
        _addon_manifest(required_scopes=["cti:read"], prohibited=["seal_evidence", "approve_finding"])
    )
    mcp = _server_with_addon_tool(gateway)
    identity = _identity_with_scopes("mcp:*")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 1},
    ):
        result = await mcp.call_tool("cti_search", {"operation": "seal_evidence"})

    assert result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["error"] == "addon_prohibited_operation"
    assert "seal_evidence" in payload["prohibited_operations"]
    assert "dispatched" not in json.dumps([i.model_dump(mode="json") for i in result.content], default=str)


def test_library_manifest_remains_non_routable():
    from sift_gateway.backends import load_and_validate_manifest

    lib_manifest = {
        "transport": "library",
        "name": "forensic-knowledge",
        "capabilities": {"provides": ["reference"], "requires": [], "enriches_responses": False, "standalone_server": False},
        "authority_contract": {"non_authoritative": True, "prohibited_operations": ["expose_mcp_surface"]},
    }
    with patch("sift_gateway.backends.Path.exists", return_value=True), patch(
        "builtins.open"
    ), patch("json.load", return_value=lib_manifest):
        result = load_and_validate_manifest("forensic-knowledge", {"type": "stdio"})
    # Accepted as a manifest, but non-routable: returns None (no backend).
    assert result is None
