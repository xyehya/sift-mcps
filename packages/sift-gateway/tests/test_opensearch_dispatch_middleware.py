"""feat/opensearch-workers: gateway OpenSearchJobDispatchMiddleware tests.

The gateway is the sole policy boundary: privileged opensearch_ingest /
opensearch_enrich_intel calls must be redirected to a NON-BLOCKING durable worker
job (never proxied to the in-gateway hardened/private-namespace stdio child),
carrying ONLY the DB-authoritative case_dir the gateway resolved — a client can
never spoof a different case. dry_run previews stay on the thin proxy.

These drive the REAL middleware through a FastMCP server (same harness style as
test_mvp_d2_jobs_and_authority) so the placement (innermost, after the evidence
gate) and the anti-spoof / path-free contracts are exercised end to end.
"""

from __future__ import annotations

import json

import pytest
from fastmcp import FastMCP

from sift_core.evidence_chain import ChainStatus
from sift_gateway.active_case import ActiveCase
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import (
    OpenSearchJobDispatchMiddleware,
    _use_gateway_active_case,
)
from sift_gateway.server import Gateway


def test_opensearch_job_dispatch_set_is_the_worker_route_invariant():
    """Guard the worker-vs-direct execution-route invariant (XYE-36).

    The split documented in DEVELOPER_ENTRYPOINT.md §`opensearch-mcp` is enforced
    by this one frozenset: ONLY the long-running ingestion/enrichment pipeline
    (which FUSE-mounts evidence and so cannot run in the gateway's private mount
    namespace) is redirected to a durable worker job. A new long-running / FUSE /
    privileged opensearch tool must be added here AND given a worker handler in
    `job_worker_cli.py` in the same change; a query/read/idempotent-admin tool
    must NOT. `opensearch_fix_host_mapping` is the documented exception (an
    idempotent, async-continuing reindex) and stays direct. If this assertion
    fails, update the doc + worker handlers to match — do not just edit the test.
    """
    from sift_gateway.policy_middleware import _OPENSEARCH_JOB_DISPATCH_TOOLS

    assert _OPENSEARCH_JOB_DISPATCH_TOOLS == frozenset(
        {"opensearch_ingest", "opensearch_enrich_intel"}
    )
    # The long-running reindex stays DIRECT by design (documented exception).
    assert "opensearch_fix_host_mapping" not in _OPENSEARCH_JOB_DISPATCH_TOOLS


_ACTIVE = ActiveCase(
    case_id="uuid-rocba",
    case_key="case-rocba-case-06132304",
    title="Rocba",
    description=None,
    status="active",
    artifact_path="/cases/case-rocba-case-06132304",
    metadata={},
    membership_role="owner",
)


class _RecordingJobService:
    """Captures enqueue_job calls; returns an opaque job id."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def enqueue_job(self, **kwargs):
        self.calls.append(kwargs)

        class _Job:
            job_id = "job-os-1"

        return _Job()


def _gateway_with_jobs():
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    gateway.job_service = _RecordingJobService()
    return gateway


def _agent_identity():
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id="t1",
        agent_id="hermes",
        created_by="alice",
        role="agent",
        source_ip=None,
        auth_surface="mcp",
        case_id="uuid-rocba",
        principal_id="hermes",
        case_memberships=(),
    )


def _server(gateway):
    """Mount ONLY the dispatch middleware over a stub proxy tool.

    The stub returns ``PROXIED`` so any test can detect a fall-through to the
    (would-be) stdio proxy instead of the durable-job dispatch.
    """
    mcp = FastMCP("parent", middleware=[OpenSearchJobDispatchMiddleware(gateway)])

    @mcp.tool(name="opensearch_ingest")
    async def _ingest(
        path: str = "",
        dry_run: bool = True,
        force: bool = False,
        case_dir: str = "",
        case_id: str = "",
        case_key: str = "",
    ):
        return "PROXIED"

    @mcp.tool(name="opensearch_enrich_intel")
    async def _enrich(force: bool = False, case_dir: str = "", case_id: str = ""):
        return "PROXIED"

    return mcp


async def _call(gateway, tool, args, *, identity=None):
    from unittest.mock import patch

    mcp = _server(gateway)
    identity = identity or _agent_identity()
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=identity), \
            _use_gateway_active_case(_ACTIVE):
        return await mcp.call_tool(tool, args)


# ---------------------------------------------------------------------------
# non-blocking dispatch
# ---------------------------------------------------------------------------


async def test_ingest_dispatches_nonblocking_and_returns_job_id():
    gateway = _gateway_with_jobs()
    result = await _call(
        gateway, "opensearch_ingest",
        {"path": "evidence/rocba-cdrive.e01", "dry_run": False, "force": True},
    )
    assert not result.is_error
    payload = json.loads(result.content[0].text)
    # Opaque job id returned immediately — the proxy tool body never ran.
    assert payload["job_id"] == "job-os-1"
    assert payload["status"] == "queued"
    assert payload["dispatched_to"] == "opensearch-worker"
    assert "PROXIED" not in result.content[0].text
    # Exactly one durable ingest job enqueued.
    assert len(gateway.job_service.calls) == 1
    assert gateway.job_service.calls[0]["job_type"] == "ingest"


async def test_enrich_dispatches_to_enrich_job():
    gateway = _gateway_with_jobs()
    result = await _call(gateway, "opensearch_enrich_intel", {"force": True})
    assert not result.is_error
    assert gateway.job_service.calls[0]["job_type"] == "enrich"


# ---------------------------------------------------------------------------
# anti-spoof: client cannot target another case / inject a case_dir
# ---------------------------------------------------------------------------


async def test_client_case_dir_is_ignored_worker_gets_db_authoritative_path():
    gateway = _gateway_with_jobs()
    await _call(
        gateway, "opensearch_ingest",
        {
            "path": "evidence/rocba-cdrive.e01",
            "dry_run": False,
            # Hostile client attempts to redirect the worker at another case.
            "case_dir": "/cases/some-other-case",
            "case_id": "uuid-attacker",
            "case_key": "case-attacker",
        },
    )
    call = gateway.job_service.calls[0]
    # The worker only ever sees the gateway-resolved (DB-authoritative) case.
    assert call["case_id"] == "uuid-rocba"
    assert call["spec_internal"]["case_dir"] == "/cases/case-rocba-case-06132304"
    assert call["spec_internal"]["case_key"] == "case-rocba-case-06132304"
    # The spoofed values never reach the worker spec.
    serialized = json.dumps(call, default=str)
    assert "some-other-case" not in serialized
    assert "uuid-attacker" not in serialized
    assert "case-attacker" not in serialized
    # spec_public is path-free (no case_dir / case_id keys at all).
    assert "case_dir" not in call["spec_public"]
    assert "case_id" not in call["spec_public"]


async def test_dry_run_preview_stays_on_thin_proxy():
    gateway = _gateway_with_jobs()
    result = await _call(
        gateway, "opensearch_ingest",
        {"path": "evidence/rocba-cdrive.e01", "dry_run": True},
    )
    # No job enqueued; the read-only preview falls through to the proxy.
    assert gateway.job_service.calls == []
    assert "PROXIED" in result.content[0].text


async def test_no_active_case_falls_through_without_enqueue():
    from unittest.mock import patch

    gateway = _gateway_with_jobs()
    mcp = _server(gateway)
    # No active case set in the contextvar -> dispatch must not enqueue.
    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_agent_identity()):
        result = await mcp.call_tool(
            "opensearch_ingest", {"path": "evidence/x.e01", "dry_run": False}
        )
    assert gateway.job_service.calls == []
    assert "PROXIED" in result.content[0].text


async def test_no_job_service_falls_through_without_error():
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    gateway.job_service = None
    result = await _call(
        gateway, "opensearch_ingest", {"path": "evidence/x.e01", "dry_run": False}
    )
    assert "PROXIED" in result.content[0].text


# ---------------------------------------------------------------------------
# B-D1: control-plane DSN injected into spec_internal (worker provenance bind)
# ---------------------------------------------------------------------------


async def test_control_plane_dsn_injected_into_spec_internal(monkeypatch):
    """B-D1: when SIFT_CONTROL_PLANE_DSN is set the gateway carries it into the
    worker spec_internal so the ingest subprocess can forward-write provenance.
    It is never copied to spec_public (which is path/secret-free)."""
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://svc:pw@db:5432/sift")
    gateway = _gateway_with_jobs()
    await _call(
        gateway, "opensearch_ingest",
        {"path": "evidence/rocba-cdrive.e01", "dry_run": False},
    )
    call = gateway.job_service.calls[0]
    assert call["spec_internal"]["control_plane_dsn"] == "postgresql://svc:pw@db:5432/sift"
    # The DSN is internal-only: it must never appear in the agent-facing spec.
    assert "control_plane_dsn" not in call["spec_public"]
    assert "postgresql://" not in json.dumps(call["spec_public"], default=str)


async def test_control_plane_dsn_absent_when_env_unset(monkeypatch):
    """B-D1: no DSN env -> the key is simply omitted (no empty-string injection),
    so the worker/subprocess no-ops the provenance write rather than mis-binding."""
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    gateway = _gateway_with_jobs()
    await _call(
        gateway, "opensearch_enrich_intel", {"force": True},
    )
    call = gateway.job_service.calls[0]
    assert "control_plane_dsn" not in call["spec_internal"]
