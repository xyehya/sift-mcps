"""B-MVP-5/6/7 binding tests for Gateway-owned job/RAG tool seams."""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from sift_core.custody_types import ChainStatus
from sift_gateway.active_case import ActiveCase
from sift_gateway.job_tools import (
    GATEWAY_JOB_TOOLS,
    gateway_job_tool_specs,
    handle_job_status,
    handle_run_command_job,
)
from sift_gateway.mcp_server import create_gateway_mcp_server


def _case(case_dir: Path) -> ActiveCase:
    return ActiveCase(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="case-one",
        title="Case One",
        description=None,
        status="active",
        artifact_path=str(case_dir),
        metadata={},
        membership_role="agent",
    )


class _ActiveCaseService:
    def __init__(self, case):
        self.case = case

    def require_active_case_for_principal(self, principal):
        return self.case


class _JobResult:
    def __init__(self, job_id):
        self.job_id = job_id

    def public_dict(self):
        return {"job_id": self.job_id}


class _JobService:
    def __init__(self):
        self.enqueued = []

    def enqueue_job(self, **kwargs):
        self.enqueued.append(kwargs)
        return _JobResult(f"job-{len(self.enqueued)}")

    def job_status_public(self, job_id, principal=None):
        return {
            "job_id": job_id,
            "status": "running",
            "spec_public": {"evidence_ref": "evidence/disk.E01"},
        }


class _EvidenceService:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.authority = {
            "storage_profile": "LOCAL_IMMUTABLE",
            "storage_source_identity": "",
            "mount_instance_identity": "",
            "storage_generation": 1,
            "storage_verified_generation": 1,
            "storage_manifest_version": 1,
            "storage_manifest_hash": "sha256:manifest",
            "storage_verification_receipt_id": "receipt-1",
        }

    def resolve_evidence_reference(self, case_id, ref, *_authority):
        path = self.case_dir / "evidence" / "disk.E01"
        st = path.stat()
        return {
            "ref": str(ref),
            "evidence_id": "ev-1",
            "version_id": "ver-1",
            "display_path": "evidence/disk.E01",
            "path": path,
            "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": st.st_size,
            "st_dev": st.st_dev,
            "st_ino": st.st_ino,
            "st_mtime_ns": st.st_mtime_ns,
            "st_ctime_ns": st.st_ctime_ns,
            "immutable_required": False,
            **self.authority,
        }

    def reconcile_for_admission(self, case_id):
        self.reconciled_case_id = case_id
        return {
            "state": "available",
            "observed": 1,
            "issues": [],
            "execution_authority": dict(self.authority),
        }

    def storage_execution_authority(self, _case_id):
        return dict(self.authority)

    def revalidate_execution_authority(self, _case_id, expected):
        if expected != self.authority:
            raise RuntimeError("authority changed")
        return dict(self.authority)

    @contextmanager
    def hold_execution_authority(self, case_id, expected):
        self.revalidate_execution_authority(case_id, expected)
        yield

    def list_evidence(self, case_id):
        return [
            {
                "evidence_id": "ev-1",
                "display_name": "disk.E01",
                "display_path": "evidence/disk.E01",
                "description": "fixture disk",
                "source": "fixture",
                "status": "sealed",
                "seal_status": "sealed",
                "current_sha256": "0" * 64,
                "current_bytes": 4,
                "sealed_at": "2026-06-09T00:00:00Z",
                "path": str(self.case_dir / "evidence" / "disk.E01"),
            },
            {
                "evidence_id": "ev-2",
                "display_name": "pending.raw",
                "display_path": "evidence/pending.raw",
                "status": "registered",
                "seal_status": "unsealed",
            },
        ]


class _Gateway:
    def __init__(self, case_dir: Path):
        self.active_case_service = _ActiveCaseService(_case(case_dir))
        # BU3 (XYE-21): tool-serving gateways always carry a control-plane DSN
        # (the ControlPlaneRequiredMiddleware backstop refuses calls without one).
        self.control_plane_dsn = "postgresql://service@localhost/sift"
        self.job_service = _JobService()
        self.evidence_service = _EvidenceService(case_dir)
        self._audit = None
        self._gateway_local_tools = {"run_command_job", "running_commands_status"}
        self._tool_manifest_meta = {}
        self.backends = {}

    def is_case_scoped_tool(self, name):
        return name in self._gateway_local_tools

    def safe_case_argument_names(self, name):
        return set()


def _payload(contents):
    return json.loads(contents[0].text)


def test_ingest_job_tool_is_fully_retired():
    """wave8/ingest-tools (Blocker A): the core ``ingest_job`` tool and its
    handler are retired. The opensearch-mcp add-on owns ingest directly; the
    gateway no longer advertises or intercepts an ingest envelope."""
    names = {spec["name"] for spec in gateway_job_tool_specs()}
    assert "ingest_job" not in names
    assert "opensearch_ingest" not in names, (
        "the gateway must not shadow/intercept the add-on opensearch_ingest tool"
    )
    assert frozenset({"run_command_job", "running_commands_status"}) == GATEWAY_JOB_TOOLS
    # The retired handlers and policy enforcer no longer exist on the module.
    import sift_gateway.job_tools as jt

    assert not hasattr(jt, "handle_ingest_job")
    assert not hasattr(jt, "handle_opensearch_ingest_redirect")
    assert not hasattr(jt, "INGEST_JOB_TOOL")
    assert not hasattr(jt, "OPENSEARCH_INGEST_TOOL")


def test_run_command_job_enqueues_public_args_and_internal_case_dir(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "disk.E01").write_bytes(b"disk")
    gateway = _Gateway(case_dir)

    result = asyncio.run(
        handle_run_command_job(
            gateway,
            {
                "command": "cat evidence/disk.E01",
                "purpose": "list filesystem",
                "evidence_refs": ["evidence/disk.E01"],
                "output_ref": "fls",
            },
            "agent-1",
        )
    )

    body = _payload(result)
    assert body["job_id"] == "job-1"
    call = gateway.job_service.enqueued[0]
    assert call["job_type"] == "run_command"
    assert call["evidence_id"] == "ev-1"
    assert call["spec_public"]["evidence_refs"] == ["evidence/disk.E01"]
    assert call["spec_internal"]["case_dir"] == str(case_dir)
    assert call["spec_internal"]["resolved_evidence_refs"] == [
        {
            "ref": "evidence/disk.E01",
            "evidence_id": "ev-1",
            "version_id": "ver-1",
            "display_path": "evidence/disk.E01",
            "path": str(case_dir / "evidence" / "disk.E01"),
            "sha256": "sha256:" + hashlib.sha256(b"disk").hexdigest(),
            "bytes": 4,
            "st_dev": (case_dir / "evidence" / "disk.E01").stat().st_dev,
            "st_ino": (case_dir / "evidence" / "disk.E01").stat().st_ino,
            "st_mtime_ns": (case_dir / "evidence" / "disk.E01").stat().st_mtime_ns,
            "st_ctime_ns": (case_dir / "evidence" / "disk.E01").stat().st_ctime_ns,
            "immutable_required": False,
            "read_only_required": False,
            **gateway.evidence_service.authority,
        }
    ]
    assert "case_dir" not in json.dumps(body)


def test_run_command_job_description_advertises_pollable_uuid():
    spec = next(item for item in gateway_job_tool_specs() if item["name"] == "run_command_job")
    description = spec["description"]
    assert "long-running or parallel work" in description
    assert "pollable UUID job_id" in description
    assert "running_commands_status" in description


def test_job_status_returns_sanitized_service_payload(tmp_path):
    gateway = _Gateway(tmp_path / "case")
    job_id = "22222222-2222-2222-2222-222222222222"
    result = asyncio.run(handle_job_status(gateway, {"job_id": job_id}, "agent-1"))
    body = _payload(result)
    assert body["status"] == "running"
    assert "spec_internal" not in json.dumps(body)


def test_job_status_rejects_malformed_job_id_with_typed_error(tmp_path):
    """AUT1: a non-UUID job_id (e.g. a run_command 'rc-<audit_id>' provenance id)
    must return a typed invalid_job_id, never a raw psycopg uuid-syntax leak."""
    gateway = _Gateway(tmp_path / "case")
    result = asyncio.run(
        handle_job_status(gateway, {"job_id": "rc-agent-20260609-001"}, "agent-1")
    )
    body = _payload(result)
    assert body == {"error": "invalid_job_id", "tool": "running_commands_status"}


def test_job_status_internal_error_is_not_leaked(tmp_path):
    """AUT1: an unexpected service exception must be reported as a generic typed
    error, not as the raw exception text (which can carry backend internals)."""
    gateway = _Gateway(tmp_path / "case")

    def _boom(job_id, principal=None):
        raise RuntimeError('invalid input syntax for type uuid: "x"\nCONTEXT: secret')

    gateway.job_service.job_status_public = _boom
    result = asyncio.run(
        handle_job_status(
            gateway, {"job_id": "33333333-3333-3333-3333-333333333333"}, "agent-1"
        )
    )
    body = _payload(result)
    assert body == {"error": "internal_error", "tool": "running_commands_status"}
    assert "CONTEXT" not in json.dumps(body)
    assert "secret" not in json.dumps(body)


# BATCH-OSX-RAG: rag_search_case was removed (gateway shim deleted). RAG now
# lives in the forensic-rag-mcp add-on as the kb_* tools; the embedding-dimension
# and query-required validation those old tests covered are exercised by the
# forensic-rag-mcp test suite instead.


async def test_gateway_mcp_registers_local_binding_tools(tmp_path):
    gateway = _Gateway(tmp_path / "case")
    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        mcp = create_gateway_mcp_server(gateway, api_keys={})
        tools = {tool.name for tool in await mcp.list_tools()}

    assert {"run_command_job", "running_commands_status"} <= tools
    # wave8/ingest-tools: the retired ingest_job tool must NOT reappear.
    assert "ingest_job" not in tools
    # The gateway must not register/shadow opensearch_ingest as a local tool —
    # the add-on proxy provides it directly.
    assert "opensearch_ingest" not in tools
    # The removed gateway RAG shim must not reappear as a local tool.
    assert "rag_search_case" not in tools


@pytest.mark.skip(
    reason="P4.23 CP1: durable evidence-binding resolve re-homed by CP2A/CP2B "
    "(custody/admission.resolve_sealed_version); positive read proven at the CP3 VM gate"
)
async def test_gateway_mcp_run_command_job_invokes_gateway_bound_handler(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "disk.E01").write_bytes(b"disk")
    gateway = _Gateway(case_dir)
    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        mcp = create_gateway_mcp_server(gateway, api_keys={})
        result = await mcp.call_tool(
            "run_command_job",
            {"command": "cat evidence/disk.E01", "purpose": "smoke"},
        )

    body = _payload(result.content)
    # §9.5: gateway now injects audit_id into every tool response; remove it
    # before comparing so the assertion stays focused on job semantics.
    body.pop("audit_id", None)
    assert body == {"job_id": "job-1", "status": "queued", "job_type": "run_command"}
    assert gateway.job_service.enqueued[0]["job_type"] == "run_command"


async def test_case_context_middleware_appends_only_to_orientation_tools(tmp_path):
    from sift_gateway.policy_middleware import CaseContextMiddleware

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    gateway = _Gateway(case_dir)
    middleware = CaseContextMiddleware(gateway)

    async def call_next(_context):
        return ToolResult(content=[TextContent(type="text", text='{"ok": true}')])

    async def call_tool_name(name: str):
        context = SimpleNamespace(message=SimpleNamespace(name=name, arguments={}))
        return await middleware.on_call_tool(context, call_next)

    help_result = await call_tool_name("get_tool_help")
    guide_result = await call_tool_name("capability_guide")

    help_text = "\n".join(item.text for item in help_result.content)
    guide_text = "\n".join(item.text for item in guide_result.content)
    assert '"case_context"' not in help_text
    assert '"case_context"' in guide_text


# --- AUT1-B1: DB-authority evidence-gate overlay on orientation tools ---

_FILE_BACKED_CASE_INFO = json.dumps(
    {
        "case_id": "case-one",
        "evidence_chain": {
            "status": "unsealed",
            "ok": False,
            "issues": ["No sealed evidence manifest"],
            "manifest_version": 0,
        },
    }
)

_FILE_BACKED_EVIDENCE_INFO = json.dumps(
    {
        "chain_status": "unsealed",
        "ok_count": 0,
        "issues": ["No sealed evidence manifest"],
        "manifest_version": 0,
        "requires_examiner_action": True,
    }
)

# Use the real ChainStatus enum (str, Enum) so the overlay is exercised against
# the exact type check_evidence_gate_db returns; the orientation field must carry
# the plain value "ok", never the enum repr "ChainStatus.OK".
_SEALED_GATE = {
    "blocked": False,
    "status": ChainStatus.OK,
    "issues": [],
    "manifest_version": 2,
}


def test_overlay_case_info_reflects_db_sealed_gate(tmp_path):
    """When the DB gate is sealed/OK but the file manifest is absent, case_info
    orientation must report the DB gate, not the contradictory file status."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ):
        out = json.loads(
            mcp_server._db_orientation_authority(gateway, "case_info", _FILE_BACKED_CASE_INFO)
        )

    chain = out["evidence_chain"]
    assert chain["status"] == "ok"
    assert chain["ok"] is True
    assert chain["manifest_version"] == 2
    assert chain["authority"] == "db"


def test_overlay_evidence_info_reflects_db_sealed_gate(tmp_path):
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ):
        out = json.loads(
            mcp_server._db_orientation_authority(
                gateway, "evidence_info", _FILE_BACKED_EVIDENCE_INFO
            )
        )

    assert out["chain_status"] == "ok"
    assert out["requires_examiner_action"] is False
    assert out["manifest_version"] == 2
    assert out["authority"] == "db"


def test_overlay_evidence_info_lists_db_evidence_without_paths(tmp_path):
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ):
        out = json.loads(
            mcp_server._db_orientation_authority(
                gateway, "evidence_info", _FILE_BACKED_EVIDENCE_INFO
            )
        )

    assert out["listing_authority"] == "db"
    assert out["total_evidence_files"] == 1
    assert out["unregistered_files"] == ["evidence/pending.raw"]
    listed = out["evidence_files"][0]
    assert listed["evidence_id"] == "ev-1"
    assert listed["display_path"] == "evidence/disk.E01"
    assert listed["sha256"] == "0" * 64
    assert "path" not in listed


def test_prepare_run_command_args_resolves_db_refs_and_strips_private(tmp_path):
    from sift_gateway import mcp_server

    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "disk.E01").write_bytes(b"disk")
    gateway = _Gateway(case_dir)
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(case_dir),
    ):
        prepared = mcp_server._prepare_core_tool_arguments(
            gateway,
            "run_command",
            {
                "command": "cat evidence/disk.E01",
                "purpose": "hash DB ref",
                "evidence_refs": ["ev-1"],
                "_resolved_evidence_refs": [{"path": "/tmp/client-controlled"}],
            },
        )

    assert prepared["_resolved_evidence_refs"] == [
        {
            "ref": "ev-1",
            "evidence_id": "ev-1",
            "version_id": "ver-1",
            "display_path": "evidence/disk.E01",
            "path": str(case_dir / "evidence" / "disk.E01"),
            "sha256": "sha256:" + hashlib.sha256(b"disk").hexdigest(),
            "bytes": 4,
            "st_dev": (case_dir / "evidence" / "disk.E01").stat().st_dev,
            "st_ino": (case_dir / "evidence" / "disk.E01").stat().st_ino,
            "st_mtime_ns": (case_dir / "evidence" / "disk.E01").stat().st_mtime_ns,
            "st_ctime_ns": (case_dir / "evidence" / "disk.E01").stat().st_ctime_ns,
            "immutable_required": False,
            "read_only_required": False,
            **gateway.evidence_service.authority,
        }
    ]
    assert "_evidence_ref_error" not in prepared


def test_overlay_blocks_when_db_gate_violated(tmp_path):
    """A DB-authoritative non-OK gate must still surface as ok=false so the agent
    correctly hands back — the overlay reflects the gate, it does not force OK."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    violated = {
        "blocked": True,
        "status": "ledger_error",
        "issues": ["Evidence integrity violation recorded"],
        "manifest_version": 3,
    }
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=violated
    ):
        out = json.loads(
            mcp_server._db_orientation_authority(gateway, "case_info", _FILE_BACKED_CASE_INFO)
        )

    assert out["evidence_chain"]["status"] == "ledger_error"
    assert out["evidence_chain"]["ok"] is False


def test_overlay_noop_in_legacy_file_mode(tmp_path):
    """No control-plane DSN → legacy file mode; orientation is left untouched."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = None
    out = mcp_server._db_orientation_authority(gateway, "case_info", _FILE_BACKED_CASE_INFO)
    assert out == _FILE_BACKED_CASE_INFO


# --- BU1: DB-authority orientation fails closed on a DB error ---
#
# Finding counters are no longer overlaid at the gateway: core's
# case_status_data is DB-authoritative for them (see test_case_ops). The gateway
# layer owns only the evidence gate + listing, and must fail closed (raise) on a
# DB error instead of serving the file-derived orientation values.


def test_db_orientation_fails_closed_on_gate_error(tmp_path):
    """A DB gate failure must raise, never return the file-backed orientation."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db",
        side_effect=RuntimeError("connection refused"),
    ):
        with pytest.raises(mcp_server._OrientationAuthorityError):
            mcp_server._db_orientation_authority(
                gateway, "case_info", _FILE_BACKED_CASE_INFO
            )


def test_db_orientation_evidence_listing_fails_closed_without_service(tmp_path):
    """An unavailable DB evidence service must fail closed for evidence_info."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    gateway.evidence_service = None
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ):
        with pytest.raises(mcp_server._OrientationAuthorityError):
            mcp_server._db_orientation_authority(
                gateway, "evidence_info", _FILE_BACKED_EVIDENCE_INFO
            )


# ---------------------------------------------------------------------------
# wave8/ingest-tools (Blocker A): opensearch_ingest runs DIRECT through the
# add-on proxy. The gateway no longer intercepts it; dry_run=False is accepted
# (no deny/redirect) and it is subject only to the same evidence gate every tool
# gets — there is no special ingest gatekeeper.
# ---------------------------------------------------------------------------


async def test_opensearch_ingest_is_not_a_gateway_local_tool(tmp_path):
    """The gateway must NOT register opensearch_ingest as a local tool, so the
    add-on proxy's real implementation (dry_run=False capable) is what runs."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    gateway = _Gateway(case_dir)
    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        mcp = create_gateway_mcp_server(gateway, api_keys={})
        tools = {tool.name for tool in await mcp.list_tools()}
    # No gateway-local opensearch_ingest. (No add-on backend is registered in
    # this unit harness, so the proxy tool simply isn't present — the assertion
    # that matters is the gateway does not SHADOW it with a local deny handler.)
    assert "opensearch_ingest" not in tools
    assert "opensearch_ingest" not in gateway._gateway_local_tools


async def test_opensearch_ingest_dry_run_false_is_not_intercepted_by_gateway(tmp_path):
    """A direct opensearch_ingest(dry_run=False) call must reach the dispatch
    (call_next) rather than being denied/redirected by a gateway gatekeeper.
    Only the shared evidence gate may stop it — proven separately below."""
    from types import SimpleNamespace

    from mcp.types import TextContent
    from sift_gateway.policy_middleware import EvidenceGateMiddleware

    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "disk.E01").write_bytes(b"disk")
    gateway = _Gateway(case_dir)

    dispatched = {"called": False}

    async def call_next(_context):
        dispatched["called"] = True
        return ToolResult(content=[TextContent(type="text", text='{"status": "started"}')])

    middleware = EvidenceGateMiddleware(gateway)
    context = SimpleNamespace(
        message=SimpleNamespace(
            name="opensearch_ingest", arguments={"path": "evidence/disk.E01", "dry_run": False}
        )
    )
    # Gate OK -> the call is dispatched, not denied/redirected.
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(case_dir),
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 2},
    ), patch(
        "sift_gateway.policy_middleware.admission.resolve_sealed_version",
        side_effect=gateway.evidence_service.resolve_evidence_reference,
    ):
        gateway.control_plane_dsn = "postgresql://x"
        result = await middleware.on_call_tool(context, call_next)

    assert dispatched["called"] is True
    body = json.loads(result.content[0].text)
    assert body == {"status": "started"}
    # The retired deny payload must never appear.
    assert "opensearch_ingest_direct_write_denied" not in json.dumps(body)


async def test_evidence_gate_still_blocks_opensearch_ingest_when_unsealed(tmp_path):
    """The shared evidence gate must still block opensearch_ingest(dry_run=False)
    when evidence is unsealed — retiring the gatekeeper must NOT weaken the
    sealed-before-analysis invariant."""
    from types import SimpleNamespace

    from sift_gateway.policy_middleware import EvidenceGateMiddleware

    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    gateway = _Gateway(case_dir)
    gateway.control_plane_dsn = "postgresql://x"

    async def call_next(_context):
        raise AssertionError("evidence gate must block before dispatch")

    middleware = EvidenceGateMiddleware(gateway)
    context = SimpleNamespace(
        message=SimpleNamespace(
            name="opensearch_ingest", arguments={"path": "evidence/disk.E01", "dry_run": False}
        )
    )
    blocked_gate = {
        "blocked": True,
        "status": "unsealed",
        "issues": ["No sealed evidence manifest"],
        "manifest_version": 0,
    }
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(case_dir),
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db", return_value=blocked_gate
    ):
        result = await middleware.on_call_tool(context, call_next)

    assert result.is_error is True
    body = result.structured_content
    assert body is not None
    # A block payload (not a dispatch) was returned for the unsealed chain.
    text = json.dumps(body)
    assert "unsealed" in text or "evidence" in text.lower()


def test_evidence_reference_argument_map_is_the_closed_registered_surface():
    """Fail if a registered evidence-reference input escapes the one map."""
    from opensearch_mcp.registry import REGISTRY
    from sift_core.agent_tools import core_tool_specs
    from sift_gateway.policy_middleware import EVIDENCE_REFERENCE_ARGUMENTS

    expected = {
        "run_command": ("evidence_refs", "command"),
        "run_command_job": ("evidence_refs", "command"),
        "opensearch_ingest": ("path",),
        "opensearch_inspect_container": ("path",),
    }
    assert dict(EVIDENCE_REFERENCE_ARGUMENTS) == expected

    schemas = {spec.name: spec.input_schema for spec in core_tool_specs()}
    schemas.update(
        {spec["name"]: spec["parameters"] for spec in gateway_job_tool_specs()}
    )
    schemas.update(
        {tool.name: tool.in_model.model_json_schema() for tool in REGISTRY}
    )

    discovered: set[str] = set()
    for tool_name, schema in schemas.items():
        for argument_name, argument_schema in schema.get("properties", {}).items():
            description = str(argument_schema.get("description") or "").lower()
            if (
                argument_name in {"path", "evidence_refs"}
                or "evidence path" in description
                or "evidence reference" in description
                or "sealed original" in description
            ):
                discovered.add(tool_name)
    assert discovered == set(expected)
    for tool_name, argument_names in expected.items():
        assert set(argument_names) <= set(schemas[tool_name]["properties"])


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("run_command", {"command": "cat evidence/disk.E01"}),
        ("run_command_job", {"command": "cat evidence/disk.E01"}),
        ("opensearch_ingest", {"path": "disk.E01", "dry_run": False}),
        ("opensearch_inspect_container", {"path": "disk.E01"}),
    ],
)
async def test_every_declared_evidence_tool_resolves_before_dispatch(
    tmp_path, tool_name, arguments
):
    """The map is executable policy: every declared tool reaches the resolver."""
    from sift_gateway.policy_middleware import EvidenceGateMiddleware

    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "disk.E01").write_bytes(b"disk")
    gateway = _Gateway(case_dir)
    context = SimpleNamespace(
        message=SimpleNamespace(name=tool_name, arguments=dict(arguments))
    )
    dispatched = {"called": False, "path": None}

    async def call_next(ctx):
        dispatched["called"] = True
        dispatched["path"] = ctx.message.arguments.get("path")
        return ToolResult(content=[TextContent(type="text", text='{"status":"ok"}')])

    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(case_dir),
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value=_SEALED_GATE,
    ), patch(
        "sift_gateway.policy_middleware.command_evidence_references",
        return_value=["evidence/disk.E01"],
    ), patch(
        "sift_gateway.policy_middleware.admission.resolve_sealed_version",
        side_effect=gateway.evidence_service.resolve_evidence_reference,
    ) as resolver:
        result = await EvidenceGateMiddleware(cast(Any, gateway)).on_call_tool(
            cast(Any, context), cast(Any, call_next)
        )

    assert result.is_error is not True
    assert dispatched["called"] is True
    assert resolver.call_count == 1
    assert resolver.call_args.args == (
        _case(case_dir).case_id,
        "evidence/disk.E01" if "command" in arguments else "disk.E01",
        str(case_dir),
        gateway.control_plane_dsn,
    )
    if tool_name.startswith("opensearch_"):
        assert dispatched["path"] == "evidence/disk.E01"


@pytest.mark.parametrize(
    "tool_name", ["opensearch_ingest", "opensearch_inspect_container"]
)
async def test_opensearch_present_unsealed_reference_denies_before_dispatch(
    tmp_path, tool_name
):
    """An OPEN case cannot make a present ignored/retired/pending path readable."""
    from sift_gateway.policy_middleware import EvidenceGateMiddleware

    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "unsealed.E01").write_bytes(b"present but not sealed")
    gateway = _Gateway(case_dir)
    context = SimpleNamespace(
        message=SimpleNamespace(
            name=tool_name, arguments={"path": "evidence/unsealed.E01"}
        )
    )
    dispatched = {"called": False}

    async def call_next(_context):
        dispatched["called"] = True
        raise AssertionError("unsealed evidence must be denied before dispatch")

    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(case_dir),
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate_db",
        return_value=_SEALED_GATE,
    ), patch(
        "sift_gateway.policy_middleware.admission.resolve_sealed_version",
        return_value=None,
    ) as resolver:
        result = await EvidenceGateMiddleware(cast(Any, gateway)).on_call_tool(
            cast(Any, context), cast(Any, call_next)
        )

    assert dispatched["called"] is False
    assert result.is_error is True
    assert resolver.call_args.args[1] == "evidence/unsealed.E01"
    assert "active sealed version" in json.dumps(result.structured_content).lower()
