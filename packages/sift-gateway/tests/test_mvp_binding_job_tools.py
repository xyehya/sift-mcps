"""B-MVP-5/6/7 binding tests for Gateway-owned job/RAG tool seams."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastmcp.tools import ToolResult
from mcp.types import TextContent
from sift_core.evidence_chain import ChainStatus

from sift_gateway.active_case import ActiveCase
from sift_gateway.job_tools import (
    gateway_job_tool_specs,
    handle_ingest_job,
    handle_job_status,
    handle_run_command_job,
)
from sift_gateway.mcp_server import create_gateway_mcp_server
from sift_gateway.rag_bridge import handle_rag_search_case, rag_search_case_schema


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

    def resolve_evidence_reference(self, case_id, ref):
        return {
            "evidence_id": "ev-1",
            "display_path": "evidence/disk.E01",
            "path": self.case_dir / "evidence" / "disk.E01",
        }

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
        self.job_service = _JobService()
        self.evidence_service = _EvidenceService(case_dir)
        self.rag_query_service = None
        self._audit = None
        self._gateway_local_tools = {"ingest_job", "run_command_job", "job_status"}
        self._tool_manifest_meta = {}
        self.backends = {}

    def is_case_scoped_tool(self, name):
        return name in self._gateway_local_tools

    def safe_case_argument_names(self, name):
        return set()


def _payload(contents):
    return json.loads(contents[0].text)


def test_ingest_job_writes_path_only_to_spec_internal(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "disk.E01").write_bytes(b"disk")
    gateway = _Gateway(case_dir)

    result = asyncio.run(
        handle_ingest_job(
            gateway,
            {"evidence_ref": "ev-1", "hostname": "host-a", "include": ["winevt"]},
            "agent-1",
        )
    )

    body = _payload(result)
    assert body == {"job_id": "job-1", "status": "queued", "job_type": "ingest"}
    call = gateway.job_service.enqueued[0]
    assert call["job_type"] == "ingest"
    assert call["case_id"] == "11111111-1111-1111-1111-111111111111"
    assert call["evidence_id"] == "ev-1"
    assert call["spec_public"] == {
        "evidence_ref": "evidence/disk.E01",
        "hostname": "host-a",
        "include": ["winevt"],
        "full": False,
    }
    assert call["spec_internal"]["evidence_path"].endswith("evidence/disk.E01")
    assert "/case/" not in json.dumps(body)


def test_run_command_job_enqueues_public_args_and_internal_case_dir(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    gateway = _Gateway(case_dir)

    result = asyncio.run(
        handle_run_command_job(
            gateway,
            {
                "command": "fls evidence/disk.E01",
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
            "display_path": "evidence/disk.E01",
            "path": str(case_dir / "evidence" / "disk.E01"),
        }
    ]
    assert "case_dir" not in json.dumps(body)


def test_run_command_job_description_advertises_pollable_uuid():
    spec = next(item for item in gateway_job_tool_specs() if item["name"] == "run_command_job")
    description = spec["description"]
    assert "long-running or parallel work" in description
    assert "pollable UUID job_id" in description
    assert "job_status" in description


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
    assert body == {"error": "invalid_job_id", "tool": "job_status"}


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
    assert body == {"error": "internal_error", "tool": "job_status"}
    assert "CONTEXT" not in json.dumps(body)
    assert "secret" not in json.dumps(body)


def test_rag_search_case_rejects_wrong_embedding_dimension(tmp_path):
    gateway = _Gateway(tmp_path / "case")
    gateway.rag_query_service = object()
    result = asyncio.run(
        handle_rag_search_case(gateway, {"query_embedding": [0.1, 0.2]}, "agent-1")
    )
    assert _payload(result)["error"] == "query_embedding_must_be_768_dimensional"


def test_rag_search_case_schema_is_plain_object_for_tool_clients():
    schema = rag_search_case_schema()
    assert schema["type"] == "object"
    assert {"query", "query_embedding"} <= set(schema["properties"])
    assert "anyOf" not in schema
    assert "oneOf" not in schema
    assert "allOf" not in schema
    assert "not" not in schema


def test_rag_search_case_requires_query_or_embedding(tmp_path):
    gateway = _Gateway(tmp_path / "case")
    gateway.rag_query_service = object()
    result = asyncio.run(handle_rag_search_case(gateway, {}, "agent-1"))
    assert _payload(result)["error"] == "query_or_query_embedding_required"


async def test_gateway_mcp_registers_local_binding_tools(tmp_path):
    gateway = _Gateway(tmp_path / "case")
    gateway.rag_query_service = object()
    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        mcp = create_gateway_mcp_server(gateway, api_keys={})
        tools = {tool.name for tool in await mcp.list_tools()}

    assert {"ingest_job", "run_command_job", "job_status", "rag_search_case"} <= tools


async def test_gateway_mcp_run_command_job_invokes_gateway_bound_handler(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    gateway = _Gateway(case_dir)
    with patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        mcp = create_gateway_mcp_server(gateway, api_keys={})
        result = await mcp.call_tool(
            "run_command_job",
            {"command": "cat evidence/disk.E01", "purpose": "smoke"},
        )

    body = _payload(result.content)
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
            mcp_server._overlay_db_evidence_gate(gateway, "case_info", _FILE_BACKED_CASE_INFO)
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
            mcp_server._overlay_db_evidence_gate(
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
            mcp_server._overlay_db_evidence_gate(
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
            "display_path": "evidence/disk.E01",
            "path": str(case_dir / "evidence" / "disk.E01"),
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
            mcp_server._overlay_db_evidence_gate(gateway, "case_info", _FILE_BACKED_CASE_INFO)
        )

    assert out["evidence_chain"]["status"] == "ledger_error"
    assert out["evidence_chain"]["ok"] is False


def test_overlay_noop_in_legacy_file_mode(tmp_path):
    """No control-plane DSN → legacy file mode; orientation is left untouched."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = None
    out = mcp_server._overlay_db_evidence_gate(gateway, "case_info", _FILE_BACKED_CASE_INFO)
    assert out == _FILE_BACKED_CASE_INFO


# --- AUT2-B6: DB-authority findings counters overlay on case_info ---

_FILE_BACKED_CASE_INFO_WITH_FINDINGS = json.dumps(
    {
        "case_id": "case-one",
        "evidence_chain": {
            "status": "unsealed",
            "ok": False,
            "issues": [],
            "manifest_version": 0,
        },
        "findings": {"total": 0, "draft": 0, "approved": 0},
    }
)


class _FakeInvestigationStore:
    def __init__(self, dsn):
        self.dsn = dsn

    def list_findings(self, case_id):
        return [
            {"id": "F-a-001", "status": "DRAFT"},
            {"id": "F-a-002", "status": "APPROVED"},
            {"id": "F-a-003", "status": "APPROVED"},
        ]


def test_overlay_case_info_findings_counters_match_db(tmp_path):
    """case_info findings counters must mirror app.investigation_findings, the
    same source list_existing_findings reads, and carry authority: db."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ), patch(
        "sift_core.investigation_store.PostgresInvestigationStore",
        _FakeInvestigationStore,
    ):
        out = json.loads(
            mcp_server._overlay_db_evidence_gate(
                gateway, "case_info", _FILE_BACKED_CASE_INFO_WITH_FINDINGS
            )
        )

    assert out["findings"] == {
        "total": 3,
        "draft": 1,
        "approved": 2,
        "authority": "db",
    }


def test_overlay_findings_counters_added_when_missing(tmp_path):
    """Counters block is created even if the file-backed payload lacked it."""
    from sift_gateway import mcp_server

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ), patch(
        "sift_core.investigation_store.PostgresInvestigationStore",
        _FakeInvestigationStore,
    ):
        out = json.loads(
            mcp_server._overlay_db_evidence_gate(
                gateway, "case_info", _FILE_BACKED_CASE_INFO
            )
        )

    assert out["findings"]["authority"] == "db"
    assert out["findings"]["total"] == 3


def test_overlay_findings_counters_keep_file_values_on_db_error(tmp_path):
    """DB hiccup → counters stay file-backed (no authority marker, no crash)."""
    from sift_gateway import mcp_server

    class _Boom:
        def __init__(self, dsn):
            raise RuntimeError("db down")

    gateway = _Gateway(tmp_path / "case")
    gateway.control_plane_dsn = "postgresql://x"
    with patch(
        "sift_gateway.policy_middleware._current_gateway_active_case",
        return_value=_case(tmp_path / "case"),
    ), patch(
        "sift_gateway.evidence_gate.check_evidence_gate_db", return_value=_SEALED_GATE
    ), patch(
        "sift_core.investigation_store.PostgresInvestigationStore", _Boom
    ):
        out = json.loads(
            mcp_server._overlay_db_evidence_gate(
                gateway, "case_info", _FILE_BACKED_CASE_INFO_WITH_FINDINGS
            )
        )

    assert out["findings"] == {"total": 0, "draft": 0, "approved": 0}
