"""Gateway-owned durable job MCP tools.

These tools are the agent-facing call sites for the D1 job state machine. They
enqueue only opaque case/evidence IDs plus path-free public request metadata;
absolute evidence/case paths are resolved by the Gateway and written only into
``spec_internal`` for the local worker.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from mcp.types import TextContent

logger = logging.getLogger(__name__)

INGEST_JOB_TOOL = "ingest_job"
RUN_COMMAND_JOB_TOOL = "run_command_job"
JOB_STATUS_TOOL = "job_status"

GATEWAY_JOB_TOOLS = frozenset(
    {INGEST_JOB_TOOL, RUN_COMMAND_JOB_TOOL, JOB_STATUS_TOOL}
)


class GatewayJobToolError(Exception):
    def __init__(self, reason: str, *, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


def gateway_job_tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "name": INGEST_JOB_TOOL,
            "description": (
                "Enqueue sealed evidence ingest into the derived search plane through the "
                "Postgres job state machine. Returns a job_id only."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "evidence_ref": {
                        "type": "string",
                        "description": "Sealed evidence id or relative display path.",
                    },
                    "hostname": {"type": "string"},
                    "include": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "exclude": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "full": {"type": "boolean", "default": False},
                    "priority": {"type": "integer", "default": 100},
                    "max_attempts": {"type": "integer", "default": 3},
                },
                "required": ["evidence_ref"],
            },
            "read_only": False,
            "category": "ingest",
            "phase": "INGEST",
            "handler": handle_ingest_job,
        },
        {
            "name": RUN_COMMAND_JOB_TOOL,
            "description": (
                "Enqueue a sandboxed run_command request through the Postgres "
                "job state machine. Returns a job_id only."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "purpose": {"type": "string"},
                    "timeout": {"type": "integer", "default": 0},
                    "save_output": {"type": "boolean", "default": False},
                    "evidence_refs": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "output_ref": {"type": "string"},
                    "working_dir": {"type": "string"},
                    "preview_lines": {"type": "integer", "default": 0},
                    "skip_enrichment": {"type": "boolean", "default": False},
                    "priority": {"type": "integer", "default": 100},
                    "max_attempts": {"type": "integer", "default": 1},
                },
                "required": ["command", "purpose"],
            },
            "read_only": False,
            "category": "detection",
            "phase": "TRIAGE",
            "handler": handle_run_command_job,
        },
        {
            "name": JOB_STATUS_TOOL,
            "description": "Read sanitized status for a durable Postgres job.",
            "parameters": {
                "type": "object",
                "properties": {"job_id": {"type": "string"}},
                "required": ["job_id"],
            },
            "read_only": True,
            "category": "ingest",
            "phase": "INGEST",
            "handler": handle_job_status,
        },
    ]


async def handle_ingest_job(
    gateway: Any, arguments: dict[str, Any], examiner: str | None
) -> list[TextContent]:
    try:
        case, identity = _active_case(gateway)
        evidence = _resolve_evidence(gateway, case, str(arguments.get("evidence_ref") or ""))
        job_service = _job_service(gateway)
        spec_public = _drop_none(
            {
                "evidence_ref": evidence["display_path"],
                "hostname": _optional_str(arguments.get("hostname")),
                "include": _string_list(arguments.get("include")),
                "exclude": _string_list(arguments.get("exclude")),
                "full": bool(arguments.get("full", False)),
            }
        )
        spec_internal = {
            "evidence_path": str(evidence["path"]),
            "case_dir": str(case.artifact_path or ""),
            "case_key": case.case_key,
            "examiner": examiner or getattr(identity, "principal", None) or "agent",
        }
        result = job_service.enqueue_job(
            job_type="ingest",
            case_id=case.case_id,
            evidence_id=evidence.get("evidence_id"),
            spec_public=spec_public,
            spec_internal=spec_internal,
            priority=int(arguments.get("priority") or 100),
            max_attempts=int(arguments.get("max_attempts") or 3),
            actor=identity,
        ).public_dict()
        result["status"] = "queued"
        result["job_type"] = "ingest"
    except Exception as exc:
        result = _error_payload(exc, INGEST_JOB_TOOL)
    return _json_text(result)


async def handle_run_command_job(
    gateway: Any, arguments: dict[str, Any], examiner: str | None
) -> list[TextContent]:
    try:
        case, identity = _active_case(gateway)
        if not arguments.get("command") or not arguments.get("purpose"):
            raise GatewayJobToolError("command_and_purpose_required")
        job_service = _job_service(gateway)
        spec_public = _drop_none(
            {
                "command": str(arguments.get("command")),
                "purpose": str(arguments.get("purpose")),
                "timeout": int(arguments.get("timeout") or 0),
                "save_output": bool(arguments.get("save_output", False)),
                "evidence_refs": _string_list(arguments.get("evidence_refs")),
                "output_ref": _optional_str(arguments.get("output_ref")),
                "working_dir": _optional_str(arguments.get("working_dir")),
                "preview_lines": int(arguments.get("preview_lines") or 0),
                "skip_enrichment": bool(arguments.get("skip_enrichment", False)),
            }
        )
        spec_internal = {
            "case_dir": str(case.artifact_path or ""),
            "case_key": case.case_key,
            "examiner": examiner or getattr(identity, "principal", None) or "agent",
        }
        result = job_service.enqueue_job(
            job_type="run_command",
            case_id=case.case_id,
            evidence_id=None,
            spec_public=spec_public,
            spec_internal=spec_internal,
            priority=int(arguments.get("priority") or 100),
            max_attempts=int(arguments.get("max_attempts") or 1),
            actor=identity,
        ).public_dict()
        result["status"] = "queued"
        result["job_type"] = "run_command"
    except Exception as exc:
        result = _error_payload(exc, RUN_COMMAND_JOB_TOOL)
    return _json_text(result)


async def handle_job_status(
    gateway: Any, arguments: dict[str, Any], examiner: str | None
) -> list[TextContent]:
    del examiner
    try:
        job_id = str(arguments.get("job_id") or "")
        if not job_id:
            raise GatewayJobToolError("job_id_required")
        # Durable job ids are Postgres UUIDs. Reject anything else up front so a
        # malformed id (e.g. a run_command "rc-<audit_id>" provenance id, which is
        # NOT a durable job) returns a typed, actionable error instead of letting
        # the raw psycopg "invalid input syntax for type uuid" message leak to the
        # agent and reveal backend internals.
        try:
            uuid.UUID(job_id)
        except (ValueError, AttributeError, TypeError):
            raise GatewayJobToolError("invalid_job_id")
        _case, identity = _active_case(gateway)
        result = _job_service(gateway).job_status_public(job_id, identity)
    except Exception as exc:
        result = _error_payload(exc, JOB_STATUS_TOOL)
    return _json_text(result)


def _job_service(gateway: Any) -> Any:
    service = getattr(gateway, "job_service", None)
    if service is None:
        raise GatewayJobToolError("job_service_not_wired", http_status=503)
    return service


def _active_case(gateway: Any) -> tuple[Any, Any]:
    from sift_gateway.mcp_endpoint import current_mcp_identity
    from sift_gateway.policy_middleware import _current_gateway_active_case

    identity = current_mcp_identity()
    case = _current_gateway_active_case()
    if case is not None:
        return case, identity
    service = getattr(gateway, "active_case_service", None)
    if service is None:
        raise GatewayJobToolError("active_case_service_not_wired", http_status=503)
    case = service.require_active_case_for_principal(identity)
    if case is None or not getattr(case, "case_id", None):
        raise GatewayJobToolError("active_case_required", http_status=403)
    return case, identity


def _resolve_evidence(gateway: Any, case: Any, ref: str) -> dict[str, Any]:
    if not ref:
        raise GatewayJobToolError("evidence_ref_required")
    service = getattr(gateway, "evidence_service", None)
    resolver = getattr(service, "resolve_evidence_reference", None)
    if callable(resolver):
        return resolver(case.case_id, ref)
    display_path = _relative_display_path(ref)
    if not getattr(case, "artifact_path", None):
        raise GatewayJobToolError("case_artifact_path_unavailable", http_status=404)
    case_dir = Path(str(case.artifact_path or "")).resolve()
    candidate = (case_dir / display_path).resolve()
    if not candidate.is_relative_to(case_dir) or not candidate.is_file():
        raise GatewayJobToolError("evidence_file_unavailable", http_status=404)
    return {"evidence_id": None, "display_path": display_path, "path": candidate}


def _relative_display_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    if not value:
        raise GatewayJobToolError("evidence_ref_required")
    if value.startswith("/") or "/../" in f"/{value}/" or value.startswith("../"):
        raise GatewayJobToolError("invalid_relative_evidence_ref")
    return value if value.startswith("evidence/") else f"evidence/{value}"


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        values = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        values = [str(part).strip() for part in value]
    else:
        return None
    return [part for part in values if part] or None


def _drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


def _error_payload(exc: Exception, tool: str) -> dict[str, Any]:
    # Typed gateway errors carry a safe, agent-actionable ``reason``. For any
    # other (unexpected) exception, do NOT surface ``str(exc)`` to the agent: a
    # raw DB/driver message can leak backend internals (e.g. psycopg portal
    # parameter detail) that the response guard's path/secret scanner does not
    # catch. Log the detail server-side and return a generic typed error.
    reason = getattr(exc, "reason", None)
    if reason:
        return {"error": reason, "tool": tool}
    logger.warning("job tool %s failed: %s: %s", tool, type(exc).__name__, exc)
    return {"error": "internal_error", "tool": tool}


def _json_text(payload: dict[str, Any]) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(payload, default=str))]
