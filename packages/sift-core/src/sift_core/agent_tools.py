"""Agent-facing core tool registry for the SIFT Protocol Gateway.

These are direct core operations, not MCP backend adapters. The gateway imports
this module and exposes the specs on its aggregate /mcp surface.
"""

from __future__ import annotations

import json
import os
import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sift_common.audit import AuditWriter, resolve_examiner
from sift_core.case_io import case_audit_dir, get_case_dir, resolve_case_path
from sift_core.case_manager import CaseManager, build_finding_considerations
from sift_core.case_ops import case_status_data
from sift_core.evidence_chain import ChainStatus, chain_status
from sift_core.evidence_ops import list_evidence_status_data
from sift_core.execute.catalog import get_tool_def
from sift_core.execute.exceptions import SiftError
from sift_core.execute.response import build_response
from sift_core.execute.tools.discovery import (
    check_tools as _check_tools,
    get_tool_help as _get_tool_help,
    list_available_tools as _list_available_tools,
    suggest_tools as _suggest_tools,
)
from sift_core.execute.tools.generic import run_command as _execute_command


@dataclass(frozen=True)
class CoreToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool = False


_MAX_TITLE = 500
_MAX_TEXT = 10_000
_MAX_SHORT = 200

_SECURITY_EVENT_IDS = frozenset(
    {"4624", "4625", "4634", "4648", "4672", "4688", "4720", "4732"}
)
_FILENAME_ARTIFACT_MAP = {
    "security": "event_logs_security",
    "system": "event_logs_system",
    "sysmon": "event_logs_sysmon",
    "powershell": "event_logs_powershell",
}
_NO_INPUT_CMDS = {
    "echo",
    "date",
    "hostname",
    "whoami",
    "uname",
    "uptime",
    "pwd",
    "env",
    "id",
    "df",
    "free",
    "mount",
    "lsblk",
    "lscpu",
    "ps",
    "top",
    "w",
    "who",
    "last",
    "dmesg",
    "printenv",
}


def _schema(properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict:
    result: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        result["required"] = required
    return result


CORE_TOOL_SPECS: tuple[CoreToolSpec, ...] = (
    CoreToolSpec(
        "case_status",
        "Get active case status, finding counts, timeline counts, TODO progress, evidence paths, and available platform capabilities.",
        _schema(),
        read_only=True,
    ),
    CoreToolSpec(
        "case_file_structure",
        "Recursively list files and directories in the active case workspace, excluding integrity records and transient files.",
        _schema(),
        read_only=True,
    ),
    CoreToolSpec(
        "evidence_list",
        "List files in the active case evidence directory with registration, sealing, and chain integrity status.",
        _schema(),
        read_only=True,
    ),
    CoreToolSpec(
        "evidence_verify",
        "Run a fresh integrity status check over registered evidence and the authoritative manifest.",
        _schema(),
        read_only=True,
    ),
    CoreToolSpec(
        "record_action",
        "Record an investigative action and reasoning in the active case record.",
        _schema(
            {
                "description": {"type": "string"},
                "reasoning": {"type": "string"},
                "tool": {"type": "string"},
                "command": {"type": "string"},
            },
            ["description", "reasoning"],
        ),
    ),
    CoreToolSpec(
        "log_reasoning",
        "Record analytical reasoning to the append-only audit trail.",
        _schema({"text": {"type": "string"}}, ["text"]),
    ),
    CoreToolSpec(
        "log_external_action",
        "Record a command executed outside MCP and return an audit_id that can support finding provenance.",
        _schema(
            {
                "command": {"type": "string"},
                "output_summary": {"type": "string"},
                "purpose": {"type": "string"},
                "hook_audit_id": {"type": "string"},
                "input_files": {"type": "array", "items": {"type": "string"}},
                "output_files": {"type": "array", "items": {"type": "string"}},
            },
            ["command", "output_summary", "purpose"],
        ),
    ),
    CoreToolSpec(
        "record_finding",
        "Stage a finding as DRAFT for examiner approval, with enforced validation, provenance, grounding, and considerations.",
        _schema(
            {
                "finding": {"type": "object"},
                "supporting_commands": {"type": "array", "items": {"type": "object"}},
                "artifacts": {"type": "array", "items": {"type": "object"}},
            },
            ["finding"],
        ),
    ),
    CoreToolSpec(
        "record_timeline_event",
        "Stage a timeline event as DRAFT for examiner approval.",
        _schema({"event": {"type": "object"}}, ["event"]),
    ),
    CoreToolSpec(
        "list_existing_findings",
        "List staged findings already recorded in the active case.",
        _schema(
            {
                "status": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "offset": {"type": "integer", "default": 0},
            }
        ),
        read_only=True,
    ),
    CoreToolSpec(
        "query_case",
        "Read case timeline or action records without mutating evidence or findings.",
        _schema(
            {
                "record_type": {"type": "string"},
                "status": {"type": "string"},
                "source": {"type": "string"},
                "examiner": {"type": "string"},
                "start_date": {"type": "string"},
                "end_date": {"type": "string"},
                "event_type": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            ["record_type"],
        ),
        read_only=True,
    ),
    CoreToolSpec(
        "workflow_status",
        "Detect the current investigation phase and recommend next steps from core case state.",
        _schema(),
        read_only=True,
    ),
    CoreToolSpec(
        "manage_todo",
        "Create, list, update, or complete investigation TODOs.",
        _schema(
            {
                "action": {"type": "string"},
                "todo_id": {"type": "string"},
                "description": {"type": "string"},
                "assignee": {"type": "string"},
                "priority": {"type": "string", "default": "medium"},
                "status": {"type": "string"},
                "note": {"type": "string"},
                "related_findings": {"type": "array", "items": {"type": "string"}},
            },
            ["action"],
        ),
    ),
    CoreToolSpec(
        "list_available_tools",
        "List forensic tools available on this SIFT workstation, with availability status.",
        _schema({"category": {"type": "string"}}),
        read_only=True,
    ),
    CoreToolSpec(
        "get_tool_help",
        "Get usage information, common flags, caveats, and field meanings for a cataloged forensic tool.",
        _schema({"tool_name": {"type": "string"}}, ["tool_name"]),
        read_only=True,
    ),
    CoreToolSpec(
        "check_tools",
        "Check which forensic tools are installed and available on this system.",
        _schema({"tool_names": {"type": "array", "items": {"type": "string"}}}),
        read_only=True,
    ),
    CoreToolSpec(
        "suggest_tools",
        "Suggest tools for analyzing a specific artifact type using forensic-knowledge.",
        _schema(
            {
                "artifact_type": {"type": "string"},
                "question": {"type": "string"},
            },
            ["artifact_type"],
        ),
        read_only=True,
    ),
    CoreToolSpec(
        "run_command",
        "Execute a forensic tool on this SIFT workstation through the core denylist, path jail, audit, and FK enrichment pipeline.",
        _schema(
            {
                "command": {"type": "array", "items": {"type": "string"}},
                "purpose": {"type": "string"},
                "timeout": {"type": "integer", "default": 0},
                "save_output": {"type": "boolean", "default": False},
                "input_files": {"type": "array", "items": {"type": "string"}},
                "working_dir": {"type": "string"},
                "preview_lines": {"type": "integer", "default": 0},
                "skip_enrichment": {"type": "boolean", "default": False},
            },
            ["command", "purpose"],
        ),
    ),
)


_SPECS_BY_NAME = {spec.name: spec for spec in CORE_TOOL_SPECS}


def core_tool_names() -> set[str]:
    return set(_SPECS_BY_NAME)


def core_tool_specs() -> tuple[CoreToolSpec, ...]:
    return CORE_TOOL_SPECS





def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")


def _json_result(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _build_platform_capabilities() -> dict:
    import importlib.util

    capabilities = {
        "opensearch": importlib.util.find_spec("opensearch_mcp") is not None,
        "remnux": False,
        "windows_triage": importlib.util.find_spec("windows_triage_mcp") is not None,
        "wintools": False,
        "forensic_rag": importlib.util.find_spec("rag_mcp") is not None,
        "opencti": importlib.util.find_spec("opencti_mcp") is not None,
        "sift_tools": True,
    }
    guidance = ["Available investigation capabilities:"]
    guidance.append("- SIFT forensic tools via run_command")
    if capabilities["opensearch"]:
        guidance.append("- Evidence indexing: opensearch add-on available")
    if capabilities["windows_triage"]:
        guidance.append("- Windows baseline validation add-on available")
    if capabilities["forensic_rag"]:
        guidance.append("- Knowledge search add-on available")
    if capabilities["opencti"]:
        guidance.append("- Threat intel add-on available")
    return {
        "platform_capabilities": capabilities,
        "investigation_guidance": "\n".join(guidance),
    }


def _detect_artifact_context(command: list[str]) -> str | None:
    for i, token in enumerate(command):
        value = None
        if token.startswith("--inc="):
            value = token.split("=", 1)[1]
        elif token == "--inc" and i + 1 < len(command):
            value = command[i + 1]
        if value:
            ids = set(value.replace(",", " ").split())
            if ids & _SECURITY_EVENT_IDS:
                return "event_logs_security"

    for token in command:
        if token.startswith("-"):
            continue
        basename = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        for keyword, artifact in _FILENAME_ARTIFACT_MAP.items():
            if keyword in basename:
                return artifact
    return None


def _case_file_structure() -> dict:
    case_dir = get_case_dir()
    case_resolved = case_dir.resolve()
    files_list = []
    dirs_list = []
    exclude_basenames = {"evidence-ledger.jsonl", "evidence-verify-state.json"}
    exclude_dirs = {"audit", ".git", "__pycache__"}

    for path in sorted(case_resolved.rglob("*")):
        try:
            rel_parts = path.relative_to(case_resolved).parts
        except ValueError:
            continue
        if any(part in exclude_dirs for part in rel_parts):
            continue
        if path.name in exclude_basenames or path.name.endswith(".tmp"):
            continue
        rel_path = str(path.relative_to(case_resolved))
        if path.is_dir():
            dirs_list.append(rel_path)
        elif path.is_file():
            files_list.append({"path": rel_path, "size_bytes": path.stat().st_size})

    return {
        "case_id": case_resolved.name,
        "case_dir": str(case_resolved),
        "directories": dirs_list,
        "files": files_list,
    }


def _evidence_verify() -> dict:
    status = chain_status(get_case_dir())
    result = {
        "status": status["status"],
        "issues": status["issues"],
        "manifest_version": status["manifest_version"],
        "ok_count": status["ok_count"],
        "source": "manifest_v2",
    }
    if status["status"] not in (ChainStatus.OK, ChainStatus.UNSEALED):
        result["operator_action_required"] = (
            "Integrity issues detected. Notify the operator to use the Examiner Portal "
            "Evidence tab to verify and repair the chain."
        )
    return result


def _run_command(args: dict, examiner: str, audit: AuditWriter) -> dict:
    command = args.get("command") or []
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        return {"error": "command must be a list of strings"}
    purpose = str(args.get("purpose", ""))
    if not purpose:
        return {"error": "purpose is required"}

    start = time.monotonic()
    audit_id = audit._next_audit_id(examiner=examiner)
    try:
        working_dir = str(args.get("working_dir", ""))
        if working_dir:
            cwd = str(resolve_case_path(working_dir, default_subdir=""))
        else:
            cwd = os.environ.get("SIFT_CASE_DIR", "") or None
    except ValueError:
        return build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error="Path must be within the case directory",
        )

    binary = command[0].split("/")[-1] if command else ""
    td = get_tool_def(binary)
    detection_method = ""
    detected_inputs: list[str] = []
    input_files = args.get("input_files") or None
    if input_files:
        for fpath in input_files:
            try:
                detected_inputs.append(str(resolve_case_path(str(fpath))))
            except ValueError:
                detected_inputs.append(str(fpath))
        detection_method = "llm"
    elif td and td.input_flag:
        try:
            idx = command.index(td.input_flag)
            if idx + 1 < len(command):
                detected_inputs = [command[idx + 1]]
                detection_method = "catalog"
        except ValueError:
            pass
    if not detected_inputs and not detection_method:
        for token in command[1:]:
            if token.startswith("-"):
                continue
            p = Path(token)
            if p.is_file():
                detected_inputs.append(str(p))
        if detected_inputs:
            detection_method = "parsed"
        elif td and not td.input_flag:
            detection_method = ""
        else:
            detection_method = "none"

    input_hashes: dict[str, str] = {}
    for fpath in detected_inputs:
        try:
            p = Path(fpath).resolve()
            if p.is_file():
                if p.stat().st_size > 1_000_000_000:
                    input_hashes[str(p)] = "skipped:too_large"
                else:
                    h = hashlib.sha256()
                    with open(p, "rb") as hf:
                        for chunk in iter(lambda: hf.read(65536), b""):
                            h.update(chunk)
                    input_hashes[str(p)] = h.hexdigest()
        except OSError:
            continue

    try:
        exec_result = _execute_command(
            command,
            purpose=purpose,
            timeout=int(args.get("timeout") or 0) or None,
            save_output=bool(args.get("save_output", False)),
            cwd=cwd,
            preview_lines=min(int(args.get("preview_lines") or 0), 200),
        )
        elapsed = time.monotonic() - start
        fk_name = td.knowledge_name if td else binary
        artifact_hint = _detect_artifact_context(command)
        if exec_result.get("_parsed"):
            resp_data = exec_result["_parsed"]
            resp_format = exec_result["_output_format"]
        else:
            resp_data = exec_result
            resp_format = exec_result.get("_output_format", "text")
        response = build_response(
            tool_name="run_command",
            success=exec_result["exit_code"] == 0,
            data=resp_data,
            audit_id=audit_id,
            output_format=resp_format,
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=command,
            fk_tool_name=fk_name,
            output_files=[exec_result["output_file"]] if exec_result.get("output_file") else None,
            extractions=exec_result.get("extractions"),
            skip_enrichment=bool(args.get("skip_enrichment", False)),
            artifact_context=artifact_hint,
        )
        if "privilege_escalation" in exec_result:
            response["privilege_escalation"] = exec_result["privilege_escalation"]
        if exec_result.get("output_file"):
            response["full_output_path"] = exec_result["output_file"]
            response["full_output_sha256"] = exec_result.get("output_sha256")
            response["full_output_bytes"] = exec_result.get("stdout_total_bytes")

        # Log privilege events using the same audit writer
        priv_events = exec_result.get("privilege_events", [])
        for evt in priv_events:
            audit.log(
                tool="privilege_escalation",
                params={"command": evt.get("command"), "reason": evt.get("reason", "")},
                result_summary={"status": evt.get("status"), "exit_code": evt.get("exit_code", 0)},
                examiner_override=examiner,
            )

        extra_audit = {}
        if "privilege_escalation" in exec_result:
            extra_audit["privilege_escalation"] = exec_result["privilege_escalation"]
        if "privilege_events" in exec_result:
            extra_audit["privilege_events"] = exec_result["privilege_events"]

        if audit.log(
            tool="run_command",
            params={"command": command, "purpose": purpose},
            result_summary={
                "exit_code": exec_result["exit_code"],
                "output_file": exec_result.get("output_file", ""),
                "output_sha256": exec_result.get("output_sha256", ""),
                "stdout_bytes": exec_result.get("stdout_total_bytes", 0),
                "stdout_head": (exec_result.get("stdout") or "")[:500],
            },
            audit_id=audit_id,
            elapsed_ms=elapsed * 1000,
            input_files=list(input_hashes.keys()) if input_hashes else None,
            input_sha256s=list(input_hashes.values()) if input_hashes else None,
            input_detection_method=detection_method,
            extra=extra_audit if extra_audit else None,
            examiner_override=examiner,
        ) is None:
            response["warning"] = "Audit write failed — action not recorded"
        if detection_method == "none" and binary not in _NO_INPUT_CMDS:
            response["input_files_warning"] = (
                "Could not detect input files — pass input_files parameter for provenance chain linking."
            )
        elif detection_method == "llm" and not input_hashes:
            response["input_files_warning"] = (
                "input_files provided but none resolved to existing files. Provenance chain will be incomplete."
            )
        return response
    except SiftError as exc:
        elapsed = time.monotonic() - start
        response = build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error=str(exc),
        )
        if audit.log(
            tool="run_command",
            params={"command": command, "purpose": purpose},
            result_summary={"error": str(exc)},
            audit_id=audit_id,
            elapsed_ms=elapsed * 1000,
            examiner_override=examiner,
        ) is None:
            response["warning"] = "Audit write failed — action not recorded"
        return response
    except (ValueError, OSError, RuntimeError) as exc:
        elapsed = time.monotonic() - start
        response = build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error=str(exc),
        )
        audit.log(
            tool="run_command",
            params={"command": command, "purpose": purpose},
            result_summary={"error": str(exc)},
            audit_id=audit_id,
            elapsed_ms=elapsed * 1000,
            examiner_override=examiner,
        )
        return response


def _record_action(args: dict, examiner: str, audit: AuditWriter) -> dict:
    description = str(args.get("description", ""))
    reasoning = str(args.get("reasoning", ""))
    tool = str(args.get("tool", ""))
    command = str(args.get("command", ""))
    _validate_str_length(description, "description", _MAX_TEXT)
    _validate_str_length(reasoning, "reasoning", _MAX_TEXT)
    _validate_str_length(tool, "tool", _MAX_SHORT)
    _validate_str_length(command, "command", _MAX_TEXT)

    case_dir = get_case_dir()
    ts = datetime.now(timezone.utc).isoformat()
    entry: dict = {
        "ts": ts,
        "description": description,
        "reasoning": reasoning,
        "examiner": examiner,
        "source": "mcp",
    }
    if tool:
        entry["tool"] = tool
    if command:
        entry["command"] = command

    with open(case_dir / "actions.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())

    result = {"status": "recorded", "timestamp": ts}
    if audit.log(
        tool="record_action",
        params={"description": description, "reasoning": reasoning},
        result_summary=result,
        examiner_override=examiner,
    ) is None:
        result["warning"] = "Audit write failed — action not recorded"
    return result


def _log_reasoning(args: dict, examiner: str, audit: AuditWriter) -> dict:
    text = str(args.get("text", ""))
    _validate_str_length(text, "text", _MAX_TEXT)
    result = {"status": "logged"}
    if audit.log(
        tool="log_reasoning",
        params={"text": text},
        result_summary=result,
        source="orchestrator",
        examiner_override=examiner,
    ) is None:
        result["status"] = "write_failed"
        result["warning"] = "Audit write failed — reasoning not recorded"
    return result


def _log_external_action(args: dict, examiner: str, audit: AuditWriter) -> dict:
    command = str(args.get("command", ""))
    output_summary = str(args.get("output_summary", ""))
    purpose = str(args.get("purpose", ""))
    hook_audit_id = str(args.get("hook_audit_id", ""))
    input_files = args.get("input_files") or None
    output_files = args.get("output_files") or None
    for field, value in (
        ("command", command),
        ("output_summary", output_summary),
        ("purpose", purpose),
        ("hook_audit_id", hook_audit_id),
    ):
        _validate_str_length(value, field, _MAX_TEXT if field in {"command", "output_summary", "purpose"} else _MAX_SHORT)

    source = "orchestrator_voluntary"
    if hook_audit_id:
        hook_found = False
        audit_dir = case_audit_dir(get_case_dir())
        for hook_file in sorted(audit_dir.glob("*.jsonl")) if audit_dir.is_dir() else []:
            if hook_found:
                break
            try:
                with open(hook_file, encoding="utf-8") as f:
                    for line in f:
                        if hook_audit_id not in line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if entry.get("audit_id") == hook_audit_id:
                            hook_found = True
                            break
            except OSError:
                pass
        if hook_found:
            source = "orchestrator_verified"

    audit_id = audit.log(
        tool="log_external_action",
        params={
            "command": command,
            "output_summary": output_summary,
            "purpose": purpose,
            "hook_audit_id": hook_audit_id,
        },
        result_summary={
            "status": "logged",
            "source": source,
            "output_files": output_files or [],
        },
        source=source,
        input_files=input_files,
        examiner_override=examiner,
    )
    result = {
        "status": "logged",
        "audit_id": audit_id,
        "source": source,
        "note": (
            "orchestrator_verified -- cross-referenced with hook entry"
            if source == "orchestrator_verified"
            else "orchestrator_voluntary -- not independently verified"
        ),
    }
    if audit_id is None:
        result["warning"] = "Audit write failed — action not recorded"
    if output_files and not input_files:
        result["provenance_warning"] = (
            "output_files provided without input_files — provenance chain cannot trace to evidence."
        )
    return result


def _build_validation_guidance(errors: list[str]) -> list[str]:
    guidance: list[str] = []
    for err in errors:
        lower = err.lower()
        if "audit_id" in lower:
            guidance.append("FD-001: Every claim must reference at least one audit_id from an actual tool call")
        if "confidence_justification" in lower:
            guidance.append("FD-005: Confidence must be justified with specific evidence citations")
        if "attribution" in lower and "3" in err:
            guidance.append("FD-003: Attribution requires multiple corroborating TTPs")
    return guidance


def _record_finding(args: dict, examiner: str, manager: CaseManager, audit: AuditWriter) -> dict:
    finding = args.get("finding") or {}
    supporting_commands = args.get("supporting_commands")
    artifacts = args.get("artifacts")
    if isinstance(supporting_commands, str):
        try:
            supporting_commands = json.loads(supporting_commands)
        except json.JSONDecodeError:
            supporting_commands = None
    if isinstance(artifacts, str):
        try:
            artifacts = json.loads(artifacts)
        except json.JSONDecodeError:
            artifacts = None
    result = manager.record_finding(
        finding,
        examiner_override=examiner,
        supporting_commands=supporting_commands if isinstance(supporting_commands, list) else None,
        artifacts=artifacts if isinstance(artifacts, list) else None,
        audit=audit,
    )
    if audit.log(
        tool="record_finding",
        params={"finding": finding},
        result_summary=result,
        examiner_override=examiner,
    ) is None:
        result["warning"] = "Audit write failed — action not recorded"
    if result.get("status") == "STAGED":
        result["finding_status"] = "DRAFT — requires human approval via the examiner portal"
        result["considerations"] = build_finding_considerations(finding)
        grounding = manager._score_grounding(finding)
        if grounding:
            result["grounding"] = grounding
        provenance = result.pop("provenance_detail", None)
        if provenance:
            result["provenance"] = provenance
            if provenance["summary"] == "SHELL":
                result["provenance_guidance"] = "For stronger provenance, re-run analysis through MCP tools."
    if result.get("status") == "VALIDATION_FAILED":
        result["guidance"] = _build_validation_guidance(result.get("errors", []))
    return result


def _query_case(args: dict, manager: CaseManager) -> dict:
    record_type = str(args.get("record_type", "")).strip().lower()
    limit = int(args.get("limit", 50))
    offset = int(args.get("offset", 0))
    if record_type == "timeline":
        events = manager.get_timeline(
            status=args.get("status") or None,
            source=args.get("source") or None,
            examiner=args.get("examiner") or None,
            start_date=args.get("start_date") or None,
            end_date=args.get("end_date") or None,
            event_type=args.get("event_type") or None,
        )
        total = len(events)
        return {
            "events": events[offset : offset + limit] if limit > 0 else events,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": total > offset + limit,
        }
    if record_type == "actions":
        return {"actions": manager.get_actions(limit=limit), "record_type": "actions", "limit": limit}
    return {
        "error": "unsupported_record_type",
        "message": "record_type must be 'timeline' or 'actions'. Use list_existing_findings for findings.",
        "supported_record_types": ["timeline", "actions"],
    }


def _workflow_status(manager: CaseManager) -> dict:
    try:
        case_dir = manager._require_active_case()
    except ValueError as exc:
        return {
            "phase": "NO_CASE",
            "case_id": "",
            "error": str(exc),
            "next_steps": ["Create or select a case in the Examiner Portal."],
        }
    meta = manager._load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)
    chain = chain_status(case_dir)
    findings = manager._load_findings(case_dir)
    timeline = manager._load_timeline(case_dir)
    sealed_count = len((chain.get("files") or [])) if isinstance(chain.get("files"), list) else chain.get("ok_count", 0)
    draft_count = sum(1 for f in findings if f.get("status") == "DRAFT")
    approved_count = sum(1 for f in findings if f.get("status") == "APPROVED")
    status = chain.get("status", ChainStatus.UNSEALED)
    if status != ChainStatus.OK:
        phase = "EVIDENCE_BLOCKED"
        next_steps = [
            f"Evidence chain status is {str(status).upper()}.",
            "The examiner must resolve and seal evidence in the portal before agent tools run.",
        ]
    elif approved_count:
        phase = "REPORTING"
        next_steps = ["Approved findings are ready for examiner-triggered reporting."]
    elif draft_count:
        phase = "FINDINGS"
        next_steps = ["Draft findings are waiting for examiner review."]
    else:
        phase = "TRIAGE"
        next_steps = ["Evidence is sealed. Continue analysis and stage findings as evidence supports them."]
    return {
        "phase": phase,
        "case_id": case_id,
        "evidence_chain": {
            "status": status,
            "issues": chain.get("issues", []),
            "manifest_version": chain.get("manifest_version", 0),
        },
        "evidence_summary": {"sealed_files": sealed_count},
        "findings_summary": {
            "total": len(findings),
            "draft": draft_count,
            "approved": approved_count,
            "rejected": sum(1 for f in findings if f.get("status") == "REJECTED"),
        },
        "timeline_events": len(timeline),
        "next_steps": next_steps,
    }


def _manage_todo(args: dict, examiner: str, manager: CaseManager, audit: AuditWriter) -> dict:
    action = str(args.get("action", "")).strip().lower()
    if action == "add":
        description = str(args.get("description", ""))
        if not description:
            return {"error": "missing_description", "message": "description is required when action='add'."}
        result = manager.add_todo(
            description,
            str(args.get("assignee", "")),
            str(args.get("priority", "medium")),
            args.get("related_findings"),
            examiner_override=examiner,
        )
        audit.log(tool="add_todo", params={"description": description}, result_summary=result, examiner_override=examiner)
        return result
    if action == "list":
        return {
            "todos": manager.list_todos(str(args.get("status") or "open"), str(args.get("assignee", ""))),
            "action": "list",
            "status": args.get("status") or "open",
            "assignee": args.get("assignee", ""),
        }
    if action == "update":
        todo_id = str(args.get("todo_id", ""))
        if not todo_id:
            return {"error": "missing_todo_id", "message": "todo_id is required when action='update'."}
        result = manager.update_todo(
            todo_id,
            str(args.get("status", "")),
            str(args.get("note", "")),
            str(args.get("assignee", "")),
            str(args.get("priority", "")),
            examiner_override=examiner,
        )
        audit.log(tool="update_todo", params={"todo_id": todo_id}, result_summary=result, examiner_override=examiner)
        return result
    if action == "complete":
        todo_id = str(args.get("todo_id", ""))
        if not todo_id:
            return {"error": "missing_todo_id", "message": "todo_id is required when action='complete'."}
        result = manager.complete_todo(todo_id, examiner_override=examiner)
        audit.log(tool="complete_todo", params={"todo_id": todo_id}, result_summary=result, examiner_override=examiner)
        return result
    return {
        "error": "unsupported_todo_action",
        "message": "action must be one of: add, list, update, complete",
        "supported_actions": ["add", "list", "update", "complete"],
    }


def call_core_tool(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    examiner: str | None = None,
    manager: CaseManager | None = None,
    audit: AuditWriter | None = None,
) -> str:
    """Dispatch a gateway-owned core tool and return JSON text."""
    if name not in _SPECS_BY_NAME:
        raise KeyError(name)
    args = dict(arguments or {})
    effective_examiner = (examiner or resolve_examiner()).strip().lower()
    manager = manager or CaseManager()
    audit = audit or AuditWriter(mcp_name="sift-core")

    try:
        if name == "case_status":
            result = case_status_data(get_case_dir())
            result.update(_build_platform_capabilities())
        elif name == "case_file_structure":
            result = _case_file_structure()
        elif name == "evidence_list":
            result = list_evidence_status_data(get_case_dir())
        elif name == "evidence_verify":
            result = _evidence_verify()
        elif name == "record_action":
            result = _record_action(args, effective_examiner, audit)
        elif name == "log_reasoning":
            result = _log_reasoning(args, effective_examiner, audit)
        elif name == "log_external_action":
            result = _log_external_action(args, effective_examiner, audit)
        elif name == "record_finding":
            result = _record_finding(args, effective_examiner, manager, audit)
        elif name == "record_timeline_event":
            event = args.get("event") or {}
            result = manager.record_timeline_event(event, examiner_override=effective_examiner)
            if audit.log(tool="record_timeline_event", params={"event": event}, result_summary=result, examiner_override=effective_examiner) is None:
                result["warning"] = "Audit write failed — action not recorded"
        elif name == "list_existing_findings":
            status = str(args.get("status", ""))
            limit = int(args.get("limit", 20))
            offset = int(args.get("offset", 0))
            findings = manager.get_findings(status or None)
            result = {
                "findings": findings[offset : offset + limit] if limit > 0 else findings,
                "total": len(findings),
                "limit": limit,
                "offset": offset,
            }
        elif name == "query_case":
            result = _query_case(args, manager)
        elif name == "workflow_status":
            result = _workflow_status(manager)
        elif name == "manage_todo":
            result = _manage_todo(args, effective_examiner, manager, audit)
        elif name == "list_available_tools":
            result = {"tools": _list_available_tools(category=args.get("category") or None)}
            result["count"] = len(result["tools"])
        elif name == "get_tool_help":
            result = _get_tool_help(str(args.get("tool_name", "")))
            audit.log(
                tool="get_tool_help",
                params={"tool_name": args.get("tool_name", "")},
                result_summary=result,
            )
        elif name == "check_tools":
            tool_names = args.get("tool_names")
            result = _check_tools(tool_names=tool_names if isinstance(tool_names, list) else None)
        elif name == "suggest_tools":
            result = _suggest_tools(str(args.get("artifact_type", "")), str(args.get("question", "")))
            audit.log(
                tool="suggest_tools",
                params={"artifact_type": args.get("artifact_type", "")},
                result_summary=result,
            )
        elif name == "run_command":
            result = _run_command(args, effective_examiner, audit)
        else:  # pragma: no cover - guarded by _SPECS_BY_NAME
            raise KeyError(name)
    except (ValueError, OSError, RuntimeError) as exc:
        result = {"error": str(exc)}
    return _json_result(result)
