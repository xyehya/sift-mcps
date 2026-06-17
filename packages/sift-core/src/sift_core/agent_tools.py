"""Agent-facing core tool registry for the SIFT Protocol Gateway.

These are direct core operations, not MCP backend adapters. The gateway imports
this module and exposes the specs on its aggregate /mcp surface.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sift_common.audit import AuditWriter, resolve_examiner

from sift_core.active_case_context import (
    db_authority_active as _db_authority_active,
)
from sift_core.case_io import get_case_dir, resolve_case_path
from sift_core.case_manager import (
    CaseManager,
    build_finding_considerations,
    build_platform_capabilities,
)
from sift_core.case_ops import case_status_data
from sift_core.evidence_chain import ChainStatus, chain_status
from sift_core.evidence_ops import list_evidence_status_data
from sift_core.execute.catalog import get_tool_def
from sift_core.execute.exceptions import SiftError
from sift_core.execute.response import build_response
from sift_core.execute.tools.discovery import get_tool_help as _get_tool_help
from sift_core.execute.tools.generic import run_command as _execute_command

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CoreToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool = False
    output_schema: dict[str, Any] | None = None


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
_INTERNAL_RESOLVED_EVIDENCE_REFS = "_resolved_evidence_refs"
_INTERNAL_EVIDENCE_REF_ERROR = "_evidence_ref_error"


def _schema(properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict:
    result: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        result["required"] = required
    return result


_CASE_INFO_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "string"},
        "examiner": {"type": "string"},
        "case_brief": {"type": "string"},
        "findings": {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "draft": {"type": "integer"},
                "approved": {"type": "integer"},
            },
        },
        "timeline_events": {"type": "integer"},
        "todos": {
            "type": "object",
            "properties": {"open": {"type": "integer"}, "total": {"type": "integer"}},
        },
        "evidence_chain": {
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "ok": {"type": "boolean"},
                "issues": {"type": "array", "items": {"type": "string"}},
                "manifest_version": {"type": "integer"},
            },
        },
        "file_structure": {"type": "object"},
        "platform_capabilities": {"type": "object"},
    },
    "required": ["case_id", "name", "status", "evidence_chain"],
}

_EVIDENCE_INFO_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "chain_status": {"type": "string"},
        "ok_count": {"type": "integer"},
        "issues": {"type": "array", "items": {"type": "string"}},
        "manifest_version": {"type": "integer"},
        "evidence_files": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence_id": {"type": "string"},
                    "display_path": {"type": "string"},
                    "sealed": {"type": "boolean"},
                    "chain_ok": {"type": "boolean"},
                },
            },
        },
        "total_evidence_files": {"type": "integer"},
        "unregistered_files": {"type": "array", "items": {"type": "string"}},
        "requires_examiner_action": {"type": "boolean"},
    },
    "required": ["chain_status", "evidence_files"],
}

_LIST_FINDINGS_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "status": {"type": "string"},
                    "confidence": {"type": "string"},
                    "host": {"type": "string"},
                    "type": {"type": "string"},
                    "staged": {"type": "string"},
                    "examiner": {"type": "string"},
                },
            },
        },
        "total": {"type": "integer"},
        "limit": {"type": "integer"},
        "offset": {"type": "integer"},
        "full_findings_path": {"type": "string"},
    },
    "required": ["findings", "total"],
}

CORE_TOOL_SPECS: tuple[CoreToolSpec, ...] = (
    CoreToolSpec(
        "case_info",
        "Essential case overview: status, finding/timeline/todo counts, evidence chain status, "
        "file structure summary, platform capabilities. Call at session start.",
        _schema(),
        read_only=True,
        output_schema=_CASE_INFO_OUTPUT_SCHEMA,
    ),
    CoreToolSpec(
        "evidence_info",
        "Evidence listing with registration, sealing, chain integrity, and manifest verification "
        "in a single call. Returns sealed evidence and unregistered files with required actions.",
        _schema(),
        read_only=True,
        output_schema=_EVIDENCE_INFO_OUTPUT_SCHEMA,
    ),
    CoreToolSpec(
        "record_finding",
        "Stage a finding as DRAFT for examiner approval. Findings missing required fields or "
        "provenance (audit_ids) are REJECTED.\n\n"
        "REQUIRED fields in 'finding': title, type, host, observation, interpretation, confidence, "
        "confidence_justification.\n"
        "OPTIONAL fields in 'finding': audit_ids (from tool responses — critical for provenance), "
        "mitre_ids, iocs, event_type, event_timestamp, artifact_ref, related_findings, "
        "supersedes (finding id(s) this finding corrects/replaces, for self-correction chains), "
        "affected_account.\n\n"
        "EXAMPLE: {\"finding\": {\"title\": \"Suspicious PowerShell Execution\", \"type\": \"finding\", "
        "\"host\": \"WEBSRV01\", \"observation\": \"Encoded PowerShell ran from outlook.exe — EventID 1, "
        "ParentImage: outlook.exe, Image: powershell.exe\", \"interpretation\": \"Likely initial access "
        "via phishing attachment executing a download cradle\", \"confidence\": \"HIGH\", "
        "\"confidence_justification\": \"Corroborated by Sysmon EventID 1 + outbound network connection to "
        "known-bad IP 10.0.1.50\", \"audit_ids\": [\"run_command-examiner-20260601-001\"], "
        "\"mitre_ids\": [\"T1059.001\", \"T1204.002\"], \"event_timestamp\": \"2026-06-01T14:30:00Z\"}, "
        "\"supporting_commands\": [{\"command\": \"cat evidence/events/sysmon.json | jq 'select(.EventID==1)'\", "
        "\"output_excerpt\": \"EventID: 1, ParentImage: outlook.exe, Image: powershell.exe, "
        "CommandLine: -EncodedCommand SQBFAFgA...\", \"purpose\": \"Corroborate process creation chain\", "
        "\"audit_id\": \"run_command-examiner-20260601-002\"}]}",
        _schema(
            {
                "finding": {
                    "type": "object",
                    "description": "Required: title, type, host, observation, interpretation, confidence, confidence_justification. Optional: audit_ids, mitre_ids, iocs, event_type, event_timestamp, artifact_ref, related_findings, supersedes, affected_account.",
                    "properties": {
                        "title": {"type": "string", "description": "Concise finding title"},
                        "type": {"type": "string", "enum": ["finding", "attribution", "conclusion", "exclusion"]},
                        "host": {"type": "string", "description": "Affected hostname"},
                        "observation": {"type": "string", "description": "Raw evidence observed"},
                        "interpretation": {"type": "string", "description": "Analytical interpretation of observation"},
                        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW", "SPECULATIVE"]},
                        "confidence_justification": {"type": "string", "description": "Why this confidence level is justified"},
                        "audit_ids": {"type": "array", "items": {"type": "string"}},
                        "mitre_ids": {"type": "array", "items": {"type": "string"}},
                        "iocs": {"type": "array", "items": {"type": "string"}},
                        "event_type": {"type": "string"},
                        "event_timestamp": {"type": "string", "description": "ISO 8601 timestamp of the incident event"},
                        "artifact_ref": {"type": "string"},
                        "related_findings": {"type": "array", "items": {"type": "string"}},
                        "supersedes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Finding id(s) this finding corrects or replaces (self-correction chain).",
                        },
                        "affected_account": {"type": "string"},
                    },
                    "required": ["title", "type", "host", "observation", "interpretation", "confidence", "confidence_justification"],
                },
                "supporting_commands": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                            "output_excerpt": {"type": "string"},
                            "purpose": {"type": "string"},
                            "audit_id": {"type": "string"},
                        },
                        "required": ["command", "purpose"],
                    },
                    "description": "Shell commands that produced evidence for this finding. Include audit_id from the tool response.",
                },
                "artifacts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source": {"type": "string", "description": "Evidence path"},
                            "extraction": {"type": "string", "description": "How the artifact was extracted"},
                            "content": {"type": "string", "description": "Actual evidence content"},
                            "content_type": {"type": "string"},
                            "purpose": {"type": "string"},
                            "audit_id": {"type": "string"},
                        },
                        "required": ["source", "extraction", "content"],
                    },
                    "description": "Evidence artifacts. Must include audit_id from tool response.",
                },
            },
            ["finding"],
        ),
    ),
    CoreToolSpec(
        "record_timeline_event",
        "Stage a timeline event as DRAFT for examiner approval.\n\n"
        "REQUIRED in 'event': title, timestamp (ISO 8601), description, host, source.\n"
        "OPTIONAL in 'event': event_type, related_findings, audit_ids, mitre_ids.\n\n"
        "EXAMPLE: {\"event\": {\"title\": \"Suspicious PowerShell Execution\", "
        "\"timestamp\": \"2026-06-01T14:30:00Z\", \"description\": \"Encoded PowerShell "
        "executed from outlook.exe\", \"host\": \"WEBSRV01\", "
        "\"source\": \"evidence/events/sysmon.json\", \"event_type\": \"execution\", "
        "\"related_findings\": [\"F-examiner-001\"]}}",
        _schema({
            "event": {
                "type": "object",
                "description": "Required: title, timestamp, description, host, source. Optional: event_type, related_findings, audit_ids, mitre_ids.",
                "properties": {
                    "title": {"type": "string", "description": "Concise event title"},
                    "timestamp": {"type": "string", "description": "ISO 8601 timestamp of the event"},
                    "description": {"type": "string", "description": "What occurred"},
                    "host": {"type": "string", "description": "Host where the event occurred"},
                    "source": {"type": "string", "description": "Evidence source file or log type"},
                    "event_type": {"type": "string", "enum": ["execution", "persistence", "lateral", "auth", "network", "other"]},
                    "related_findings": {"type": "array", "items": {"type": "string"}},
                    "audit_ids": {"type": "array", "items": {"type": "string"}},
                    "mitre_ids": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "timestamp", "description", "host", "source"],
            },
        }, ["event"]),
    ),
    CoreToolSpec(
        "list_existing_findings",
        "List staged findings already recorded in the active case.",
        _schema(
            {
                "status": {"type": "string", "enum": ["DRAFT", "COMMITTED", "REJECTED", "SUPERSEDED"]},
                "limit": {"type": "integer", "default": 20},
                "offset": {"type": "integer", "default": 0},
            }
        ),
        read_only=True,
        output_schema=_LIST_FINDINGS_OUTPUT_SCHEMA,
    ),
    CoreToolSpec(
        "manage_todo",
        "Manage investigation TODOs. action='create' needs description (optional "
        "priority, assignee, related_findings); 'list' takes optional status/assignee; "
        "'update' needs todo_id (optional status/note/assignee/priority); 'complete' "
        "needs todo_id.",
        _schema(
            {
                "action": {"type": "string", "enum": ["create", "list", "update", "complete"]},
                "todo_id": {"type": "string"},
                "description": {"type": "string"},
                "assignee": {"type": "string"},
                "priority": {"type": "string", "enum": ["low", "medium", "high"]},
                "status": {"type": "string", "enum": ["open", "in_progress", "completed", "blocked"]},
                "note": {"type": "string"},
                "related_findings": {"type": "array", "items": {"type": "string"}},
            },
            ["action"],
        ),
    ),
    CoreToolSpec(
        "get_tool_help",
        "Get usage information, common flags, caveats, and field meanings for a cataloged forensic tool.",
        _schema({"tool_name": {"type": "string"}}, ["tool_name"]),
        read_only=True,
    ),
    CoreToolSpec(
        "run_command",
        "Execute a quick, synchronous validated command on this SIFT VM and return "
        "inline preview/receipt output. The returned rc-* receipt id is not a "
        "durable job id; use run_command_job for long-running or parallel work "
        "that should be polled with running_commands_status. Pass a single command string; "
        "pipes (|), sequencing (&&/||/;), and redirects (>,>>,<,2>&1) are supported. "
        "Set preview_lines to cap inline stdout and save_output for large output. "
        "Case path jails, audit logging, and provenance hashing are enforced.",
        _schema(
            {
                "command": {"type": "string", "description": "Command to execute. May include pipes, &&/||/;, and redirects."},
                "purpose": {"type": "string", "description": "Short reason for this command, recorded in the audit trail."},
                "timeout": {"type": "integer", "default": 0, "description": "Per-command timeout in seconds. 0 uses the platform default."},
                "save_output": {"type": "boolean", "default": False, "description": "Persist full stdout/stderr to agent/run_commands/."},
                "evidence_refs": {"type": "array", "items": {"type": "string"}, "description": "Sealed evidence references (evidence_id or relative display path) this command reads. Resolved to local paths internally; the agent never supplies absolute paths."},
                "output_ref": {"type": "string", "description": "Logical name for saved output. Resolved internally to a writable location under agent/run_commands/; returned as a relative output ref."},
                "input_files": {"type": "array", "items": {"type": "string"}, "description": "Deprecated: prefer evidence_refs. Evidence/input file paths this command reads, for provenance hashing."},
                "working_dir": {"type": "string", "description": "Working directory, relative to the case directory."},
                "preview_lines": {"type": "integer", "default": 0, "description": "Cap inline stdout to this many lines (0 = no inline cap)."},
                "skip_enrichment": {"type": "boolean", "default": False, "description": "Skip forensic-knowledge enrichment after the first call."},
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


_ARRAY_OPERATOR_TOKENS = frozenset(
    {"|", "&&", "||", ";", "&", ">", ">>", "<", "<<", "2>&1", "2>", "2>>", "&>", "&>>"}
)


def _coerce_run_command(command: Any) -> tuple[str | None, str | None]:
    if isinstance(command, str):
        return command, None
    if isinstance(command, list) and all(isinstance(item, str) for item in command):
        for token in command:
            if token in _ARRAY_OPERATOR_TOKENS or any(
                op in token for op in ("|", "&&", "||", ";", ">", "<")
            ):
                return (
                    None,
                    "command arrays are literal argv and cannot contain shell operators. "
                    "Pass command as a single string when using pipes, redirects, "
                    "semicolons, &&, or ||.",
                )
        import shlex

        return shlex.join(command), None
    return None, "command must be a string or an array of strings"


def _trusted_internal_evidence_refs(
    refs: Any, *, case_root: str
) -> tuple[list[str], list[str]]:
    """Return internal evidence paths + public refs injected by the Gateway.

    This path closes the DB/file-manifest mismatch for Gateway calls while
    keeping direct/core legacy behavior unchanged. The Gateway strips any
    client-supplied private fields before injecting these values; core still
    requires a DB-active AuthorityContext and validates containment as defense
    in depth.
    """
    if not refs:
        return [], []
    try:
        from sift_core.active_case_context import current_active_case

        ctx = current_active_case()
    except ImportError:  # pragma: no cover
        ctx = None
    if ctx is None or not getattr(ctx, "db_active", False):
        raise ValueError("internal evidence refs require DB authority context")
    if not isinstance(refs, list):
        raise ValueError("internal evidence refs must be an array")

    case_resolved = Path(case_root).resolve()
    paths: list[str] = []
    public_refs: list[str] = []
    for item in refs:
        if not isinstance(item, dict):
            raise ValueError("internal evidence ref entries must be objects")
        path_text = str(item.get("path") or "")
        if not path_text:
            raise ValueError("internal evidence ref missing path")
        path = Path(path_text).resolve()
        if not path.is_relative_to(case_resolved) or not path.is_file():
            raise ValueError("internal evidence ref is unavailable")
        paths.append(str(path))
        public_refs.append(
            str(
                item.get("evidence_id")
                or item.get("display_path")
                or item.get("ref")
                or ""
            )
        )
    return paths, [ref for ref in public_refs if ref]


# platform_capabilities is built declaration-driven in
# sift_core.case_manager.build_platform_capabilities (sourced from the
# gateway's registered+available backends, not installed packages).


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


def _case_info(manager: CaseManager) -> dict:
    """Consolidated case overview: status, file structure, evidence chain, capabilities."""
    case_dir = get_case_dir()
    status = case_status_data(case_dir)
    structure = _case_file_structure()
    caps = build_platform_capabilities()

    chain = chain_status(case_dir)
    evidence_ok = chain["status"] == ChainStatus.OK

    return {
        "case_id": status["case_id"],
        "name": status["name"],
        "status": status["status"],
        "examiner": status["examiner"],
        "case_dir": status["path"],
        "case_brief": status["case_brief"],
        "findings": {
            "total": status["finding_count"],
            "draft": status["finding_draft"],
            "approved": status["finding_approved"],
        },
        "timeline_events": status["timeline_count"],
        "todos": {"open": status["todo_open"], "total": status["todo_total"]},
        "evidence_chain": {
            "status": chain["status"],
            "ok": evidence_ok,
            "issues": chain["issues"],
            "manifest_version": chain["manifest_version"],
        },
        "file_structure": {
            "top_level_dirs": structure.get("top_level_dirs", []),
            "total_files": structure.get("total_files", 0),
            "total_dirs": structure.get("total_dirs", 0),
            "subtree_counts": structure.get("file_counts_by_subtree", {}),
        },
        "platform_capabilities": caps["platform_capabilities"],
    }


def _evidence_info() -> dict:
    """Consolidated evidence overview: listing + chain verification."""
    case_dir = get_case_dir()
    evidence = list_evidence_status_data(case_dir)
    verify = _evidence_verify()

    return {
        "chain_status": verify["status"],
        "ok_count": verify["ok_count"],
        "issues": verify["issues"],
        "manifest_version": verify["manifest_version"],
        "evidence_files": evidence.get("evidence", []),
        "total_evidence_files": evidence.get("total_evidence_files", 0),
        "unregistered_files": evidence.get("unregistered_files", []),
        "requires_examiner_action": evidence.get("requires_examiner_action", False),
    }


def _is_transient_mount_dir(name: str) -> bool:
    """Skip transient ingest-mount staging dirs (B2).

    OpenSearch ingest workers FUSE-mount evidence (e01) under
    ``tmp/ingest-<id>/xmount-<...>/``. Those mounts can raise
    ``OSError: [Errno 5] Input/output error`` while being walked and must
    never be descended into by ``case_info`` — the mount staging is not part
    of the case file structure.
    """
    return name.startswith("ingest-") or name.startswith("xmount-")


def _case_file_structure() -> dict:
    case_dir = get_case_dir()
    case_resolved = case_dir.resolve()
    files_list = []
    dirs_list = []
    exclude_basenames = {"evidence-ledger.jsonl", "evidence-verify-state.json"}
    exclude_dirs = {"audit", ".git", "__pycache__"}

    # Manual stack walk (not rglob) so we can prune transient ingest-mount
    # subtrees BEFORE descending into them, and so a per-entry OSError on an
    # erroring path (e.g. a FUSE mount mid-ingest) skips that entry instead of
    # taking down case_info for every agent. B2: while an OpenSearch worker has
    # an E01 FUSE-mounted under tmp/, walking into it raises Errno 5.
    stack: list[Path] = [case_resolved]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            # Transient/IO-erroring directory (e.g. live FUSE mount) — skip,
            # never crash the whole tool.
            continue
        for entry in sorted(entries, key=lambda e: e.name):
            try:
                rel_path_obj = Path(entry.path).relative_to(case_resolved)
            except ValueError:
                continue
            rel_parts = rel_path_obj.parts
            if any(part in exclude_dirs for part in rel_parts):
                continue
            # Prune transient ingest-mount staging dirs (do not descend).
            if any(_is_transient_mount_dir(part) for part in rel_parts):
                continue
            if entry.name in exclude_basenames or entry.name.endswith(".tmp"):
                continue
            rel_path = str(rel_path_obj)
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                # Stat on the entry failed (transient/io-erroring path) — skip.
                continue
            if is_dir:
                dirs_list.append(rel_path)
                stack.append(Path(entry.path))
            elif is_file:
                try:
                    size_bytes = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                files_list.append({"path": rel_path, "size_bytes": size_bytes})

    full = {
        "case_id": case_resolved.name,
        "case_dir": str(case_resolved),
        "directories": dirs_list,
        "files": files_list,
    }

    # Save full tree and return a slim summary
    full_path: str | None = None
    try:
        agent_dir = case_resolved / "agent"
        agent_dir.mkdir(exist_ok=True)
        out = agent_dir / "case_file_structure.json"
        out.write_text(json.dumps(full, indent=2), encoding="utf-8")
        full_path = str(out)
    except OSError:
        pass

    # Top-level directory names only (depth-1 children of case_dir)
    top_dirs = sorted({p.split("/")[0] for p in dirs_list if "/" not in p})
    # File counts per top-level subtree
    subtree_counts: dict[str, int] = {}
    for f in files_list:
        top = f["path"].split("/")[0]
        subtree_counts[top] = subtree_counts.get(top, 0) + 1

    slim: dict[str, Any] = {
        "case_id": case_resolved.name,
        "case_dir": str(case_resolved),
        "top_level_dirs": top_dirs,
        "file_counts_by_subtree": subtree_counts,
        "total_dirs": len(dirs_list),
        "total_files": len(files_list),
    }
    if full_path:
        slim["full_tree_path"] = full_path
    return slim


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
    start = time.monotonic()
    audit_id = audit._next_audit_id(examiner=examiner)

    command, command_error = _coerce_run_command(args.get("command") or "")
    if command_error:
        return build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error=command_error,
            examiner=examiner,
        )
    assert command is not None
    purpose = str(args.get("purpose", ""))
    if not purpose:
        return build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error="purpose is required",
            examiner=examiner,
        )
    try:
        working_dir = str(args.get("working_dir", ""))
        if working_dir:
            cwd = str(resolve_case_path(working_dir, default_subdir=""))
        else:
            try:
                from sift_core.active_case_context import current_active_case

                ctx = current_active_case()
                cwd = str(ctx.case_dir) if ctx and ctx.case_dir is not None else None
            except ImportError:  # pragma: no cover - defensive for unusual packaging
                cwd = None
            if cwd is None:
                cwd = os.environ.get("SIFT_CASE_DIR", "") or None
    except ValueError:
        return build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error="Path must be within the case directory",
            examiner=examiner,
        )

    # The case ROOT (not the per-call working_dir, which may be a subdir like
    # agent/scratch) anchors evidence/output-ref resolution and path
    # sanitization, so relative display paths are reported from the case root.
    try:
        case_root = str(get_case_dir())
    except Exception:
        case_root = os.environ.get("SIFT_CASE_DIR", "") or cwd

    # Parse command using our split/parse state machines to extract binary and detect inputs
    from sift_core.execute.security import (
        EvidenceRefError,
        parse_subcommand_argv_and_redirects,
        resolve_evidence_ref,
        resolve_output_ref,
        sanitize_path_value,
        sanitize_paths_deep,
        split_command_by_operators,
    )

    # Evidence refs (BATCH-I1): the agent references sealed evidence by opaque id
    # or relative display path; we resolve to the absolute path internally for
    # provenance hashing and never echo it back. Fail closed if a ref does not
    # match an ACTIVE sealed manifest entry.
    evidence_refs = args.get("evidence_refs") or None
    evidence_ref_error = args.get(_INTERNAL_EVIDENCE_REF_ERROR)
    if evidence_ref_error:
        return build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error=str(evidence_ref_error),
            examiner=examiner,
        )
    resolved_evidence_paths: list[str] = []
    public_evidence_refs: list[str] = []
    if evidence_refs:
        if not isinstance(evidence_refs, list):
            return build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=audit_id,
                error="evidence_refs must be an array of strings",
                examiner=examiner,
            )
        try:
            resolved_evidence_paths, public_evidence_refs = _trusted_internal_evidence_refs(
                args.get(_INTERNAL_RESOLVED_EVIDENCE_REFS), case_root=case_root
            )
        except ValueError as exc:
            return build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=audit_id,
                error=str(exc),
                examiner=examiner,
            )
        if resolved_evidence_paths:
            if not public_evidence_refs:
                public_evidence_refs = [str(ref) for ref in evidence_refs]
        else:
            if _db_authority_active():
                return build_response(
                    tool_name="run_command",
                    success=False,
                    data=None,
                    audit_id=audit_id,
                    error=(
                        "evidence_refs require gateway-resolved DB evidence refs "
                        "in DB-authority mode"
                    ),
                    examiner=examiner,
                )
            public_evidence_refs = [str(ref) for ref in evidence_refs]
            for ref in evidence_refs:
                try:
                    resolved_evidence_paths.append(
                        resolve_evidence_ref(str(ref), case_dir=case_root)
                    )
                except EvidenceRefError as exc:
                    return build_response(
                        tool_name="run_command",
                        success=False,
                        data=None,
                        audit_id=audit_id,
                        error=str(exc),
                        examiner=examiner,
                    )

    # Output ref (BATCH-I1): a logical name the agent picks; we choose the real
    # writable location under agent/run_commands/ and return it as a relative ref.
    output_ref = args.get("output_ref") or None
    save_dir: str | None = None
    if output_ref:
        try:
            save_dir = resolve_output_ref(str(output_ref), case_dir=case_root)
        except EvidenceRefError as exc:
            return build_response(
                tool_name="run_command",
                success=False,
                data=None,
                audit_id=audit_id,
                error=str(exc),
                examiner=examiner,
            )

    subcmds = split_command_by_operators(command)

    first_binary = ""
    detected_inputs: list[str] = []

    input_files = args.get("input_files") or None
    if resolved_evidence_paths:
        detected_inputs.extend(resolved_evidence_paths)
        if input_files:
            for fpath in input_files:
                try:
                    detected_inputs.append(str(resolve_case_path(str(fpath))))
                except ValueError:
                    detected_inputs.append(str(fpath))
        detection_method = "evidence_ref"
    elif input_files:
        for fpath in input_files:
            try:
                detected_inputs.append(str(resolve_case_path(str(fpath))))
            except ValueError:
                detected_inputs.append(str(fpath))
        detection_method = "llm"
    else:
        for subcmd_str, _ in subcmds:
            if not subcmd_str.strip():
                continue
            try:
                argv, redirects = parse_subcommand_argv_and_redirects(subcmd_str)
                if argv:
                    binary = argv[0].split('/')[-1]
                    if not first_binary:
                        first_binary = binary
                    td = get_tool_def(binary)
                    
                    # Redirections
                    for op, target in redirects:
                        if op in ("<", "<<"):
                            detected_inputs.append(target)
                            
                    # input flag
                    if td and td.input_flag:
                        try:
                            idx = argv.index(td.input_flag)
                            if idx + 1 < len(argv):
                                detected_inputs.append(argv[idx + 1])
                        except ValueError:
                            pass
                    else:
                        for token in argv[1:]:
                            if token.startswith("-"):
                                continue
                            p = Path(token)
                            if "/" in token or ".." in token:
                                detected_inputs.append(token)
            except Exception:
                pass
        if detected_inputs:
            detection_method = "parsed"
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
            save_output=bool(args.get("save_output", False)) or bool(save_dir),
            save_dir=save_dir,
            cwd=cwd,
            preview_lines=min(int(args.get("preview_lines") or 0), 200),
        )
        elapsed = time.monotonic() - start
        # Capture internal bookkeeping fields BEFORE stripping them from the
        # inline data block. They drive full_output_path, the output format, the
        # stage summary, and the audit record below. Popping them first (the
        # original bug) raised KeyError on the large-output `_parsed` path and
        # silently dropped full_output_path for every saved output.
        output_file = exec_result.get("output_file")
        output_sha256 = exec_result.get("output_sha256")
        output_format = exec_result.get("_output_format", "text")
        raw_stages = exec_result.get("stages") or []
        stdout_total_bytes = exec_result.get("stdout_total_bytes")
        # generic.run_command stamps partial_failure / partial_failure_note onto
        # the exec_result ROOT (a stage exited nonzero but still produced output).
        # Capture them BEFORE the _internal pop so they are surfaced on the
        # response root below — identically on the parsed and unparsed paths.
        # Without this they were dropped when output was catalog-parsed (resp_data
        # = _parsed) yet leaked into the inline data block when it was not
        # (resp_data = exec_result) — an inconsistent, branch-dependent signal.
        partial_failure = exec_result.get("partial_failure")
        partial_failure_note = exec_result.get("partial_failure_note")
        for _internal in ("stages", "_output_format", "executor", "runtime_user",
                          "output_file", "output_sha256",
                          "stderr_file", "stderr_sha256",
                          "partial_failure", "partial_failure_note"):
            exec_result.pop(_internal, None)
        # Context efficiency: for a single-stage command the structured
        # command echo pure-duplicates the response-level command string —
        # drop it. Multi-segment commands keep original_command + per-stage
        # argv (QA finding 5: compound command provenance contract).
        if len(raw_stages) <= 1:
            exec_result.pop("command", None)
            exec_result.pop("original_command", None)

        # AUT2-B5: a pipeline must not mask an upstream failure behind a
        # succeeding final stage (`mmls ... | head` exits 0 via head while mmls
        # failed). SIGPIPE deaths of non-final stages (rc 141 / -13) are normal
        # when a downstream consumer closes early and stay exempt.
        failed_stages = []
        for idx, s in enumerate(raw_stages):
            rc = s.get("exit_code")
            if rc in (0, None):
                continue
            if rc in (141, -13) and idx < len(raw_stages) - 1:
                continue
            argv0 = (s.get("argv") or [""])[0]
            entry = {
                "binary": s.get("binary") or str(argv0).split("/")[-1],
                "exit_code": rc,
            }
            if s.get("stderr_tail"):
                entry["stderr_tail"] = s["stderr_tail"]
            else:
                entry["hint"] = (
                    "stage produced no stderr; re-run it alone and consult "
                    "get_tool_help for the binary before trusting downstream output"
                )
            failed_stages.append(entry)
        pipeline_ok = exec_result["exit_code"] == 0 and not failed_stages
        fk_name = get_tool_def(first_binary).knowledge_name if get_tool_def(first_binary) else first_binary
        artifact_hint = _detect_artifact_context([command])
        resp_data = exec_result["_parsed"] if exec_result.get("_parsed") else exec_result
        # Output ref: the agent only ever sees a case-relative reference to the
        # saved output, never the absolute path the worker wrote to.
        output_file_ref = (
            sanitize_path_value(output_file, case_dir=case_root) if output_file else None
        )
        response = build_response(
            tool_name="run_command",
            success=pipeline_ok,
            data=resp_data,
            audit_id=audit_id,
            output_format=output_format,
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=[command],
            fk_tool_name=fk_name,
            output_files=[output_file_ref] if output_file_ref else None,
            extractions=exec_result.get("extractions"),
            skip_enrichment=bool(args.get("skip_enrichment", False)),
            artifact_context=artifact_hint,
            examiner=examiner,
        )
        # Provenance receipt: a stable job/receipt id binds this execution to its
        # audit record, input evidence hashes, and output hashes — reportable
        # without exposing any local path. D1 durable jobs are enqueued by the
        # Gateway for long-running work; for the synchronous run_command path the
        # receipt id is derived from the audit id so downstream report/provenance
        # consumers always have a hash-linked handle. Stored only inside provenance
        # to avoid duplication at the response root (run_command_job reads provenance
        # first, with fallback to root, so removing root job_id is safe).
        job_id = f"rc-{audit_id}"
        if "warnings" in exec_result:
            response["warnings"] = exec_result["warnings"]
            if "agent_action" in exec_result:
                response["agent_action"] = exec_result["agent_action"]
        if "privilege_escalation" in exec_result:
            response["privilege_escalation"] = exec_result["privilege_escalation"]
        if len(raw_stages) > 1:
            response["stages"] = [
                {"binary": s["binary"], "exit_code": s["exit_code"]}
                for s in raw_stages
                if "binary" in s
            ]
        if failed_stages:
            response["failed_stages"] = failed_stages
            if exec_result["exit_code"] == 0:
                response["error"] = (
                    "An upstream pipeline stage failed; downstream output may "
                    "be incomplete. See failed_stages."
                )
        # Surface the engine's partial_failure summary on the response root the
        # same way failed_stages/error are surfaced above. It was popped from
        # exec_result with the other _internal keys, so it never lands in the
        # inline data block on either path — the agent sees it here whether or
        # not the output was catalog-parsed.
        if partial_failure:
            response["partial_failure"] = True
            if partial_failure_note:
                response["partial_failure_note"] = partial_failure_note
        if output_file_ref:
            # full_output_ref is the canonical output path key (case-relative,
            # never absolute). full_output_path was an alias — dropped to avoid
            # duplication; all consumers (tests, audit_helpers, run_command_job)
            # use full_output_ref. full_output_sha256/bytes remain at root because
            # audit_helpers._RUN_COMMAND_DETAIL_KEYS reads them directly.
            response["full_output_ref"] = output_file_ref
            response["full_output_sha256"] = output_sha256
            response["full_output_bytes"] = stdout_total_bytes

        # Provenance receipt: hash-linked, path-free record the agent can cite in
        # findings/reports. Input hashes prove which sealed evidence was read;
        # output hash proves the artifact produced.
        # job_id is the canonical receipt handle here; audit_id lives at response
        # root (set by build_response) and is not repeated in provenance to avoid
        # duplication. run_command_job reads provenance.job_id with fallback to
        # result.job_id (now absent); it reads provenance.audit_id or result.audit_id
        # (root still present), so both consumers are satisfied.
        provenance = {
            "job_id": job_id,
            "input_sha256s": sorted(set(input_hashes.values())) if input_hashes else [],
            "input_count": len(input_hashes),
            "evidence_refs": public_evidence_refs if evidence_refs else [],
        }
        if output_sha256:
            provenance["output_sha256"] = output_sha256
        if output_file_ref:
            provenance["output_ref"] = output_file_ref
        response["provenance"] = provenance

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
        if raw_stages:
            extra_audit["stages"] = raw_stages

        if (
            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={
                    "exit_code": exec_result["exit_code"],
                    "output_file": output_file or "",
                    "output_sha256": output_sha256 or "",
                    "stdout_bytes": stdout_total_bytes or 0,
                    "stdout_head": (exec_result.get("stdout") or "")[:500],
                },
                audit_id=audit_id,
                elapsed_ms=elapsed * 1000,
                input_files=list(input_hashes.keys()) if input_hashes else None,
                input_sha256s=list(input_hashes.values()) if input_hashes else None,
                input_detection_method=detection_method,
                extra=extra_audit if extra_audit else None,
                examiner_override=examiner,
            )
            is None
            and not _db_authority_active()
        ):
            # File-authority mode only: a None return is a genuine JSONL write
            # failure. In DB-authority mode the gateway MCP envelope is the
            # authoritative audit trail (it captures command + provenance), so a
            # missing local file ledger is expected and not an error.
            response["warning"] = "Audit write failed — action not recorded"
        if detection_method == "none" and first_binary not in _NO_INPUT_CMDS:
            response["input_files_warning"] = (
                "Could not detect input files — pass input_files parameter for provenance chain linking."
            )
        elif detection_method == "llm" and not input_hashes:
            response["input_files_warning"] = (
                "input_files provided but none resolved to existing files. Provenance chain will be incomplete."
            )
        # Final defense-in-depth: scrub every path-like value in the agent-facing
        # response. In-case absolutes (including those embedded in tool stdout)
        # collapse to relative display paths; any other case/evidence/mount path
        # becomes [REDACTED:absolute_path]. The audit record above already
        # captured the unredacted values for the operator.
        return sanitize_paths_deep(response, case_dir=case_root)

    except SiftError as exc:
        elapsed = time.monotonic() - start
        response = build_response(
            tool_name="run_command",
            success=False,
            data=None,
            audit_id=audit_id,
            error=str(exc),
            examiner=examiner,
        )
        if (
            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(exc)},
                audit_id=audit_id,
                elapsed_ms=elapsed * 1000,
                examiner_override=examiner,
            )
            is None
            and not _db_authority_active()
        ):
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
            examiner=examiner,
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


def _manage_todo(args: dict, examiner: str, manager: CaseManager, audit: AuditWriter) -> dict:
    action = str(args.get("action", "")).strip().lower()
    # 'create' is the canonical verb (matches the input schema and description);
    # 'add' is accepted as a backward-compatible alias.
    if action in ("create", "add"):
        description = str(args.get("description", ""))
        if not description:
            return {"error": "missing_description", "message": "description is required when action='create'."}
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
        "message": "action must be one of: create, list, update, complete",
        "supported_actions": ["create", "list", "update", "complete"],
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
        if name == "case_info":
            result = _case_info(manager)
        elif name == "evidence_info":
            result = _evidence_info()
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
            page = findings[offset : offset + limit] if limit > 0 else findings

            findings_file: str | None = None
            try:
                case_dir = get_case_dir()
                agent_dir = case_dir / "agent"
                agent_dir.mkdir(exist_ok=True)
                findings_path = agent_dir / "findings_list.json"
                findings_path.write_text(
                    json.dumps({"findings": findings, "total": len(findings)}, indent=2),
                    encoding="utf-8",
                )
                findings_file = str(findings_path)
            except OSError:
                pass

            _SUMMARY_KEYS = {"id", "title", "status", "confidence", "host", "type", "staged", "examiner", "created_by", "event_timestamp"}
            summaries = [{k: v for k, v in f.items() if k in _SUMMARY_KEYS} for f in page]
            result = {
                "findings": summaries,
                "total": len(findings),
                "limit": limit,
                "offset": offset,
            }
            if findings_file:
                result["full_findings_path"] = findings_file
        elif name == "manage_todo":
            result = _manage_todo(args, effective_examiner, manager, audit)
        elif name == "get_tool_help":
            result = _get_tool_help(str(args.get("tool_name", "")))
            audit.log(
                tool="get_tool_help",
                params={"tool_name": args.get("tool_name", "")},
                result_summary=result,
            )
        elif name == "run_command":
            result = _run_command(args, effective_examiner, audit)
        else:  # pragma: no cover - guarded by _SPECS_BY_NAME
            raise KeyError(name)
    except Exception as exc:
        # The only genuine "unknown tool" signal is the KeyError raised above,
        # BEFORE this try block, when name is not in _SPECS_BY_NAME. Any error
        # raised while executing a KNOWN tool (KeyError, TypeError, etc.) is a
        # tool-execution failure. Convert it to a structured envelope so the
        # gateway never misreports it as "unknown tool {name}".
        logger.exception("core tool %s failed", name)
        result = {
            "success": False,
            "tool": name,
            "data": None,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return _json_result(result)
