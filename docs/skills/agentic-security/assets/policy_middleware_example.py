"""Minimal policy gate pattern for high-risk MCP tools.

This is a design template, not drop-in production code.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Actor:
    user_id: str
    role: str
    scopes: set[str]


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    case_id: str
    args: dict[str, Any]
    risk_tier: str


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    audit_fields: dict[str, Any]


ALLOWED_CASE_ROOT = Path("/cases").resolve()


def _resolve_case_path(case_id: str, relative_path: str) -> str:
    base = (ALLOWED_CASE_ROOT / case_id).resolve()
    target = (base / relative_path).resolve()
    if target != base and base not in target.parents:
        raise ValueError("path escapes case root")
    return str(target)


def evaluate_tool_call(actor: Actor, call: ToolCall) -> PolicyResult:
    if not call.case_id:
        return PolicyResult(Decision.DENY, "missing case_id", {"tool": call.tool_name})

    if call.risk_tier in {"high_impact", "destructive"} and actor.role != "lead":
        return PolicyResult(Decision.DENY, "role cannot invoke high-risk tool", {"tool": call.tool_name, "case_id": call.case_id})

    if call.risk_tier in {"high_impact", "destructive"}:
        return PolicyResult(Decision.REQUIRE_APPROVAL, "high-risk tool requires explicit approval", {"tool": call.tool_name, "case_id": call.case_id})

    # Normalize known path fields before execution. Reject unknown path use by default.
    normalized_args = dict(call.args)
    if "relative_path" in normalized_args:
        normalized_args["resolved_path"] = _resolve_case_path(call.case_id, str(normalized_args["relative_path"]))

    return PolicyResult(Decision.ALLOW, "allowed", {"tool": call.tool_name, "case_id": call.case_id, "args": normalized_args})
