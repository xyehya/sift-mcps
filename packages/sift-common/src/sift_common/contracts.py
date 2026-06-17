"""D27a shared tool contract conventions from doc 16 section 1.

Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""
# ruff: noqa: E501, UP035

from __future__ import annotations

from enum import Enum
from typing import Any, Callable

from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field


class ResultMeta(BaseModel):
    audit_id: str | None = Field(None, description="Audit-log id for this call; None if the audit write failed.")
    examiner: str | None = Field(None, description="Resolved examiner identity recorded in audit.")
    caveats: list[str] = Field(default_factory=list, description="Interpretation caveats for this tool's output.")
    interpretation_constraint: str | None = Field(None, description="What this result may NOT be used to conclude.")
    audit_warning: str | None = Field(None, description="Set when the audit write failed — action not recorded.")


class ErrorCode(str, Enum):
    invalid_input        = "invalid_input"        # schema/enum/range violation caught pre-dispatch
    not_found            = "not_found"            # entity/index/document/path absent
    upstream_unavailable = "upstream_unavailable" # OpenSearch / OpenCTI / DB down or unreachable
    upstream_degraded    = "upstream_degraded"    # reachable but partial (yellow cluster, missing optional DB/plugin)
    rate_limited         = "rate_limited"         # OpenCTI rate limiter tripped
    not_configured       = "not_configured"       # backend misconfigured (creds/paths)
    no_active_case       = "no_active_case"       # case-scoped tool with no resolvable active case
    capacity_refused     = "capacity_refused"     # write refused pre-flight (shard/circuit capacity)
    internal             = "internal"             # unexpected; message is sanitized


class ToolError(BaseModel):
    error: ErrorCode = Field(..., description="Machine-readable error category.")
    message: str = Field(..., description="Human-readable, secret-free explanation.")
    remediation: str = Field(..., description="Concrete next step the caller can take.")
    retryable: bool = Field(False, description="True if retrying the same call may succeed (e.g. transient upstream loss).")
    details: dict[str, Any] = Field(default_factory=dict, description="Optional structured context (e.g. supported_types, halt_reason).")


class ToolDef(BaseModel, arbitrary_types_allowed=True):
    name: str
    fn: Callable
    in_model: type[BaseModel]
    out_model: type[BaseModel]
    annotations: ToolAnnotations
    title: str
    description: str
