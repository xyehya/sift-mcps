"""Exposure-agnostic FastMCP 3 registry for the Windows triage backend."""

from __future__ import annotations

import atexit
import inspect
import time
from collections.abc import Callable
from enum import Enum
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.tools import FunctionTool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from sift_common.instructions import WINDOWS_TRIAGE as _INSTRUCTIONS

from .contracts import ErrorCode, ResultMeta, ToolDef, ToolError
from .exceptions import DatabaseError, ValidationError as TriageValidationError
from .exceptions import WindowsTriageError
from .tool_metadata import DEFAULT_METADATA, TOOL_METADATA


class PromptDef(BaseModel, arbitrary_types_allowed=True):
    name: str
    fn: Callable
    title: str
    description: str


class ResourceDef(BaseModel, arbitrary_types_allowed=True):
    uri: str
    fn: Callable
    name: str
    title: str
    description: str
    mime_type: str = Field("application/json", description="MCP resource MIME type.")


class ToolAliasDef(BaseModel, arbitrary_types_allowed=True):
    name: str
    in_model: type[BaseModel]
    transform: Callable[[BaseModel], BaseModel]
    title: str | None = None
    description: str | None = None


class Verdict(str, Enum):
    EXPECTED = "EXPECTED"
    EXPECTED_LOLBIN = "EXPECTED_LOLBIN"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class ArtifactType(str, Enum):
    file = "file"
    hash = "hash"
    filename = "filename"
    lolbin = "lolbin"
    dll = "dll"


class Finding(BaseModel):
    type: str = Field(..., description="Machine-readable finding type.")
    severity: Literal["critical", "high", "medium", "low"] = Field(
        ..., description="Finding severity."
    )
    description: str = Field(..., description="Human-readable finding summary.")
    extra: dict[str, Any] = Field(
        default_factory=dict, description="Type-specific finding details."
    )


class VerdictOut(BaseModel):
    verdict: Verdict = Field(..., description="Offline Windows baseline verdict.")
    reasons: list[str] = Field(..., description="Why this verdict was assigned.")
    confidence: Literal["high", "medium", "low"] = Field(
        ..., description="Confidence in the baseline verdict."
    )
    findings: list[Finding] = Field(
        default_factory=list, description="Suspicious or contextual findings."
    )


class CheckArtifactIn(BaseModel):
    type: ArtifactType = Field(
        ...,
        description=(
            "file=path baseline (+optional hash); hash=LOLDrivers vulnerable-driver "
            "lookup; filename=deception heuristics; lolbin=LOLBin context; "
            "dll=hijackability."
        ),
    )
    value: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description=(
            "file=Windows path; hash=MD5/SHA1/SHA256; filename/lolbin=filename; "
            "dll=DLL name. No null bytes; length-capped per type."
        ),
    )
    hash: str | None = Field(
        None,
        max_length=128,
        description="Optional file hash when type='file' (baseline mismatch check).",
    )
    os_version: str | None = Field(
        None,
        max_length=256,
        description="Optional OS filter for type='file' (e.g. Win10_21H2_Pro).",
    )

    @field_validator("value", "hash", "os_version")
    @classmethod
    def _reject_null_bytes(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("null bytes are not allowed")
        return value

    @model_validator(mode="after")
    def _type_specific_lengths(self) -> CheckArtifactIn:
        if self.type is ArtifactType.hash and len(self.value) > 128:
            raise ValueError("hash value exceeds maximum length of 128 characters")
        return self


class CheckArtifactOut(VerdictOut):
    artifact_type: ArtifactType = Field(..., description="Artifact subtype checked.")
    path_in_baseline: bool | None = Field(
        None, description="For type='file': exact path exists in the baseline."
    )
    filename_in_baseline: bool | None = Field(
        None, description="For type='file': filename exists anywhere in the baseline."
    )
    is_system_path: bool | None = Field(
        None, description="For type='file': path is under a Windows system directory."
    )
    is_lolbin: bool = Field(
        False, description="True when the filename is a known living-off-the-land binary."
    )
    lolbin_functions: list[str] = Field(
        default_factory=list, description="LOLBAS abuse functions when known."
    )
    subtype_data: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Type-specific fields such as vulnerable_driver, algorithm, hash, "
            "scenarios_by_type, or filename analysis."
        ),
    )


class CheckFileAliasIn(BaseModel):
    path: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Deprecated alias argument: Windows file path.",
    )
    hash: str | None = Field(
        None,
        max_length=128,
        description="Deprecated alias argument: optional file hash.",
    )
    os_version: str | None = Field(
        None,
        max_length=256,
        description="Deprecated alias argument: optional OS filter.",
    )

    @field_validator("path", "hash", "os_version")
    @classmethod
    def _reject_null_bytes(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("null bytes are not allowed")
        return value


class CheckHashAliasIn(BaseModel):
    hash: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Deprecated alias argument: MD5, SHA1, or SHA256 hash.",
    )

    @field_validator("hash")
    @classmethod
    def _reject_null_bytes(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("null bytes are not allowed")
        return value


class FilenameAliasIn(BaseModel):
    filename: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Deprecated alias argument: filename to analyze.",
    )

    @field_validator("filename")
    @classmethod
    def _reject_null_bytes(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("null bytes are not allowed")
        return value


class DllAliasIn(BaseModel):
    dll_name: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Deprecated alias argument: DLL name to check.",
    )

    @field_validator("dll_name")
    @classmethod
    def _reject_null_bytes(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("null bytes are not allowed")
        return value


class CheckProcessTreeIn(BaseModel):
    process_name: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Child process name (e.g. 'cmd.exe').",
    )
    parent_name: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Parent process name (e.g. 'winword.exe').",
    )
    path: str | None = Field(
        None,
        max_length=4096,
        description="Optional executable path for tighter matching.",
    )
    user: str | None = Field(
        None,
        max_length=256,
        description="Optional user context (SYSTEM vs user).",
    )

    @field_validator("process_name", "parent_name", "path", "user")
    @classmethod
    def _reject_null_bytes(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("null bytes are not allowed")
        return value


class CheckProcessTreeOut(VerdictOut):
    in_expectations_db: bool = Field(
        ..., description="True when the child process exists in the local expectations DB."
    )
    expected_parents: list[str] = Field(
        default_factory=list,
        description="Known-good parent process names for this child process.",
    )
    suspicious_parents: list[str] = Field(
        default_factory=list,
        description="Known suspicious parent names for this child process.",
    )
    user_context: dict[str, Any] | None = Field(
        None, description="User-context validation details when user was provided."
    )


REGISTRY: list[ToolDef] = []
ALIAS_REGISTRY: dict[str, list[ToolAliasDef]] = {}
PROMPT_REGISTRY: list[PromptDef] = []
RESOURCE_REGISTRY: list[ResourceDef] = []

_runtime: Any | None = None


def set_runtime_for_testing(runtime: Any | None) -> None:
    """Inject a runtime for tests without opening production databases."""
    global _runtime
    _runtime = runtime


def get_runtime() -> Any:
    """Get or lazily initialize the Windows triage runtime."""
    global _runtime
    if _runtime is None:
        from .server import WindowsTriageServer

        _runtime = WindowsTriageServer()
        atexit.register(_runtime.close_databases)
    return _runtime


def create_server() -> FastMCP:
    """Create the standalone FastMCP server from registry definitions."""
    mcp = FastMCP("windows-triage-mcp", instructions=_INSTRUCTIONS)
    register_all(mcp)
    return mcp


def register_all(mcp: FastMCP) -> None:
    """Register tools, deprecated aliases, prompts, and resources."""
    for tool_def in REGISTRY:
        mcp.add_tool(_function_tool(tool_def, tool_def.name))
        for alias in ALIAS_REGISTRY.get(tool_def.name, []):
            mcp.add_tool(_function_tool(tool_def, alias.name, alias=alias))
    for prompt_def in PROMPT_REGISTRY:
        mcp.prompt(
            name=prompt_def.name,
            title=prompt_def.title,
            description=prompt_def.description,
        )(prompt_def.fn)
    for resource_def in RESOURCE_REGISTRY:
        mcp.resource(
            resource_def.uri,
            name=resource_def.name,
            title=resource_def.title,
            description=resource_def.description,
            mime_type=resource_def.mime_type,
        )(resource_def.fn)


def _function_tool(
    tool_def: ToolDef,
    name: str,
    alias: ToolAliasDef | None = None,
) -> FunctionTool:
    in_model = alias.in_model if alias else tool_def.in_model
    description = tool_def.description
    title = tool_def.title
    meta: dict[str, Any] | None = None
    if alias is not None:
        title = alias.title or f"Deprecated: {tool_def.title}"
        alias_description = alias.description or ""
        description = (
            f"DEPRECATED alias for `{tool_def.name}`. "
            "Use the canonical tool; this alias will be removed after one cutover cycle."
        )
        if alias_description:
            description = f"{description}\n\n{alias_description}"
        description = f"{description}\n\n{tool_def.description}"
        meta = {"deprecated": True, "canonical_name": tool_def.name}

    async def invoke(**kwargs: Any) -> ToolResult:
        try:
            params = in_model.model_validate(kwargs)
            canonical_params = alias.transform(params) if alias else params
        except ValidationError as exc:
            return _error_result(
                ErrorCode.invalid_input,
                "Input did not match the tool schema.",
                "Correct the invalid argument values and retry.",
                details={"errors": exc.errors(include_url=False)},
            )

        context = {
            "tool_name": name,
            "canonical_name": tool_def.name,
            "deprecated_alias": alias is not None,
        }
        try:
            result = _call_with_optional_context(tool_def.fn, canonical_params, context)
            if inspect.isawaitable(result):
                result = await result
            return _success_result(result, tool_def.out_model)
        except Exception:
            return _error_result(
                ErrorCode.internal,
                "Tool execution failed.",
                "Check backend logs for details, then retry or narrow the request.",
            )

    return FunctionTool(
        name=name,
        title=title,
        description=description,
        fn=invoke,
        return_type=ToolResult,
        parameters=in_model.model_json_schema(),
        output_schema=tool_def.out_model.model_json_schema(),
        annotations=tool_def.annotations,
        meta=meta,
        run_in_thread=False,
    )


def _call_with_optional_context(
    fn: Callable, params: BaseModel, context: dict[str, Any]
) -> Any:
    signature = inspect.signature(fn)
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 2:
        return fn(params, context)
    return fn(params)


def _success_result(result: Any, out_model: type[BaseModel]) -> ToolResult:
    if isinstance(result, ToolResult):
        return result
    if isinstance(result, BaseModel):
        out = result
    else:
        out = out_model.model_validate(result)
    structured = out.model_dump(mode="json")
    return ToolResult(
        content=out.model_dump_json(),
        structured_content=structured,
        meta=ResultMeta().model_dump(mode="json"),
    )


def _error_result(
    code: ErrorCode,
    message: str,
    remediation: str,
    *,
    retryable: bool = False,
    details: dict[str, Any] | None = None,
    meta: ResultMeta | None = None,
) -> ToolResult:
    error = ToolError(
        error=code,
        message=message,
        remediation=remediation,
        retryable=retryable,
        details=details or {},
    )
    return ToolResult(
        content=error.model_dump_json(),
        structured_content=error.model_dump(mode="json"),
        meta=(meta or ResultMeta()).model_dump(mode="json"),
        is_error=True,
    )


def _annotation(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )


async def wintriage_check_artifact(
    params: CheckArtifactIn, context: dict[str, Any] | None = None
) -> ToolResult:
    runtime = get_runtime()
    tool_name = (context or {}).get("tool_name", "wintriage_check_artifact")
    raw_args = params.model_dump(mode="json", exclude_none=True)
    audit_id = runtime._audit._next_audit_id()
    start = time.monotonic()
    try:
        if params.type is ArtifactType.file:
            raw = await runtime._check_file(params.value, params.hash, params.os_version)
        elif params.type is ArtifactType.hash:
            raw = await runtime._check_hash(params.value)
        elif params.type is ArtifactType.filename:
            raw = await runtime._analyze_filename(params.value)
        elif params.type is ArtifactType.lolbin:
            raw = await runtime._check_lolbin(params.value)
        else:
            raw = await runtime._check_hijackable_dll(params.value)
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(runtime, tool_name, raw_args, raw, audit_id, elapsed_ms)
        if "error" in raw:
            return _legacy_error_result(raw, meta)
        out = _artifact_out(params.type, raw)
        return _model_result(out, meta)
    except TriageValidationError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(
            runtime,
            tool_name,
            raw_args,
            {"error": "validation_error"},
            audit_id,
            elapsed_ms,
        )
        return _error_result(
            ErrorCode.invalid_input,
            str(exc),
            "Correct the invalid artifact value and retry.",
            meta=meta,
        )
    except DatabaseError:
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(
            runtime,
            tool_name,
            raw_args,
            {"error": "database_error"},
            audit_id,
            elapsed_ms,
        )
        return _error_result(
            ErrorCode.upstream_degraded,
            "A baseline database error occurred.",
            "Check the local Windows triage database installation and retry.",
            retryable=True,
            meta=meta,
        )
    except WindowsTriageError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(
            runtime,
            tool_name,
            raw_args,
            {"error": "server_error"},
            audit_id,
            elapsed_ms,
        )
        return _error_result(
            ErrorCode.internal,
            str(exc),
            "Check backend logs for details, then retry.",
            meta=meta,
        )


def _artifact_out(artifact_type: ArtifactType, raw: dict[str, Any]) -> CheckArtifactOut:
    if artifact_type is ArtifactType.filename:
        findings = _findings(raw.get("findings", []))
        verdict = Verdict.SUSPICIOUS if findings or raw.get("is_suspicious") else Verdict.UNKNOWN
        confidence: Literal["high", "medium", "low"] = (
            "high"
            if any(item.severity == "critical" for item in findings)
            else "medium"
            if findings
            else "low"
        )
        reasons = (
            [item.description for item in findings[:3]]
            if findings
            else ["No suspicious filename characteristics found in local heuristics"]
        )
        subtype_data = {
            key: value
            for key, value in raw.items()
            if key not in {"findings", "is_suspicious"}
        }
        return CheckArtifactOut(
            artifact_type=artifact_type,
            verdict=verdict,
            reasons=reasons,
            confidence=confidence,
            findings=findings,
            subtype_data=subtype_data,
        )

    if artifact_type is ArtifactType.lolbin:
        functions = list(raw.get("functions", []) or [])
        is_lolbin = bool(raw.get("is_lolbin"))
        return CheckArtifactOut(
            artifact_type=artifact_type,
            verdict=Verdict.EXPECTED_LOLBIN if is_lolbin else Verdict.UNKNOWN,
            reasons=[
                "Filename is a known LOLBin with abuse potential"
                if is_lolbin
                else "Filename is not in the local LOLBin catalog"
            ],
            confidence="high" if is_lolbin else "low",
            is_lolbin=is_lolbin,
            lolbin_functions=functions,
            subtype_data={
                key: value
                for key, value in raw.items()
                if key not in {"is_lolbin", "functions"}
            },
        )

    if artifact_type is ArtifactType.dll:
        is_hijackable = bool(raw.get("is_hijackable"))
        verdict = Verdict(raw.get("verdict", "UNKNOWN"))
        return CheckArtifactOut(
            artifact_type=artifact_type,
            verdict=verdict,
            reasons=[
                "DLL appears in the local hijackability catalog"
                if is_hijackable
                else "DLL is not in the local hijackability catalog"
            ],
            confidence="medium" if is_hijackable else "low",
            subtype_data=raw,
        )

    subtype_data = {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "verdict",
            "reasons",
            "confidence",
            "findings",
            "path_in_baseline",
            "filename_in_baseline",
            "is_system_path",
            "is_lolbin",
            "lolbin_functions",
        }
    }
    return CheckArtifactOut(
        artifact_type=artifact_type,
        verdict=Verdict(raw.get("verdict", "UNKNOWN")),
        reasons=list(raw.get("reasons", [])),
        confidence=raw.get("confidence", "low"),
        findings=_findings(raw.get("findings", [])),
        path_in_baseline=raw.get("path_in_baseline"),
        filename_in_baseline=raw.get("filename_in_baseline"),
        is_system_path=raw.get("is_system_path"),
        is_lolbin=bool(raw.get("is_lolbin", False)),
        lolbin_functions=list(raw.get("lolbin_functions", []) or []),
        subtype_data=subtype_data,
    )


def _findings(items: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for item in items:
        extra = dict(item)
        finding_type = str(extra.pop("type", "finding"))
        severity = str(extra.pop("severity", "medium")).lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"
        description = str(extra.pop("description", finding_type))
        findings.append(
            Finding(
                type=finding_type,
                severity=severity,  # type: ignore[arg-type]
                description=description,
                extra=extra,
            )
        )
    return findings


def _audit_meta(
    runtime: Any,
    tool_name: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    audit_id: str | None,
    elapsed_ms: float,
) -> ResultMeta:
    summary = result if "error" not in result else {"error": result["error"]}
    recorded_audit_id = runtime._audit.log(
        tool=tool_name,
        params=arguments,
        result_summary=summary,
        audit_id=audit_id,
        elapsed_ms=elapsed_ms,
    )
    metadata = TOOL_METADATA.get(
        tool_name, TOOL_METADATA.get("wintriage_check_artifact", DEFAULT_METADATA)
    )
    return ResultMeta(
        audit_id=recorded_audit_id,
        examiner=_resolve_examiner(),
        caveats=list(metadata["caveats"]),
        interpretation_constraint=str(metadata["interpretation_constraint"]),
        audit_warning=None
        if recorded_audit_id is not None
        else "Audit write failed - action not recorded.",
    )


def _resolve_examiner() -> str | None:
    from .audit import resolve_examiner

    return resolve_examiner()


def _legacy_error_result(raw: dict[str, Any], meta: ResultMeta) -> ToolResult:
    details = {
        key: value
        for key, value in raw.items()
        if key not in {"error", "message", "next_step"}
    }
    return _error_result(
        ErrorCode.invalid_input,
        str(raw.get("message") or raw.get("error") or "Invalid input."),
        str(raw.get("next_step") or "Correct the request and retry."),
        details=details,
        meta=meta,
    )


def _model_result(out: BaseModel, meta: ResultMeta) -> ToolResult:
    return ToolResult(
        content=out.model_dump_json(),
        structured_content=out.model_dump(mode="json"),
        meta=meta.model_dump(mode="json"),
    )


async def wintriage_check_process_tree(
    params: CheckProcessTreeIn, context: dict[str, Any] | None = None
) -> ToolResult:
    runtime = get_runtime()
    tool_name = (context or {}).get("tool_name", "wintriage_check_process_tree")
    raw_args = params.model_dump(mode="json", exclude_none=True)
    audit_id = runtime._audit._next_audit_id()
    start = time.monotonic()
    try:
        raw = await runtime._check_process_tree(
            params.process_name,
            params.parent_name,
            params.path,
            params.user,
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(runtime, tool_name, raw_args, raw, audit_id, elapsed_ms)
        if "error" in raw:
            return _legacy_error_result(raw, meta)
        out = CheckProcessTreeOut(
            verdict=Verdict(raw.get("verdict", "UNKNOWN")),
            reasons=list(raw.get("reasons", [])),
            confidence=raw.get("confidence", "low"),
            findings=_findings(raw.get("findings", [])),
            in_expectations_db=bool(raw.get("in_expectations_db", False)),
            expected_parents=list(raw.get("expected_parents", []) or []),
            suspicious_parents=list(raw.get("suspicious_parents", []) or []),
            user_context=raw.get("user_context"),
        )
        return _model_result(out, meta)
    except TriageValidationError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(
            runtime,
            tool_name,
            raw_args,
            {"error": "validation_error"},
            audit_id,
            elapsed_ms,
        )
        return _error_result(
            ErrorCode.invalid_input,
            str(exc),
            "Correct the process, parent, path, or user argument and retry.",
            meta=meta,
        )
    except DatabaseError:
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(
            runtime,
            tool_name,
            raw_args,
            {"error": "database_error"},
            audit_id,
            elapsed_ms,
        )
        return _error_result(
            ErrorCode.upstream_degraded,
            "A baseline database error occurred.",
            "Check the local Windows triage database installation and retry.",
            retryable=True,
            meta=meta,
        )
    except WindowsTriageError as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        meta = _audit_meta(
            runtime,
            tool_name,
            raw_args,
            {"error": "server_error"},
            audit_id,
            elapsed_ms,
        )
        return _error_result(
            ErrorCode.internal,
            str(exc),
            "Check backend logs for details, then retry.",
            meta=meta,
        )


def _check_file_alias(params: BaseModel) -> CheckArtifactIn:
    alias = CheckFileAliasIn.model_validate(params)
    return CheckArtifactIn(
        type=ArtifactType.file,
        value=alias.path,
        hash=alias.hash,
        os_version=alias.os_version,
    )


def _check_hash_alias(params: BaseModel) -> CheckArtifactIn:
    alias = CheckHashAliasIn.model_validate(params)
    return CheckArtifactIn(type=ArtifactType.hash, value=alias.hash)


def _filename_alias(artifact_type: ArtifactType) -> Callable[[BaseModel], CheckArtifactIn]:
    def transform(params: BaseModel) -> CheckArtifactIn:
        alias = FilenameAliasIn.model_validate(params)
        return CheckArtifactIn(type=artifact_type, value=alias.filename)

    return transform


def _dll_alias(params: BaseModel) -> CheckArtifactIn:
    alias = DllAliasIn.model_validate(params)
    return CheckArtifactIn(type=ArtifactType.dll, value=alias.dll_name)


REGISTRY.append(
    ToolDef(
        name="wintriage_check_artifact",
        fn=wintriage_check_artifact,
        in_model=CheckArtifactIn,
        out_model=CheckArtifactOut,
        annotations=_annotation("Check Windows Artifact"),
        title="Check Windows Artifact",
        description=(
            "Validate one Windows artifact against local offline baselines. Use "
            "`type='file'` for a Windows path with optional hash, `type='hash'` "
            "for a LOLDrivers vulnerable-driver lookup, `type='filename'` for "
            "deception heuristics, `type='lolbin'` for LOLBin context, or "
            "`type='dll'` for DLL hijackability. UNKNOWN is neutral: it means "
            "not present in the local DB, not evidence of malice. For hash/IOC "
            "reputation use `cti_lookup_ioc`. Example: "
            "`wintriage_check_artifact(type='file', "
            "value='C:\\\\Windows\\\\System32\\\\svchost.exe', "
            "os_version='Win10_21H2_Pro')`."
        ),
    )
)

REGISTRY.append(
    ToolDef(
        name="wintriage_check_process_tree",
        fn=wintriage_check_process_tree,
        in_model=CheckProcessTreeIn,
        out_model=CheckProcessTreeOut,
        annotations=_annotation("Check Process Tree"),
        title="Check Process Tree",
        description=(
            "Validate a parent-to-child Windows process relationship against the "
            "local process-tree baseline. It checks never-spawns rules for "
            "injection targets, suspicious-parent blacklists such as Office or "
            "browsers spawning shells, and valid-parent allowlists such as "
            "`svchost.exe` descending from `services.exe`. Use on process-creation "
            "evidence. UNKNOWN is neutral when the process is not in the local "
            "expectations DB. Example: "
            "`wintriage_check_process_tree(process_name='cmd.exe', "
            "parent_name='winword.exe')`."
        ),
    )
)

ALIAS_REGISTRY["wintriage_check_artifact"] = [
    ToolAliasDef(
        name="check_file",
        in_model=CheckFileAliasIn,
        transform=_check_file_alias,
        title="Deprecated: Check File",
        description=(
            "Maps legacy `check_file(path, hash, os_version)` calls to "
            "`wintriage_check_artifact(type='file', value=path, ...)`."
        ),
    ),
    ToolAliasDef(
        name="check_hash",
        in_model=CheckHashAliasIn,
        transform=_check_hash_alias,
        title="Deprecated: Check Hash",
        description=(
            "Maps legacy `check_hash(hash)` calls to "
            "`wintriage_check_artifact(type='hash', value=hash)`."
        ),
    ),
    ToolAliasDef(
        name="analyze_filename",
        in_model=FilenameAliasIn,
        transform=_filename_alias(ArtifactType.filename),
        title="Deprecated: Analyze Filename",
        description=(
            "Maps legacy `analyze_filename(filename)` calls to "
            "`wintriage_check_artifact(type='filename', value=filename)`."
        ),
    ),
    ToolAliasDef(
        name="check_lolbin",
        in_model=FilenameAliasIn,
        transform=_filename_alias(ArtifactType.lolbin),
        title="Deprecated: Check LOLBin",
        description=(
            "Maps legacy `check_lolbin(filename)` calls to "
            "`wintriage_check_artifact(type='lolbin', value=filename)`."
        ),
    ),
    ToolAliasDef(
        name="check_hijackable_dll",
        in_model=DllAliasIn,
        transform=_dll_alias,
        title="Deprecated: Check Hijackable DLL",
        description=(
            "Maps legacy `check_hijackable_dll(dll_name)` calls to "
            "`wintriage_check_artifact(type='dll', value=dll_name)`."
        ),
    ),
]
