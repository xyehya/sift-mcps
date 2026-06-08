"""Durable-job handler for sandboxed run_command."""

from __future__ import annotations

import json
from typing import Any

from sift_common.audit import AuditWriter

from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.agent_tools import _run_command
from sift_core.execute.job_worker import ClaimedJob, FatalJobError, JobContext, JobResult


def run_command_job_handler(job: ClaimedJob, ctx: JobContext) -> JobResult:
    """Run an I1 run_command request from a D1 durable job.

    The worker receives command arguments in spec_public and the local case
    artifact path only in spec_internal. The result_public returned to Postgres
    is already path-sanitized by _run_command and then trimmed to a JSON-safe
    dict before completion.
    """
    if not job.case_id:
        raise FatalJobError("run_command job missing case_id")
    case_dir = str(job.spec_internal.get("case_dir") or job.spec_internal.get("artifact_path") or "")
    case_key = str(job.spec_internal.get("case_key") or "")
    if not case_dir:
        raise FatalJobError("run_command job missing worker case path")
    args = dict(job.spec_public or {})
    examiner = str(job.spec_internal.get("examiner") or "agent")
    audit = AuditWriter(mcp_name="sift-core-run-command-job")
    ctx.record_step(0, "run_command", status="running")
    context = ActiveCaseContext(
        case_id=str(job.case_id),
        case_key=case_key or str(job.case_id),
        artifact_path=case_dir,
        membership_role=None,
    )
    with use_active_case_context(context):
        result = _run_command(args, examiner, audit)
    ctx.record_step(
        0,
        "run_command",
        status="succeeded" if not result.get("error") else "failed",
        detail={"exit_code": result.get("exit_code")},
    )
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    provenance_id = (
        str(provenance.get("job_id"))
        if provenance.get("job_id")
        else str(result.get("job_id") or "")
    ) or None
    return JobResult(result_public=_jsonable(result), provenance_id=provenance_id)


def _jsonable(value: Any) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, default=str)
        decoded = json.loads(encoded)
    except (TypeError, ValueError):
        return {"error": "run_command_result_not_jsonable"}
    return decoded if isinstance(decoded, dict) else {"result": decoded}
