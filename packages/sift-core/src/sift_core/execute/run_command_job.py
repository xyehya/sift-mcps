"""Durable-job handler for sandboxed run_command."""

from __future__ import annotations

import hashlib
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

    K5: a path-free command receipt is persisted to Postgres so the execution is
    reportable without local paths. The receipt is written both as a job-step
    detail (durable, queryable per run) and embedded in result_public. It binds
    the command plan hash, evidence refs, stdout/stderr preview hashes, output
    ref + output hash, audit id, and job id together.
    """
    if not job.case_id:
        raise FatalJobError("run_command job missing case_id")
    case_dir = str(job.spec_internal.get("case_dir") or job.spec_internal.get("artifact_path") or "")
    case_key = str(job.spec_internal.get("case_key") or "")
    if not case_dir:
        raise FatalJobError("run_command job missing worker case path")
    args = dict(job.spec_public or {})
    resolved_refs = job.spec_internal.get("resolved_evidence_refs")
    if resolved_refs:
        args["_resolved_evidence_refs"] = resolved_refs
    examiner = str(job.spec_internal.get("examiner") or "agent")
    audit = AuditWriter(mcp_name="sift-core-run-command-job")
    ctx.record_step(0, "run_command", status="running")
    context = ActiveCaseContext(
        case_id=str(job.case_id),
        case_key=case_key or str(job.case_id),
        artifact_path=case_dir,
        membership_role=None,
        db_active=True,
    )
    with use_active_case_context(context):
        result = _run_command(args, examiner, audit)

    receipt = _build_receipt(job, args, result)
    ctx.record_step(
        0,
        "run_command",
        status="succeeded" if not result.get("error") else "failed",
        detail={"exit_code": result.get("exit_code"), "receipt": receipt},
    )

    # Surface the receipt in the durable result so a report/provenance consumer
    # can cite it without any local path. result_public is already path-free
    # (sanitized by _run_command); the receipt only adds hashes and opaque refs.
    result_public = _jsonable(result)
    result_public["receipt"] = receipt
    return JobResult(result_public=result_public, provenance_id=None)


def _build_receipt(job: ClaimedJob, args: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Assemble a path-free, hash-linked command receipt for Postgres.

    Every value here is either an opaque id, a hash, a case-relative ref, or a
    small integer/string — never an absolute path or secret. The agent-facing
    ``result`` was already path-sanitized upstream, so any ref we copy from it
    is safe to persist.
    """
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    command = str(args.get("command") or "")
    plan_hash = hashlib.sha256(command.encode("utf-8")).hexdigest() if command else ""

    stdout_preview = result.get("stdout")
    stderr_preview = result.get("stderr")
    receipt: dict[str, Any] = {
        "job_id": str(job.job_id),
        "receipt_id": str(provenance.get("job_id") or result.get("job_id") or ""),
        "audit_id": str(provenance.get("audit_id") or result.get("audit_id") or ""),
        "command_plan_sha256": plan_hash,
        "purpose": str(args.get("purpose") or ""),
        "success": bool(result.get("success")),
        "evidence_refs": list(provenance.get("evidence_refs") or []),
        "input_sha256s": list(provenance.get("input_sha256s") or []),
        "input_count": int(provenance.get("input_count") or 0),
        "stdout_preview_sha256": _preview_hash(stdout_preview),
        "stderr_preview_sha256": _preview_hash(stderr_preview),
    }
    if result.get("exit_code") is not None:
        receipt["exit_code"] = result.get("exit_code")
    # Output artifact refs/hashes (case-relative refs only; never absolute).
    output_ref = provenance.get("output_ref") or result.get("full_output_ref")
    if output_ref:
        receipt["output_ref"] = str(output_ref)
    output_sha256 = provenance.get("output_sha256") or result.get("full_output_sha256")
    if output_sha256:
        receipt["output_sha256"] = str(output_sha256)
    if result.get("full_output_bytes") is not None:
        receipt["output_bytes"] = result.get("full_output_bytes")
    return receipt


def _preview_hash(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _jsonable(value: Any) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, default=str)
        decoded = json.loads(encoded)
    except (TypeError, ValueError):
        return {"error": "run_command_result_not_jsonable"}
    return decoded if isinstance(decoded, dict) else {"result": decoded}
