"""Durable-job handler for sandboxed run_command."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sift_common.audit import AuditWriter

from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.agent_tools import _run_command
from sift_core.evidence_storage import StorageProfile
from sift_core.execute.evidence_binding import (
    classify_inventory_entries,
    use_final_open_authority_validator,
)
from sift_core.execute.evidence_binding import (
    inventory_token as _inventory_token,
)
from sift_core.execute.job_worker import (
    ClaimedJob,
    FatalJobError,
    JobContext,
    JobResult,
)


def build_custody_validator(dsn: str):
    """Build the fail-closed DB validator used at durable claim and execution."""

    def validate(job: ClaimedJob, phase: str) -> None:
        del phase
        if not job.case_id:
            raise FatalJobError("custody_admission_denied")
        deny_after_commit = False
        try:
            import psycopg

            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cur:
                    expected_inventory = str(
                        job.spec_internal.get("evidence_inventory_token") or ""
                    )
                    case_dir = str(job.spec_internal.get("case_dir") or "")
                    _validate_storage_authority(job)
                    current_inventory = ""
                    try:
                        current_inventory = _inventory_token(case_dir)
                    except OSError:
                        # P4.23.1 has no persisted UNAVAILABLE enum yet. Do not
                        # misclassify an infrastructure outage as tampering.
                        deny_after_commit = True
                    if (
                        not expected_inventory
                        or current_inventory != expected_inventory
                    ):
                        if not deny_after_commit:
                            _record_inventory_change(cur, job, case_dir)
                        deny_after_commit = True
                    if not deny_after_commit:
                        cur.execute(
                            "select app.custody_gate_state(%s)",
                            (job.case_id,),
                        )
                        gate = cur.fetchone()
                        if not gate or gate[0] != "OPEN":
                            raise FatalJobError("custody_admission_denied")
                        for item in (
                            job.spec_internal.get("resolved_evidence_refs") or []
                        ):
                            if not isinstance(item, dict):
                                raise FatalJobError("custody_admission_denied")
                            cur.execute(
                                """
                                select 1
                                from app.evidence_objects o
                                join app.evidence_versions v on v.id = o.current_version_id
                                where o.case_id = %s and o.id = %s and v.id = %s
                                  and o.status = 'sealed' and o.seal_status = 'sealed'
                                  and v.entry_status = 'ACTIVE' and v.sha256 = %s
                                """,
                                (
                                    job.case_id,
                                    item.get("evidence_id"),
                                    item.get("version_id"),
                                    item.get("sha256"),
                                ),
                            )
                            if not cur.fetchone():
                                raise FatalJobError("custody_admission_denied")
        except FatalJobError:
            raise
        except Exception as exc:
            raise FatalJobError("custody_admission_denied") from exc
        if deny_after_commit:
            # Raise only after psycopg's context has exited normally and
            # committed any DETECTED/VIOLATION custody observations.
            raise FatalJobError("custody_admission_denied")

    @contextmanager
    def hold_execution_authority(job: ClaimedJob, phase: str) -> Iterator[None]:
        del phase
        if not job.case_id:
            raise FatalJobError("custody_admission_denied")
        try:
            import psycopg

            conn_context = psycopg.connect(dsn)
        except Exception as exc:
            raise FatalJobError("custody_admission_denied") from exc
        with conn_context as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "select pg_advisory_xact_lock_shared("
                        "hashtextextended(%s::text, 0))",
                        (job.case_id,),
                    )
                    _validate_custody_read_only(cur, job)
            except FatalJobError:
                raise
            except Exception as exc:
                raise FatalJobError("custody_admission_denied") from exc
            yield

    validate.hold_execution_authority = hold_execution_authority  # type: ignore[attr-defined]
    return validate


def _validate_custody_read_only(cur: Any, job: ClaimedJob) -> None:
    """Validate dispatch authority under the held lock without writing drift."""
    case_dir = str(job.spec_internal.get("case_dir") or "")
    _validate_storage_authority(job)
    expected_inventory = str(job.spec_internal.get("evidence_inventory_token") or "")
    try:
        current_inventory = _inventory_token(case_dir)
    except OSError as exc:
        raise FatalJobError("custody_admission_denied") from exc
    if not expected_inventory or current_inventory != expected_inventory:
        raise FatalJobError("custody_admission_denied")
    cur.execute(
        "select app.custody_gate_state(%s)",
        (job.case_id,),
    )
    gate = cur.fetchone()
    if not gate or gate[0] != "OPEN":
        raise FatalJobError("custody_admission_denied")
    for item in job.spec_internal.get("resolved_evidence_refs") or []:
        if not isinstance(item, dict):
            raise FatalJobError("custody_admission_denied")
        cur.execute(
            """select 1
               from app.evidence_objects o
               join app.evidence_versions v on v.id=o.current_version_id
               where o.case_id=%s and o.id=%s and v.id=%s
                 and o.status='sealed' and o.seal_status='sealed'
                 and v.entry_status='ACTIVE' and v.sha256=%s""",
            (
                job.case_id,
                item.get("evidence_id"),
                item.get("version_id"),
                item.get("sha256"),
            ),
        )
        if not cur.fetchone():
            raise FatalJobError("custody_admission_denied")


def _validate_storage_authority(job: ClaimedJob) -> None:
    """Deny any durable job whose storage authority is not local-immutable.

    LOCAL_IMMUTABLE is the only supported storage profile (P4.23). Its guarantees
    come from the sealed-version re-check + computed gate + the per-descriptor
    identity/immutable pin, so no external-storage authority table is queried.
    Any other profile is denied fail-closed.
    """
    expected = job.spec_internal.get("storage_execution_authority")
    if not isinstance(expected, dict) or not expected:
        raise FatalJobError("custody_admission_denied")
    if str(expected.get("storage_profile")) != StorageProfile.LOCAL_IMMUTABLE:
        raise FatalJobError("custody_admission_denied")


def _record_inventory_change(cur: Any, job: ClaimedJob, case_dir: str) -> None:
    """Persist one read-only reconciliation before denying a stale durable job.

    Routes through the same ``app.custody_reconcile`` RPC and the same canonical
    scanner the Gateway sync path uses, so the durable worker's observation and
    the computed gate stay consistent with reconcile-before-dispatch. Never reads
    file bytes; never mutates evidence.
    """
    from psycopg.types.json import Jsonb

    entries = classify_inventory_entries(case_dir)
    cur.execute(
        "select app.custody_reconcile(%s, %s, %s, %s, %s, null, null)",
        (
            job.case_id,
            Jsonb(entries or []),
            entries is not None,
            "dispatch",
            str(job.job_id),
        ),
    )


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
    case_dir = str(
        job.spec_internal.get("case_dir")
        or job.spec_internal.get("artifact_path")
        or ""
    )
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
    # Claim/execution validation protects the durable queue boundary; repeat
    # once more immediately before the command handler can create a process.
    ctx.validate_custody("preexec")
    with ctx.hold_custody("dispatch_lock"):
        with (
            use_active_case_context(context),
            # The holder validated authority after acquiring the shared case
            # lock and retains it through _run_command. Exclusive custody
            # transitions therefore cannot commit before descriptor pinning.
            use_final_open_authority_validator(lambda _expected: None),
        ):
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


def _build_receipt(
    job: ClaimedJob, args: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    """Assemble a path-free, hash-linked command receipt for Postgres.

    Every value here is either an opaque id, a hash, a case-relative ref, or a
    small integer/string — never an absolute path or secret. The agent-facing
    ``result`` was already path-sanitized upstream, so any ref we copy from it
    is safe to persist.
    """
    raw_provenance = result.get("provenance")
    provenance: dict[str, Any] = (
        raw_provenance if isinstance(raw_provenance, dict) else {}
    )
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
