"""Durable-job handler for sandboxed run_command."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from sift_common.audit import AuditWriter

from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.agent_tools import _run_command
from sift_core.evidence_storage import (
    StorageAuthorityError,
    StorageProfile,
    external_storage_facts,
)
from sift_core.execute.evidence_binding import inventory_token as _inventory_token
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
                    _validate_storage_authority(cur, job, case_dir)
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
                            "select seal_status from app.evidence_gate_status(%s)",
                            (job.case_id,),
                        )
                        gate = cur.fetchone()
                        if not gate or gate[0] != "sealed":
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

    return validate


def _validate_storage_authority(cur: Any, job: ClaimedJob, case_dir: str) -> None:
    """Validate current DB authority and external mount facts for every job."""
    expected = job.spec_internal.get("storage_execution_authority")
    if not isinstance(expected, dict) or not expected:
        raise FatalJobError("custody_admission_denied")
    cur.execute(
        """select a.profile,a.source_identity,a.verified_mount_instance,a.state,
                  a.generation,a.verified_generation,a.read_only,h.manifest_version,
                  h.manifest_hash,
                  (select v.id::text from app.evidence_storage_verifications v
                   where v.case_id=a.case_id and v.outcome='SUCCESS'
                     and v.generation=a.generation and v.profile=a.profile
                     and v.manifest_version=h.manifest_version
                     and v.manifest_hash=h.manifest_hash
                   order by v.created_at desc,v.id desc limit 1)
           from app.evidence_storage_authorities a
           join app.evidence_chain_heads h on h.case_id=a.case_id
           where a.case_id=%s""",
        (job.case_id,),
    )
    row = cur.fetchone()
    if not row:
        raise FatalJobError("custody_admission_denied")
    current = {
        "storage_profile": str(row[0]),
        "storage_source_identity": str(row[1] or ""),
        "mount_instance_identity": str(row[2] or ""),
        "storage_generation": int(row[4]),
        "storage_verified_generation": int(row[5]) if row[5] is not None else -1,
        "storage_manifest_version": int(row[7] or 0),
        "storage_manifest_hash": str(row[8] or ""),
        "storage_verification_receipt_id": str(row[9] or ""),
    }
    if str(row[3]) != "AVAILABLE" or row[5] != row[4] or current != expected:
        raise FatalJobError("custody_admission_denied")
    for item in job.spec_internal.get("resolved_evidence_refs") or []:
        if not isinstance(item, dict) or any(
            item.get(key) != value for key, value in current.items()
        ):
            raise FatalJobError("custody_admission_denied")
    if current["storage_profile"] == StorageProfile.EXTERNALLY_READ_ONLY:
        root_fd: int | None = None
        try:
            root_fd = os.open(
                Path(case_dir) / "evidence",
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0),
            )
            facts = external_storage_facts(root_fd)
        except (OSError, StorageAuthorityError) as exc:
            raise FatalJobError("custody_admission_denied") from exc
        finally:
            if root_fd is not None:
                os.close(root_fd)
        if (
            row[6] is not True
            or facts.read_only is not True
            or facts.source_identity != current["storage_source_identity"]
            or facts.mount_instance_identity != current["mount_instance_identity"]
        ):
            raise FatalJobError("custody_admission_denied")
    elif current["storage_profile"] != StorageProfile.LOCAL_IMMUTABLE:
        raise FatalJobError("custody_admission_denied")


def _record_inventory_change(cur: Any, job: ClaimedJob, case_dir: str) -> None:
    """Persist read-only worker observations before denying a stale durable job."""
    evidence_dir = Path(case_dir).resolve() / "evidence"
    cur.execute(
        """select id::text, display_path, status, seal_status, current_bytes, sealed_at
           from app.evidence_objects where case_id = %s""",
        (job.case_id,),
    )
    known = {str(row[1]): row for row in cur.fetchall()}
    live: set[str] = set()
    with os.scandir(evidence_dir) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            rel = f"evidence/{entry.name}"
            live.add(rel)
            try:
                st = entry.stat(follow_symlinks=False)
                safe = stat.S_ISREG(st.st_mode) and st.st_nlink == 1
            except OSError:
                st = None
                safe = False
            if rel not in known:
                cur.execute(
                    "select app.evidence_observe_admission(%s, %s, %s, %s, %s, null, null)",
                    (
                        job.case_id,
                        rel,
                        entry.name,
                        st.st_size if st else None,
                        str(job.job_id),
                    ),
                )
                detected = cur.fetchone()
                if not safe:
                    cur.execute(
                        "select app.evidence_mark_admission_violation"
                        "(%s, %s, %s, %s::jsonb, %s, null, null)",
                        (
                            job.case_id,
                            detected[0] if detected else None,
                            "unsafe_evidence_inventory_entry",
                            json.dumps(["unsafe_evidence_inventory_entry"]),
                            str(job.job_id),
                        ),
                    )
            else:
                row = known[rel]
                if row[2] == "sealed" and row[3] == "sealed":
                    sealed_at = row[5]
                    sealed_ns = (
                        int(sealed_at.timestamp() * 1_000_000_000)
                        if hasattr(sealed_at, "timestamp")
                        else 0
                    )
                    changed = (
                        not safe
                        or st is None
                        or (row[4] is not None and st.st_size != int(row[4]))
                        or (sealed_ns and st.st_ctime_ns > sealed_ns)
                    )
                    if changed:
                        cur.execute(
                            "select app.evidence_mark_admission_violation"
                            "(%s, %s, %s, %s::jsonb, %s, null, null)",
                            (
                                job.case_id,
                                row[0],
                                "sealed_evidence_changed",
                                json.dumps(["sealed_evidence_changed"]),
                                str(job.job_id),
                            ),
                        )
    for rel, row in known.items():
        if row[2] == "sealed" and row[3] == "sealed" and rel not in live:
            cur.execute(
                "select app.evidence_mark_admission_violation"
                "(%s, %s, %s, %s::jsonb, %s, null, null)",
                (
                    job.case_id,
                    row[0],
                    "sealed_evidence_missing",
                    json.dumps(["sealed_evidence_missing"]),
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
