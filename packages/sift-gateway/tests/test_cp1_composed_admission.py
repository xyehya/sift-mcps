"""CP1 Foundation — composed force-add -> denial through the real seams.

The single composed public-surface acceptance test (SPEC §Custody Simplification
Proof Gate step 1; OPERATING-MODEL §9). It force-adds an unadmitted file and
proves the Custody Gate denies BEFORE process creation on BOTH real enforcement
paths, against a migrated PostgreSQL:

* **Sync dispatch** — the composed FastMCP policy-middleware stack
  (``gateway_policy_middlewares``): ``mcp.call_tool("run_command", ...)`` runs
  reconcile-before-dispatch through ``check_evidence_gate_db`` ->
  ``custody.admission.reconcile`` -> ``app.custody_reconcile``, computes
  ``BLOCKED_PENDING``, and denies before the tool body can create a process.
* **Durable path** — ``build_custody_validator(dsn)``, the validator
  ``run_command_job_handler`` invokes as ``ctx.validate_custody("preexec")``
  immediately before the command handler. It queries ``app.custody_gate_state``
  and raises ``FatalJobError`` before enqueue/exec. This is the durable admission
  SQL path.

Both deny for the SAME computed reason: nothing is sealed, so the gate is
fail-closed ``BLOCKED_PENDING`` (SPEC scenario 6/14). Gated on
``SIFT_CONTROL_PLANE_DSN`` and marked integration, exactly like
``test_cp1_custody_postgres.py``; CI's Postgres job and the CP3 VM gate run it,
locally it skips.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for the CP1 composed admission test")
    return dsn


class _CaseService:
    """Minimal active-case service (a real class, so the middleware uses it)."""

    def __init__(self, case):
        self.case = case

    def require_active_case_for_principal(self, _principal):
        return self.case


def _committed_case(dsn: str, artifact_path: str):
    """Insert and COMMIT a case so the separate reconcile connection sees it.

    Returns the ActiveCase. The row and any append-only admission_observations it
    later accrues are permanent by design (the observation history has an
    append-only no-delete trigger, so a cascade delete of the case is blocked);
    on the disposable integration DB that is the intended custody behavior.
    """
    import psycopg
    from sift_gateway.active_case import ActiveCase

    case_id = str(uuid.uuid4())
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "insert into app.cases(id,case_key,title,status) "
            "values(%s,%s,'CP1 composed test','active')",
            (case_id, "cp1c-" + uuid.uuid4().hex),
        )
    return ActiveCase(
        case_id=case_id,
        case_key="cp1c",
        title="CP1 composed test",
        description=None,
        status="active",
        artifact_path=artifact_path,
        metadata={},
        membership_role="agent",
    )


def _gateway(dsn: str, case):
    gateway = MagicMock()
    gateway.control_plane_dsn = dsn
    gateway.active_case_service = _CaseService(case)
    gateway.evidence_service = None
    gateway._tool_map = {}
    gateway._audit.log.return_value = "audit-1"
    return gateway


@pytest.mark.asyncio
async def test_force_add_denies_before_process_on_sync_and_durable(tmp_path) -> None:
    import psycopg
    from sift_core.execute.evidence_binding import inventory_token
    from sift_core.execute.job_worker import ClaimedJob, FatalJobError
    from sift_core.execute.run_command_job import build_custody_validator
    from sift_gateway.policy_middleware import gateway_policy_middlewares

    dsn = _dsn()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    planted = evidence / "force-added.bin"
    planted.write_bytes(b"unadmitted secret bytes")  # a force-added, unsealed file

    case = _committed_case(dsn, str(tmp_path))
    try:
        # --- Sync dispatch: the composed /mcp middleware stack denies -----------
        gateway = _gateway(dsn, case)
        mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
        ran = False

        @mcp.tool(name="run_command")
        async def run_command(command: str):
            # This body must never run — the gate denies before dispatch.
            nonlocal ran
            ran = True
            return command

        with patch(
            "sift_gateway.policy_middleware.current_mcp_identity", return_value=None
        ):
            result = await mcp.call_tool(
                "run_command", {"command": "sha256sum evidence/force-added.bin"}
            )

        # The real reconcile ran, persisted the pending entry, computed the gate,
        # and the tool body never executed (no process could have started).
        assert ran is False
        assert result.is_error is True
        assert b"unadmitted secret bytes" not in str(result.content).encode()

        # --- Durable path: the real admission SQL validator denies --------------
        token = inventory_token(str(tmp_path))
        job = ClaimedJob(
            job_id=str(uuid.uuid4()),
            job_type="run_command",
            case_id=case.case_id,
            evidence_id=None,
            spec_public={"command": "sha256sum evidence/force-added.bin"},
            spec_internal={
                "case_dir": str(tmp_path),
                "evidence_inventory_token": token,
                "storage_execution_authority": {"storage_profile": "LOCAL_IMMUTABLE"},
                "resolved_evidence_refs": [],
            },
            attempts=1,
            max_attempts=3,
            worker_id="cp1-composed",
        )
        validate = build_custody_validator(dsn)
        with pytest.raises(FatalJobError, match="custody_admission_denied"):
            validate(job, "preexec")

        # --- Both denials share the computed reason: BLOCKED_PENDING -----------
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("select app.custody_gate_state(%s)", (case.case_id,))
            gate_row = cur.fetchone()
            assert gate_row is not None and gate_row[0] == "BLOCKED_PENDING"
            # The sync path persisted the pending inventory observation (proof the
            # real reconcile RPC executed, not a mocked gate).
            cur.execute(
                "select count(*) from app.evidence_inventory "
                "where case_id=%s and disposition='pending' and entry_kind='regular'",
                (case.case_id,),
            )
            count_row = cur.fetchone()
            assert count_row is not None and count_row[0] == 1
    finally:
        # evidence_inventory is a live snapshot (deletable); admission_observations
        # and the case row are append-only custody history and stay (by design).
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "delete from app.evidence_inventory where case_id=%s", (case.case_id,)
            )
