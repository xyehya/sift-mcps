"""Evidence chain gate for the MCP endpoint.

check_evidence_gate_db(case_id, dsn) → {blocked, status, issues, manifest_version}
invalidate_evidence_cache(case_dir_str) → None (retained no-op, see below)

Gate behaviour:
  - UNSEALED or any violation → blocked=True, structured response for Hermes
  - OK → blocked=False, proceed to backend

DB-authority resolution path (BATCH-C1; sole path as of BU3/XYE-21):
  - check_evidence_gate_db() resolves seal status from Postgres
    (app.evidence_gate_status) by case_id, NOT from files. Postgres is the
    authority; file manifests/proofs are exports.
  - BU3 removed the file-backed ``check_evidence_gate()`` entirely: the gateway
    is the only policy boundary and has no file-mode fallback (no control-plane
    DSN ⇒ the gateway refuses to serve DFIR tools), so the only evidence-gate
    path that can govern a DFIR tool call is this DB-authority one.
  - Fail-closed: any DB/resolution error → blocked=True (UNSEALED).
  - The agent never receives a local path; case_id is opaque and resolves to a
    mount path only inside broker/worker code.
"""

from __future__ import annotations

import logging

from sift_core.evidence_chain import ChainStatus

logger = logging.getLogger(__name__)

PORTAL_REMEDIATION = (
    "Open the Examiner Portal and use the Evidence tab to review and seal "
    "the evidence chain before proceeding with agent analysis."
)


def invalidate_evidence_cache(case_dir_str: str) -> None:
    """Retained no-op (BU3/XYE-21).

    The file-backed gate kept a 30s TTL cache that the portal invalidated after
    sealing. The DB-authority gate (:func:`check_evidence_gate_db`) reads
    Postgres on every call and holds no cache, so there is nothing to drop. The
    function is kept so the gateway's evidence-watcher wiring and the portal's
    seal callback (case-dashboard) keep their stable call signature without an
    out-of-scope edit.
    """
    del case_dir_str


# ---------------------------------------------------------------------------
# DB-authority resolution path (BATCH-C1)
# ---------------------------------------------------------------------------
# Maps the Postgres aggregate seal_status onto the same gate result shape used
# by the file-backed path so callers/response shaping are unchanged.
_DB_STATUS_MAP = {
    "sealed": ChainStatus.OK,
    "unsealed": ChainStatus.UNSEALED,
    "violated": ChainStatus.LEDGER_ERROR,
}


def check_evidence_gate_db(case_id: str | None, dsn: str | None) -> dict:
    """Resolve the evidence gate from Postgres authority for a case_id.

    Reads app.evidence_gate_status(case_id) via the service DSN. Returns the
    standard {blocked, status, issues, manifest_version} shape. Fail-closed:
    a missing case_id, missing DSN, or any DB error returns a blocked result.

    Postgres is the authority here; file manifests/proofs are exports only. The
    agent never receives a local path — case_id is opaque and resolves to a
    mount path only inside broker/worker code.
    """
    if not case_id or not dsn:
        return {
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No active case — create a case in the portal first"],
            "manifest_version": 0,
        }

    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        logger.error("evidence_gate_db: psycopg unavailable: %s", exc)
        return {
            "blocked": True,
            "status": ChainStatus.LEDGER_ERROR,
            "issues": ["Evidence authority unavailable"],
            "manifest_version": 0,
        }

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select seal_status, manifest_version, issues "
                    "from app.evidence_gate_status(%s)",
                    (case_id,),
                )
                row = cur.fetchone()
    except Exception as exc:
        logger.error("evidence_gate_db: status query failed for %s: %s", case_id, exc)
        return {
            "blocked": True,
            "status": ChainStatus.LEDGER_ERROR,
            "issues": [f"Internal error resolving evidence authority: {exc}"],
            "manifest_version": 0,
        }

    if not row:
        # Fail-closed: no head row means nothing sealed for this case yet.
        return {
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No sealed evidence for this case"],
            "manifest_version": 0,
        }

    seal_status, manifest_version, issues = row
    status = _DB_STATUS_MAP.get(seal_status, ChainStatus.UNSEALED)
    issue_list = issues if isinstance(issues, list) else []
    if status != ChainStatus.OK and not issue_list:
        issue_list = (
            ["No sealed evidence manifest"]
            if status == ChainStatus.UNSEALED
            else ["Evidence integrity violation recorded"]
        )
    return {
        "blocked": status != ChainStatus.OK,
        "status": status,
        "issues": issue_list,
        "manifest_version": manifest_version or 0,
    }


def build_block_response(tool_name: str, gate: dict) -> dict:
    """Build the structured block response returned to Hermes."""
    status = gate["status"]
    if status == ChainStatus.UNSEALED:
        reason = "evidence_chain_unsealed"
        detail = (
            "No sealed evidence manifest. This tool requires evidence to be registered "
            "and sealed before it can be used."
        )
    else:
        reason = "evidence_chain_violation"
        detail = "Evidence integrity check failed."
    return {
        "blocked": True,
        "reason": reason,
        "tool": tool_name,
        "status": status,
        "issues": gate["issues"],
        "manifest_version": gate["manifest_version"],
        "detail": detail,
        "remediation": PORTAL_REMEDIATION,
    }
