"""Evidence chain gate for the MCP endpoint.

check_evidence_gate(case_dir_str) → {blocked, status, issues, manifest_version}
check_evidence_gate_db(case_id, dsn) → {blocked, status, issues, manifest_version}
invalidate_evidence_cache(case_dir_str) → None

Performance model (per spec):
  - 30s TTL cache (stat-check only, no rehash, no key needed)
  - Manifest mtime change detected via os.stat() → immediate cache invalidation
  - mtime is used as a cache invalidation hint only, never as an integrity assertion

Gate behaviour:
  - UNSEALED or any violation → blocked=True, structured response for Hermes
  - OK → blocked=False, proceed to backend

DB-authority resolution path (BATCH-C1):
  - check_evidence_gate_db() resolves seal status from Postgres
    (app.evidence_gate_status) by case_id, NOT from files. Postgres is the
    authority; file manifests/proofs are exports. This is the path the Gateway
    should prefer once cases carry DB evidence state. The file-backed
    check_evidence_gate() above remains for the legacy/bridge file flow.
  - Fail-closed: any DB/resolution error → blocked=True (UNSEALED).
  - The agent never receives a local path; case_id is opaque and resolves to a
    mount path only inside broker/worker code.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from sift_core.evidence_chain import ChainStatus, chain_status, manifest_path as _manifest_path

logger = logging.getLogger(__name__)

_CACHE: dict[str, dict] = {}
_TTL = 30.0  # seconds

PORTAL_REMEDIATION = (
    "Open the Examiner Portal and use the Evidence tab to review and seal "
    "the evidence chain before proceeding with agent analysis."
)


def check_evidence_gate(case_dir_str: str | None) -> dict:
    """Return gate result for the given case directory.

    Returns {blocked, status, issues, manifest_version}.
    Never raises — on unexpected error returns a blocked result.
    """
    if not case_dir_str:
        return {
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No active case — create a case in the portal first"],
            "manifest_version": 0,
        }

    case_dir = Path(case_dir_str)
    manifest_path = _manifest_path(case_dir)
    now = time.monotonic()
    cached = _CACHE.get(case_dir_str)

    if cached and now < cached["expire_at"]:
        # Fast path: check whether manifest file has changed since we cached
        try:
            current_mtime = manifest_path.stat().st_mtime_ns
            if current_mtime == cached["manifest_mtime"]:
                return _result(cached)
        except OSError:
            pass
        # mtime changed or stat failed — fall through to fresh check

    return _refresh(case_dir_str, case_dir, manifest_path, now)


def invalidate_evidence_cache(case_dir_str: str) -> None:
    """Immediately drop the cached status for this case directory.

    Called by the portal after sealing a new manifest version.
    """
    _CACHE.pop(case_dir_str, None)


def _refresh(case_dir_str: str, case_dir: Path, manifest_path: Path, now: float) -> dict:
    try:
        manifest_mtime = manifest_path.stat().st_mtime_ns if manifest_path.exists() else 0
    except OSError:
        manifest_mtime = 0

    try:
        status_dict = chain_status(case_dir)
    except Exception as exc:
        logger.error("evidence_gate: chain_status error for %s: %s", case_dir_str, exc)
        status_dict = {
            "status": ChainStatus.LEDGER_ERROR,
            "issues": [f"Internal error checking evidence chain: {exc}"],
            "manifest_version": 0,
            "ok_count": 0,
        }

    _CACHE[case_dir_str] = {
        "expire_at": now + _TTL,
        "manifest_mtime": manifest_mtime,
        "status": status_dict["status"],
        "issues": status_dict.get("issues", []),
        "manifest_version": status_dict.get("manifest_version", 0),
        "ok_count": status_dict.get("ok_count", 0),
    }
    return _result(_CACHE[case_dir_str])


def _result(cached: dict) -> dict:
    status = cached["status"]
    return {
        "blocked": status != ChainStatus.OK,
        "status": status,
        "issues": cached["issues"],
        "manifest_version": cached["manifest_version"],
    }


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
