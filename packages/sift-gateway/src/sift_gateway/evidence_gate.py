"""Evidence chain gate for the MCP endpoint.

check_evidence_gate(case_dir_str) → {blocked, status, issues, manifest_version}
invalidate_evidence_cache(case_dir_str) → None

Performance model (per spec):
  - 30s TTL cache (stat-check only, no rehash, no key needed)
  - Manifest mtime change detected via os.stat() → immediate cache invalidation
  - mtime is used as a cache invalidation hint only, never as an integrity assertion

Gate behaviour:
  - UNSEALED or any violation → blocked=True, structured response for Hermes
  - OK → blocked=False, proceed to backend
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

# Statuses that represent an integrity violation — block ALL tools including read-only.
# UNSEALED is NOT a violation: it means no evidence registered yet (valid at case start).
VIOLATION_STATUSES = frozenset({
    ChainStatus.MODIFIED,
    ChainStatus.MISSING,
    ChainStatus.UNREGISTERED,
    ChainStatus.LEDGER_ERROR,
})


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
        "status": status,  # ChainStatus str-enum — callers compare with ChainStatus.X
        "issues": cached["issues"],
        "manifest_version": cached["manifest_version"],
    }


def is_violation(status) -> bool:
    """Return True if status is an integrity violation (blocks read-only tools too).

    UNSEALED is not a violation — it means no evidence registered yet.
    MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR are violations.
    """
    return status in VIOLATION_STATUSES


def build_unsealed_warning(tool_name: str, gate: dict) -> dict:
    """Build the _agentir_context warning injected when a read-only tool is allowed
    through on UNSEALED status."""
    return {
        "evidence_gate_warning": True,
        "status": str(gate["status"]),
        "manifest_version": gate["manifest_version"],
        "message": (
            f"Evidence manifest not yet sealed. Tool '{tool_name}' is read-only and "
            "was allowed through. Register and seal evidence in the Examiner Portal "
            "before conducting analysis."
        ),
        "remediation": PORTAL_REMEDIATION,
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
