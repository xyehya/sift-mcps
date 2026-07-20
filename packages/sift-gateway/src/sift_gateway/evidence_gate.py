"""Evidence chain gate for the MCP endpoint.

check_evidence_gate_db(case_id, dsn) → {blocked, gate_state, status, issues,
manifest_version}

This is the thin, stable read shim in front of the P4.23 target custody gate.
The authoritative decision is the computed four-state ``app.custody_gate_state``
projection, resolved through :func:`sift_gateway.custody.admission.gate_state`.
This module keeps the legacy ``{blocked, status, issues, manifest_version}``
envelope so the middleware and orientation response shaping are unchanged during
the rewire (the four-state value is also carried as ``gate_state``).

  - OPEN → blocked=False, proceed to backend.
  - BLOCKED_PENDING / BLOCKED_VIOLATION / BLOCKED_UNAVAILABLE → blocked=True.
  - Fail-closed: a missing case/DSN or any DB error → blocked=True.

Postgres is the sole authority; the agent never receives a local path — case_id
is opaque and resolves to a local path only inside Gateway/worker code.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from sift_core.custody_types import ChainStatus

from sift_gateway.custody import admission

logger = logging.getLogger(__name__)

PORTAL_REMEDIATION = (
    "Open the Examiner Portal and use the Evidence tab to review and seal "
    "the evidence chain before proceeding with agent analysis."
)


def check_evidence_gate_db(
    case_id: str | None, dsn: str | None, case_dir: str | None = None
) -> dict:
    """Resolve the computed custody gate for a case_id (fail-closed).

    This is the single gate seam for the policy chain. When ``case_dir`` is given
    (dispatch), it performs reconcile-before-dispatch through
    :func:`sift_gateway.custody.admission.reconcile` — a read-only scan that
    persists the inventory snapshot + observation and returns the computed
    four-state gate. With no ``case_dir`` (orientation reads: case_info/
    evidence_info) it is a pure computed-gate read. Both return the standard
    ``{blocked, gate_state, status, issues, manifest_version}`` envelope.
    """
    if case_dir is not None:
        return dict(admission.reconcile(case_id, case_dir, dsn))
    return dict(admission.gate_state(case_id, dsn))


def build_block_response(tool_name: str, gate: Mapping[str, Any]) -> dict:
    """Build the structured block response returned to the agent."""
    gate_state = gate.get("gate_state")
    status = gate["status"]
    if gate_state == "BLOCKED_PENDING" or status == ChainStatus.UNSEALED:
        reason = "evidence_chain_unsealed"
        detail = (
            "Unadmitted or unsealed local evidence. This tool requires evidence "
            "to be sealed through the Portal before it can be used."
        )
    elif gate_state == "BLOCKED_UNAVAILABLE":
        reason = "evidence_storage_unavailable"
        detail = "The canonical evidence directory is unavailable."
    else:
        reason = "evidence_chain_violation"
        detail = "Evidence integrity check failed."
    return {
        "blocked": True,
        "reason": reason,
        "tool": tool_name,
        "status": status,
        "gate_state": gate_state,
        "issues": gate["issues"],
        "manifest_version": gate["manifest_version"],
        "detail": detail,
        "remediation": PORTAL_REMEDIATION,
    }
