"""Tests for the custody gate seam ``check_evidence_gate_db`` (P4.23 target).

``check_evidence_gate_db`` is the single gate seam for the policy chain. It
delegates to the target admission module's computed four-state gate
(``app.custody_gate_state``), reconciling first (``app.custody_reconcile``) when a
``case_dir`` is supplied (dispatch). These tests patch the admission module so
they exercise the delegation + envelope shaping without a live database.
"""

from __future__ import annotations

from unittest.mock import patch

from sift_core.custody_types import ChainStatus
from sift_gateway.custody import admission
from sift_gateway.evidence_gate import build_block_response, check_evidence_gate_db

_DSN = "postgresql://service@localhost/sift"
_CASE = "11111111-1111-1111-1111-111111111111"


def test_no_case_or_dsn_is_fail_closed() -> None:
    assert check_evidence_gate_db(None, _DSN)["blocked"] is True
    assert check_evidence_gate_db(_CASE, None)["blocked"] is True


def test_gate_read_delegates_to_computed_gate_when_no_case_dir() -> None:
    with patch.object(
        admission, "gate_state", return_value=admission._gate_result("OPEN")
    ) as mocked:
        gate = check_evidence_gate_db(_CASE, _DSN)
    assert gate["blocked"] is False
    assert gate["gate_state"] == "OPEN"
    assert gate["status"] == ChainStatus.OK
    mocked.assert_called_once_with(_CASE, _DSN)


def test_dispatch_reconciles_before_reading_the_gate() -> None:
    # With a case_dir, the seam MUST reconcile (populate inventory + observation)
    # and return the computed gate — reconcile-before-dispatch is the sole
    # enforcement authority.
    with patch.object(
        admission, "reconcile", return_value=admission._gate_result("BLOCKED_PENDING")
    ) as reconcile:
        gate = check_evidence_gate_db(_CASE, _DSN, "/cases/c1")
    reconcile.assert_called_once_with(_CASE, "/cases/c1", _DSN)
    assert gate["blocked"] is True
    assert gate["gate_state"] == "BLOCKED_PENDING"
    assert gate["status"] == ChainStatus.UNSEALED


def test_four_states_map_to_the_block_envelope() -> None:
    for state, expected_reason in [
        ("BLOCKED_PENDING", "evidence_chain_unsealed"),
        ("BLOCKED_VIOLATION", "evidence_chain_violation"),
        ("BLOCKED_UNAVAILABLE", "evidence_storage_unavailable"),
    ]:
        with patch.object(
            admission, "reconcile", return_value=admission._gate_result(state)
        ):
            gate = check_evidence_gate_db(_CASE, _DSN, "/cases/c1")
        body = build_block_response("run_command", gate)
        assert body["blocked"] is True
        assert body["gate_state"] == state
        assert body["reason"] == expected_reason
        # Shaped, operator-facing — never raw DB text.
        assert "SQLSTATE" not in body["detail"]
