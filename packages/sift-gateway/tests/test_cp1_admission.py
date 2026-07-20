"""CP1 Foundation — admission, gate projection, binding, and live-path routing.

These are the non-DB CP1 acceptance tests (the DB contract runs on a migrated
PostgreSQL in ``test_cp1_custody_postgres.py``). They prove:

* the EC-6 canonical reauth binding is byte-order stable (the permanent
  mixed-case regression fixture);
* the shared read-only scanner classifies entry kinds, including the EC-5
  partial-transfer rule that keeps in-flight copies out of Pending;
* the four computed gate states project onto the response envelope;
* the LIVE sync + durable admission paths route ONLY through the target
  ``custody/admission`` seam (fail-on-revert routing tests).
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

from sift_core.custody_types import ChainStatus
from sift_core.execute import run_command_job
from sift_core.execute.evidence_binding import classify_inventory_entries
from sift_gateway.custody import admission, reauth


# ---------------------------------------------------------------------------
# EC-6 — the single canonical reauth binding (permanent regression fixture)
# ---------------------------------------------------------------------------
def test_ec6_binding_targets_are_byte_order_stable() -> None:
    # The Rocba fixture: mixed-case names whose Python code-point sort must equal
    # the SQL COLLATE "C" byte order. 'R'(0x52) sorts before 'r'(0x72).
    binding = reauth.build_binding(
        "key-1",
        "  seal the rocba set  ",
        ["evidence/rocba-cdrive.e01", "evidence/Rocba-Memory.raw"],
    )
    assert binding.targets == (
        "evidence/Rocba-Memory.raw",
        "evidence/rocba-cdrive.e01",
    )
    # Reason is stripped to match the SQL btrim; order of input is irrelevant.
    assert binding.reason == "seal the rocba set"
    reversed_input = reauth.build_binding(
        "key-1",
        "seal the rocba set",
        ["evidence/Rocba-Memory.raw", "evidence/rocba-cdrive.e01"],
    )
    assert binding.as_dict() == reversed_input.as_dict()


# ---------------------------------------------------------------------------
# EC-5 + classification — the single read-only scanner
# ---------------------------------------------------------------------------
def test_scanner_classifies_entry_kinds_and_ignores_partial_transfers(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.e01").write_bytes(b"data")
    (evidence / ".disk.e01.5trokB").write_bytes(b"partial")  # rsync temp (EC-5)
    (evidence / "copy.part").write_bytes(b"partial")  # partial suffix (EC-5)
    (evidence / "sub").mkdir()
    (evidence / "link").symlink_to(evidence / "disk.e01")
    hard = evidence / "hard1"
    hard.write_bytes(b"x")
    os.link(hard, evidence / "hard2")  # both become multilink (st_nlink=2)

    by_name = {e["display_name"]: e for e in classify_inventory_entries(str(tmp_path))}
    assert by_name["disk.e01"]["entry_kind"] == "regular"
    assert by_name[".disk.e01.5trokB"]["entry_kind"] == "partial"
    assert by_name["copy.part"]["entry_kind"] == "partial"
    assert by_name["sub"]["entry_kind"] == "directory"
    assert by_name["link"]["entry_kind"] == "symlink"
    assert by_name["hard1"]["entry_kind"] == "multilink"
    # display_path is always case-relative under evidence/.
    assert by_name["disk.e01"]["display_path"] == "evidence/disk.e01"


def test_scanner_returns_none_when_directory_unavailable(tmp_path: Path) -> None:
    assert classify_inventory_entries(str(tmp_path / "missing")) is None


# ---------------------------------------------------------------------------
# Gate projection envelope
# ---------------------------------------------------------------------------
def test_gate_result_maps_four_states() -> None:
    assert admission._gate_result("OPEN") == {
        "blocked": False,
        "gate_state": "OPEN",
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 0,
    }
    for state, status in [
        ("BLOCKED_PENDING", ChainStatus.UNSEALED),
        ("BLOCKED_VIOLATION", ChainStatus.LEDGER_ERROR),
        ("BLOCKED_UNAVAILABLE", ChainStatus.MISSING),
    ]:
        result = admission._gate_result(state)
        assert result["blocked"] is True
        assert result["gate_state"] == state
        assert result["status"] == status
        assert result["issues"]  # a shaped, operator-facing issue is present


def test_reconcile_and_gate_are_fail_closed_without_case_or_dsn() -> None:
    assert admission.reconcile(None, "/c", "dsn")["blocked"] is True
    assert admission.reconcile("case", "/c", None)["blocked"] is True
    assert admission.gate_state("case", None)["blocked"] is True


# ---------------------------------------------------------------------------
# Live-path routing (fail-on-revert): sync + durable go ONLY through the target
# computed gate + reconcile RPCs — never the retired latched-gate / observe RPCs.
# ---------------------------------------------------------------------------
def test_durable_admission_routes_through_computed_gate_not_latched() -> None:
    src = inspect.getsource(run_command_job)
    # New target surface present on the durable path.
    assert "app.custody_gate_state" in src
    assert "app.custody_reconcile" in src
    # Retired surfaces must never come back on the durable path.
    assert "app.evidence_gate_status" not in src
    assert "evidence_observe_admission" not in src
    assert "evidence_mark_admission_violation" not in src


def test_sync_gate_seam_routes_through_admission() -> None:
    from sift_gateway import evidence_gate

    src = inspect.getsource(evidence_gate)
    assert "admission.reconcile" in src
    assert "admission.gate_state" in src
    assert "app.evidence_gate_status" not in src
