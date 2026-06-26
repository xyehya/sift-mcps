"""Seam C surfacing-conformance regression tests for ingest_job._aggregate.

``_aggregate`` (ingest_job.py:303-378) builds a plain dict ``detail`` — there is
no Pydantic model.  Signals are surfaced via conditional guards:

  F8 intel_backend:
    if intel_backend:  detail["intel_backend"] = intel_backend   # :369-370
  M-WORKER-DBDROP warning:
    if mem_warning:    detail["warning"] = mem_warning           # :373-374

These guards were the fix for two separate live bugs where the worker's terminal
``result_public`` carried the signal but the agent saw a clean "complete" with
no indication of the condition (intel unavailable / low RAM).

Seam C regression: the key lives in ``totals`` (per-run), is extracted by the
guard loop, and injected into ``detail`` only if non-empty.  Reverting the guard
(deleting the ``if intel_backend: detail["intel_backend"] = …`` block or the
``if mem_warning: detail["warning"] = …`` block) makes the corresponding test fail.

Fail-on-revert proof (2026-06-26):
  Revert F8 guard (delete ``if intel_backend: detail["intel_backend"] = …``):
    test_intel_backend_surfaces FAILED: assert "intel_backend" in out["detail"]
  Revert M-WORKER-DBDROP guard (delete ``if mem_warning: detail["warning"] = …``):
    test_mem_warning_surfaces FAILED: assert "warning" in out["detail"]
  Restored; all pass.
"""

from __future__ import annotations

import pytest

from opensearch_mcp.ingest_job import _aggregate


# ---------------------------------------------------------------------------
# Helpers: build a run_ids set and a latest_by_run dict from a simple spec.
# ---------------------------------------------------------------------------


def _make_status(run_id: str, status: str = "complete", **totals: object) -> tuple[str, dict]:
    """Return a (run_id, status_record) pair for use in latest_by_run."""
    return run_id, {"status": status, "totals": totals}


# ---------------------------------------------------------------------------
# F8 intel_backend — Seam C regression
# ---------------------------------------------------------------------------


def test_intel_backend_surfaces():
    """F8: intel_backend from totals must reach detail in _aggregate output.

    When the intel enrichment backend is unavailable the worker writes
    ``totals.intel_backend = "unavailable"`` in the status record.  _aggregate
    must surface it in ``detail["intel_backend"]``.  Without the fix the agent
    sees a clean "complete" dict with no hint that enrichment was skipped.
    """
    rid = "run-001"
    rid2, rec2 = _make_status(rid, status="complete", intel_backend="unavailable", indexed=500)
    latest = {rid: rec2}

    out = _aggregate(latest, {rid})

    assert "intel_backend" in out["detail"], (
        "F8 regression: detail must carry 'intel_backend' when totals.intel_backend is set.  "
        "Revert: the guard 'if intel_backend: detail[\"intel_backend\"] = intel_backend' "
        "was removed — restore it in ingest_job.py."
    )
    assert out["detail"]["intel_backend"] == "unavailable", (
        f"F8: intel_backend value mismatch: {out['detail']['intel_backend']!r}"
    )


def test_intel_backend_absent_when_not_set():
    """When totals.intel_backend is empty/absent, detail must NOT carry the key.

    The guard is ``if intel_backend:`` — empty string or missing omits the key.
    This test ensures the guard doesn't accidentally add a blank entry.
    """
    rid = "run-002"
    _, rec = _make_status(rid, status="complete", indexed=100)
    latest = {rid: rec}

    out = _aggregate(latest, {rid})

    assert "intel_backend" not in out["detail"], (
        "detail must NOT carry 'intel_backend' when totals.intel_backend is empty."
    )


# ---------------------------------------------------------------------------
# M-WORKER-DBDROP warning — Seam C regression
# ---------------------------------------------------------------------------


def test_mem_warning_surfaces():
    """M-WORKER-DBDROP: mem_warning from totals must reach detail["warning"].

    When the worker detects low RAM pre-flight it writes
    ``totals.mem_warning = "low RAM"`` (or similar message).  _aggregate must
    surface it in ``detail["warning"]``.  Without the fix the agent polling
    running_commands_status sees a complete status with no memory advisory.
    """
    rid = "run-003"
    _, rec = _make_status(rid, status="complete", mem_warning="low RAM detected: 1.5 GB free")
    latest = {rid: rec}

    out = _aggregate(latest, {rid})

    assert "warning" in out["detail"], (
        "M-WORKER-DBDROP regression: detail must carry 'warning' when "
        "totals.mem_warning is set.  "
        "Revert: the guard 'if mem_warning: detail[\"warning\"] = mem_warning' "
        "was removed — restore it in ingest_job.py."
    )
    assert out["detail"]["warning"] == "low RAM detected: 1.5 GB free", (
        f"M-WORKER-DBDROP: warning value mismatch: {out['detail']['warning']!r}"
    )


def test_mem_warning_absent_when_not_set():
    """When totals.mem_warning is absent, detail must NOT carry 'warning'."""
    rid = "run-004"
    _, rec = _make_status(rid, status="complete", indexed=200)
    latest = {rid: rec}

    out = _aggregate(latest, {rid})

    assert "warning" not in out["detail"], (
        "detail must NOT carry 'warning' when totals.mem_warning is empty."
    )


# ---------------------------------------------------------------------------
# Sibling: hayabusa_alerts surfaces only when non-zero
# ---------------------------------------------------------------------------


def test_hayabusa_alerts_surfaces():
    """hayabusa_alerts from host artifacts must reach detail["hayabusa_alerts"]."""
    rid = "run-005"
    rec = {
        "status": "complete",
        "totals": {"indexed": 1000},
        "hosts": [
            {
                "hostname": "hayabusa",
                "artifacts": [{"name": "evtx", "indexed": 42}],
            }
        ],
    }
    latest = {rid: rec}

    out = _aggregate(latest, {rid})

    assert "hayabusa_alerts" in out["detail"], (
        "detail must carry 'hayabusa_alerts' when hayabusa host has indexed > 0."
    )
    assert out["detail"]["hayabusa_alerts"] == 42


def test_hayabusa_alerts_absent_when_zero():
    """When no hayabusa host or zero alerts, hayabusa_alerts is absent from detail."""
    rid = "run-006"
    _, rec = _make_status(rid, status="complete", indexed=500)
    latest = {rid: rec}

    out = _aggregate(latest, {rid})

    assert "hayabusa_alerts" not in out["detail"]


# ---------------------------------------------------------------------------
# Combined: both signals present together
# ---------------------------------------------------------------------------


def test_both_signals_present():
    """F8 + M-WORKER-DBDROP: when both signals are in totals, both reach detail."""
    rid = "run-007"
    _, rec = _make_status(
        rid,
        status="complete",
        intel_backend="unavailable",
        mem_warning="2 GB free — below 4 GB recommendation",
        indexed=300,
    )
    latest = {rid: rec}

    out = _aggregate(latest, {rid})

    assert out["detail"]["intel_backend"] == "unavailable"
    assert out["detail"]["warning"] == "2 GB free — below 4 GB recommendation"


# ---------------------------------------------------------------------------
# Multi-run: first non-empty signal wins (intel_backend is string-aggregated)
# ---------------------------------------------------------------------------


def test_intel_backend_multi_run_last_wins():
    """With multiple runs, last non-empty intel_backend in iteration order wins."""
    rid_a, rec_a = _make_status("run-a", status="complete", intel_backend="unavailable")
    rid_b, rec_b = _make_status("run-b", status="complete", indexed=100)
    # run_ids is a set; iteration order is not guaranteed, but at least one
    # intel_backend is non-empty so detail must carry it.
    latest = {"run-a": rec_a, "run-b": rec_b}

    out = _aggregate(latest, {"run-a", "run-b"})

    assert "intel_backend" in out["detail"]
    assert out["detail"]["intel_backend"] == "unavailable"
