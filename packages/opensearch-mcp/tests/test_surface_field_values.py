"""M-FIELDVALS surfacing-conformance regression test.

Seam A regression: ``run_opensearch_field_values`` (registry.py:1063-1068) builds
``FieldValuesOut`` with an **explicit** field-by-field constructor.  The
``advisory`` key was missing from that constructor — the field existed in
``FieldValuesOut`` but the wrapper never read ``raw.get("advisory")``.

Fix (live-proven 2026-06-25): ``advisory=raw.get("advisory")`` added to the
constructor call (registry.py:1067).

This test drives the REAL ``run_opensearch_field_values`` wrapper (not a stub)
with a controlled raw dict that carries ``advisory``, and asserts the key reaches
``structured_content`` (the agent-visible surface).  Reverting either:
  (a) the ``advisory`` field from ``FieldValuesOut``, or
  (b) the ``advisory=raw.get("advisory")`` line in ``run_opensearch_field_values``
makes this test fail (proven below in the module docstring).

Fail-on-revert proof (2026-06-26):
  Revert (a): deleted FieldValuesOut.advisory field → test_advisory_surfaces
    FAILED: AssertionError: expected key 'advisory' missing from structured_content.
  Revert (b): commented out advisory=raw.get("advisory") line → same failure.
  Restored production code; all tests pass.
"""

from __future__ import annotations

import pytest

from sift_common.testing.surface import assert_surfaces, call_through_registry


# ---------------------------------------------------------------------------
# Baseline raw dict: all required fields for a successful field_values call.
# ---------------------------------------------------------------------------
_BASE_RAW = {
    "field": "event.code",
    "values": [{"value": "4624", "count": 10}],
    "truncated": False,
}

_RAW_WITH_ADVISORY = {
    **_BASE_RAW,
    "advisory": "field not mapped; available: event.category, event.type",
}


# ---------------------------------------------------------------------------
# M-FIELDVALS regression: advisory must surface
# ---------------------------------------------------------------------------


def test_advisory_surfaces(monkeypatch):
    """M-FIELDVALS: advisory set by impl must reach structured_content.

    When the field is absent from the index mapping the implementation sets
    ``advisory`` on the raw dict.  Without the fix the run_* wrapper's explicit
    constructor omitted ``advisory=raw.get("advisory")``, so the key was silently
    dropped before Pydantic even saw it.  This drives the real wrapper.
    """
    from opensearch_mcp.registry import FieldValuesIn, run_opensearch_field_values

    result = assert_surfaces(
        run_opensearch_field_values,
        FieldValuesIn(field="event.code"),
        raw=_RAW_WITH_ADVISORY,
        expected={"advisory": "field not mapped; available: event.category, event.type"},
        monkeypatch_impl=monkeypatch,
    )
    sc = result.structured_content
    # Also assert the non-optional fields arrive correctly.
    assert sc["field"] == "event.code"
    assert sc["truncated"] is False
    assert len(sc["values"]) == 1
    assert sc["values"][0]["value"] == "4624"


def test_advisory_none_when_absent(monkeypatch):
    """When impl does not set advisory, structured_content carries advisory=null."""
    from opensearch_mcp.registry import FieldValuesIn, run_opensearch_field_values

    result = call_through_registry(
        run_opensearch_field_values,
        FieldValuesIn(field="event.code"),
        raw_dict=_BASE_RAW,
        monkeypatch_impl=monkeypatch,
    )
    sc = result.structured_content
    assert isinstance(sc, dict)
    # advisory must be present in the model (declared field) but be None.
    assert "advisory" in sc
    assert sc["advisory"] is None


def test_field_values_out_has_advisory_field():
    """Structural guard: FieldValuesOut must declare advisory as a model field.

    Reverting the field definition itself fails this test before any surface
    test even runs.
    """
    from opensearch_mcp.registry import FieldValuesOut

    assert "advisory" in FieldValuesOut.model_fields, (
        "FieldValuesOut must declare 'advisory' as a model field.  "
        "M-FIELDVALS regression: deleting this field silently drops advisory "
        "from every structured_content response."
    )
    # Must be Optional (None when field is mapped).
    field_info = FieldValuesOut.model_fields["advisory"]
    assert field_info.default is None, (
        "FieldValuesOut.advisory must default to None (it is optional)."
    )
