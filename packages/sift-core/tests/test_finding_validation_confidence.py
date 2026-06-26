"""C3: confidence must be strictly required, non-empty, and a valid enum member.

Regression: an empty string "" for confidence previously slipped the enum check
(the `if confidence and confidence not in valid_confidence` guard short-circuits
on falsy). The required-field check catches it via `not finding.get("confidence")`,
but the C3 fix adds an explicit non-empty guard in the confidence branch too so
the behavior is unambiguous regardless of required-field check ordering.
"""

from __future__ import annotations

from sift_core.finding_validation import validate

VALID_BASE = {
    "title": "Test Finding",
    "type": "finding",
    "host": "HOST01",
    "observation": "obs",
    "interpretation": "interp",
    "confidence_justification": "test",
    "event_timestamp": "2026-06-24T00:00:00Z",
}


def _with_confidence(value):
    return {**VALID_BASE, "confidence": value}


def _without_confidence():
    return dict(VALID_BASE)  # no "confidence" key at all


# ---------------------------------------------------------------------------
# C3: missing / empty / invalid → VALIDATION_FAILED
# ---------------------------------------------------------------------------


def test_missing_confidence_is_rejected():
    result = validate(_without_confidence())
    assert result["valid"] is False
    errors_str = " ".join(result["errors"])
    assert "confidence" in errors_str.lower()


def test_empty_string_confidence_is_rejected():
    result = validate(_with_confidence(""))
    assert result["valid"] is False
    errors_str = " ".join(result["errors"])
    assert "confidence" in errors_str.lower()


def test_bogus_confidence_is_rejected():
    result = validate(_with_confidence("bogus"))
    assert result["valid"] is False
    errors_str = " ".join(result["errors"])
    assert "bogus" in errors_str or "Invalid confidence" in errors_str


def test_whitespace_confidence_is_rejected():
    # "   ".upper() -> "   " which is non-empty but not in the valid set.
    result = validate(_with_confidence("   "))
    assert result["valid"] is False


def test_lowercase_valid_enum_is_accepted():
    # Case-insensitive: "high" -> "HIGH" via .upper() -> valid.
    result = validate(_with_confidence("high"))
    assert result["valid"] is True, result


def test_high_is_accepted():
    result = validate(_with_confidence("HIGH"))
    assert result["valid"] is True, result


def test_medium_is_accepted():
    result = validate(_with_confidence("MEDIUM"))
    assert result["valid"] is True, result


def test_low_is_accepted():
    result = validate(_with_confidence("LOW"))
    assert result["valid"] is True, result


def test_speculative_is_accepted():
    result = validate(_with_confidence("SPECULATIVE"))
    assert result["valid"] is True, result
