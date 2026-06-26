"""F9: flag unresolved numeric SRUM application ids.

Confirmed-from-code root cause: opensearch-mcp does NO application-id → name
resolution during SRUM ingest; the `application` field is written 1:1 from the
parser tool (SrumECmd / Plaso).  A bare numeric SruDbId (e.g. "1") therefore
gets indexed as if it were an application NAME.

`flag_unresolved_srum_application` is the non-destructive flagging half of the
fix (resolved rows like "TermService" are untouched; unresolved numeric ids are
flagged).  It is unit-tested here but NOT yet wired into the live ingest path —
that wiring needs a real SRUM sample to confirm the SrumECmd/Plaso column
semantics (see the NOTE in parse_srum.py).
"""

from __future__ import annotations

from opensearch_mcp.parse_srum import flag_unresolved_srum_application


class TestFlagUnresolvedSrumApplication:
    def test_bare_integer_string_is_flagged(self):
        doc = {"application": "1", "bytes_sent": 314_000_000}
        out = flag_unresolved_srum_application(doc)
        assert out["application_unresolved"] is True
        assert out["application_id"] == "1"
        # Original value preserved (caller decides how to render).
        assert out["application"] == "1"

    def test_bare_int_is_flagged(self):
        out = flag_unresolved_srum_application({"application": 1})
        assert out["application_unresolved"] is True
        assert out["application_id"] == "1"

    def test_resolved_name_is_untouched(self):
        doc = {"application": "TermService", "bytes_sent": 250_000_000}
        out = flag_unresolved_srum_application(doc)
        assert "application_unresolved" not in out
        assert "application_id" not in out
        assert out["application"] == "TermService"

    def test_path_like_name_is_untouched(self):
        doc = {"application": r"\Device\HarddiskVolume2\Windows\System32\svchost.exe"}
        out = flag_unresolved_srum_application(doc)
        assert "application_unresolved" not in out

    def test_missing_application_is_noop(self):
        doc = {"bytes_sent": 100}
        out = flag_unresolved_srum_application(doc)
        assert "application_unresolved" not in out
        assert out == {"bytes_sent": 100}

    def test_empty_application_is_noop(self):
        out = flag_unresolved_srum_application({"application": ""})
        assert "application_unresolved" not in out

    def test_whitespace_padded_integer_is_flagged(self):
        out = flag_unresolved_srum_application({"application": "  42 "})
        assert out["application_unresolved"] is True
        assert out["application_id"] == "42"

    def test_bool_is_not_treated_as_integer(self):
        # True is an int subclass — must NOT be flagged as a numeric app id.
        out = flag_unresolved_srum_application({"application": True})
        assert "application_unresolved" not in out

    def test_non_dict_returned_unchanged(self):
        assert flag_unresolved_srum_application(None) is None  # type: ignore[arg-type]

    def test_alphanumeric_id_not_flagged(self):
        # Only pure-digit values are unresolved SruDbIds; 'app1' is a name.
        out = flag_unresolved_srum_application({"application": "app1"})
        assert "application_unresolved" not in out
