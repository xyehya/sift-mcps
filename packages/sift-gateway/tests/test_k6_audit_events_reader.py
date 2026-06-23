"""BATCH-K6 — InvestigationService.audit_events sources audit from Postgres.

The portal audit view must read the audit trail from app.audit_events (DB
authority), scoped to the case, rather than scanning the local audit/*.jsonl
mirror — so JSONL tampering cannot spoof, hide, or fabricate audit entries.

Extended (audit-id resolver fix): audit_events now resolves finding.audit_ids
via uuid PK, backend_audit_id, and audit_aliases — all scoped to case_id.
"""

from __future__ import annotations

from datetime import datetime, timezone

from mcp.types import TextContent

from sift_gateway.audit_helpers import _AUDIT_MAX_DEPTH, _collect_audit_ids_from_obj, _extract_all_audit_ids
from sift_gateway.portal_services import InvestigationService


class _FakeCursor:
    def __init__(self, recorder, rows, *, call_key="sql", description=None):
        self._recorder = recorder
        self._rows = rows
        self._call_key = call_key
        self.description = description or [
            ("id",), ("event_type",), ("actor_type",), ("source",), ("status",),
            ("summary",), ("request_id",), ("job_id",), ("created_at",), ("details",),
        ]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params):
        # call_key is "sql" for the main query (back-compat: recorder["sql"],
        # recorder["params"]) and "call_sql" for the paired-call fetch
        # (recorder["call_sql"], recorder["call_params"]).
        self._recorder[self._call_key] = sql
        params_key = "params" if self._call_key == "sql" else "call_params"
        self._recorder[params_key] = params

    def fetchall(self):
        return self._rows


class _FakeConn:
    """Fake connection supporting two sequential cursor() calls.

    First cursor() call → main result rows (the resolver query).
    Second cursor() call → paired-call rows (the envelope_event_id batch fetch).
    Extra cursor() calls return empty rows.
    """

    def __init__(self, recorder, rows, *, call_rows=None):
        self._recorder = recorder
        self._rows = rows
        self._call_rows = call_rows or []  # rows for the paired-call fetch
        self._cursor_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        self._cursor_count += 1
        if self._cursor_count == 1:
            # Main resolver query: recorder["sql"] + recorder["params"] (back-compat).
            return _FakeCursor(self._recorder, self._rows, call_key="sql")
        # Second cursor: paired-call batch fetch → recorder["call_sql"] + recorder["call_params"].
        return _FakeCursor(self._recorder, self._call_rows, call_key="call_sql")


def _service(rows, recorder, *, call_rows=None):
    svc = InvestigationService("postgresql://fake")
    svc._connect = lambda: _FakeConn(recorder, rows, call_rows=call_rows)  # type: ignore[assignment]
    return svc


def test_audit_events_queries_db_scoped_to_case():
    recorder: dict = {}
    rows = [
        (
            "evt-1", "TOOL_CALL", "agent", "gateway", "success",
            "ran tool", "req-1", None, datetime(2026, 6, 8, tzinfo=timezone.utc), {},
        )
    ]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-1", ["evt-1", "evt-2"])

    assert "app.audit_events" in recorder["sql"]
    assert "case_id = %s" in recorder["sql"]
    # Scoped to the case; ids are passed three times (uuid, backend_audit_id, aliases).
    assert recorder["params"][0] == "case-1"
    assert recorder["params"][1] == ["evt-1", "evt-2"]
    assert recorder["params"][2] == ["evt-1", "evt-2"]  # backend_audit_id match
    assert recorder["params"][3] == ["evt-1", "evt-2"]  # audit_aliases ?| match
    assert out[0]["id"] == "evt-1"
    assert out[0]["created_at"] == "2026-06-08T00:00:00+00:00"


def test_audit_events_empty_ids_returns_empty_without_query():
    recorder: dict = {}
    svc = _service([], recorder)
    assert svc.audit_events("case-1", []) == []
    assert "sql" not in recorder  # no DB hit for an empty id set


def test_audit_events_drops_blank_ids():
    recorder: dict = {}
    svc = _service([], recorder)
    svc.audit_events("case-1", ["", "  ", "evt-9"])
    assert recorder["params"][1] == ["evt-9"]


def test_audit_events_recent_collapses_tool_call_pairs():
    recorder: dict = {}
    rows = [
        (
            "evt-result",
            "TOOL_CALL",
            "agent",
            "gateway",
            "success",
            "completed",
            "req-1",
            None,
            datetime(2026, 6, 8, 0, 1, tzinfo=timezone.utc),
            {"tool": "record_finding", "backend": "core", "principal": "agent"},
        ),
        (
            "evt-request",
            "TOOL_CALL",
            "agent",
            "gateway",
            "requested",
            "requested",
            "req-1",
            None,
            datetime(2026, 6, 8, 0, 0, tzinfo=timezone.utc),
            {
                "phase": "pre_dispatch",
                "tool": "record_finding",
                "arguments": {"title": "External RDP", "confidence": "HIGH"},
            },
        ),
    ]
    svc = _service(rows, recorder)
    out = svc.audit_events_recent("case-1", limit=5)

    assert "app.audit_events" in recorder["sql"]
    assert "case_id = %s" in recorder["sql"]
    assert recorder["params"] == ("case-1", 10)
    assert out == [
        {
            "id": "evt-result",
            "ts": "2026-06-08T00:01:00+00:00",
            "tool": "record_finding",
            "backend": "core",
            "status": "success",
            "principal": "agent",
            "kind": "discovery",
            "text": "Recorded finding - External RDP (HIGH)",
        }
    ]


def test_audit_events_recent_maps_failures_and_defaults_bad_limit():
    recorder: dict = {}
    rows = [
        (
            "evt-fail",
            "TOOL_CALL",
            "agent",
            "gateway",
            "failure",
            "failed",
            "req-2",
            None,
            datetime(2026, 6, 8, 0, 2, tzinfo=timezone.utc),
            {"tool": "run_command", "backend": "shell", "detail": {"message": "policy denied"}},
        )
    ]
    svc = _service(rows, recorder)
    out = svc.audit_events_recent("case-1", limit="not-a-number")  # type: ignore[arg-type]

    assert recorder["params"] == ("case-1", 60)
    assert out[0]["kind"] == "alert"
    assert out[0]["text"] == "run_command failed - policy denied"


# ---------------------------------------------------------------------------
# Resolver fix: audit_events matches via backend_audit_id and audit_aliases
# ---------------------------------------------------------------------------


def _row(pk, *, created_at=None):
    """Return a minimal _FakeCursor row tuple for the audit_events column list."""
    return (
        pk, "TOOL_CALL", "agent", "gateway", "success",
        "summary", "req-x", None,
        created_at or datetime(2026, 6, 23, tzinfo=timezone.utc), {},
    )


def test_audit_events_sql_includes_backend_audit_id_and_aliases_predicates():
    """SQL must resolve ids via uuid PK, backend_audit_id, and audit_aliases."""
    recorder: dict = {}
    svc = _service([], recorder)
    svc.audit_events("case-A", ["siftgateway-claud-20260622-036"])
    sql = recorder["sql"]
    # All three match paths must appear in the WHERE clause.
    assert "id::text = any(%s)" in sql
    assert "details->>'backend_audit_id' = any(%s)" in sql
    assert "details->'audit_aliases' ?|" in sql
    # Every predicate is scoped to case_id.
    assert sql.count("case_id = %s") >= 1


def test_audit_events_all_three_params_carry_same_ids():
    """The ids list is passed to all three match slots so every path is tried."""
    recorder: dict = {}
    svc = _service([], recorder)
    ids = ["siftgateway-claud-20260622-036", "shell-claud-20260622-001"]
    svc.audit_events("case-A", ids)
    # params: (case_id, ids, ids, ids)
    assert recorder["params"] == ("case-A", ids, ids, ids)


def test_audit_events_resolves_row_when_backend_audit_id_matches():
    """A requested id that matches details->>'backend_audit_id' is returned."""
    recorder: dict = {}
    # The DB returns one row (the SQL WHERE already filtered by backend_audit_id).
    rows = [_row("uuid-pk-001")]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-A", ["siftgateway-claud-20260622-036"])
    # The id list is forwarded to all three predicates.
    assert recorder["params"][1] == ["siftgateway-claud-20260622-036"]
    assert recorder["params"][2] == ["siftgateway-claud-20260622-036"]
    assert recorder["params"][3] == ["siftgateway-claud-20260622-036"]
    # Row is returned (the fake cursor returns whatever the fake DB returns).
    assert out[0]["id"] == "uuid-pk-001"


def test_audit_events_resolves_row_when_audit_alias_matches():
    """A requested id that matches an audit_aliases entry is returned."""
    recorder: dict = {}
    rows = [_row("uuid-pk-002")]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-B", ["opensearchingest951032-sift-service-20260618-035"])
    assert out[0]["id"] == "uuid-pk-002"
    # aliases slot carries the requested id.
    assert "opensearchingest951032-sift-service-20260618-035" in recorder["params"][3]


def test_audit_events_cross_case_id_never_surfaced():
    """case_id is always the first param — the fake DB only returns rows we
    inject, so we verify that the SQL itself enforces scoping (the WHERE always
    starts with case_id = %s) and that params[0] is the caller's case_id."""
    recorder: dict = {}
    svc = _service([], recorder)
    svc.audit_events("case-A", ["leaked-id-from-case-B"])
    # case_id is always the first bind parameter.
    assert recorder["params"][0] == "case-A"
    sql = recorder["sql"]
    # The WHERE clause must open with a case_id predicate so row-level scoping
    # is enforced by the DB, not just by the application layer.
    assert "where case_id = %s" in sql


# ---------------------------------------------------------------------------
# _extract_all_audit_ids unit tests
# ---------------------------------------------------------------------------


def _text(payload: dict) -> TextContent:
    import json
    return TextContent(type="text", text=json.dumps(payload))


def test_extract_all_audit_ids_collects_top_level():
    result = [_text({"audit_id": "siftgateway-claud-20260622-036", "other": "x"})]
    assert _extract_all_audit_ids(result) == ["siftgateway-claud-20260622-036"]


def test_extract_all_audit_ids_collects_nested_audit_id():
    payload = {
        "tool": "run_command",
        "provenance": {
            "audit_id": "shell-claud-20260622-001",
            "input_sha256s": ["a" * 64],
        },
        "stages": [{"binary": "grep", "exit_code": 0}],
    }
    result = [_text(payload)]
    ids = _extract_all_audit_ids(result)
    assert "shell-claud-20260622-001" in ids


def test_extract_all_audit_ids_collects_audit_ids_list():
    payload = {
        "audit_id": "parent-001",
        "audit_ids": ["child-a", "child-b"],
    }
    result = [_text(payload)]
    ids = _extract_all_audit_ids(result)
    assert "parent-001" in ids
    assert "child-a" in ids
    assert "child-b" in ids


def test_extract_all_audit_ids_deduplicates():
    payload = {
        "audit_id": "siftgateway-claud-001",
        "provenance": {"audit_id": "siftgateway-claud-001"},
    }
    result = [_text(payload)]
    ids = _extract_all_audit_ids(result)
    assert ids.count("siftgateway-claud-001") == 1


def test_extract_all_audit_ids_ignores_non_audit_keys():
    payload = {"command": "grep x", "output": "some text", "tool": "run_command"}
    result = [_text(payload)]
    assert _extract_all_audit_ids(result) == []


def test_extract_all_audit_ids_empty_on_non_json():
    from mcp.types import TextContent as TC
    result = [TC(type="text", text="not json at all")]
    assert _extract_all_audit_ids(result) == []


def test_extract_all_audit_ids_empty_list_on_empty_result():
    assert _extract_all_audit_ids([]) == []


def test_collect_audit_ids_depth_cap_returns_early_without_crash():
    """A response nested far beyond _AUDIT_MAX_DEPTH must not recurse to Python's
    stack limit — _collect_audit_ids_from_obj returns early at the cap."""
    # Build a dict nested 2 * _AUDIT_MAX_DEPTH deep with an audit_id at the bottom.
    depth = _AUDIT_MAX_DEPTH * 2
    obj: Any = {"audit_id": "deep-id"}
    for _ in range(depth):
        obj = {"nested": obj}
    out: list[str] = []
    budget = [200]
    # Must return without RecursionError and without finding the deeply-nested id.
    _collect_audit_ids_from_obj(obj, out, budget)
    assert "deep-id" not in out  # capped before reaching it


def test_collect_audit_ids_depth_cap_does_not_block_shallow_ids():
    """Ids within the depth cap are still collected normally."""
    payload = {
        "audit_id": "top-level",
        "provenance": {"audit_id": "nested-1"},
    }
    out: list[str] = []
    budget = [200]
    _collect_audit_ids_from_obj(payload, out, budget)
    assert "top-level" in out
    assert "nested-1" in out


# ---------------------------------------------------------------------------
# audit_id labeling: each returned row carries the requested human id it matched
# ---------------------------------------------------------------------------


def _row_with_details(pk, *, details=None, created_at=None):
    """Return a _FakeCursor row tuple, injecting a details dict."""
    return (
        pk, "TOOL_CALL", "agent", "gateway", "success",
        "summary", "req-x", None,
        created_at or datetime(2026, 6, 23, tzinfo=timezone.utc),
        details or {},
    )


def test_audit_events_labels_row_with_uuid_id_when_matched_by_pk():
    """When a requested id equals the row's uuid PK, audit_id = that id."""
    recorder: dict = {}
    rows = [_row_with_details("uuid-pk-aaa")]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-A", ["uuid-pk-aaa"])
    assert len(out) == 1
    assert out[0]["audit_id"] == "uuid-pk-aaa"


def test_audit_events_labels_row_with_backend_audit_id_match():
    """When a requested id matches details->>'backend_audit_id', that id is the label."""
    recorder: dict = {}
    rows = [_row_with_details(
        "uuid-pk-bbb",
        details={"backend_audit_id": "siftgateway-claud-20260622-036"},
    )]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-A", ["siftgateway-claud-20260622-036"])
    assert len(out) == 1
    assert out[0]["audit_id"] == "siftgateway-claud-20260622-036"
    assert out[0]["id"] == "uuid-pk-bbb"


def test_audit_events_labels_row_with_alias_match():
    """When a requested id is in audit_aliases, that id becomes the label."""
    recorder: dict = {}
    rows = [_row_with_details(
        "uuid-pk-ccc",
        details={
            "backend_audit_id": "siftgateway-claud-20260622-001",
            "audit_aliases": ["shell-claud-20260622-001", "opensearchingest951032-sift-service-20260618-035"],
        },
    )]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-A", ["opensearchingest951032-sift-service-20260618-035"])
    assert len(out) == 1
    assert out[0]["audit_id"] == "opensearchingest951032-sift-service-20260618-035"
    assert out[0]["id"] == "uuid-pk-ccc"


def test_audit_events_one_row_matching_two_ids_emits_two_entries():
    """A single DB row satisfying two requested ids → two returned entries."""
    recorder: dict = {}
    rows = [_row_with_details(
        "uuid-pk-ddd",
        details={
            "backend_audit_id": "siftgateway-claud-20260622-999",
            "audit_aliases": ["shell-claud-20260622-999"],
        },
    )]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-A", [
        "siftgateway-claud-20260622-999",
        "shell-claud-20260622-999",
    ])
    assert len(out) == 2
    labeled = {r["audit_id"] for r in out}
    assert labeled == {"siftgateway-claud-20260622-999", "shell-claud-20260622-999"}
    # Both copies refer to the same underlying DB row.
    assert all(r["id"] == "uuid-pk-ddd" for r in out)


def test_audit_events_labels_preserve_other_columns():
    """The audit_id label is added alongside existing columns; none are lost."""
    recorder: dict = {}
    rows = [_row_with_details(
        "uuid-pk-eee",
        details={"backend_audit_id": "siftgateway-claud-20260623-001"},
    )]
    svc = _service(rows, recorder)
    out = svc.audit_events("case-B", ["siftgateway-claud-20260623-001"])
    assert len(out) == 1
    row = out[0]
    assert row["audit_id"] == "siftgateway-claud-20260623-001"
    assert row["id"] == "uuid-pk-eee"
    assert row["event_type"] == "TOOL_CALL"
    assert row["status"] == "success"
    assert row["created_at"] is not None


# ---------------------------------------------------------------------------
# Paired-call fetch: reader attaches arguments from the envelope call event
# ---------------------------------------------------------------------------


def _result_row_with_envelope(pk, *, envelope_event_id, backend_audit_id=None):
    """Result row that carries a details.envelope_event_id linking to its call event."""
    return _row_with_details(
        pk,
        details={
            "backend_audit_id": backend_audit_id or f"siftgateway-claud-{pk}",
            "envelope_event_id": envelope_event_id,
            "tool": "run_command",
            "result_summary": {"success": True},
        },
    )


def _call_row(call_id, arguments):
    """Simulates the mcp.tool.call DB row returned by the paired-call fetch.

    The paired-call cursor returns (id::text, details) tuples only.
    """
    return (call_id, {"arguments": arguments, "phase": "pre_dispatch"})


def test_reader_attaches_arguments_from_paired_call_event():
    """When a result row has details.envelope_event_id and the paired call event
    exists in the DB, reader attaches its arguments as row['arguments']."""
    recorder: dict = {}
    result_rows = [_result_row_with_envelope("uuid-pk-r1", envelope_event_id="uuid-call-1")]
    call_rows = [_call_row("uuid-call-1", {"command": "ls -la evidence", "purpose": "list files"})]
    svc = _service(result_rows, recorder, call_rows=call_rows)
    out = svc.audit_events("case-A", ["siftgateway-claud-uuid-pk-r1"])
    assert len(out) == 1
    assert out[0].get("arguments") == {"command": "ls -la evidence", "purpose": "list files"}


def test_reader_paired_call_query_is_case_scoped():
    """The paired-call batch query must be scoped to case_id (security invariant)."""
    recorder: dict = {}
    result_rows = [_result_row_with_envelope("uuid-pk-r2", envelope_event_id="uuid-call-2")]
    call_rows = [_call_row("uuid-call-2", {"command": "fls -r image.E01"})]
    svc = _service(result_rows, recorder, call_rows=call_rows)
    svc.audit_events("case-B", ["siftgateway-claud-uuid-pk-r2"])
    # The paired-call SQL must also be scoped to the case.
    call_sql = recorder.get("call_sql", "")
    assert "app.audit_events" in call_sql
    assert "case_id = %s" in call_sql
    call_params = recorder.get("call_params", ())
    assert call_params[0] == "case-B"


def test_reader_row_without_envelope_event_id_is_untouched():
    """A row with no details.envelope_event_id gets no 'arguments' key attached."""
    recorder: dict = {}
    # Row has no envelope_event_id in details.
    result_rows = [_row_with_details("uuid-pk-r3", details={"tool": "case_info"})]
    svc = _service(result_rows, recorder)
    out = svc.audit_events("case-A", ["uuid-pk-r3"])
    assert len(out) == 1
    assert "arguments" not in out[0]


def test_reader_no_paired_call_rows_leaves_arguments_absent():
    """If the paired-call fetch returns no matching rows, 'arguments' is not set."""
    recorder: dict = {}
    result_rows = [_result_row_with_envelope("uuid-pk-r4", envelope_event_id="uuid-call-missing")]
    # call_rows is empty — the call event was not found.
    svc = _service(result_rows, recorder, call_rows=[])
    out = svc.audit_events("case-A", ["siftgateway-claud-uuid-pk-r4"])
    assert len(out) == 1
    assert "arguments" not in out[0]
