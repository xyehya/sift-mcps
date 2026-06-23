"""BATCH-K6 — InvestigationService.audit_events sources audit from Postgres.

The portal audit view must read the audit trail from app.audit_events (DB
authority), scoped to the case, rather than scanning the local audit/*.jsonl
mirror — so JSONL tampering cannot spoof, hide, or fabricate audit entries.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sift_gateway.portal_services import InvestigationService


class _FakeCursor:
    def __init__(self, recorder, rows):
        self._recorder = recorder
        self._rows = rows
        self.description = [
            ("id",), ("event_type",), ("actor_type",), ("source",), ("status",),
            ("summary",), ("request_id",), ("job_id",), ("created_at",), ("details",),
        ]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params):
        self._recorder["sql"] = sql
        self._recorder["params"] = params

    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self, recorder, rows):
        self._recorder = recorder
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self._recorder, self._rows)


def _service(rows, recorder):
    svc = InvestigationService("postgresql://fake")
    svc._connect = lambda: _FakeConn(recorder, rows)  # type: ignore[assignment]
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
    # Scoped to the case + the requested ids.
    assert recorder["params"][0] == "case-1"
    assert recorder["params"][1] == ["evt-1", "evt-2"]
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
