from __future__ import annotations

import pytest

from sift_gateway.active_case import ActiveCaseError, ActiveCaseService


_CASE_ROW = (
    "11111111-1111-1111-1111-111111111111",
    "db-case",
    "DB Case",
    None,
    "active",
    "/cases/db-case",
    {},
)


class _Cursor:
    def __init__(self, conn):
        self.conn = conn
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.statements.append((sql, params))
        normalized = " ".join(sql.lower().split())
        if "from app.active_case_state" in normalized:
            self._row = self.conn.active_row
        elif "from app.cases" in normalized and "where id =" in normalized:
            self._row = self.conn.case_row
        elif "from app.case_members" in normalized:
            self._row = self.conn.membership_row
        elif "returning id::text" in normalized:
            self._row = self.conn.case_row
        else:
            self._row = None

    def fetchone(self):
        return self._row

    def fetchall(self):
        return [self._row] if self._row is not None else []


class _Connection:
    def __init__(self, *, active_row=None, case_row=None, membership_row=None):
        self.active_row = active_row
        self.case_row = case_row
        self.membership_row = membership_row
        self.statements = []
        self.committed = False
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def _operator(role="operator"):
    return {
        "principal_type": "operator",
        "principal_id": "22222222-2222-2222-2222-222222222222",
        "system_role": "operator",
        "case_memberships": [
            {
                "case_id": "11111111-1111-1111-1111-111111111111",
                "role": role,
            }
        ],
    }


def test_get_active_case_absent_returns_typed_denial(monkeypatch):
    conn = _Connection(active_row=None)
    monkeypatch.setattr("sift_gateway.active_case._connect", lambda dsn: conn)

    service = ActiveCaseService("postgres://example")
    with pytest.raises(ActiveCaseError) as exc:
        service.get_active_case(_operator())

    assert exc.value.reason == "no_active_case"
    assert exc.value.http_status == 404


def test_set_active_case_updates_deployment_row_and_audit(monkeypatch):
    conn = _Connection(case_row=_CASE_ROW, membership_row=("operator",))
    monkeypatch.setattr("sift_gateway.active_case._connect", lambda dsn: conn)

    service = ActiveCaseService("postgres://example")
    case = service.set_active_case("db-case", _operator())

    assert case.case_key == "db-case"
    assert conn.committed is True
    joined_sql = "\n".join(sql.lower() for sql, _ in conn.statements)
    assert "insert into app.active_case_state" in joined_sql
    assert "insert into app.audit_events" in joined_sql


def test_set_active_case_denies_without_membership(monkeypatch):
    conn = _Connection(case_row=_CASE_ROW, membership_row=None)
    monkeypatch.setattr("sift_gateway.active_case._connect", lambda dsn: conn)
    principal = dict(_operator(), case_memberships=[])

    service = ActiveCaseService("postgres://example")
    with pytest.raises(ActiveCaseError) as exc:
        service.set_active_case("db-case", principal)

    assert exc.value.reason == "active_case_membership_required"
    assert exc.value.http_status == 403
    assert conn.committed is False
