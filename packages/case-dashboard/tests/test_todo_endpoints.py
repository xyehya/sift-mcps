"""Tests for portal TODO CRUD endpoints.

Covers: POST /api/todos, PATCH /api/todos/{id}, DELETE /api/todos/{id}.
Writes are direct (no signed-commit flow) — todos are operational task tracking,
not evidentiary findings. Schema mirrors forensic-mcp's add_todo/update_todo so
the agent and portal interoperate on todos.json.

Security invariants: examiner role required for writes (readonly → 403),
authenticated session required (401), must_reset blocks writes (403).

B-MVP-023: migrated from the legacy sift_session JWT cookie to the
Supabase-envelope harness. The legacy plane is disabled
(legacy_portal_session_enabled=False) and a fake Supabase auth callback
provides operator identity.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import case_dashboard.routes as routes_mod
import pytest
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import SESSION_ENVELOPE_COOKIE_NAME
from starlette.testclient import TestClient

from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    operator_principal,
    operator_envelope,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        supabase_auth=ReauthFakeSupabaseAuth(),
        legacy_portal_session_enabled=False,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def active_case_dir(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "test-case"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: test-case\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    return case_dir


@pytest.fixture()
def examiner_cookie():
    """Session envelope cookie dict for the default operator (alice/examiner)."""
    return {SESSION_ENVELOPE_COOKIE_NAME: operator_envelope(_SECRET)}


def _todos_on_disk(case_dir: Path) -> list:
    return json.loads((case_dir / "todos.json").read_text())


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class TestCreateTodo:
    def test_creates_todo_with_canonical_schema(self, client, active_case_dir, examiner_cookie):
        resp = client.post(
            "/api/todos",
            json={"description": "Carve the pagefile", "priority": "high"},
            cookies=examiner_cookie,
        )
        assert resp.status_code == 201
        todo = resp.json()
        assert todo["todo_id"] == "TODO-alice-001"
        assert todo["description"] == "Carve the pagefile"
        assert todo["status"] == "open"
        assert todo["priority"] == "high"
        assert todo["created_by"] == "alice"
        assert todo["examiner"] == "alice"
        assert todo["related_findings"] == []
        assert todo["completed_at"] is None
        assert todo["notes"] == []
        # Persisted
        assert _todos_on_disk(active_case_dir)[0]["todo_id"] == "TODO-alice-001"

    def test_sequence_increments_per_examiner(self, client, active_case_dir, examiner_cookie):
        for _ in range(3):
            client.post("/api/todos", json={"description": "x"}, cookies=examiner_cookie)
        ids = [t["todo_id"] for t in _todos_on_disk(active_case_dir)]
        assert ids == ["TODO-alice-001", "TODO-alice-002", "TODO-alice-003"]

    def test_default_priority_is_medium(self, client, active_case_dir, examiner_cookie):
        resp = client.post("/api/todos", json={"description": "x"}, cookies=examiner_cookie)
        assert resp.json()["priority"] == "medium"

    def test_related_findings_preserved(self, client, active_case_dir, examiner_cookie):
        resp = client.post(
            "/api/todos",
            json={"description": "x", "related_findings": ["F-001", "F-002"]},
            cookies=examiner_cookie,
        )
        assert resp.json()["related_findings"] == ["F-001", "F-002"]

    def test_empty_description_rejected(self, client, active_case_dir, examiner_cookie):
        resp = client.post("/api/todos", json={"description": "   "}, cookies=examiner_cookie)
        assert resp.status_code == 400

    def test_invalid_priority_rejected(self, client, active_case_dir, examiner_cookie):
        resp = client.post(
            "/api/todos",
            json={"description": "x", "priority": "urgent"},
            cookies=examiner_cookie,
        )
        assert resp.status_code == 400

    def test_bad_related_findings_rejected(self, client, active_case_dir, examiner_cookie):
        resp = client.post(
            "/api/todos",
            json={"description": "x", "related_findings": "F-001"},
            cookies=examiner_cookie,
        )
        assert resp.status_code == 400

    def test_requires_auth(self, client, active_case_dir):
        # No session → role check fails first (403), same ordering as /api/delta.
        resp = client.post("/api/todos", json={"description": "x"})
        assert resp.status_code == 403

    def test_readonly_role_forbidden(self, active_case_dir, tmp_path, monkeypatch):
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path / "passwords")
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(system_role="readonly")
            ),
            legacy_portal_session_enabled=False,
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.post("/api/todos", json={"description": "x"})
        assert resp.status_code == 403

    def test_must_reset_forbidden(self, active_case_dir, passwords_dir, tmp_path, monkeypatch):
        # CL3b: the forced-reset write block now derives from the Supabase
        # 'invited' status on the session principal (not a file flag), so it is
        # exercised through a Supabase-envelope session for an invited operator.
        from _supabase_reauth_harness import (
            ReauthFakeSupabaseAuth,
            operator_principal,
            set_operator_session,
        )

        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(status="invited"),
            ),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.post("/api/todos", json={"description": "x"})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


class TestUpdateTodo:
    def _create(self, client, cookie, **kw):
        body = {"description": "task", **kw}
        return client.post("/api/todos", json=body, cookies=cookie).json()["todo_id"]

    def test_update_fields(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        resp = client.patch(
            f"/api/todos/{tid}",
            json={"description": "renamed", "priority": "low"},
            cookies=examiner_cookie,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["description"] == "renamed"
        assert body["priority"] == "low"

    def test_complete_sets_completed_at(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        resp = client.patch(
            f"/api/todos/{tid}", json={"status": "completed"}, cookies=examiner_cookie
        )
        assert resp.json()["status"] == "completed"
        assert resp.json()["completed_at"] is not None

    def test_reopen_clears_completed_at(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        client.patch(f"/api/todos/{tid}", json={"status": "completed"}, cookies=examiner_cookie)
        resp = client.patch(
            f"/api/todos/{tid}", json={"status": "open"}, cookies=examiner_cookie
        )
        assert resp.json()["status"] == "open"
        assert resp.json()["completed_at"] is None

    def test_note_appended(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        resp = client.patch(
            f"/api/todos/{tid}", json={"note": "looked at it"}, cookies=examiner_cookie
        )
        notes = resp.json()["notes"]
        assert len(notes) == 1
        assert notes[0]["note"] == "looked at it"
        assert notes[0]["by"] == "alice"

    def test_empty_description_rejected(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        resp = client.patch(
            f"/api/todos/{tid}", json={"description": " "}, cookies=examiner_cookie
        )
        assert resp.status_code == 400

    def test_invalid_status_rejected(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        resp = client.patch(
            f"/api/todos/{tid}", json={"status": "done"}, cookies=examiner_cookie
        )
        assert resp.status_code == 400

    def test_not_found(self, client, active_case_dir, examiner_cookie):
        resp = client.patch(
            "/api/todos/TODO-alice-999", json={"status": "open"}, cookies=examiner_cookie
        )
        assert resp.status_code == 404

    def test_readonly_forbidden(self, client, active_case_dir, examiner_cookie, tmp_path, monkeypatch):
        tid = self._create(client, examiner_cookie)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path / "passwords")
        ro_app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(system_role="readonly")
            ),
            legacy_portal_session_enabled=False,
        )
        ro_client = TestClient(ro_app, raise_server_exceptions=True)
        set_operator_session(ro_client, _SECRET)
        resp = ro_client.patch(f"/api/todos/{tid}", json={"status": "completed"})
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


class TestDeleteTodo:
    def _create(self, client, cookie):
        return client.post(
            "/api/todos", json={"description": "task"}, cookies=cookie
        ).json()["todo_id"]

    def test_delete_removes_todo(self, client, active_case_dir, examiner_cookie):
        tid = self._create(client, examiner_cookie)
        resp = client.delete(f"/api/todos/{tid}", cookies=examiner_cookie)
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
        assert _todos_on_disk(active_case_dir) == []

    def test_delete_only_targets_matching_id(self, client, active_case_dir, examiner_cookie):
        keep = self._create(client, examiner_cookie)
        drop = self._create(client, examiner_cookie)
        client.delete(f"/api/todos/{drop}", cookies=examiner_cookie)
        remaining = [t["todo_id"] for t in _todos_on_disk(active_case_dir)]
        assert remaining == [keep]

    def test_not_found(self, client, active_case_dir, examiner_cookie):
        resp = client.delete("/api/todos/TODO-alice-999", cookies=examiner_cookie)
        assert resp.status_code == 404

    def test_requires_auth(self, client, active_case_dir):
        # No session → role check fails first (403), same ordering as /api/delta.
        resp = client.delete("/api/todos/TODO-alice-001")
        assert resp.status_code == 403

    def test_readonly_forbidden(self, client, active_case_dir, examiner_cookie, tmp_path, monkeypatch):
        tid = self._create(client, examiner_cookie)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path / "passwords")
        ro_app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(system_role="readonly")
            ),
            legacy_portal_session_enabled=False,
        )
        ro_client = TestClient(ro_app, raise_server_exceptions=True)
        set_operator_session(ro_client, _SECRET)
        resp = ro_client.delete(f"/api/todos/{tid}")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Round-trip with GET
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_created_todo_appears_in_get(self, client, active_case_dir, examiner_cookie):
        client.post("/api/todos", json={"description": "find it"}, cookies=examiner_cookie)
        resp = client.get("/api/todos", cookies=examiner_cookie)
        assert resp.status_code == 200
        assert any(t["description"] == "find it" for t in resp.json())
