"""BU2: portal case writes are DB-only + re-auth on metadata edit + CASE.yaml export.

In DB-authority mode (active-case + evidence DB services wired):
  - editing case metadata is a sensitive action gated by the same fail-closed
    Supabase re-auth as evidence seal / report export, and writes app.cases only;
  - after a successful create/edit the on-disk CASE.yaml is a NON-AUTHORITATIVE
    DB->file compat export, never an authority write.
"""

from __future__ import annotations

import secrets

import yaml
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app

from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)
_CASE_ID = "11111111-1111-1111-1111-111111111111"


class _FakeCase:
    def __init__(self, artifact_path, *, metadata=None, title="Edited", status="active"):
        self.case_id = _CASE_ID
        self.case_key = "inc-bu2"
        self.artifact_path = str(artifact_path)
        self._metadata = metadata or {"examiner": "alice", "severity": "high"}
        self._title = title
        self._status = status

    def as_dict(self):
        return {
            "case_id": self.case_id,
            "case_key": self.case_key,
            "title": self._title,
            "name": self._title,
            "description": "d",
            "status": self._status,
            "artifact_path": self.artifact_path,
            "case_dir": self.artifact_path,
            "metadata": dict(self._metadata),
            "membership_role": "owner",
        }


class _FakeActiveCases:
    def __init__(self, artifact_path):
        self.artifact_path = artifact_path
        self.update_calls: list = []
        self.create_calls: list = []

    def get_active_case(self, principal=None):
        return _FakeCase(self.artifact_path)

    def update_case_metadata(self, case_id, principal, body):
        self.update_calls.append((case_id, dict(body)))
        meta = {"examiner": "alice", str(body.get("field", "severity")): body.get("value", "x")}
        return _FakeCase(self.artifact_path, metadata=meta)

    def create_case(self, payload, principal):
        self.create_calls.append(dict(payload))
        return _FakeCase(
            payload["artifact_path"],
            metadata=payload.get("metadata") or {},
            title=payload.get("title", "x"),
            status=payload.get("status", "open"),
        )


class _FakeEvidenceDB:
    def __init__(self):
        self.reauth_calls: list = []

    def record_reauth_event(self, *, case_id, actor, examiner, action):
        self.reauth_calls.append((examiner, action))
        return "audit-evt-bu2"

    def gate_status(self, case_id):
        return {"seal_status": "unsealed", "manifest_version": 0, "active_count": 0,
                "issues": [], "head_hash": "", "last_verified_at": None}

    def list_evidence(self, case_id):
        return []


def _build(tmp_path, *, fake_auth, with_evidence=True):
    active = _FakeActiveCases(tmp_path)
    ev = _FakeEvidenceDB() if with_evidence else None
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        active_case_service=active,
        evidence_service=ev,
        supabase_auth=fake_auth,
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    return client, active, ev


def _edit(client, **body):
    return client.post("/api/case/metadata", json=body)


class TestMetadataEditReauth:
    def test_missing_password_denied_403_no_write(self, tmp_path):
        client, active, ev = _build(tmp_path, fake_auth=ReauthFakeSupabaseAuth())
        resp = _edit(client, field="severity", value="high")
        assert resp.status_code == 403
        assert "password" in resp.json()["error"].lower()
        assert active.update_calls == []
        assert ev.reauth_calls == []

    def test_wrong_password_denied_no_write_no_reauth(self, tmp_path):
        client, active, ev = _build(tmp_path, fake_auth=ReauthFakeSupabaseAuth())
        resp = _edit(client, field="severity", value="high", password="wrong-password")
        assert resp.status_code == 401
        assert active.update_calls == []
        assert ev.reauth_calls == []

    def test_control_plane_down_fails_closed_no_write(self, tmp_path):
        client, active, ev = _build(
            tmp_path, fake_auth=ReauthFakeSupabaseAuth(control_plane_down=True)
        )
        resp = _edit(client, field="severity", value="high", password=GOOD_PASSWORD)
        assert resp.status_code == 503
        assert active.update_calls == []
        assert ev.reauth_calls == []

    def test_good_password_writes_db_records_reauth_and_exports(self, tmp_path):
        client, active, ev = _build(tmp_path, fake_auth=ReauthFakeSupabaseAuth())
        resp = _edit(client, field="severity", value="high", password=GOOD_PASSWORD)
        assert resp.status_code == 200
        # DB-shaped response (the DB write is the sole authority), not the file
        # setter's {"status": "set", ...}.
        assert resp.json()["case_key"] == "inc-bu2"
        assert active.update_calls and active.update_calls[0][1]["field"] == "severity"
        assert ev.reauth_calls == [("alice", "case.metadata.update")]
        # CASE.yaml refreshed as a NON-AUTHORITATIVE export from DB.
        text = (tmp_path / "CASE.yaml").read_text()
        assert text.startswith("# NON-AUTHORITATIVE")
        meta = yaml.safe_load(text)
        assert meta["compat_export"]["authoritative"] is False
        assert meta["compat_export"]["source"] == "postgres"
        assert meta["severity"] == "high"


class TestCaseCreateExport:
    def test_create_db_mode_writes_nonauthoritative_export(self, tmp_path, monkeypatch):
        case_root = tmp_path / "cases"
        case_root.mkdir()
        monkeypatch.setenv("SIFT_CASES_ROOT", str(case_root))
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)

        client, active, ev = _build(tmp_path, fake_auth=ReauthFakeSupabaseAuth())
        resp = client.post(
            "/api/case/create", json={"casename": "bu2case", "title": "BU2 Case"}
        )
        assert resp.status_code == 200, resp.text
        assert active.create_calls, "create_case must be the DB authority write"

        created_dir = active.create_calls[0]["artifact_path"]
        text = (routes_mod.Path(created_dir) / "CASE.yaml").read_text()
        # The on-disk file is the non-authoritative DB->file export, not an
        # authority write.
        assert text.startswith("# NON-AUTHORITATIVE")
        meta = yaml.safe_load(text)
        assert meta["compat_export"]["authoritative"] is False
        assert meta["name"] == "BU2 Case"
