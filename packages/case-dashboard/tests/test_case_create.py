import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

import case_dashboard.routes as routes_mod
import pytest
import yaml
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    """Redirect _PASSWORDS_DIR to a temp directory for test isolation."""
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def case_env(tmp_path, monkeypatch):
    """Setup temporary case root and gateway config."""
    case_root = tmp_path / "cases"
    case_root.mkdir(parents=True, exist_ok=True)

    cfg_path = tmp_path / "gateway.yaml"
    config = {
        "case": {
            "root": str(case_root),
            "dir": ""
        }
    }
    cfg_path.write_text(yaml.dump(config), encoding="utf-8")

    monkeypatch.setenv("SIFT_CASES_ROOT", str(case_root))
    monkeypatch.setattr(routes_mod, "_GATEWAY_CONFIG_PATH", cfg_path)

    return case_root, cfg_path


@pytest.fixture()
def app(passwords_dir, case_env, tmp_path, monkeypatch):
    # Redirect Path.home() so lockout files land in tmp, not ~/.sift
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(case_env[1])
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


def _setup_cookie(client, examiner="alice", role="examiner", must_reset=False, passwords_dir=None):
    if passwords_dir:
        passwords_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "hash": "dummyhash",
            "salt": "dummysalt",
            "must_reset_password": must_reset
        }
        (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))

    token = generate_jwt(examiner, role, _SECRET, max_age=3600)
    client.cookies[COOKIE_NAME] = token
    return token


def test_unauthorized_returns_401(client):
    resp = client.post("/api/case/create", json={
        "casename": "case1",
        "title": "Case 1",
    })
    assert resp.status_code == 401


def test_readonly_role_returns_403(client, passwords_dir):
    _setup_cookie(client, examiner="alice", role="readonly", passwords_dir=passwords_dir)
    resp = client.post("/api/case/create", json={
        "casename": "case1",
        "title": "Case 1",
    })
    assert resp.status_code == 403


def test_must_reset_password_returns_403(passwords_dir, tmp_path, monkeypatch):
    # CL3b: forced-reset now derives from the Supabase 'invited' status on the
    # session principal, not a file flag.
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
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    resp = client.post("/api/case/create", json={
        "casename": "case1",
        "title": "Case 1",
    })
    assert resp.status_code == 403


def test_portal_case_create_lowercases_casename(client, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    resp = client.post("/api/case/create", json={
        "casename": "Case1",
        "title": "Case 1",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "casename must be lowercase"


def test_portal_case_create_rejects_free_form_directory(client, case_env, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    resp = client.post("/api/case/create", json={
        "casename": "case1",
        "title": "Case 1",
        "dir": str(case_env[0] / "case1"),
    })
    assert resp.status_code == 400
    assert "computed by the portal" in resp.json()["error"]


def test_case_id_format_validation_regex():
    # A1-BOOTSTRAP: strict format case-<slug>-<MMDDHHSS> (8-digit timestamp)
    assert routes_mod._valid_case_id("case-rocba-cdrive-05251433")  # frozen format
    assert routes_mod._valid_case_id("case-brief-case-05251400")    # frozen format
    # Legacy slugs still accepted (backwards compat)
    assert routes_mod._valid_case_id("case-20260525-1412")
    assert routes_mod._valid_case_id("rocba_cdrive-20260525-1412")
    # Invalid cases
    assert not routes_mod._valid_case_id("Case-20260525-1412")
    assert not routes_mod._valid_case_id("1case-20260525-1412")
    assert not routes_mod._valid_case_id("c")
    assert not routes_mod._valid_case_id("case/escape-20260525-1412")


def test_portal_case_create_rejects_path_traversal(client, passwords_dir, monkeypatch):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    monkeypatch.setattr(routes_mod, "_slugify_case_name", lambda _: "../escape")
    monkeypatch.setattr(routes_mod, "_valid_case_id", lambda _: True)

    resp = client.post("/api/case/create", json={
        "casename": "case1",
        "title": "Case 1",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "Directory must be under case root"


def test_portal_case_create_computes_case_id_with_time(client, case_env, passwords_dir, monkeypatch):
    # A1-BOOTSTRAP: frozen format is case-<slug>-<MMDDHHSS> where MMDDHHSS =
    # strftime("%m%d%H%S") on SIFT VM local time.
    # 2026-05-25T14:12:33 → MM=05 DD=25 HH=14 SS=33 → "05251433"
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 5, 25, 14, 12, 33, tzinfo=timezone.utc)
            return value if tz is None else value.astimezone(tz)

    case_root, cfg_path = case_env
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime)
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    resp = client.post("/api/case/create", json={
        "casename": "rocba cdrive!",
        "title": "ROCBA C Drive",
    })

    expected_id = "case-rocba-cdrive-05251433"
    expected_dir = case_root / expected_id
    assert resp.status_code == 200
    assert resp.json()["case_id"] == expected_id
    assert resp.json()["case_dir"] == str(expected_dir)

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    assert cfg["case"]["dir"] == ""


def test_successful_case_creation(client, case_env, passwords_dir, monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 5, 25, 14, 13, 0, tzinfo=timezone.utc)
            return value if tz is None else value.astimezone(tz)

    case_root, cfg_path = case_env
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime)
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    # A1-BOOTSTRAP: frozen format case-<slug>-<MMDDHHSS>.
    # casename "case-2026-001" → slug "case-2026-001" → id "case-case-2026-001-<MMDDHHSS>"
    # 2026-05-25T14:13:00 → MMDDHHSS = strftime("%m%d%H%S") = "05251400"
    requested_dir = case_root / "case-case-2026-001-05251400"

    resp = client.post("/api/case/create", json={
        "casename": "case-2026-001",
        "title": "Case 2026 001",
    })

    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["case_id"] == "case-case-2026-001-05251400"
    assert resp.json()["case_dir"] == str(requested_dir)

    assert requested_dir.exists()
    assert (requested_dir / "audit").is_dir()
    assert (requested_dir / "evidence").is_dir()
    assert (requested_dir / "extractions").is_dir()
    assert (requested_dir / "reports").is_dir()
    assert (requested_dir / "agent").is_dir()

    case_yaml_path = requested_dir / "CASE.yaml"
    assert case_yaml_path.exists()
    with open(case_yaml_path) as f:
        meta = yaml.safe_load(f)
    assert meta["case_id"] == "case-case-2026-001-05251400"
    assert meta["title"] == "Case 2026 001"
    assert meta["status"] == "open"
    assert meta["examiner"] == "alice"
    assert meta["created_at"] == "2026-05-25T14:13:00+00:00"

    for fname in ("findings.json", "timeline.json", "todos.json", "iocs.json", "evidence-manifest.json"):
        assert (requested_dir / fname).exists()

    with open(requested_dir / "evidence-manifest.json") as f:
        manifest = json.load(f)
    assert manifest["version"] == 0
    assert manifest["files"] == []
    assert manifest["manifest_hash"].startswith("sha256:")

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    assert cfg["case"]["dir"] == ""

    assert os.environ.get("SIFT_CASE_DIR") != str(requested_dir)
    assert not (Path.home() / ".sift" / "active_case").exists()


def test_case_creation_persists_optional_synopsis(client, case_env, passwords_dir, monkeypatch):
    """D-006-note: an optional synopsis is stored as CASE.yaml `description`."""
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 5, 25, 14, 13, 0, tzinfo=timezone.utc)
            return value if tz is None else value.astimezone(tz)

    case_root, _cfg_path = case_env
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime)
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    resp = client.post("/api/case/create", json={
        "casename": "brief-case",
        "title": "Brief Case",
        "description": "Home break-in targeting an SRL-issued laptop; determine exfiltration.",
    })
    assert resp.status_code == 200
    # A1-BOOTSTRAP: frozen format case-<slug>-<MMDDHHSS> → "case-brief-case-05251400"
    case_dir = case_root / "case-brief-case-05251400"
    with open(case_dir / "CASE.yaml") as f:
        meta = yaml.safe_load(f)
    assert meta["description"].startswith("Home break-in")


def test_case_creation_invokes_runtime_acl_setup(client, case_env, passwords_dir, monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 5, 25, 14, 13, 0, tzinfo=timezone.utc)
            return value if tz is None else value.astimezone(tz)

    case_root, _cfg_path = case_env
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime)
    acl_cases = []
    monkeypatch.setattr(
        routes_mod,
        "_configure_agent_runtime_case_acl",
        lambda case_dir: acl_cases.append(case_dir) or {"status": "configured"},
    )
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    resp = client.post("/api/case/create", json={
        "casename": "runtime-acl",
        "title": "Runtime ACL",
    })

    expected_dir = case_root / "case-runtime-acl-05251400"
    assert resp.status_code == 200
    assert acl_cases == [expected_dir]


def test_runtime_acl_helper_sets_case_permissions(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    for subdir in ("agent", "evidence", "extractions", "audit"):
        (case_dir / subdir).mkdir(parents=True, exist_ok=True)
    for filename in ("approvals.jsonl", "evidence-ledger.jsonl", "evidence-manifest.json"):
        (case_dir / filename).write_text("", encoding="utf-8")

    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "agent_runtime")
    monkeypatch.setattr(routes_mod.pwd, "getpwnam", lambda name: object())
    monkeypatch.setattr(routes_mod.shutil, "which", lambda name: "/usr/bin/setfacl")
    calls = []

    class Result:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Result()

    monkeypatch.setattr(routes_mod.subprocess, "run", fake_run)

    result = routes_mod._configure_agent_runtime_case_acl(case_dir)

    assert result == {"status": "configured", "user": "agent_runtime"}
    assert (case_dir / "agent" / "run_commands").is_dir()
    assert (case_dir / "tmp").is_dir()
    assert any(cmd[-1] == str(case_dir) and "u:agent_runtime:r-x" in cmd for cmd in calls)
    assert any(
        cmd[-1] == str(case_dir / "agent" / "run_commands")
        and "u:agent_runtime:rwx" in cmd
        for cmd in calls
    )
    assert any(
        cmd[-1] == str(case_dir / "evidence") and "u:agent_runtime:r-x" in cmd
        for cmd in calls
    )
    assert any(
        cmd[-1] == str(case_dir / "audit") and "u:agent_runtime:---" in cmd
        for cmd in calls
    )


def test_runtime_acl_helper_skips_same_user_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "__current__")
    monkeypatch.setattr(
        routes_mod.subprocess,
        "run",
        lambda *a, **k: pytest.fail("setfacl must not run in same-user mode"),
    )
    assert routes_mod._configure_agent_runtime_case_acl(tmp_path) == {
        "status": "skipped",
        "reason": "same_user",
    }


def test_case_creation_rejects_oversized_synopsis(client, case_env, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    resp = client.post("/api/case/create", json={
        "casename": "big-case",
        "title": "Big Case",
        "description": "x" * 10_001,
    })
    assert resp.status_code == 400


def test_case_creation_invokes_activation_callback(passwords_dir, case_env, tmp_path, monkeypatch):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 5, 25, 14, 14, 0, tzinfo=timezone.utc)
            return value if tz is None else value.astimezone(tz)

    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime)
    _case_root, cfg_path = case_env
    activated = []

    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        on_case_activated=lambda case_dir: activated.append(case_dir),
    )
    client = TestClient(app, raise_server_exceptions=True)
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    resp = client.post("/api/case/create", json={
        "casename": "case-activation",
        "title": "Case Activation",
    })

    assert resp.status_code == 200
    assert activated == []


def test_concurrent_case_creation_returns_409(client, case_env, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    routes_mod._case_create_lock.acquire()

    try:
        resp = client.post("/api/case/create", json={
            "casename": "case-concurrent",
            "title": "Case Concurrent",
        })
        assert resp.status_code == 409
        assert resp.json()["error"] == "Another case creation is in progress"
    finally:
        routes_mod._case_create_lock.release()


def test_get_cases_returns_cases_list(client, case_env, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    case_root, _ = case_env
    # Create a couple of case directories with CASE.yaml
    case1_dir = case_root / "case-one-20260525-1414"
    case1_dir.mkdir(parents=True)
    (case1_dir / "CASE.yaml").write_text("case_id: case-one-20260525-1414\nname: Case One\n")

    case2_dir = case_root / "case-two-20260525-1414"
    case2_dir.mkdir(parents=True)
    (case2_dir / "CASE.yaml").write_text("case_id: case-two-20260525-1414\nname: Case Two\n")

    resp = client.get("/api/cases")
    assert resp.status_code == 200
    data = resp.json()
    assert "cases" in data
    case_ids = [c["id"] for c in data["cases"]]
    assert "case-one-20260525-1414" in case_ids
    assert "case-two-20260525-1414" in case_ids


def test_get_case_activate_challenge_file_backed_requires_supabase_reauth(client, passwords_dir):
    # CL3b: the file-backed activation challenge no longer mints a file-HMAC
    # nonce/salt. Without an active-case service wired it reports that re-auth is
    # required and routed through Supabase; the activation POST then re-verifies
    # the operator password against Supabase GoTrue (fail closed).
    token = generate_jwt("alice", "examiner", _SECRET, max_age=3600)
    client.cookies[COOKIE_NAME] = token
    resp = client.get("/api/case/activate/challenge")
    assert resp.status_code == 200
    body = resp.json()
    assert body["required"] is True
    assert body["authority"] == "supabase"


def test_supabase_db_case_routes_use_active_case_service(passwords_dir, case_env, tmp_path, monkeypatch):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    case_root, cfg_path = case_env

    class FakeCase:
        case_id = "db-uuid-1"
        case_key = "db-case"

        def as_dict(self):
            return {
                "case_id": self.case_id,
                "case_key": self.case_key,
                "title": "DB Case",
                "status": "active",
                "artifact_path": str(case_root / "db-case"),
                "case_dir": str(case_root / "db-case"),
                "metadata": {"severity": "high"},
            }

    class FakeActiveCases:
        def __init__(self):
            self.calls = []

        def list_cases(self, principal):
            self.calls.append(("list", principal))
            return [FakeCase().as_dict()]

        def get_active_case(self, principal=None):
            self.calls.append(("get_active", principal))
            return FakeCase()

        def set_active_case(self, case_id, principal):
            self.calls.append(("set", case_id, principal))
            return FakeCase()

        def update_case_metadata(self, case_id, principal, body):
            self.calls.append(("metadata", case_id, body))
            return FakeCase()

        def create_case(self, payload, principal):
            self.calls.append(("create", payload, principal))
            return FakeCase()

    # B-MVP-021 (CL3b): the DB-active activation branch now re-verifies the
    # operator password against Supabase before set_active_case. Drive the test
    # with a real operator session (Supabase envelope) + a reauth-capable fake.
    from _supabase_reauth_harness import (
        GOOD_PASSWORD,
        ReauthFakeSupabaseAuth,
        operator_principal,
        set_operator_session,
    )

    operator = operator_principal()
    active = FakeActiveCases()
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        supabase_auth=ReauthFakeSupabaseAuth(principal=operator),
        active_case_service=active,
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)

    assert client.get("/api/case/activate/challenge").json()["required"] is False
    assert client.get("/api/cases").json()["cases"][0]["case_key"] == "db-case"
    assert client.get("/api/case").json()["case_key"] == "db-case"
    assert client.post(
        "/api/case/activate", json={"case_id": "db-case", "password": GOOD_PASSWORD}
    ).json()["ok"] is True
    assert client.post("/api/case/metadata", json={"field": "severity", "value": "low"}).status_code == 200
    assert client.post("/api/case/create", json={"casename": "db-case", "title": "DB Case"}).status_code == 200

    assert ("set", "db-case", operator) in active.calls
    assert any(call[0] == "metadata" for call in active.calls)
    assert any(call[0] == "create" for call in active.calls)
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    assert cfg["case"]["dir"] == ""
    assert not (Path.home() / ".sift" / "active_case").exists()


def test_db_active_case_activate_denied_on_wrong_password(case_env, passwords_dir, tmp_path, monkeypatch):
    """B-MVP-021 (CL3b): the DB-active activation branch re-verifies against
    Supabase before set_active_case. A wrong password denies with NO activation."""
    from _supabase_reauth_harness import (
        ReauthFakeSupabaseAuth,
        operator_principal,
        set_operator_session,
    )

    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    case_root, cfg_path = case_env

    class _Case:
        case_id = "db-uuid-1"
        case_key = "db-case"

        def as_dict(self):
            return {"case_id": self.case_id, "case_key": self.case_key}

    class _ActiveCases:
        def __init__(self):
            self.calls = []

        def set_active_case(self, case_id, principal):
            self.calls.append(("set", case_id, principal))
            return _Case()

    active = _ActiveCases()
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        supabase_auth=ReauthFakeSupabaseAuth(principal=operator_principal()),
        active_case_service=active,
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)

    resp = client.post(
        "/api/case/activate", json={"case_id": "db-case", "password": "wrong-password"}
    )
    assert resp.status_code == 401
    # Fail closed: the active-case service was never asked to switch the case.
    assert not any(c[0] == "set" for c in active.calls)


def test_db_active_case_activate_denied_when_control_plane_down(case_env, passwords_dir, tmp_path, monkeypatch):
    """B-MVP-021 (CL3b): control plane unreachable -> 503, no activation."""
    from _supabase_reauth_harness import (
        GOOD_PASSWORD,
        ReauthFakeSupabaseAuth,
        operator_principal,
        set_operator_session,
    )

    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    case_root, cfg_path = case_env

    class _ActiveCases:
        def __init__(self):
            self.calls = []

        def set_active_case(self, case_id, principal):
            self.calls.append(("set", case_id, principal))
            raise AssertionError("set_active_case must not run when re-auth fails")

    active = _ActiveCases()
    fake = ReauthFakeSupabaseAuth(principal=operator_principal())
    fake.control_plane_down = True
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        supabase_auth=fake,
        active_case_service=active,
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)

    resp = client.post(
        "/api/case/activate", json={"case_id": "db-case", "password": GOOD_PASSWORD}
    )
    assert resp.status_code == 503
    assert not active.calls


def test_post_case_activate_success(case_env, passwords_dir, tmp_path, monkeypatch):
    """CL3a: the file-backed activation branch re-verifies the operator password
    against Supabase (fail closed), not the local HMAC challenge."""
    from _supabase_reauth_harness import (
        GOOD_PASSWORD,
        ReauthFakeSupabaseAuth,
        set_operator_session,
    )

    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    case_root, cfg_path = case_env
    # File-backed activation: no active-case service wired, Supabase re-auth on.
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)

    # Create the case to activate
    case_id = "case-to-activate-20260525-1414"
    case_dir = case_root / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\nname: To Activate\n")

    # Activate with the operator password (re-verified against Supabase).
    resp = client.post("/api/case/activate", json={
        "case_id": case_id,
        "password": GOOD_PASSWORD,
    })

    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert resp.json()["case_id"] == case_id

    # Verify gateway config was updated
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    assert cfg["case"]["dir"] == ""


def test_post_case_activate_wrong_password_denied(case_env, passwords_dir, tmp_path, monkeypatch):
    """CL3a: a wrong password is denied (401) and never activates the case."""
    from _supabase_reauth_harness import (
        ReauthFakeSupabaseAuth,
        set_operator_session,
    )

    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    case_root, cfg_path = case_env
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)

    case_id = "case-to-activate-20260525-1500"
    (case_root / case_id).mkdir(parents=True)
    (case_root / case_id / "CASE.yaml").write_text(f"case_id: {case_id}\n")

    resp = client.post("/api/case/activate", json={
        "case_id": case_id,
        "password": "wrong-password",
    })
    assert resp.status_code == 401
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    # Activation must not have changed the case dir.
    assert cfg["case"]["dir"] == ""
