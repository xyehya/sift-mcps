import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt

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


def test_must_reset_password_returns_403(client, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", must_reset=True, passwords_dir=passwords_dir)
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
    assert routes_mod._valid_case_id("case-20260525-1412")
    assert routes_mod._valid_case_id("rocba_cdrive-20260525-1412")
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

    expected_id = "rocba-cdrive-20260525-1412"
    expected_dir = case_root / expected_id
    assert resp.status_code == 200
    assert resp.json()["case_id"] == expected_id
    assert resp.json()["case_dir"] == str(expected_dir)

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    assert cfg["case"]["dir"] == str(expected_dir)


def test_successful_case_creation(client, case_env, passwords_dir, monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = cls(2026, 5, 25, 14, 13, 0, tzinfo=timezone.utc)
            return value if tz is None else value.astimezone(tz)

    case_root, cfg_path = case_env
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime)
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    requested_dir = case_root / "case-2026-001-20260525-1413"

    resp = client.post("/api/case/create", json={
        "casename": "case-2026-001",
        "title": "Case 2026 001",
    })

    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["case_id"] == "case-2026-001-20260525-1413"
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
    assert meta["case_id"] == "case-2026-001-20260525-1413"
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
    assert cfg["case"]["dir"] == str(requested_dir)

    assert os.environ.get("SIFT_CASE_DIR") == str(requested_dir)
    assert os.environ.get("SIFT_CASES_ROOT") == str(case_root)
    assert (Path.home() / ".sift" / "active_case").read_text().strip() == str(requested_dir)


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
    case_dir = case_root / "brief-case-20260525-1413"
    with open(case_dir / "CASE.yaml") as f:
        meta = yaml.safe_load(f)
    assert meta["description"].startswith("Home break-in")


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
    case_root, cfg_path = case_env
    activated = []

    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        gateway_config_path=str(cfg_path),
        on_case_activated=lambda case_dir: activated.append(case_dir),
    )
    client = TestClient(app, raise_server_exceptions=True)
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

    requested_dir = case_root / "case-activation-20260525-1414"
    resp = client.post("/api/case/create", json={
        "casename": "case-activation",
        "title": "Case Activation",
    })

    assert resp.status_code == 200
    assert activated == [str(requested_dir)]


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


def test_get_case_activate_challenge_requires_password_setup(client, passwords_dir):
    # Setup examiner cookie but do NOT write password entry (no entry exists)
    token = generate_jwt("alice", "examiner", _SECRET, max_age=3600)
    client.cookies[COOKIE_NAME] = token
    resp = client.get("/api/case/activate/challenge")
    assert resp.status_code == 403
    assert "No password configured" in resp.json()["error"]


def test_post_case_activate_success(client, case_env, passwords_dir, monkeypatch):
    import hmac
    import hashlib

    # 1. Setup examiner password and cookie
    examiner = "alice"
    passwords_dir.mkdir(parents=True, exist_ok=True)
    pbkdf2_bin = hashlib.pbkdf2_hmac("sha256", b"password123", b"salt123", 600000)
    entry = {
        "hash": pbkdf2_bin.hex(),
        "salt": "salt123",
        "must_reset_password": False
    }
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))

    token = generate_jwt(examiner, "examiner", _SECRET, max_age=3600)
    client.cookies[COOKIE_NAME] = token

    case_root, cfg_path = case_env
    # Create the case to activate
    case_id = "case-to-activate-20260525-1414"
    case_dir = case_root / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\nname: To Activate\n")

    # 2. Get challenge
    resp = client.get("/api/case/activate/challenge")
    assert resp.status_code == 200
    chal = resp.json()
    assert "challenge_id" in chal
    assert "nonce" in chal

    # Verify salt/iterations match entry
    assert chal["salt"] == "salt123"
    assert chal["iterations"] == 600000

    # 3. Compute response: HMAC-SHA256(stored_pbkdf2_hash, nonce)
    expected_response = hmac.new(
        pbkdf2_bin, chal["nonce"].encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # 4. Activate
    resp = client.post("/api/case/activate", json={
        "case_id": case_id,
        "challenge_id": chal["challenge_id"],
        "response": expected_response
    })

    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["case_id"] == case_id

    # Verify gateway config was updated
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    assert cfg["case"]["dir"] == str(case_dir)
