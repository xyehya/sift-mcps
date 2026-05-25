import json
import os
import secrets
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
    
    monkeypatch.setenv("AGENTIR_CASES_ROOT", str(case_root))
    monkeypatch.setattr(routes_mod, "_GATEWAY_CONFIG_PATH", cfg_path)
    
    return case_root, cfg_path


@pytest.fixture()
def app(passwords_dir, case_env, tmp_path, monkeypatch):
    # Redirect Path.home() so lockout files land in tmp, not ~/.agentir
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
        "case_id": "case1",
        "title": "Case 1",
        "dir": "/cases/case1"
    })
    assert resp.status_code == 401


def test_readonly_role_returns_403(client, passwords_dir):
    _setup_cookie(client, examiner="alice", role="readonly", passwords_dir=passwords_dir)
    resp = client.post("/api/case/create", json={
        "case_id": "case1",
        "title": "Case 1",
        "dir": "/cases/case1"
    })
    assert resp.status_code == 403


def test_must_reset_password_returns_403(client, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", must_reset=True, passwords_dir=passwords_dir)
    resp = client.post("/api/case/create", json={
        "case_id": "case1",
        "title": "Case 1",
        "dir": "/cases/case1"
    })
    assert resp.status_code == 403


def test_invalid_case_id_returns_400(client, passwords_dir):
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    resp = client.post("/api/case/create", json={
        "case_id": "Case1!",  # Upper case, special chars
        "title": "Case 1",
        "dir": "/cases/case1"
    })
    assert resp.status_code == 400


def test_symlink_escape_returns_400(client, case_env, passwords_dir):
    case_root, _ = case_env
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    
    outside_dir = case_root.parent / "outside_dir"
    
    resp = client.post("/api/case/create", json={
        "case_id": "case1",
        "title": "Case 1",
        "dir": str(outside_dir)
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "Directory must be under case root"


def test_successful_case_creation(client, case_env, passwords_dir):
    case_root, cfg_path = case_env
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    
    requested_dir = case_root / "case-2026-001"
    
    resp = client.post("/api/case/create", json={
        "case_id": "case-2026-001",
        "title": "Case 2026 001",
        "dir": str(requested_dir)
    })
    
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["case_dir"] == str(requested_dir)
    
    assert requested_dir.exists()
    assert (requested_dir / "audit").is_dir()
    assert (requested_dir / "evidence").is_dir()
    assert (requested_dir / "extractions").is_dir()
    assert (requested_dir / "reports").is_dir()
    
    case_yaml_path = requested_dir / "CASE.yaml"
    assert case_yaml_path.exists()
    with open(case_yaml_path) as f:
        meta = yaml.safe_load(f)
    assert meta["case_id"] == "case-2026-001"
    assert meta["title"] == "Case 2026 001"
    assert meta["status"] == "open"
    assert meta["examiner"] == "alice"
    
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
    
    assert os.environ.get("AGENTIR_CASE_DIR") == str(requested_dir)
    assert os.environ.get("AGENTIR_CASES_ROOT") == str(case_root)
    assert (Path.home() / ".agentir" / "active_case").read_text().strip() == str(requested_dir)


def test_case_creation_invokes_activation_callback(passwords_dir, case_env, tmp_path, monkeypatch):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
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

    requested_dir = case_root / "case-activation"
    resp = client.post("/api/case/create", json={
        "case_id": "case-activation",
        "title": "Case Activation",
        "dir": str(requested_dir)
    })

    assert resp.status_code == 200
    assert activated == [str(requested_dir)]


def test_concurrent_case_creation_returns_409(client, case_env, passwords_dir):
    case_root, _ = case_env
    _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
    
    requested_dir = case_root / "case-concurrent"
    
    routes_mod._case_create_lock.acquire()
    
    try:
        resp = client.post("/api/case/create", json={
            "case_id": "case-concurrent",
            "title": "Case Concurrent",
            "dir": str(requested_dir)
        })
        assert resp.status_code == 409
        assert resp.json()["error"] == "Another case creation is in progress"
    finally:
        routes_mod._case_create_lock.release()
