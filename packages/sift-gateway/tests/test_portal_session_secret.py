"""B-MVP-010: portal session secret env-indirection in config loading."""

import yaml

from sift_gateway.config import load_config, resolve_portal_session_secret


def _execute_security():
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def test_session_secret_resolved_from_env(tmp_path, monkeypatch):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "portal": {"session_secret_env": "SIFT_PORTAL_SESSION_SECRET"},
                **_execute_security(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SIFT_PORTAL_SESSION_SECRET", "deadbeef" * 8)

    config = load_config(str(cfg_path))

    # The loader populates the literal in-memory from the named env var so the
    # rest of the gateway (server.py) reads portal.session_secret unchanged.
    assert config["portal"]["session_secret"] == "deadbeef" * 8


def test_no_literal_session_secret_in_config_file(tmp_path, monkeypatch):
    """The committed config must NOT carry a literal secret — only the env name."""
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "portal": {"session_secret_env": "SIFT_PORTAL_SESSION_SECRET"},
                **_execute_security(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("SIFT_PORTAL_SESSION_SECRET", raising=False)

    raw = yaml.safe_load(cfg_path.read_text())
    assert "session_secret" not in raw["portal"]
    assert raw["portal"]["session_secret_env"] == "SIFT_PORTAL_SESSION_SECRET"


def test_literal_session_secret_still_honored_back_compat():
    """Older configs with a literal session_secret keep working unchanged."""
    config = {"portal": {"session_secret": "legacy-literal"}}
    resolve_portal_session_secret(config)
    assert config["portal"]["session_secret"] == "legacy-literal"


def test_env_indirection_overrides_when_set(monkeypatch):
    monkeypatch.setenv("MY_SECRET_ENV", "from-env")
    config = {"portal": {"session_secret_env": "MY_SECRET_ENV"}}
    resolve_portal_session_secret(config)
    assert config["portal"]["session_secret"] == "from-env"


def test_empty_env_does_not_clobber_existing_literal(monkeypatch):
    monkeypatch.delenv("MISSING_ENV", raising=False)
    config = {"portal": {"session_secret_env": "MISSING_ENV", "session_secret": "kept"}}
    resolve_portal_session_secret(config)
    assert config["portal"]["session_secret"] == "kept"
