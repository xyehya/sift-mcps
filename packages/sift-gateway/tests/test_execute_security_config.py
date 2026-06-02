import os
from pathlib import Path

import pytest
import yaml

from sift_core.execute.catalog import load_security_policy
from sift_core.execute.security_policy import SECURITY_POLICY_ENV
from sift_gateway.config import EXECUTE_AS_USER_ENV, load_config


def test_gateway_config_exports_effective_executor_policy(tmp_path, monkeypatch):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "case": {"root": str(tmp_path / "cases"), "dir": ""},
                "execute": {
                    "runtime_user": "agent_runtime",
                    "security": {"denied_binaries": ["echo"]},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv(SECURITY_POLICY_ENV, raising=False)
    monkeypatch.delenv(EXECUTE_AS_USER_ENV, raising=False)

    load_config(str(cfg_path))

    assert os.environ[SECURITY_POLICY_ENV]
    policy = load_security_policy()
    assert policy["mode"] == "denylist"
    assert "echo" in policy["denied_binaries"]
    assert "env" in policy["denied_binaries"]
    assert Path(os.environ["SIFT_CASES_ROOT"]) == tmp_path / "cases"
    assert os.environ[EXECUTE_AS_USER_ENV] == "agent_runtime"


def test_gateway_config_exports_allowlist_executor_policy(tmp_path, monkeypatch):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "case": {"root": str(tmp_path / "cases"), "dir": ""},
                "execute": {
                    "runtime_user": "__current__",
                    "security": {
                        "mode": "allowlist",
                        "allowed_binaries": ["date"],
                        "denied_binaries": ["echo"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv(SECURITY_POLICY_ENV, raising=False)
    monkeypatch.delenv(EXECUTE_AS_USER_ENV, raising=False)

    load_config(str(cfg_path))

    policy = load_security_policy()
    assert policy["mode"] == "allowlist"
    assert "date" in policy["allowed_binaries"]
    assert "echo" in policy["denied_binaries"]
    assert "env" in policy["denied_binaries"]
    assert os.environ[EXECUTE_AS_USER_ENV] == "__current__"


def test_gateway_config_rejects_empty_executor_policy(tmp_path):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "case": {"root": str(tmp_path / "cases"), "dir": ""},
                "execute": {"security": {}},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cannot be empty"):
        load_config(str(cfg_path))


def test_gateway_config_requires_executor_policy(tmp_path):
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump({"case": {"root": str(tmp_path / "cases"), "dir": ""}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="execute.security is required"):
        load_config(str(cfg_path))
