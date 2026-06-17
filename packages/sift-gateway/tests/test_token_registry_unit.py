"""Unit tests for sift_gateway.token_registry — config parsing and factory."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest import mock

import pytest
from sift_gateway.token_registry import (
    CONTROL_PLANE_DSN_ENV,
    TOKEN_PEPPER_ENV,
    RegistryToken,
    create_token_registry,
    registry_config,
)


class TestRegistryToken:
    def test_frozen_dataclass(self):
        t = RegistryToken(
            id="tok-1",
            token_fingerprint="abcd1234",
            role="agent",
            principal="agent-1",
            principal_type="agent",
            agent_id="a-1",
            service_identity_id=None,
            created_by="user-1",
            case_id="case-1",
            label="test",
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            scopes=frozenset(["tools:read"]),
        )
        assert t.role == "agent"
        assert "tools:read" in t.scopes
        with pytest.raises(AttributeError):
            t.role = "admin"  # type: ignore[misc]

    def test_default_scopes(self):
        t = RegistryToken(
            id="tok-2",
            token_fingerprint="abcd1234",
            role="service",
            principal="svc-1",
            principal_type="service",
            agent_id=None,
            service_identity_id="svc-uuid",
            created_by=None,
            case_id=None,
            label=None,
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        assert t.scopes == frozenset()


class TestRegistryConfig:
    def test_empty_config(self):
        env = os.environ.copy()
        env.pop(CONTROL_PLANE_DSN_ENV, None)
        env.pop(TOKEN_PEPPER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            dsn, pepper = registry_config({})
            assert dsn is None
            assert pepper is None

    def test_config_from_dict(self):
        config = {
            "control_plane": {"postgres_dsn": "postgresql://localhost/sift"},
            "token_registry": {"pepper": "my-pepper"},
        }
        dsn, pepper = registry_config(config)
        assert dsn == "postgresql://localhost/sift"
        assert pepper == "my-pepper"

    def test_dsn_from_env(self):
        env = os.environ.copy()
        env[CONTROL_PLANE_DSN_ENV] = "postgresql://env/sift"
        env.pop(TOKEN_PEPPER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            dsn, pepper = registry_config({})
            assert dsn == "postgresql://env/sift"
            assert pepper is None

    def test_pepper_from_env(self):
        env = os.environ.copy()
        env.pop(CONTROL_PLANE_DSN_ENV, None)
        env[TOKEN_PEPPER_ENV] = "env-pepper"
        with mock.patch.dict(os.environ, env, clear=True):
            dsn, pepper = registry_config({})
            assert dsn is None
            assert pepper == "env-pepper"

    def test_custom_env_var_names(self):
        env = os.environ.copy()
        env["CUSTOM_DSN"] = "postgresql://custom/db"
        env["CUSTOM_PEPPER"] = "custom-pep"
        env.pop(CONTROL_PLANE_DSN_ENV, None)
        env.pop(TOKEN_PEPPER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            config = {
                "control_plane": {"postgres_dsn_env": "CUSTOM_DSN"},
                "token_registry": {"pepper_env": "CUSTOM_PEPPER"},
            }
            dsn, pepper = registry_config(config)
            assert dsn == "postgresql://custom/db"
            assert pepper == "custom-pep"

    def test_non_dict_sections_tolerated(self):
        config = {
            "token_registry": "not-a-dict",
            "control_plane": "also-not-a-dict",
        }
        env = os.environ.copy()
        env.pop(CONTROL_PLANE_DSN_ENV, None)
        env.pop(TOKEN_PEPPER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            dsn, pepper = registry_config(config)
            assert dsn is None
            assert pepper is None


class TestCreateTokenRegistry:
    def test_no_dsn_returns_none(self):
        env = os.environ.copy()
        env.pop(CONTROL_PLANE_DSN_ENV, None)
        env.pop(TOKEN_PEPPER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            assert create_token_registry({}) is None

    def test_no_pepper_returns_none(self):
        config = {"control_plane": {"postgres_dsn": "postgresql://localhost/sift"}}
        env = os.environ.copy()
        env.pop(TOKEN_PEPPER_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True):
            assert create_token_registry(config) is None

    def test_both_present_returns_instance(self):
        config = {
            "control_plane": {"postgres_dsn": "postgresql://localhost/sift"},
            "token_registry": {"pepper": "my-pepper"},
        }
        reg = create_token_registry(config)
        assert reg is not None
        assert hasattr(reg, "lookup_token")
