from __future__ import annotations

import pytest

from sift_gateway.mcp_backends_registry import (
    BackendRegistryError,
    normalize_connection_config,
    resolve_runtime_config,
)


def test_http_backend_stores_only_credential_references():
    stored = normalize_connection_config(
        {
            "type": "http",
            "url": "https://backend.example/mcp",
            "bearer_token_env": "SIFT_BACKEND_TOKEN",
            "tls_cert_env": "SIFT_BACKEND_TLS_CERT",
        }
    )

    assert stored == {
        "type": "http",
        "url": "https://backend.example/mcp",
        "bearer_token_env": "SIFT_BACKEND_TOKEN",
        "tls_cert_env": "SIFT_BACKEND_TLS_CERT",
    }
    assert "bearer_token" not in stored
    assert "tls_cert" not in stored

    runtime = resolve_runtime_config(
        stored,
        environ={
            "SIFT_BACKEND_TOKEN": "token-value",
            "SIFT_BACKEND_TLS_CERT": "/run/sift/backend-ca.pem",
        },
    )

    assert runtime["bearer_token"] == "token-value"
    assert runtime["tls_cert"] == "/run/sift/backend-ca.pem"


def test_stdio_env_refs_resolve_to_runtime_env_only():
    stored = normalize_connection_config(
        {
            "type": "stdio",
            "command": "/opt/backend/bin/server",
            "args": ["--stdio"],
            "env_refs": {
                "BACKEND_API_TOKEN": "SIFT_BACKEND_API_TOKEN",
                "BACKEND_PROFILE": "SIFT_BACKEND_PROFILE",
            },
        }
    )

    assert stored["env_refs"] == {
        "BACKEND_API_TOKEN": "SIFT_BACKEND_API_TOKEN",
        "BACKEND_PROFILE": "SIFT_BACKEND_PROFILE",
    }
    assert "env" not in stored

    runtime = resolve_runtime_config(
        stored,
        environ={
            "SIFT_BACKEND_API_TOKEN": "secret-token",
            "SIFT_BACKEND_PROFILE": "lab",
        },
    )

    assert runtime["env"] == {
        "BACKEND_API_TOKEN": "secret-token",
        "BACKEND_PROFILE": "lab",
    }


@pytest.mark.parametrize("raw_key", ["bearer_token", "tls_cert", "env", "headers", "password"])
def test_raw_secret_connection_fields_are_rejected(raw_key):
    config = {"type": "http", "url": "https://backend.example/mcp", raw_key: "secret"}

    with pytest.raises(BackendRegistryError, match="raw backend secret fields"):
        normalize_connection_config(config)


def test_missing_runtime_env_reference_blocks_backend_load():
    stored = normalize_connection_config(
        {
            "type": "http",
            "url": "https://backend.example/mcp",
            "bearer_token_env": "SIFT_BACKEND_TOKEN",
        }
    )

    with pytest.raises(BackendRegistryError, match="missing environment variable"):
        resolve_runtime_config(stored, environ={})
