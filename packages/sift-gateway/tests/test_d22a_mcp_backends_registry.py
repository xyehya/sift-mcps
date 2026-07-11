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


def test_stdio_command_whitespace_is_stripped():
    # B-MVP-035: a stray trailing/leading space pasted into the portal register
    # form must be trimmed before storage. Untrimmed, the space reached spawn as
    # a non-existent executable path (FileNotFoundError) and hung tools/list.
    stored = normalize_connection_config(
        {
            "type": "stdio",
            "command": "  /opt/backend/bin/server  ",
            "args": [" --stdio ", "  --flag"],
        }
    )

    assert stored["command"] == "/opt/backend/bin/server"
    assert stored["args"] == ["--stdio", "--flag"]


def test_stdio_command_only_whitespace_is_rejected():
    # A command that is nothing but whitespace strips to empty -> must fail the
    # same "stdio backend requires command" guard, not silently store "".
    with pytest.raises(BackendRegistryError, match="stdio backend requires command"):
        normalize_connection_config({"type": "stdio", "command": "   "})


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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bearer_token_env", "SIFT_CONTROL_PLANE_DSN"),
        ("tls_cert_env", "SUPABASE_SERVICE_ROLE_KEY"),
        ("bearer_token_env", "VENDOR_DATABASE_DSN"),
    ],
)
def test_http_refs_reject_gateway_authority_credentials(field, value):
    with pytest.raises(BackendRegistryError, match="gateway authority credential"):
        normalize_connection_config(
            {"type": "http", "url": "https://backend.example/mcp", field: value}
        )


@pytest.mark.parametrize(
    "env_refs",
    [
        {"BACKEND_DSN": "SIFT_BACKEND_API_TOKEN"},
        {"BACKEND_DATABASE_URL": "SIFT_BACKEND_API_TOKEN"},
        {"BACKEND_TOKEN": "SIFT_AUDIT_WRITER_DSN"},
        {"SUPABASE_ANON_KEY": "SIFT_BACKEND_API_TOKEN"},
    ],
)
def test_stdio_refs_reject_authority_source_and_target_names(env_refs):
    with pytest.raises(BackendRegistryError, match="gateway authority credential"):
        normalize_connection_config(
            {
                "type": "stdio",
                "command": "/opt/backend/bin/server",
                "env_refs": env_refs,
            }
        )


def test_unknown_gateway_env_ref_namespace_is_rejected():
    with pytest.raises(BackendRegistryError, match="approved add-on credential namespace"):
        normalize_connection_config(
            {
                "type": "stdio",
                "command": "/opt/backend/bin/server",
                "env_refs": {"BACKEND_TOKEN": "UNSCOPED_GATEWAY_TOKEN"},
            }
        )


@pytest.mark.parametrize(
    "connection",
    [
        {
            "type": "stdio",
            "command": "/opt/backend/bin/server",
            "env_refs": {"BACKEND_TOKEN": "SIFT_CONTROL_PLANE_DSN"},
        },
        {
            "type": "http",
            "url": "https://backend.example/mcp",
            "bearer_token_env": "SIFT_AUDIT_WRITER_DSN",
        },
        {
            "type": "http",
            "url": "https://backend.example/mcp",
            "tls_cert_env": "SUPABASE_SERVICE_ROLE_KEY",
        },
    ],
)
def test_runtime_rejects_persisted_authority_reference_bypass(connection):
    with pytest.raises(BackendRegistryError, match="gateway authority credential"):
        resolve_runtime_config(
            connection,
            environ={
                "SIFT_CONTROL_PLANE_DSN": "postgresql://authority",
                "SIFT_AUDIT_WRITER_DSN": "postgresql://audit",
                "SUPABASE_SERVICE_ROLE_KEY": "service-role",
            },
        )


def test_legitimate_opencti_and_opensearch_refs_remain_allowed():
    stored = normalize_connection_config(
        {
            "type": "stdio",
            "command": "/opt/backend/bin/server",
            "env_refs": {
                "OPENCTI_TOKEN": "SIFT_OPENCTI_TOKEN",
                "OPENCTI_URL": "SIFT_OPENCTI_URL",
                "OPENSEARCH_CONFIG": "OPENSEARCH_CONFIG",
                "OPENSEARCH_HOST": "OPENSEARCH_HOST",
            },
        }
    )
    runtime = resolve_runtime_config(
        stored,
        environ={
            "SIFT_OPENCTI_TOKEN": "token",
            "SIFT_OPENCTI_URL": "https://opencti.example",
            "OPENSEARCH_CONFIG": "/var/lib/sift/.sift/opensearch.yaml",
            "OPENSEARCH_HOST": "https://127.0.0.1:9200",
        },
    )
    assert set(runtime["env"]) == {
        "OPENCTI_TOKEN",
        "OPENCTI_URL",
        "OPENSEARCH_CONFIG",
        "OPENSEARCH_HOST",
    }
