"""Fail-closed contract tests for the OpenCTI shared-search target path."""

from __future__ import annotations

import subprocess

from _installer_support import REPO_ROOT

SHARED_COMPOSE = REPO_ROOT / "docker-compose.opencti-shared.yml"
ROLE = REPO_ROOT / "configs" / "opensearch" / "security" / "opencti-platform-role.yml"
CHECK = REPO_ROOT / "scripts" / "prepare-opencti-shared-opensearch.sh"
SETUP = REPO_ROOT / "scripts" / "setup-addon.sh"


def test_shared_compose_has_no_dedicated_search_and_keeps_tls_prefix_boundary() -> None:
    source = SHARED_COMPOSE.read_text(encoding="utf-8")
    assert "opencti-opensearch" not in source
    assert "ELASTICSEARCH__ENGINE_SELECTOR=opensearch" in source
    assert "ELASTICSEARCH__ENGINE_CHECK=true" in source
    assert "ELASTICSEARCH__INDEX_PREFIX=opencti" in source
    assert "ELASTICSEARCH__SSL__REJECT_UNAUTHORIZED=true" in source
    assert "external: true" in source
    assert "internal: true" in source
    assert "127.0.0.1:8080:8080" in source
    assert "RABBITMQ__PASSWORD=${OPENCTI_RABBITMQ_PASSWORD" in source
    assert "MINIO__SECRET_KEY=${OPENCTI_MINIO_SECRET_KEY" in source
    assert "OPENCTI_TOKEN=${OPENCTI_WORKER_TOKEN" in source
    assert "RABBITMQ_DEFAULT_PASS=${OPENCTI_RABBITMQ_PASSWORD" in source
    assert "MINIO_ROOT_PASSWORD=${OPENCTI_MINIO_SECRET_KEY" in source
    assert "RABBITMQ__PASSWORD=${OPENCTI_ADMIN_TOKEN" not in source
    assert "MINIO__SECRET_KEY=${OPENCTI_ADMIN_TOKEN" not in source


def test_opencti_role_is_prefix_only_and_not_security_admin() -> None:
    source = ROLE.read_text(encoding="utf-8")
    assert "opencti*" in source
    for forbidden in ("all_access", "readall", "restapi:admin", "index_patterns: ['*']"):
        assert forbidden not in source
    assert "indices_all" in source


def test_shared_check_is_read_only_and_requires_secure_core_contract() -> None:
    source = CHECK.read_text(encoding="utf-8")
    assert "docker compose -f \"$shared_compose\" config --quiet" in source
    assert "docker compose.* up" not in source
    assert "docker compose.* down" not in source
    result = subprocess.run(
        ["bash", str(CHECK), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "must be an immutable @sha256 image reference" in result.stderr
    assert "OPENSEARCH_INITIAL_ADMIN_PASSWORD" in source
    assert "https://localhost:9200" in source


def test_external_helper_exposes_only_explicit_shared_check() -> None:
    source = SETUP.read_text(encoding="utf-8")
    assert "--shared-opensearch-check" in source
    assert "prepare-opencti-shared-opensearch.sh" in source
    assert 'source "$REPO_ROOT/install.sh"' not in source
